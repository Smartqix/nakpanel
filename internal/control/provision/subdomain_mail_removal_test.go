package provision

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/workspace"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestSubdomainMailRemovalRequiresReviewedScope(t *testing.T) {
	f := newChildMailLifecycleFixture(t)
	before := f.mailData(t)
	canaries := f.records(t, "owner_site_id<>"+strconv.FormatInt(f.child, 10))
	service := NewSiteRemovalService(f.db, f.worker.phase6.river, workspace.NewStore(f.db), SiteRemovalOptions{})
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin, Email: "admin@nakpanel.test"}
	preview, err := service.PreviewSiteRemoval(context.Background(), actor, f.child)
	if err != nil || !preview.Allowed {
		t.Fatalf("preview unavailable: allowed=%t err=%v", preview.Allowed, err)
	}
	if len(preview.Snapshot.Sites) != 1 || preview.Snapshot.Sites[0].SiteID != f.child {
		t.Fatal("child removal included another site")
	}
	kinds := map[string]bool{}
	for _, resource := range preview.Snapshot.Resources {
		if resource.Kind == "mail_domain" || resource.Kind == "mailbox" || resource.Kind == "mail_alias" {
			if resource.SiteID != f.child {
				t.Fatal("foreign mail resource in child removal")
			}
			kinds[resource.Kind] = true
		}
	}
	for _, kind := range []string{"mail_domain", "mailbox", "mail_alias"} {
		if !kinds[kind] {
			t.Fatalf("preview omitted %s dependency", kind)
		}
	}
	encoded, _ := json.Marshal(preview)
	if strings.Contains(string(encoded), "preserved-fixture-hash") {
		t.Fatal("preview exposed mailbox secret")
	}
	base := types.RemoveSiteReq{SiteID: f.child, RequestID: strings.Repeat("d", 32), PreviewDigest: preview.Digest, ConfirmDomain: preview.Domain, AcknowledgePermanent: true}
	for _, invalid := range []string{"acknowledgement", "hostname", "digest"} {
		req := base
		switch invalid {
		case "acknowledgement":
			req.AcknowledgePermanent = false
		case "hostname":
			req.ConfirmDomain = "parent-mail.test"
		case "digest":
			req.PreviewDigest = "stale"
		}
		if _, err := service.RemoveSiteFor(context.Background(), actor, req); err == nil {
			t.Fatalf("unreviewed removal accepted: %s", invalid)
		}
		var count int
		if err := f.db.QueryRow(`SELECT count(*) FROM site_removal_operations`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("unconfirmed removal persisted: %d %v", count, err)
		}
		if f.mailData(t) != before {
			t.Fatal("unconfirmed removal changed mailbox data")
		}
	}
	op, err := service.RemoveSiteFor(context.Background(), actor, base)
	if err != nil {
		t.Fatal(err)
	}
	f.visible(t, f.child, false)
	f.visible(t, f.parent, true)
	f.visible(t, f.foreign, true)
	if f.mailData(t) != before || f.records(t, "owner_site_id<>"+strconv.FormatInt(f.child, 10)) != canaries {
		t.Fatal("reservation changed stored mail data or parent/sibling DNS")
	}
	var targets, audits int
	if err := f.db.QueryRow(`SELECT count(*) FROM site_removal_targets WHERE operation_id=$1 AND site_id=$2`, op.ID, f.child).Scan(&targets); err != nil || targets != 1 {
		t.Fatalf("reservation scope=%d err=%v", targets, err)
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='site.removal_requested' AND target_id=$1 AND subscription_id=1 AND customer_id=$2 AND actor_user_id=1`, op.ID, preview.CustomerID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("removal audit ownership=%d err=%v", audits, err)
	}
}
