package provision

import (
	"context"
	"encoding/json"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/workspace"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"strconv"
	"strings"
	"testing"
)

type removalMailExecutionAgent struct {
	controlquota.SubscriptionConvergenceAgent
	childMailDNSAgent
}

func (a removalMailExecutionAgent) EnsureSubscriptionAccount(context.Context, types.EnsureSubscriptionAccountReq) (types.Response, error) {
	return types.Response{OK: true}, nil
}
func (a removalMailExecutionAgent) ApplyScheduledTasks(context.Context, types.ApplyScheduledTasksReq) (types.Response, error) {
	return types.Response{OK: true}, nil
}
func (a removalMailExecutionAgent) EnsureFTPS(context.Context, types.EnsureFTPSReq) (types.EnsureFTPSResult, error) {
	return types.EnsureFTPSResult{}, nil
}
func (a removalMailExecutionAgent) ConfigureDNSZone(context.Context, types.ConfigureDNSZoneReq) (types.Response, error) {
	return types.Response{OK: true, Data: json.RawMessage(`{}`)}, nil
}

func TestSubdomainMailRemovalExecutesSharedServices(t *testing.T) {
	f := newChildMailLifecycleFixture(t)
	survivingMail := func() string {
		var value string
		if err := f.db.QueryRow(`SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(box) ORDER BY box.id) FROM mailboxes box JOIN mail_domains domain ON domain.id=box.mail_domain_id WHERE domain.site_id<>$1),(SELECT jsonb_agg(to_jsonb(alias) ORDER BY alias.id) FROM mail_aliases alias JOIN mail_domains domain ON domain.id=alias.mail_domain_id WHERE domain.site_id<>$1))::text`, f.child).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := survivingMail()
	dnsBefore := f.records(t, "owner_site_id<>"+strconv.FormatInt(f.child, 10))
	service := NewSiteRemovalService(f.db, f.worker.phase6.river, workspace.NewStore(f.db), SiteRemovalOptions{})
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin, Email: "admin@example.test"}
	preview, err := service.PreviewSiteRemoval(context.Background(), actor, f.child)
	if err != nil || !preview.Allowed {
		t.Fatalf("preview=%+v error=%v", preview, err)
	}
	op, err := service.RemoveSiteFor(context.Background(), actor, types.RemoveSiteReq{SiteID: f.child, RequestID: strings.Repeat("e", 32), PreviewDigest: preview.Digest, ConfirmDomain: preview.Domain, AcknowledgePermanent: true})
	if err != nil {
		t.Fatal(err)
	}
	shared := NewSiteRemovalSharedServices(f.db, removalMailExecutionAgent{}, nil)
	shared.SetRiverClient(f.worker.phase6.river)
	if err = NewRemoveSiteWorker(service, &removalAgentFixture{}, shared).Work(context.Background(), &river.Job[RemoveSiteArgs]{Args: RemoveSiteArgs{OperationID: op.ID, Revision: op.Revision}}); err != nil {
		t.Fatalf("executed child removal: %v", err)
	}
	f.visible(t, f.parent, true)
	f.visible(t, f.foreign, true)
	f.visible(t, f.sibling, false)
	if survivingMail() != before {
		t.Fatal("parent/sibling/control mail rows changed")
	}
	if f.records(t, "owner_site_id<>"+strconv.FormatInt(f.child, 10)) != dnsBefore {
		t.Fatal("parent/sibling DNS records changed")
	}
	var remaining int
	if err = f.db.QueryRow("SELECT count(*) FROM sites WHERE id=$1", f.child).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("child was not removed: %d %v", remaining, err)
	}
}
