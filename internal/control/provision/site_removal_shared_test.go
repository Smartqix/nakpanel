package provision

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/workspace"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
	"strings"
	"testing"
)

func removalDNSZone(t *testing.T, db *sql.DB, siteID int64, domain, mode string, parent any) int64 {
	t.Helper()
	var id int64
	if err := db.QueryRow(`INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,mode,parent_zone_id,template_revision,status) SELECT owner_user_id,id,$2,'192.0.2.1',1,$3,$4,(SELECT revision.revision FROM dns_template_revisions revision JOIN dns_template_state state ON state.active_revision_id=revision.id WHERE state.singleton),'active' FROM sites WHERE id=$1 RETURNING id`, siteID, domain, mode, parent).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRemoveChildPreservesParentZone(t *testing.T) {
	db, service, actor, req := removalServiceFixture(t)
	var primary int64
	db.QueryRow("SELECT primary_site_id FROM subscriptions WHERE id=1").Scan(&primary)
	zone := removalDNSZone(t, db, primary, "primary.test", "primary", nil)
	// The add-on is independent; give its child a parent-owned zone.
	addonZone := removalDNSZone(t, db, req.SiteID, "addon.test", "primary", nil)
	var child int64
	db.QueryRow("SELECT id FROM sites WHERE parent_site_id=$1", req.SiteID).Scan(&child)
	removalDNSZone(t, db, child, "child.addon.test", "disabled", addonZone)
	if _, err := db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl) VALUES($1,$2,'child','A','192.0.2.1',3600),($1,NULL,'unrelated','TXT','keep-me',3600),($3,NULL,'unrelated','TXT','primary-keep',3600)`, addonZone, child, zone); err != nil {
		t.Fatal(err)
	}
	preview, err := service.PreviewSiteRemoval(context.Background(), actor, child)
	if err != nil {
		t.Fatal(err)
	}
	req = types.RemoveSiteReq{SiteID: child, RequestID: strings.Repeat("b", 32), PreviewDigest: preview.Digest, ConfirmDomain: preview.Domain, AcknowledgePermanent: true}
	op, err := service.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	shared := NewSiteRemovalSharedServices(db, nil, nil)
	if err = shared.prepareDNS(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	var remaining int
	db.QueryRow("SELECT count(*) FROM dns_records WHERE value IN ('keep-me','primary-keep')").Scan(&remaining)
	if remaining != 2 {
		t.Fatal("unrelated records changed")
	}
	db.QueryRow("SELECT count(*) FROM dns_records WHERE owner_site_id=$1", child).Scan(&remaining)
	if remaining != 0 {
		t.Fatal("child-owned record survives")
	}
	db.QueryRow("SELECT count(*) FROM dns_zones WHERE id IN ($1,$2)", zone, addonZone).Scan(&remaining)
	if remaining != 2 {
		t.Fatal("parent zone removed")
	}
	if err = shared.prepareDNS(context.Background(), op); err != nil {
		t.Fatal("idempotent DNS preparation", err)
	}
}

func TestRemoveRootPreservesSiblingDNS(t *testing.T) {
	db, service, actor, req := removalServiceFixture(t)
	var primary int64
	db.QueryRow("SELECT primary_site_id FROM subscriptions WHERE id=1").Scan(&primary)
	siblingZone := removalDNSZone(t, db, primary, "primary.test", "primary", nil)
	removalDNSZone(t, db, req.SiteID, "addon.test", "primary", nil)
	preview, err := service.PreviewSiteRemoval(context.Background(), actor, req.SiteID)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.Digest
	op, err := service.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	if err = NewSiteRemovalSharedServices(db, nil, nil).prepareDNS(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	var serial int64
	if err = db.QueryRow("SELECT serial FROM dns_zones WHERE id=$1", siblingZone).Scan(&serial); err != nil || serial != 1 {
		t.Fatal("sibling DNS changed", serial, err)
	}
}

func TestRemovalBlocksSurvivingDNSDependents(t *testing.T) {
	db := removaldb.New(t, "")
	removaldb.Site(t, db, 1, "primary.test", nil)
	addon := removaldb.Site(t, db, 1, "addon.test", nil)
	independent := removaldb.Site(t, db, 1, "other.addon.test", nil)
	zone := removalDNSZone(t, db, addon, "addon.test", "primary", nil)
	removalDNSZone(t, db, independent, "other.addon.test", "disabled", zone)
	preview, err := NewSiteRemovalService(db, nil, workspace.NewStore(db), SiteRemovalOptions{}).PreviewSiteRemoval(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, addon)
	if err != nil || preview.Allowed {
		t.Fatalf("surviving DNS dependent unprotected: %#v %v", preview, err)
	}
}

func TestRemovalRejectsManualExactDNSHostAndServiceDependencies(t *testing.T) {
	db, service, actor, req := removalServiceFixture(t)
	var primary int64
	db.QueryRow("SELECT primary_site_id FROM subscriptions WHERE id=1").Scan(&primary)
	zone := removalDNSZone(t, db, primary, "primary.test", "primary", nil)
	// A child of the primary uses unowned exact-host records too.
	child := removaldb.Site(t, db, 1, "child.primary.test", primary)
	preview, err := service.PreviewSiteRemoval(context.Background(), actor, child)
	if err != nil {
		t.Fatal(err)
	}
	req = types.RemoveSiteReq{SiteID: child, RequestID: strings.Repeat("c", 32), PreviewDigest: preview.Digest, ConfirmDomain: preview.Domain, AcknowledgePermanent: true}
	if _, err = service.RemoveSiteFor(context.Background(), actor, req); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO dns_records(zone_id,host,record_type,value,ttl) VALUES($1,'child','TXT','must-not-add',3600)`, zone); err == nil {
		t.Fatal("manual exact-host mutation during removal")
	}
	if _, err = db.Exec(`UPDATE mail_settings SET mail_hostname='mail.child.primary.test' WHERE id`); err == nil {
		t.Fatal("new server dependency during removal")
	}
	if _, err = db.Exec(`INSERT INTO dns_records(zone_id,host,record_type,value,ttl) VALUES($1,'other','TXT','unrelated-allowed',3600)`, zone); err != nil {
		t.Fatal("unrelated parent record blocked", err)
	}
}

func TestRemovalStagingMetadataWithTwoApprovedEndpoints(t *testing.T) {
	db, service, actor, req := removalServiceFixture(t)
	other := removaldb.Site(t, db, 1, "other.test", nil)
	var staging int64
	if err := db.QueryRow(`INSERT INTO staging_operations(source_site_id,target_site_id,direction,status) VALUES($1,$2,'copy_to_staging','succeeded') RETURNING id`, req.SiteID, other).Scan(&staging); err != nil {
		t.Fatal(err)
	}
	preview, err := service.PreviewSiteRemoval(context.Background(), actor, req.SiteID)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.Digest
	first, err := service.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	preview, err = service.PreviewSiteRemoval(context.Background(), actor, other)
	if err != nil {
		t.Fatal(err)
	}
	secondReq := types.RemoveSiteReq{SiteID: other, RequestID: strings.Repeat("d", 32), PreviewDigest: preview.Digest, ConfirmDomain: preview.Domain, AcknowledgePermanent: true}
	if _, err = service.RemoveSiteFor(context.Background(), actor, secondReq); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec("SELECT set_config('nakpanel.site_removal_operation',$1,true)", fmt.Sprint(first.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("DELETE FROM staging_operations WHERE id=$1", staging); err != nil {
		t.Fatal("approved metadata blocked by independently removing endpoint", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestRemovalRejectsStaleSharedSnapshots(t *testing.T) {
	db, service, actor, req := removalServiceFixture(t)
	op, err := service.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE site_removal_operations SET state='failed',revision=revision+1 WHERE id=$1", op.ID); err != nil {
		t.Fatal(err)
	}
	if err = NewSiteRemovalSharedServices(db, nil, nil).prepareDNS(context.Background(), op); err == nil {
		t.Fatal("stale shared intent acknowledged")
	}
}
