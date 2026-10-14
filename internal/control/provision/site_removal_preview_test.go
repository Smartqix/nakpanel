package provision

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/workspace"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"strings"
	"testing"
)

func TestSiteRemovalProtectedPrimaryAndHostname(t *testing.T) {
	db := removaldb.New(t, "")
	primary := removaldb.Site(t, db, 1, "primary.test", nil)
	host := removaldb.Site(t, db, 1, "panel.test", nil)
	service := NewSiteRemovalService(db, nil, workspace.NewStore(db), SiteRemovalOptions{PanelHostname: "panel.test"})
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	for _, id := range []int64{primary, host} {
		preview, err := service.PreviewSiteRemoval(context.Background(), actor, id)
		if err != nil || preview.Allowed || len(preview.BlockedReasons) == 0 {
			t.Fatalf("protected preview=%#v %v", preview, err)
		}
	}
}

type removalDependenciesFixture struct{}

func (removalDependenciesFixture) SiteServiceDependencies(context.Context) ([]string, error) {
	return []string{"ftp.test"}, nil
}
func TestSiteRemovalProtectsTrustedAgentDependencies(t *testing.T) {
	db := removaldb.New(t, "")
	removaldb.Site(t, db, 1, "primary.test", nil)
	addon := removaldb.Site(t, db, 1, "ftp.test", nil)
	service := NewSiteRemovalService(db, nil, workspace.NewStore(db), SiteRemovalOptions{Dependencies: removalDependenciesFixture{}})
	preview, err := service.PreviewSiteRemoval(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, addon)
	if err != nil || preview.Allowed {
		t.Fatalf("server dependency not protected: %#v %v", preview, err)
	}
}

func TestSiteRemovalPreviewKeepsDataByDefault(t *testing.T) {
	db := removaldb.New(t, "")
	removaldb.Site(t, db, 1, "primary.test", nil)
	addon := removaldb.Site(t, db, 1, "addon.test", nil)
	removaldb.Site(t, db, 1, "child.addon.test", addon)
	if _, err := db.Exec(`INSERT INTO databases(owner_user_id,customer_id,subscription_id,site_id,engine,db_name,db_user,status)
 SELECT owner_user_id,customer_id,subscription_id,id,'mariadb','fixture_db','fixture_user','active' FROM sites WHERE id=$1`, addon); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO backups(owner_user_id,customer_id,subscription_id,site_id,target_kind,target_name,status)
 SELECT owner_user_id,customer_id,subscription_id,id,'site',domain,'active' FROM sites WHERE id=$1`, addon); err != nil {
		t.Fatal(err)
	}
	service := NewSiteRemovalService(db, nil, workspace.NewStore(db), SiteRemovalOptions{PanelHostname: "panel.test"})
	preview, err := service.PreviewSiteRemoval(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, addon)
	if err != nil || !preview.Allowed || len(preview.Snapshot.Sites) != 2 || len(preview.Snapshot.Databases) != 1 || len(preview.Snapshot.Backups) != 1 {
		t.Fatalf("preview=%#v %v", preview, err)
	}
}

func TestSiteRemovalCrossScopeNotFound(t *testing.T) {
	db := removaldb.New(t, "")
	removaldb.Site(t, db, 1, "primary.test", nil)
	addon := removaldb.Site(t, db, 1, "addon.test", nil)
	service := NewSiteRemovalService(db, nil, workspace.NewStore(db), SiteRemovalOptions{})
	_, err := service.PreviewSiteRemoval(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, addon)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-scope=%v", err)
	}
}

func TestSiteRemovalProviderCanCleanSuspendedCustomer(t *testing.T) {
	db := removaldb.New(t, "")
	removaldb.Site(t, db, 1, "primary.test", nil)
	addon := removaldb.Site(t, db, 1, "addon.test", nil)
	if _, err := db.Exec("UPDATE customers SET status='suspended' WHERE id=(SELECT customer_id FROM subscriptions WHERE id=1)"); err != nil {
		t.Fatal(err)
	}
	service := NewSiteRemovalService(db, nil, workspace.NewStore(db), SiteRemovalOptions{})
	preview, err := service.PreviewSiteRemoval(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, addon)
	if err != nil || !preview.Allowed {
		t.Fatalf("provider cleanup=%#v %v", preview, err)
	}
}

func TestSiteRemovalProtectsServerDNSDependency(t *testing.T) {
	db := removaldb.New(t, "")
	removaldb.Site(t, db, 1, "primary.test", nil)
	addon := removaldb.Site(t, db, 1, "nameservers.test", nil)
	if _, err := db.Exec(`WITH revision AS (INSERT INTO dns_template_revisions(revision,primary_nameserver,responsible_mailbox)
 SELECT MAX(revision)+1,'ns1.nameservers.test','admin.nameservers.test' FROM dns_template_revisions RETURNING id)
 UPDATE dns_template_state SET active_revision_id=(SELECT id FROM revision) WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	service := NewSiteRemovalService(db, nil, workspace.NewStore(db), SiteRemovalOptions{})
	preview, err := service.PreviewSiteRemoval(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, addon)
	if err != nil || preview.Allowed {
		t.Fatalf("DNS dependency=%#v %v", preview, err)
	}
}

func TestSiteRemovalRejectsCorruptChildTree(t *testing.T) {
	db := removaldb.New(t, "")
	removaldb.Site(t, db, 1, "primary.test", nil)
	addon := removaldb.Site(t, db, 1, "addon.test", nil)
	foreign := removaldb.Site(t, db, 2, "foreign.test", nil)
	// Corrupt historic ownership cannot become an expanded deletion scope.
	if _, err := db.Exec("UPDATE subscriptions SET primary_site_id=NULL WHERE id=2"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE sites SET parent_site_id=$1 WHERE id=$2", addon, foreign); err != nil {
		t.Fatal(err)
	}
	service := NewSiteRemovalService(db, nil, workspace.NewStore(db), SiteRemovalOptions{})
	if _, err := service.PreviewSiteRemoval(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, addon); err == nil {
		t.Fatal("foreign descendant accepted")
	}
}

func TestSiteRemovalPreviewSecrecyAndChangedScope(t *testing.T) {
	db := removaldb.New(t, "")
	removaldb.Site(t, db, 1, "primary.test", nil)
	addon := removaldb.Site(t, db, 1, "addon.test", nil)
	var gitID int64
	if err := db.QueryRow("INSERT INTO git_repositories(site_id,mode,remote_url,deploy_key_ciphertext) VALUES($1,'remote','https://git.example.test/project.git',convert_to('secret-marker','UTF8')) RETURNING id", addon).Scan(&gitID); err != nil {
		t.Fatal(err)
	}
	service := NewSiteRemovalService(db, nil, workspace.NewStore(db), SiteRemovalOptions{})
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	before, err := service.PreviewSiteRemoval(context.Background(), actor, addon)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range before.Snapshot.Resources {
		if item.Kind == "git" && item.ID == gitID {
			found = true
		}
	}
	if !found {
		t.Fatal("Git inventory missing")
	}
	encoded, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-marker") || strings.Contains(string(encoded), "remote_url") {
		t.Fatal("private/source data leaked")
	}
	again, err := service.PreviewSiteRemoval(context.Background(), actor, addon)
	if err != nil || again.Digest != before.Digest {
		t.Fatalf("unchanged preview unstable: %v", err)
	}
	removaldb.Site(t, db, 1, "new.addon.test", addon)
	after, err := service.PreviewSiteRemoval(context.Background(), actor, addon)
	if err != nil || after.Digest == before.Digest {
		t.Fatalf("expanded scope retained approval: %v", err)
	}
}

func TestSiteRemovalNonstandardRootIsBlocked(t *testing.T) {
	db := removaldb.New(t, "")
	removaldb.Site(t, db, 1, "primary.test", nil)
	addon := removaldb.Site(t, db, 1, "addon.test", nil)
	if _, err := db.Exec("UPDATE sites SET document_root='/unmanaged/content' WHERE id=$1", addon); err != nil {
		t.Fatal(err)
	}
	service := NewSiteRemovalService(db, nil, workspace.NewStore(db), SiteRemovalOptions{})
	preview, err := service.PreviewSiteRemoval(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, addon)
	if err != nil || preview.Allowed || len(preview.BlockedReasons) == 0 {
		t.Fatalf("nonstandard root allowed: %#v %v", preview, err)
	}
}

func TestSiteRemovalRejectsForeignParent(t *testing.T) {
	db := removaldb.New(t, "")
	parent := removaldb.Site(t, db, 1, "parent.test", nil)
	removaldb.Site(t, db, 2, "primary.test", nil)
	child := removaldb.Site(t, db, 2, "child.parent.test", parent)
	service := NewSiteRemovalService(db, nil, workspace.NewStore(db), SiteRemovalOptions{})
	if _, err := service.PreviewSiteRemoval(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, child); err == nil {
		t.Fatal("foreign parent accepted")
	}
}

func TestSiteRemovalLegacyMailDomainAndDNSChanges(t *testing.T) {
	db := removaldb.New(t, "")
	removaldb.Site(t, db, 1, "primary.test", nil)
	addon := removaldb.Site(t, db, 1, "addon.test", nil)
	if _, err := db.Exec("INSERT INTO mail_domains(subscription_id,domain) VALUES(1,'addon.test')"); err != nil {
		t.Fatal(err)
	}
	var zone int64
	if err := db.QueryRow("INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,status,template_revision) SELECT owner_user_id,id,domain,'192.0.2.1',1,'active',(SELECT active_revision_id FROM dns_template_state WHERE singleton) FROM sites WHERE id=$1 RETURNING id", addon).Scan(&zone); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO dns_records(zone_id,host,record_type,value) VALUES($1,'@','A','192.0.2.1')", zone); err != nil {
		t.Fatal(err)
	}
	service := NewSiteRemovalService(db, nil, workspace.NewStore(db), SiteRemovalOptions{})
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	before, err := service.PreviewSiteRemoval(context.Background(), actor, addon)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range before.Snapshot.Resources {
		if item.Kind == "mail_domain" && item.SiteID == addon {
			found = true
		}
	}
	if !found {
		t.Fatal("legacy linked mail domain missing")
	}
	if _, err := db.Exec("UPDATE dns_records SET value='192.0.2.2' WHERE zone_id=$1", zone); err != nil {
		t.Fatal(err)
	}
	after, err := service.PreviewSiteRemoval(context.Background(), actor, addon)
	if err != nil {
		t.Fatal(err)
	}
	if before.Digest == after.Digest {
		t.Fatal("changed DNS record retained approval")
	}
}
