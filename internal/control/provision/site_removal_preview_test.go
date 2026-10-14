package provision

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/workspace"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
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

type removalDatabaseInspectorFixture struct{}

func (removalDatabaseInspectorFixture) InspectDatabaseAdmin(context.Context, types.InspectDatabaseAdminReq) (types.DatabaseAdminSnapshot, error) {
	return types.DatabaseAdminSnapshot{Databases: []types.TrackedDatabaseState{{DatabaseID: 1, OwnershipVerified: false}}}, nil
}
func TestSiteRemovalUnverifiedDatabaseIsKept(t *testing.T) {
	db := removaldb.New(t, "")
	removaldb.Site(t, db, 1, "primary.test", nil)
	addon := removaldb.Site(t, db, 1, "addon.test", nil)
	if _, err := db.Exec("INSERT INTO databases(owner_user_id,customer_id,subscription_id,site_id,engine,db_name,db_user,status) SELECT owner_user_id,customer_id,subscription_id,id,'mariadb','fixture_db','fixture_user','active' FROM sites WHERE id=$1", addon); err != nil {
		t.Fatal(err)
	}
	service := NewSiteRemovalService(db, nil, workspace.NewStore(db), SiteRemovalOptions{DatabaseInspector: removalDatabaseInspectorFixture{}})
	preview, err := service.PreviewSiteRemoval(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, addon)
	if err != nil || !preview.Allowed || len(preview.Snapshot.Databases) != 1 || preview.Snapshot.Databases[0].DeletionEligible || preview.Snapshot.Databases[0].IneligibleReason == "" {
		t.Fatalf("unverified database selectable: %#v %v", preview, err)
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

func TestSiteRemovalRetainsSiblingConnectionBindings(t *testing.T) {
	for _, binding := range []struct{ name, value string }{
		{"DATABASE_URL", "mysql://user:private-password@localhost/fixture_db"},
		{"DB_DSN", "mysql:host=localhost;dbname=fixture_db"},
		{"DATABASE_DSN", "user:private-password@tcp(localhost:3306)/fixture_db"},
	} {
		t.Run(binding.name, func(t *testing.T) {
			db, service, actor, req := removalServiceFixture(t)
			if _, err := db.Exec(`INSERT INTO databases(owner_user_id,customer_id,subscription_id,site_id,engine,db_name,db_user,status) SELECT owner_user_id,customer_id,subscription_id,id,'mariadb','fixture_db','fixture_user','active' FROM sites WHERE id=$1`, req.SiteID); err != nil {
				t.Fatal(err)
			}
			var appID int64
			if err := db.QueryRow(`SELECT id FROM php_applications WHERE site_id=(SELECT id FROM sites WHERE domain='primary.test')`).Scan(&appID); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO php_environment_bindings(subscription_id,application_id,name,plain_value) VALUES(1,$1,$2,$3)`, appID, binding.name, binding.value); err != nil {
				t.Fatal(err)
			}
			p, err := service.PreviewSiteRemoval(context.Background(), actor, req.SiteID)
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Snapshot.Databases) != 1 || p.Snapshot.Databases[0].DeletionEligible {
				t.Fatal("surviving application's database remained selectable")
			}
			encoded, _ := json.Marshal(p)
			if strings.Contains(string(encoded), "private-password") {
				t.Fatal("database binding leaked into preview")
			}
		})
	}
}

func TestSiteRemovalFreezesNewSiblingDatabaseBindings(t *testing.T) {
	db, service, actor, req := removalServiceFixture(t)
	var databaseID, appID int64
	if err := db.QueryRow(`INSERT INTO databases(owner_user_id,customer_id,subscription_id,site_id,engine,db_name,db_user,status) SELECT owner_user_id,customer_id,subscription_id,id,'mariadb','fixture_db','fixture_user','active' FROM sites WHERE id=$1 RETURNING id`, req.SiteID).Scan(&databaseID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT id FROM php_applications WHERE site_id=(SELECT id FROM sites WHERE domain='primary.test')`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	p, err := service.PreviewSiteRemoval(context.Background(), actor, req.SiteID)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = p.Digest
	req.DeleteDatabaseIDs = []int64{databaseID}
	if _, err = service.RemoveSiteFor(context.Background(), actor, req); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO php_environment_bindings(subscription_id,application_id,name,plain_value) VALUES(1,$1,'DATABASE_URL','mysql://localhost/fixture_db')`, appID); err == nil {
		t.Fatal("new sibling database consumer accepted after destructive scope was reserved")
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
