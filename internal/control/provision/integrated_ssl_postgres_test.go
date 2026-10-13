package provision

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/store"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
)

// Explicit isolated database gate: never exercise mutation fixtures against the live panel.
func TestIntegratedSSLPostgreSQLRecovery(t *testing.T) {
	dsn := os.Getenv("NAKPANEL_SSL_TEST_DSN")
	if dsn == "" {
		t.Skip("requires migrated nakpanel_ssl_test database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var name string
	if err = db.QueryRow(`SELECT current_database()`).Scan(&name); err != nil || name != "nakpanel_ssl_test" {
		t.Fatalf("isolated database required: %q %v", name, err)
	}
	ctx := context.Background()
	var sub, customer, actor int64
	if err = db.QueryRow(`SELECT sub.id,sub.customer_id,COALESCE(customer.login_user_id,1) FROM subscriptions sub
 JOIN customers customer ON customer.id=sub.customer_id JOIN subscription_entitlements e ON e.subscription_id=sub.id
 JOIN subscription_system_accounts account ON account.subscription_id=sub.id
 WHERE sub.status='active' AND customer.status='active' AND e.allow_tls LIMIT 1`).Scan(&sub, &customer, &actor); err != nil {
		t.Fatal(err)
	}
	client, err := river.NewClient(riverdatabasesql.New(db), &river.Config{})
	if err != nil {
		t.Fatal(err)
	}
	quota := controlquota.NewSQLStore(db, client)
	policy, err := quota.EffectiveSubscriptionPolicy(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewSQLSiteRepository(db, store.New(db), client)
	id, err := repo.CreateSite(ctx, actor, types.CreateSiteReq{SubscriptionID: sub, Domain: "ssl-integration.example.test", PHPVersion: policy.PHP.DefaultVersion, SecureWithSSL: true, RequestedByUserID: actor, Limits: controlquota.SiteResourceLimitsFromPolicy(policy)})
	if err != nil {
		t.Fatal(err)
	}
	var requested bool
	var tls string
	var count int
	if err = db.QueryRow(`SELECT ssl_setup_requested,tls_status FROM sites WHERE id=$1`, id).Scan(&requested, &tls); err != nil || !requested || tls != "pending" {
		t.Fatalf("durable intent=%v TLS=%s %v", requested, tls, err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM river_job WHERE kind IN('create_site','issue_cert') AND args->>'site_id'=$1`, strconv.FormatInt(id, 10)).Scan(&count); err != nil || count != 2 {
		t.Fatalf("atomic jobs=%d error=%v", count, err)
	}
	if _, err = db.Exec(`CREATE FUNCTION reject_ssl_job() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected SSL enqueue failure'; END $$;
CREATE TRIGGER reject_ssl_job BEFORE INSERT ON river_job FOR EACH ROW WHEN(NEW.kind='issue_cert') EXECUTE FUNCTION reject_ssl_job()`); err != nil {
		t.Fatal(err)
	}
	_, err = repo.CreateSite(ctx, actor, types.CreateSiteReq{SubscriptionID: sub, Domain: "ssl-rollback.example.test", PHPVersion: policy.PHP.DefaultVersion, SecureWithSSL: true, RequestedByUserID: actor, Limits: controlquota.SiteResourceLimitsFromPolicy(policy)})
	if err == nil {
		t.Fatal("injected SSL enqueue did not roll back")
	}
	if err = db.QueryRow(`SELECT count(*) FROM sites WHERE domain='ssl-rollback.example.test'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial creation committed: %d %v", count, err)
	}
	if _, err = db.Exec(`DROP TRIGGER reject_ssl_job ON river_job;DROP FUNCTION reject_ssl_job()`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE river_job SET state='cancelled',finalized_at=now() WHERE kind='issue_cert'`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sites SET status='active' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	preflight := NewSQLProvisioningCertificateSetup(db, client)
	prepared, err := preflight.PrepareProvisionedCertificate(ctx, IssueCertArgs{SiteID: id, SubscriptionID: sub, CustomerID: customer, Domain: "ssl-integration.example.test", AfterProvisioning: true})
	if err != nil || !prepared.Ready {
		t.Fatalf("external DNS must reach public challenge preflight: %#v %v", prepared, err)
	}
	if _, err = db.Exec(`UPDATE sites SET status='active',tls_status='active',tls_issuer='acme',tls_expires_at=$2,tls_cert_path='/test/cert.pem',tls_key_path='/test/key.pem',settings_status='failed',settings_error='nginx reload failed' WHERE id=$1`, id, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.RetryCreationSSL(ctx, actor, "ssl-integration.example.test"); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT tls_status FROM sites WHERE id=$1`, id).Scan(&tls); err != nil || tls != "active" {
		t.Fatalf("HTTPS retry lost installed certificate: %s %v", tls, err)
	}
	setup := NewSQLProvisioningCertificateSetup(db, client)
	state, err := setup.PrepareProvisionedCertificate(ctx, IssueCertArgs{SiteID: id, SubscriptionID: sub, CustomerID: customer, Domain: "ssl-integration.example.test", AfterProvisioning: true})
	if err != nil || !state.Installed {
		t.Fatalf("retry preparation=%#v error=%v", state, err)
	}
	if err = setup.EnableProvisionedHTTPS(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sites SET settings_status='in_sync',https_redirect=true WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM river_job WHERE kind='issue_cert'`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE river_job SET state='completed',finalized_at=now() WHERE kind='create_site'`); err != nil {
		t.Fatal(err)
	}
	result, err := repo.ReadSiteSetup(ctx, id)
	if err != nil || !result.SSLRequested || result.State != "ready" {
		t.Fatalf("history-independent setup=%#v error=%v", result, err)
	}
	if _, err = db.Exec(`UPDATE sites SET desired_status='suspended',desired_php_version='8.5' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err = setup.EnableProvisionedHTTPS(ctx, id); err == nil {
		t.Fatal("HTTPS setup reactivated suspended site")
	}
	var desired, php string
	if err = db.QueryRow(`SELECT desired_status,desired_php_version FROM sites WHERE id=$1`, id).Scan(&desired, &php); err != nil || desired != "suspended" || php != "8.5" {
		t.Fatalf("intent overwritten: %s %s %v", desired, php, err)
	}
}
