package migrations

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"context"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func removalSchema(t *testing.T) (*sql.DB, string, string) {
	t.Helper()
	up, down := migrationSections(t, "20261013000053_domain_removal.sql")
	dsn := os.Getenv("NAKPANEL_REMOVAL_TEST_DSN")
	if dsn == "" {
		t.Skip("requires isolated nakpanel_removal_test database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	var name string
	if err = db.QueryRow("SELECT current_database()").Scan(&name); err != nil || name != "nakpanel_removal_test" {
		db.Close()
		t.Fatalf("isolated removal database required: %q %v", name, err)
	}
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("removal_%d", time.Now().UnixNano())
	if _, err = db.Exec("CREATE SCHEMA " + schema + ";SET search_path TO " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec("SET search_path TO public;DROP SCHEMA " + schema + " CASCADE"); db.Close() })
	files, err := filepath.Glob("*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if file >= "20261013000053" {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		baseline := strings.SplitN(string(data), "-- +goose Down", 2)[0]
		if _, err = db.Exec(baseline); err != nil {
			t.Fatalf("baseline %s: %v", file, err)
		}
	}
	return db, up, down
}

func removalFixture(t *testing.T, db *sql.DB) (int64, int64, int64, int64) {
	t.Helper()
	var sub, root, addon, child int64
	if err := db.QueryRow("SELECT id FROM subscriptions ORDER BY id LIMIT 1").Scan(&sub); err != nil {
		t.Fatal(err)
	}
	insert := func(domain string, parent any) int64 {
		var id int64
		err := db.QueryRow(`INSERT INTO sites(owner_user_id,subscription_id,customer_id,system_account_id,username,document_root,domain,php_version,desired_php_version,parent_site_id,status)
 SELECT s.customer_user_id,s.id,s.customer_id,account.id,account.username,account.home_path||'/domains/'||$2||'/public_html',$2,'8.4','8.4',$3,'active'
 FROM subscriptions s JOIN subscription_system_accounts account ON account.subscription_id=s.id WHERE s.id=$1 RETURNING id`, sub, domain, parent).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	root = insert("primary.example.test", nil)
	addon = insert("addon.example.test", nil)
	child = insert("child.addon.example.test", addon)
	return sub, root, addon, child
}

func TestDomainRemovalPrimaryBackfillPostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	sub, root, _, _ := removalFixture(t, db)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	var primary int64
	if err := db.QueryRow("SELECT primary_site_id FROM subscriptions WHERE id=$1", sub).Scan(&primary); err != nil || primary != root {
		t.Fatalf("primary=%d want=%d err=%v", primary, root, err)
	}
}

func TestDomainRemovalPrimaryOwnershipPostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	sub, root, _, child := removalFixture(t, db)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE subscriptions SET primary_site_id=$2 WHERE id=$1", sub, child); err == nil {
		t.Fatal("child accepted as primary")
	}
	if _, err := db.Exec("DELETE FROM sites WHERE id=$1", root); err == nil {
		t.Fatal("primary deletion accepted")
	}
	var other int64
	if err := db.QueryRow("SELECT id FROM subscriptions WHERE id<>$1 ORDER BY id LIMIT 1", sub).Scan(&other); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE subscriptions SET primary_site_id=$2 WHERE id=$1", other, root); err == nil {
		t.Fatal("foreign subscription primary accepted")
	}
}

func TestDomainRemovalMutationGuardsPostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	_, root, addon, _ := removalFixture(t, db)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE sites SET removal_state='queued' WHERE id=$1", addon); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE sites SET desired_php_version='8.5' WHERE id=$1", addon); err == nil {
		t.Fatal("removing site remained mutable")
	}
	if _, err := db.Exec("UPDATE sites SET desired_php_version='8.5' WHERE id=$1", root); err != nil {
		t.Fatalf("sibling blocked: %v", err)
	}
}

func TestDomainRemovalSchemaDownPostgreSQL(t *testing.T) {
	db, up, down := removalSchema(t)
	removalFixture(t, db)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(down); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='sites' AND column_name='removal_state'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("down count=%d err=%v", count, err)
	}
}

func TestDomainRemovalStagingDestinationGuardPostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	_, root, addon, _ := removalFixture(t, db)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE sites SET removal_state='queued' WHERE id=$1", addon); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO staging_operations(source_site_id,target_site_id,direction) VALUES($1,$2,'copy_to_staging')", root, addon); err == nil {
		t.Fatal("removed staging destination accepted")
	}
}

func TestDomainRemovalParentZoneGuardPostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	_, root, _, child := removalFixture(t, db)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	var zone int64
	if err := db.QueryRow("INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,status,template_revision) SELECT owner_user_id,id,domain,'192.0.2.1',1,'active',(SELECT active_revision_id FROM dns_template_state WHERE singleton) FROM sites WHERE id=$1 RETURNING id", root).Scan(&zone); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE sites SET removal_state='queued' WHERE id=$1", child); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl) VALUES($1,$2,'child','A','192.0.2.1',3600)", zone, child); err == nil {
		t.Fatal("removed child DNS record accepted")
	}
	if _, err := db.Exec("INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl) VALUES($1,$2,'other','A','192.0.2.1',3600)", zone, root); err != nil {
		t.Fatalf("parent zone blocked: %v", err)
	}
}

func TestDomainRemovalClaimFirstRootPostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	_, root, _, _ := removalFixture(t, db)
	var primary int64
	if err := db.QueryRow("SELECT primary_site_id FROM subscriptions WHERE id=(SELECT subscription_id FROM sites WHERE id=$1)", root).Scan(&primary); err != nil || primary != root {
		t.Fatalf("first root not claimed: %d %v", primary, err)
	}
}

func TestDomainRemovalFailedAllocationPostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	sub, _, addon, _ := removalFixture(t, db)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE sites SET status='failed',removal_state='failed' WHERE id=$1", addon); err != nil {
		t.Fatal(err)
	}
	usage, err := controlquota.NewSQLStore(db).GetUsageForSubscription(context.Background(), sub)
	if err != nil || usage.Domains != 2 {
		t.Fatalf("reserved domains=%d want=2 err=%v", usage.Domains, err)
	}
}

func TestDomainRemovalMailAliasIsolationPostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	sub, root, addon, _ := removalFixture(t, db)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	var parentMail, addonMail int64
	if err := db.QueryRow("INSERT INTO mail_domains(subscription_id,site_id,domain,effective_enabled) VALUES($1,$2,'primary.example.test',true) RETURNING id", sub, root).Scan(&parentMail); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("INSERT INTO mail_domains(subscription_id,site_id,domain,effective_enabled) VALUES($1,$2,'addon.example.test',true) RETURNING id", sub, addon).Scan(&addonMail); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO mailboxes(mail_domain_id,local_part,password_hash) VALUES($1,'stay','fixture-hash')", parentMail); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO mail_aliases(mail_domain_id,local_part,destinations) VALUES($1,'removed',ARRAY['stay@primary.example.test'])", addonMail); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE sites SET removal_state='queued' WHERE id=$1", addon); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM stalwart_emails WHERE address='removed@addon.example.test'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("removed alias remained active: %d %v", count, err)
	}
}

func TestDomainRemovalSiteMutationLockPostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	_, root, addon, _ := removalFixture(t, db)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE sites SET removal_state='queued' WHERE id=$1", addon); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = controlquota.LockSiteMutationTx(context.Background(), tx, addon); err == nil {
		t.Fatal("removing site lock allowed mutation")
	}
	tx.Rollback()
	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = controlquota.LockSiteMutationTx(context.Background(), tx, root); err != nil {
		t.Fatal(err)
	}
}

func TestDomainRemovalBillingPrimaryBackfillPostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	sub, _, addon, _ := removalFixture(t, db)
	if _, err := db.Exec("INSERT INTO billing_accounts(subscription_id,public_id,external_ref,primary_site_id,provisioning_state) VALUES($1,'acc_abcdefghijklmnopqrst','removal-fixture',$2,'active')", sub, addon); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	var primary int64
	if err := db.QueryRow("SELECT primary_site_id FROM subscriptions WHERE id=$1", sub).Scan(&primary); err != nil || primary != addon {
		t.Fatalf("billing primary=%d want=%d %v", primary, addon, err)
	}
}

func TestDomainRemovalOwnerFreezePostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	sub, _, addon, _ := removalFixture(t, db)
	if _, err := db.Exec("INSERT INTO billing_accounts(subscription_id,public_id,external_ref,primary_site_id,provisioning_state) VALUES($1,'acc_abcdefghijklmnopqrst','removal-fixture',NULL,'active')", sub); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO site_removal_operations(request_id,site_id,subscription_id,customer_id,actor_label,domain,snapshot,preview_digest)
 SELECT repeat('a',32),id,subscription_id,customer_id,'fixture',domain,jsonb_build_object('sites',jsonb_build_array(jsonb_build_object('site_id',id))),'fixture'
 FROM sites WHERE id=$1`, addon); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"UPDATE customers SET reseller_id=99999 WHERE id=(SELECT customer_id FROM subscriptions WHERE id=$1)",
		"UPDATE subscriptions SET customer_id=(SELECT id FROM customers WHERE id<>subscriptions.customer_id LIMIT 1) WHERE id=$1",
		"UPDATE billing_accounts SET provisioning_state='terminating' WHERE subscription_id=$1",
	} {
		if _, err := db.Exec(query, sub); err == nil || !strings.Contains(err.Error(), "finish or retry website removal") {
			t.Fatalf("owner freeze query %s: %v", query, err)
		}
	}
}

func TestDomainRemovalWholeAccountCompatibilityPostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	sub, _, _, _ := removalFixture(t, db)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec("SELECT set_config('nakpanel.account_teardown','on',true)"); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("UPDATE subscriptions SET primary_site_id=NULL WHERE id=$1", sub); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("DELETE FROM sites WHERE subscription_id=$1", sub); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestDomainRemovalBillingTeardownCanFinalizeOnlyInAuthorizedTransaction(t *testing.T) {
	db, up, _ := removalSchema(t)
	sub, root, _, _ := removalFixture(t, db)
	if _, err := db.Exec("INSERT INTO billing_accounts(subscription_id,public_id,external_ref,primary_site_id,provisioning_state) VALUES($1,'acc_abcdefghijklmnopqrst','removal-finalize',$2,'active')", sub, root); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE billing_accounts SET provisioning_state='terminating' WHERE subscription_id=$1", sub); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE billing_accounts SET provisioning_state='terminated' WHERE subscription_id=$1", sub); err == nil {
		t.Fatal("unprivileged terminal transition was accepted")
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec("SELECT set_config('nakpanel.account_teardown','on',true)"); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("UPDATE subscriptions SET primary_site_id=NULL WHERE id=$1", sub); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("DELETE FROM sites WHERE subscription_id=$1", sub); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("UPDATE billing_accounts SET provisioning_state='terminated' WHERE subscription_id=$1", sub); err != nil {
		t.Fatalf("authorized account teardown could not finalize: %v", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestDomainRemovalConcurrentFirstRootPostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	var schema string
	var sub int64
	if err := db.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT id FROM subscriptions ORDER BY id LIMIT 1").Scan(&sub); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(os.Getenv("NAKPANEL_REMOVAL_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	parallel, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer parallel.Close()
	parallel.SetMaxOpenConns(2)
	first, err := parallel.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback()
	statement := `INSERT INTO sites(owner_user_id,subscription_id,customer_id,system_account_id,username,document_root,domain,php_version,desired_php_version,status)
 SELECT s.customer_user_id,s.id,s.customer_id,account.id,account.username,account.home_path||'/domains/'||$2||'/public_html',$2,'8.4','8.4','active'
 FROM subscriptions s JOIN subscription_system_accounts account ON account.subscription_id=s.id WHERE s.id=$1 RETURNING id`
	var primary int64
	if err = first.QueryRow(statement, sub, "first.example.test").Scan(&primary); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		var sibling int64
		done <- parallel.QueryRow(statement, sub, "second.example.test").Scan(&sibling)
	}()
	select {
	case err := <-done:
		t.Fatalf("second intent did not wait for primary lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err = first.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second site remained blocked")
	}
	var actual int64
	if err = db.QueryRow("SELECT primary_site_id FROM subscriptions WHERE id=$1", sub).Scan(&actual); err != nil || actual != primary {
		t.Fatalf("primary=%d want=%d %v", actual, primary, err)
	}
}

func TestDomainRemovalApprovalImmutablePostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	_, _, addon, _ := removalFixture(t, db)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := db.QueryRow(`INSERT INTO site_removal_operations(request_id,site_id,subscription_id,customer_id,actor_label,domain,snapshot,preview_digest)
 SELECT repeat('b',32),id,subscription_id,customer_id,'fixture',domain,'{}','fixture' FROM sites WHERE id=$1 RETURNING id`, addon).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE site_removal_operations SET snapshot='{\"changed\":true}' WHERE id=$1", id); err == nil {
		t.Fatal("approved scope changed")
	}
}

func TestDomainRemovalOverlappingTargetsPostgreSQL(t *testing.T) {
	db, up, _ := removalSchema(t)
	_, _, addon, child := removalFixture(t, db)
	if _, err := db.Exec(up); err != nil {
		t.Fatal(err)
	}
	var first, second int64
	statement := `INSERT INTO site_removal_operations(request_id,site_id,subscription_id,customer_id,actor_label,domain,snapshot,preview_digest)
 SELECT repeat($2::text,32),id,subscription_id,customer_id,'fixture',domain,'{}','fixture' FROM sites WHERE id=$1 RETURNING id`
	if err := db.QueryRow(statement, child, "c").Scan(&first); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(statement, addon, "d").Scan(&second); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO site_removal_targets(operation_id,site_id) VALUES($1,$2)", first, child); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO site_removal_targets(operation_id,site_id) VALUES($1,$2)", second, child); err == nil {
		t.Fatal("two removals reserved the same child")
	}
}
