package quota

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func platformBootstrapDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("NAKPANEL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NAKPANEL_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("platform_bootstrap_%d", time.Now().UnixNano())
	if _, err = db.Exec("CREATE SCHEMA " + schema + ";SET search_path TO " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec("SET search_path TO public;DROP SCHEMA " + schema + " CASCADE"); db.Close() })
	files, err := filepath.Glob("../../../migrations/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatal("migration files missing", err)
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(strings.SplitN(string(raw), "-- +goose Down", 2)[0]); err != nil {
			t.Fatalf("migrate %s: %v", file, err)
		}
	}
	return db
}

func TestBootstrapNativePlansPostgreSQL(t *testing.T) {
	db := platformBootstrapDB(t)
	var previous string
	if err := db.QueryRow(`SELECT string_agg(definition_hash,',' ORDER BY id) FROM plan_revisions`).Scan(&previous); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := BootstrapNativePlans(context.Background(), db, "ubuntu-26.04-native", []string{"8.5"}, "installer", true); err != nil {
			t.Fatalf("bootstrap attempt %d: %v", attempt, err)
		}
	}
	var good, revisions, receipts int
	if err := db.QueryRow(`SELECT count(*) FROM plans p JOIN plan_service_presets ps ON ps.plan_id=p.id WHERE p.name IN ('Starter','Business','Pro') AND p.revision=3 AND p.php_allowlist='8.5' AND p.default_php_version='8.5' AND p.hosting_policy#>'{php,allowed_versions}'='["8.5"]' AND ps.php->>'allowed_versions'='8.5'`).Scan(&good); err != nil {
		t.Fatal(err)
	}
	if good != 3 {
		t.Fatalf("adapted plans=%d", good)
	}
	var after string
	if err := db.QueryRow(`SELECT string_agg(definition_hash,',' ORDER BY id) FROM plan_revisions WHERE revision<3`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != previous {
		t.Fatal("historical revisions changed")
	}
	if err := db.QueryRow(`SELECT count(*) FROM plan_revisions WHERE revision=3`).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='platform.plans_bootstrapped'`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if revisions != 3 || receipts != 1 {
		t.Fatalf("revisions=%d receipts=%d", revisions, receipts)
	}
}

func TestBootstrapNativePlansRejectsUnsafeStatePostgreSQL(t *testing.T) {
	for _, tt := range []struct {
		name, mutation, profile string
		ready                   []string
	}{
		{"wrong profile", "", "ubuntu-24.04", []string{"8.5"}},
		{"unready", "", "ubuntu-26.04-native", nil},
		{"custom definition", `UPDATE plans SET description='Imported custom plan' WHERE name='Starter'`, "ubuntu-26.04-native", []string{"8.5"}},
		{"custom preset", `UPDATE plan_service_presets SET logs='{"retention_days":99}' WHERE plan_id=(SELECT id FROM plans WHERE name='Starter')`, "ubuntu-26.04-native", []string{"8.5"}},
		{"populated", `INSERT INTO users(email,password_hash,role) VALUES('test@example.test','unused','client'); INSERT INTO subscriptions(customer_id,customer_user_id,plan_id,status) SELECT c.id,c.login_user_id,p.id,'active' FROM customers c CROSS JOIN plans p WHERE p.name='Starter' LIMIT 1`, "ubuntu-26.04-native", []string{"8.5"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db := platformBootstrapDB(t)
			if tt.mutation != "" {
				if _, err := db.Exec(tt.mutation); err != nil {
					t.Fatal(err)
				}
			}
			if err := BootstrapNativePlans(context.Background(), db, tt.profile, tt.ready, "installer", true); err == nil {
				t.Fatal("unsafe bootstrap succeeded")
			}
			var count int
			if err := db.QueryRow(`SELECT count(*) FROM plans WHERE revision=3`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatal("rejected operation modified plans")
			}
		})
	}
}

func TestBootstrapNativePlansDemoDiscardRejectsDriftPostgreSQL(t *testing.T) {
	for _, mutation := range []string{
		`UPDATE users SET login_disabled=true WHERE email='client@nakpanel.test'`,
		`UPDATE customers SET display_name='Real customer' WHERE id=1`,
		`UPDATE subscriptions SET name='Custom subscription' WHERE id=1`,
		`UPDATE subscription_entitlements SET default_php_version='8.5' WHERE subscription_id=1`,
		`UPDATE subscription_system_accounts SET last_error='changed' WHERE id=1`,
	} {
		t.Run(mutation, func(t *testing.T) {
			db := platformBootstrapDB(t)
			if _, err := db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			if err := BootstrapNativePlans(context.Background(), db, "ubuntu-26.04-native", []string{"8.5"}, "installer", true); err == nil {
				t.Fatal("modified demo state accepted")
			}
			var count int
			if err := db.QueryRow(`SELECT count(*) FROM subscriptions`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 2 {
				t.Fatal("demo subscriptions removed on rejection")
			}
		})
	}
}
func TestBootstrapNativePlansRequiresExplicitDemoDiscardPostgreSQL(t *testing.T) {
	db := platformBootstrapDB(t)
	if err := BootstrapNativePlans(context.Background(), db, "ubuntu-26.04-native", []string{"8.5"}, "installer", false); err == nil {
		t.Fatal("demo subscriptions discarded without explicit flag")
	}
}

func TestBootstrapNativePlansRollsBackDiscardAndRevisionsOnAuditFailurePostgreSQL(t *testing.T) {
	db := platformBootstrapDB(t)
	if _, err := db.Exec(`CREATE FUNCTION reject_bootstrap_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit failure'; END $$; CREATE TRIGGER reject_bootstrap_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_bootstrap_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := BootstrapNativePlans(context.Background(), db, "ubuntu-26.04-native", []string{"8.5"}, "installer", true); err == nil || !strings.Contains(err.Error(), "test audit failure") {
		t.Fatalf("expected audit failure, got %v", err)
	}
	var subscriptions, revisions int
	if err := db.QueryRow(`SELECT count(*) FROM subscriptions`).Scan(&subscriptions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM plan_revisions WHERE revision=3`).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if subscriptions != 2 || revisions != 0 {
		t.Fatalf("rollback subscriptions=%d revisions=%d", subscriptions, revisions)
	}
}

func TestBootstrapNativePlansRetryRejectsChangedCommittedPlansPostgreSQL(t *testing.T) {
	db := platformBootstrapDB(t)
	if err := BootstrapNativePlans(context.Background(), db, "ubuntu-26.04-native", []string{"8.5"}, "installer", true); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE plans SET description='Operator customization' WHERE name='Starter'`); err != nil {
		t.Fatal(err)
	}
	if err := BootstrapNativePlans(context.Background(), db, "ubuntu-26.04-native", []string{"8.5"}, "installer", true); err == nil {
		t.Fatal("changed plans accepted via existing audit receipt")
	}
}

// Phase 7/8 used to start panel River workers before the native bootstrap. The
// real convergence worker failed against the incomplete SFTP/tooling setup and
// persisted these states. Do not normalize this drift into an "untouched" seed:
// installers must defer panel workers while leaving the agent available.
func TestBootstrapNativePlansRejectsPrematureWorkerConvergencePostgreSQL(t *testing.T) {
	db := platformBootstrapDB(t)
	const failure = "agent account convergence failed: validate Nakpanel SFTP configuration: exit status 255"
	if _, err := db.Exec(`UPDATE subscription_system_accounts SET applied_state='failed',convergence_status='failed',last_error=$1`, failure); err != nil {
		t.Fatal(err)
	}
	if err := BootstrapNativePlans(context.Background(), db, "ubuntu-26.04-native", []string{"8.5"}, "installer", true); err == nil || !strings.Contains(err.Error(), "changed demo subscription_system_accounts") {
		t.Fatalf("converged demo drift accepted or unexpected error: %v", err)
	}
	var subscriptions, failures, nativePlans int
	if err := db.QueryRow(`SELECT count(*) FROM subscriptions`).Scan(&subscriptions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM subscription_system_accounts WHERE applied_state='failed' AND convergence_status='failed' AND last_error=$1`, failure).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM plans WHERE default_php_version='8.5'`).Scan(&nativePlans); err != nil {
		t.Fatal(err)
	}
	if subscriptions != 2 || failures != 2 || nativePlans != 0 {
		t.Fatalf("rejected bootstrap changed drifted state: subscriptions=%d failures=%d native plans=%d", subscriptions, failures, nativePlans)
	}
}
