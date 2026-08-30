package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPhase30MigrationPostgreSQLConstraintsBackfillAndDown(t *testing.T) {
	db := phase30Postgres(t)
	createPhase30Baseline(t, db)

	up, down := phase30MigrationSections(t)
	if _, err := db.Exec(up); err != nil {
		t.Fatalf("Phase 30 Up: %v", err)
	}

	var backfilled, totalApplications int
	if err := db.QueryRow(`SELECT count(*) FROM php_applications application
JOIN sites site ON site.id=application.site_id
WHERE application.subscription_id=site.subscription_id
  AND application.hosting_mode='classic'
  AND application.php_version=site.php_version
  AND application.desired_state=site.desired_status
  AND application.observed_state='classic'
  AND application.repository_id IS NULL
  AND application.framework_profile='plain'
  AND application.health_path='/'
  AND application.shared_paths='[]'::jsonb
  AND NOT application.composer_install
  AND NOT application.composer_allow_scripts
  AND NOT application.composer_allow_plugins
  AND application.active_deployment_id IS NULL
  AND application.previous_deployment_id IS NULL
  AND application.desired_revision=1
  AND application.applied_revision=1
  AND application.convergence_status='in_sync'`).Scan(&backfilled); err != nil {
		t.Fatal(err)
	}
	if backfilled != 2 {
		t.Fatalf("canonical Classic backfill count = %d, want 2", backfilled)
	}
	if err := db.QueryRow(`SELECT count(*) FROM php_applications`).Scan(&totalApplications); err != nil {
		t.Fatal(err)
	}
	if totalApplications != 2 {
		t.Fatalf("total Classic backfill count = %d, want exactly 2", totalApplications)
	}

	var app1, app2 int64
	if err := db.QueryRow(`SELECT id FROM php_applications WHERE site_id=101`).Scan(&app1); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT id FROM php_applications WHERE site_id=202`).Scan(&app2); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`INSERT INTO sites(id,subscription_id,php_version,desired_status) VALUES(303,1,'8.4','active')`); err != nil {
		t.Fatal(err)
	}
	var app3 int64
	if err := db.QueryRow(`SELECT id FROM php_applications WHERE site_id=303 AND subscription_id=1
AND hosting_mode='classic' AND php_version='8.4' AND applied_revision=1`).Scan(&app3); err != nil {
		t.Fatalf("new site Classic application trigger: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sites(id,subscription_id,php_version,desired_status) VALUES(404,1,'8.4','active')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM php_applications WHERE site_id=404`); err != nil {
		t.Fatal(err)
	}
	expectPhase30ConstraintError(t, db, `INSERT INTO php_applications(subscription_id,site_id,php_version) VALUES(2,404,'8.4')`)
	expectPhase30ConstraintError(t, db, `INSERT INTO php_applications(subscription_id,site_id,php_version,repository_id) VALUES(1,404,'8.4',11)`)
	expectPhase30ConstraintError(t, db, `INSERT INTO php_applications(subscription_id,site_id,php_version,framework_profile) VALUES(1,404,'8.4','wordpress')`)
	expectPhase30ConstraintError(t, db, `INSERT INTO php_applications(subscription_id,site_id,php_version,health_path) VALUES(1,404,'8.4','relative')`)
	expectPhase30ConstraintError(t, db, `INSERT INTO php_applications(subscription_id,site_id,php_version,shared_paths) VALUES(1,404,'8.4','["../escape"]')`)
	expectPhase30ConstraintError(t, db, `INSERT INTO php_applications(subscription_id,site_id,php_version,shared_paths) VALUES(1,404,'8.4','[1]')`)
	if _, err := db.Exec(`DELETE FROM sites WHERE id=404`); err != nil {
		t.Fatal(err)
	}

	expectPhase30ConstraintError(t, db, fmt.Sprintf(`INSERT INTO php_deployments(subscription_id,application_id,requested_revision,release_number) VALUES(2,%d,'main',1)`, app1))
	expectPhase30ConstraintError(t, db, fmt.Sprintf(`INSERT INTO php_deployments(subscription_id,application_id,requested_revision,resolved_revision,release_number) VALUES(1,%d,'main','%s',99)`, app1, strings.Repeat("a", 41)))
	expectPhase30ConstraintError(t, db, fmt.Sprintf(`INSERT INTO php_environment_bindings(subscription_id,application_id,name,plain_value) VALUES(2,%d,'APP_ENV','production')`, app1))
	expectPhase30ConstraintError(t, db, fmt.Sprintf(`INSERT INTO php_workers(subscription_id,application_id,name,script) VALUES(2,%d,'queue','artisan')`, app1))

	var deployment1, deployment2 int64
	if err := db.QueryRow(fmt.Sprintf(`INSERT INTO php_deployments(subscription_id,application_id,requested_revision,release_number,status) VALUES(1,%d,'main',1,'healthy') RETURNING id`, app1)).Scan(&deployment1); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(fmt.Sprintf(`INSERT INTO php_deployments(subscription_id,application_id,requested_revision,release_number,status) VALUES(2,%d,'main',1,'healthy') RETURNING id`, app2)).Scan(&deployment2); err != nil {
		t.Fatal(err)
	}
	expectPhase30ConstraintError(t, db, fmt.Sprintf(`UPDATE php_applications SET active_deployment_id=%d WHERE id=%d`, deployment2, app1))
	expectPhase30ConstraintError(t, db, fmt.Sprintf(`UPDATE php_applications SET previous_deployment_id=%d WHERE id=%d`, deployment2, app1))
	expectPhase30ConstraintError(t, db, fmt.Sprintf(`INSERT INTO php_deployments(subscription_id,application_id,requested_revision,release_number,previous_deployment_id) VALUES(1,%d,'rollback',2,%d)`, app1, deployment2))

	expectPhase30ConstraintError(t, db, fmt.Sprintf(`INSERT INTO php_environment_bindings(subscription_id,application_id,name,plain_value,secret_id) VALUES(1,%d,'BOTH','value',41)`, app1))
	expectPhase30ConstraintError(t, db, fmt.Sprintf(`INSERT INTO php_environment_bindings(subscription_id,application_id,name,plain_value) VALUES(1,%d,'lowercase','value')`, app1))
	expectPhase30ConstraintError(t, db, fmt.Sprintf(`INSERT INTO php_environment_bindings(subscription_id,application_id,name,secret_id) VALUES(1,%d,'APP_KEY',42)`, app1))
	if _, err := db.Exec(fmt.Sprintf(`INSERT INTO php_environment_bindings(subscription_id,application_id,name,secret_id) VALUES(1,%d,'APP_KEY',41)`, app1)); err != nil {
		t.Fatalf("insert correctly scoped secret binding: %v", err)
	}
	expectPhase30ConstraintError(t, db, fmt.Sprintf(`INSERT INTO php_workers(subscription_id,application_id,name,script) VALUES(1,%d,'queue','../escape')`, app1))
	expectPhase30ConstraintError(t, db, fmt.Sprintf(`INSERT INTO php_workers(subscription_id,application_id,name,script,processes) VALUES(1,%d,'queue','artisan',65)`, app1))
	if _, err := db.Exec(`DELETE FROM php_deployments`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM php_environment_bindings`); err != nil {
		t.Fatal(err)
	}

	for name, statements := range map[string][2]string{
		"repository binding": {
			fmt.Sprintf(`UPDATE php_applications SET repository_id=11 WHERE id=%d`, app1),
			fmt.Sprintf(`UPDATE php_applications SET repository_id=NULL WHERE id=%d`, app1),
		},
		"Composer setting": {
			fmt.Sprintf(`UPDATE php_applications SET composer_install=true WHERE id=%d`, app1),
			fmt.Sprintf(`UPDATE php_applications SET composer_install=false WHERE id=%d`, app1),
		},
		"framework profile": {
			fmt.Sprintf(`UPDATE php_applications SET framework_profile='laravel' WHERE id=%d`, app1),
			fmt.Sprintf(`UPDATE php_applications SET framework_profile='plain' WHERE id=%d`, app1),
		},
		"revision": {
			fmt.Sprintf(`UPDATE php_applications SET desired_revision=2 WHERE id=%d`, app1),
			fmt.Sprintf(`UPDATE php_applications SET desired_revision=1 WHERE id=%d`, app1),
		},
		"convergence state": {
			fmt.Sprintf(`UPDATE php_applications SET convergence_status='failed' WHERE id=%d`, app1),
			fmt.Sprintf(`UPDATE php_applications SET convergence_status='in_sync' WHERE id=%d`, app1),
		},
	} {
		if _, err := db.Exec(statements[0]); err != nil {
			t.Fatalf("set noncanonical %s: %v", name, err)
		}
		if _, err := db.Exec(down); err == nil || !strings.Contains(err.Error(), "canonical Classic backfill") {
			t.Fatalf("Down with noncanonical %s error = %v", name, err)
		}
		if _, err := db.Exec(statements[1]); err != nil {
			t.Fatalf("restore canonical %s: %v", name, err)
		}
	}
	if _, err := db.Exec(down); err != nil {
		t.Fatalf("clean Phase 30 Down: %v", err)
	}
	var applicationTable *string
	if err := db.QueryRow(`SELECT to_regclass('php_applications')::text`).Scan(&applicationTable); err != nil {
		t.Fatal(err)
	}
	if applicationTable != nil {
		t.Fatalf("php_applications remains after Down: %q", *applicationTable)
	}
	var phase30ParentConstraints int
	if err := db.QueryRow(`SELECT count(*) FROM pg_constraint WHERE conname IN (
        'sites_phase30_identity_key','git_repositories_phase30_identity_key','service_secrets_phase30_identity_key'
    )`).Scan(&phase30ParentConstraints); err != nil {
		t.Fatal(err)
	}
	if phase30ParentConstraints != 0 {
		t.Fatalf("Phase 30 parent constraints remaining after Down = %d", phase30ParentConstraints)
	}
}

func TestPhase30IntegrationNotificationKindsPostgreSQL(t *testing.T) {
	db := phase30Postgres(t)
	createPhase30Baseline(t, db)
	phase30Up, _ := phase30MigrationSections(t)
	if _, err := db.Exec(phase30Up); err != nil {
		t.Fatal(err)
	}
	up, down := migrationSections(t, "20260830000045_phase30_integration.sql")
	if _, err := db.Exec(up); err != nil {
		t.Fatalf("Phase 30 integration Up: %v", err)
	}
	for _, kind := range []string{"php_worker_failed", "php_composer_security", "php_runtime_missing", "php_end_of_support"} {
		if _, err := db.Exec(`INSERT INTO notifications(kind) VALUES($1)`, kind); err != nil {
			t.Fatalf("insert %s notification: %v", kind, err)
		}
	}
	if _, err := db.Exec(down); err != nil {
		t.Fatalf("Phase 30 integration Down: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO notifications(kind) VALUES('php_worker_failed')`); err == nil {
		t.Fatal("Phase 30 integration Down still permits php_worker_failed")
	}
}

func TestPhase30SitePHPVersionConstraintPostgreSQL(t *testing.T) {
	db := phase30Postgres(t)
	if _, err := db.Exec(`CREATE TABLE sites(
		id BIGINT PRIMARY KEY,
		php_version TEXT NOT NULL,
		CONSTRAINT sites_php_version_check CHECK (php_version IN ('8.2','8.3'))
	);
	INSERT INTO sites(id,php_version) VALUES(1,'8.2'),(2,'8.3');`); err != nil {
		t.Fatal(err)
	}
	up, down := migrationSections(t, "20260830000046_phase30_site_php_versions.sql")
	if _, err := db.Exec(up); err != nil {
		t.Fatalf("Phase 30 site PHP versions Up: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sites(id,php_version) VALUES(3,'8.4'),(4,'8.5')`); err != nil {
		t.Fatalf("Phase 30 versions were rejected: %v", err)
	}
	expectPhase30ConstraintError(t, db, `INSERT INTO sites(id,php_version) VALUES(5,'8.6')`)
	if _, err := db.Exec(down); err == nil || !strings.Contains(err.Error(), "cannot restore the pre-Phase 30 PHP version constraint") {
		t.Fatalf("Down with Phase 30 sites error = %v", err)
	}
	if _, err := db.Exec(`DELETE FROM sites WHERE php_version IN ('8.4','8.5')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(down); err != nil {
		t.Fatalf("clean Phase 30 site PHP versions Down: %v", err)
	}
	expectPhase30ConstraintError(t, db, `INSERT INTO sites(id,php_version) VALUES(6,'8.4')`)
}

func phase30Postgres(t *testing.T) *sql.DB {
	t.Helper()
	candidates := []string{os.Getenv("NAKPANEL_TEST_DATABASE_URL")}
	if candidates[0] == "" {
		candidates = []string{
			"postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable",
			"postgres:///postgres?host=/var/run/postgresql&sslmode=disable",
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var db *sql.DB
	for _, dsn := range candidates {
		candidate, err := sql.Open("pgx", dsn)
		if err == nil {
			err = candidate.PingContext(ctx)
		}
		if err == nil {
			db = candidate
			break
		}
		if candidate != nil {
			candidate.Close()
		}
	}
	if db == nil {
		t.Skip("PostgreSQL is unavailable and NAKPANEL_TEST_DATABASE_URL is not usable")
	}
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("phase30_task1_%d", time.Now().UnixNano())
	if _, err := db.Exec(`CREATE SCHEMA ` + schema); err != nil {
		db.Close()
		t.Fatalf("create isolated PostgreSQL schema: %v", err)
	}
	if _, err := db.Exec(`SET search_path TO ` + schema); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`SET search_path TO public`)
		_, _ = db.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`)
		db.Close()
	})
	return db
}

func createPhase30Baseline(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
CREATE TABLE users(id BIGINT PRIMARY KEY);
CREATE TABLE subscriptions(id BIGINT PRIMARY KEY);
CREATE TABLE sites(
    id BIGINT PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id),
    php_version TEXT NOT NULL,
    desired_status TEXT NOT NULL
);
CREATE TABLE git_repositories(
    id BIGINT PRIMARY KEY,
    site_id BIGINT NOT NULL REFERENCES sites(id)
);
CREATE TABLE service_secrets(
    id BIGINT PRIMARY KEY,
    scope TEXT NOT NULL
);
CREATE TABLE notifications(
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL,
    CONSTRAINT notifications_kind_check CHECK (kind IN (
        'threshold','over_limit','collection_failed','suspended','sync_failed',
        'maintenance_failed','certificate_expiring','mail_outbound_spike',
        'scheduled_task_failed','server_backup_failed','login_new_device','login_failed_burst'
    ))
);
CREATE FUNCTION nakpanel_assert_account_mutable(BIGINT) RETURNS VOID
LANGUAGE plpgsql AS $$ BEGIN RETURN; END; $$;
INSERT INTO subscriptions(id) VALUES(1),(2);
INSERT INTO users(id) VALUES(1);
INSERT INTO sites(id,subscription_id,php_version,desired_status)
VALUES(101,1,'8.4','active'),(202,2,'8.3','suspended');
INSERT INTO git_repositories(id,site_id) VALUES(11,101),(22,202);
INSERT INTO service_secrets(id,scope)
VALUES(41,'php.application.1'),(42,'php.application.999');
`)
	if err != nil {
		t.Fatal(err)
	}
}

func phase30MigrationSections(t *testing.T) (string, string) {
	t.Helper()
	data, err := os.ReadFile("20260829000044_phase30_production_php.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(data), "-- +goose Down", 2)
	if len(parts) != 2 {
		t.Fatal("Phase 30 migration has no Down section")
	}
	return parts[0], parts[1]
}

func migrationSections(t *testing.T, name string) (string, string) {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(data), "-- +goose Down", 2)
	if len(parts) != 2 {
		t.Fatalf("migration %s has no Down section", name)
	}
	return parts[0], parts[1]
}

func expectPhase30ConstraintError(t *testing.T, db *sql.DB, statement string) {
	t.Helper()
	if _, err := db.Exec(statement); err == nil {
		t.Fatalf("constraint accepted invalid statement: %s", statement)
	}
}
