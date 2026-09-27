package migrations

import (
	"database/sql"
	"strings"
	"testing"
)

func createPhase32WordPressPrerequisites(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`
CREATE TABLE users(id BIGINT PRIMARY KEY);
CREATE TABLE subscriptions(id BIGINT PRIMARY KEY);
CREATE TABLE sites(
    id BIGINT PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id),
    UNIQUE(id,subscription_id)
);
CREATE TABLE databases(
    id BIGINT PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id),
    site_id BIGINT REFERENCES sites(id),
    status TEXT NOT NULL
);
CREATE TABLE backups(
    id BIGINT PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id),
    site_id BIGINT REFERENCES sites(id),
    status TEXT NOT NULL
);
CREATE TABLE service_secrets(
    id BIGINT PRIMARY KEY,
    scope TEXT NOT NULL,
    name TEXT NOT NULL,
    UNIQUE(id,scope),
    UNIQUE(scope,name)
);
CREATE TABLE notifications(
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL,
    CONSTRAINT notifications_kind_check CHECK(kind IN ('threshold','php_deployment_failed'))
);
CREATE FUNCTION nakpanel_guard_php_account_teardown() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RETURN COALESCE(NEW,OLD); END; $$;
INSERT INTO users VALUES(1);
INSERT INTO subscriptions VALUES(10),(20);
INSERT INTO sites VALUES(101,10),(201,20);
INSERT INTO databases VALUES(301,10,101,'active'),(401,20,201,'active');
INSERT INTO backups VALUES(501,10,101,'active');
INSERT INTO service_secrets VALUES(601,'wordpress.instance.1','admin');
`); err != nil {
		t.Fatal(err)
	}
}

func TestPhase32WordPressOwnershipSecretsAndOperationsPostgreSQL(t *testing.T) {
	up, down := migrationSections(t, "20260830000048_phase32_wordpress_toolkit.sql")
	db := phase30Postgres(t)
	createPhase32WordPressPrerequisites(t, db)
	if _, err := db.Exec(up); err != nil {
		t.Fatalf("Phase 32 Up: %v", err)
	}

	var instanceID int64
	if err := db.QueryRow(`INSERT INTO wordpress_instances(
subscription_id,site_id,database_id,admin_user,admin_email,admin_secret_id,admin_secret_scope)
VALUES(10,101,301,'siteadmin','admin@example.test',601,'wordpress.instance.1') RETURNING id`).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO wordpress_instances(subscription_id,site_id,database_id,admin_user,admin_email)
VALUES(10,201,301,'wrongsite','wrong@example.test')`); err == nil {
		t.Fatal("cross-subscription site was accepted")
	}
	if _, err := db.Exec(`INSERT INTO wordpress_operations(subscription_id,instance_id,kind,status,requested_by_user_id)
VALUES(10,$1,'update','pending',1)`, instanceID); err != nil {
		t.Fatal(err)
	}
	var maintenanceEnabled bool
	if err := db.QueryRow(`INSERT INTO wordpress_operations(subscription_id,instance_id,kind,status,maintenance_enabled)
VALUES(10,$1,'maintenance','failed',true) RETURNING maintenance_enabled`, instanceID).Scan(&maintenanceEnabled); err != nil {
		t.Fatalf("maintenance desired state was not persisted: %v", err)
	}
	if !maintenanceEnabled {
		t.Fatal("maintenance desired state changed during persistence")
	}
	if _, err := db.Exec(`INSERT INTO wordpress_operations(subscription_id,instance_id,kind,status)
VALUES(20,$1,'update','pending')`, instanceID); err == nil {
		t.Fatal("cross-subscription operation was accepted")
	}
	if _, err := db.Exec(`UPDATE wordpress_instances SET inventory='[]'::jsonb WHERE id=$1`, instanceID); err == nil || !strings.Contains(err.Error(), "inventory") {
		t.Fatalf("non-object inventory error = %v", err)
	}
	if _, err := db.Exec(`INSERT INTO notifications(kind) VALUES('wordpress_operation_failed')`); err != nil {
		t.Fatalf("WordPress notification kind rejected: %v", err)
	}

	if _, err := db.Exec(down); err != nil {
		t.Fatalf("Phase 32 Down: %v", err)
	}
	var instances, operations int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_name='wordpress_instances'`).Scan(&instances); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_name='wordpress_operations'`).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if instances != 0 || operations != 0 {
		t.Fatalf("Phase 32 tables remain after down: instances=%d operations=%d", instances, operations)
	}
}
