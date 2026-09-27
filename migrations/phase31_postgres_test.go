package migrations

import (
	"strings"
	"testing"
)

func TestPhase31PlanLifecycleRevisionAndCompliancePostgreSQL(t *testing.T) {
	up, down := migrationSections(t, "20260830000047_phase31_production_service_plans.sql")
	db := phase30Postgres(t)
	if _, err := db.Exec(`
CREATE TABLE users(id BIGINT PRIMARY KEY);
CREATE TABLE plans(
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    revision INTEGER NOT NULL DEFAULT 1,
    hosting_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE plan_service_presets(
    plan_id BIGINT PRIMARY KEY REFERENCES plans(id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL DEFAULT 1,
    hosting JSONB NOT NULL DEFAULT '{}'::jsonb,
    php JSONB NOT NULL DEFAULT '{}'::jsonb,
    mail JSONB NOT NULL DEFAULT '{}'::jsonb,
    dns JSONB NOT NULL DEFAULT '{}'::jsonb,
    performance JSONB NOT NULL DEFAULT '{}'::jsonb,
    logs JSONB NOT NULL DEFAULT '{}'::jsonb,
    applications JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE subscriptions(
    id BIGSERIAL PRIMARY KEY,
    plan_id BIGINT REFERENCES plans(id),
    sync_mode TEXT NOT NULL DEFAULT 'synced',
    sync_status TEXT NOT NULL DEFAULT 'in_sync',
    plan_revision INTEGER NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO users(id) VALUES(11);
INSERT INTO plans(id,name,is_active,revision,hosting_policy) VALUES
    (1,'Published',true,3,'{"schema_version":3,"resources":{"disk_mb":1024},"permissions":{"hosting":true},"php":{"default_version":"8.4","allowed_versions":["8.4"]}}'),
    (2,'Legacy inactive',false,2,'{"schema_version":3}');
INSERT INTO plan_service_presets(plan_id,schema_version,hosting,php,logs) VALUES
    (1,2,'{"web_server":"nginx"}','{"max_execution_seconds":120}','{"retention_days":30}');
INSERT INTO subscriptions(id,plan_id) VALUES(21,1);
`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(up); err != nil {
		t.Fatalf("Phase 31 Up: %v", err)
	}

	var active, retired string
	if err := db.QueryRow(`SELECT lifecycle_status FROM plans WHERE id=1`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT lifecycle_status FROM plans WHERE id=2`).Scan(&retired); err != nil {
		t.Fatal(err)
	}
	if active != "active" || retired != "retired" {
		t.Fatalf("lifecycle backfill = %q/%q, want active/retired", active, retired)
	}

	var revisionCount int
	var definitionHash, actorLabel string
	if err := db.QueryRow(`SELECT count(*),min(definition_hash),min(actor_label) FROM plan_revisions WHERE plan_id=1 AND revision=3`).Scan(&revisionCount, &definitionHash, &actorLabel); err != nil {
		t.Fatal(err)
	}
	if revisionCount != 1 || len(definitionHash) != 64 || actorLabel != "migration" {
		t.Fatalf("revision backfill = count %d hash %q actor %q", revisionCount, definitionHash, actorLabel)
	}
	var presetSchema, executionSeconds, retentionDays int
	if err := db.QueryRow(`SELECT
COALESCE((definition#>>'{presets,schema_version}')::int,0),
COALESCE((definition#>>'{presets,php,max_execution_seconds}')::int,0),
COALESCE((definition#>>'{presets,logs,retention_days}')::int,0)
FROM plan_revisions WHERE plan_id=1 AND revision=3`).Scan(&presetSchema, &executionSeconds, &retentionDays); err != nil {
		t.Fatal(err)
	}
	if presetSchema != 2 || executionSeconds != 120 || retentionDays != 30 {
		t.Fatalf("revision backfill omitted service presets: schema=%d execution=%d retention=%d", presetSchema, executionSeconds, retentionDays)
	}
	if _, err := db.Exec(`UPDATE plan_revisions SET change_reason='tampered' WHERE plan_id=1 AND revision=3`); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("immutable revision update error = %v", err)
	}
	if _, err := db.Exec(`DELETE FROM plan_revisions WHERE plan_id=1 AND revision=3`); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("immutable revision delete error = %v", err)
	}
	if _, err := db.Exec(`INSERT INTO plan_revisions(plan_id,revision,lifecycle_status,definition,definition_hash,actor_user_id,actor_label,change_reason)
VALUES(1,4,'active','{}',repeat('a',64),11,'admin@example.test','actor retention test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM users WHERE id=11`); err != nil {
		t.Fatalf("delete revision actor: %v", err)
	}
	var actorID *int64
	var retainedLabel string
	if err := db.QueryRow(`SELECT actor_user_id,actor_label FROM plan_revisions WHERE plan_id=1 AND revision=4`).Scan(&actorID, &retainedLabel); err != nil {
		t.Fatal(err)
	}
	if actorID != nil || retainedLabel != "admin@example.test" {
		t.Fatalf("revision actor after user removal = id %v label %q", actorID, retainedLabel)
	}

	var compliance string
	if err := db.QueryRow(`SELECT compliance_status FROM subscriptions WHERE id=21`).Scan(&compliance); err != nil {
		t.Fatal(err)
	}
	if compliance != "unknown" {
		t.Fatalf("compliance backfill = %q, want unknown", compliance)
	}
	expectPhase30ConstraintError(t, db, `UPDATE subscriptions SET compliance_status='invented' WHERE id=21`)

	if _, err := db.Exec(`INSERT INTO plans(id,name,is_active) VALUES(3,'New draft',false)`); err != nil {
		t.Fatal(err)
	}
	var lifecycle string
	var isActive bool
	if err := db.QueryRow(`SELECT lifecycle_status,is_active FROM plans WHERE name='New draft'`).Scan(&lifecycle, &isActive); err != nil {
		t.Fatal(err)
	}
	if lifecycle != "draft" || isActive {
		t.Fatalf("new plan state = %q/%v, want draft/false", lifecycle, isActive)
	}
	if _, err := db.Exec(`UPDATE plans SET lifecycle_status='active' WHERE name='New draft'`); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT lifecycle_status,is_active FROM plans WHERE name='New draft'`).Scan(&lifecycle, &isActive); err != nil {
		t.Fatal(err)
	}
	if lifecycle != "active" || !isActive {
		t.Fatalf("activated plan state = %q/%v, want active/true", lifecycle, isActive)
	}

	if _, err := db.Exec(down); err != nil {
		t.Fatalf("Phase 31 Down: %v", err)
	}
	var lifecycleColumnCount, revisionsTableCount int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_name='plans' AND column_name='lifecycle_status'`).Scan(&lifecycleColumnCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_name='plan_revisions'`).Scan(&revisionsTableCount); err != nil {
		t.Fatal(err)
	}
	if lifecycleColumnCount != 0 || revisionsTableCount != 0 {
		t.Fatalf("Phase 31 metadata remains after Down: lifecycle=%d revisions=%d", lifecycleColumnCount, revisionsTableCount)
	}
	var preservedPlans, preservedSubscriptions int
	if err := db.QueryRow(`SELECT count(*) FROM plans`).Scan(&preservedPlans); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM subscriptions`).Scan(&preservedSubscriptions); err != nil {
		t.Fatal(err)
	}
	if preservedPlans != 3 || preservedSubscriptions != 1 {
		t.Fatalf("rollback removed business data: plans=%d subscriptions=%d", preservedPlans, preservedSubscriptions)
	}
}
