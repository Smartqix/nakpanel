package phpapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestPostgresSubscriptionWorkerBudgetAndProductionMutationGuards(t *testing.T) {
	db := phpApplicationPostgres(t)
	_, err := db.Exec(`
CREATE TABLE billing_accounts(subscription_id BIGINT PRIMARY KEY,provisioning_state TEXT NOT NULL);
CREATE TABLE customers(id BIGINT PRIMARY KEY,login_user_id BIGINT,reseller_id BIGINT,email TEXT NOT NULL DEFAULT '',status TEXT NOT NULL);
CREATE TABLE subscriptions(id BIGINT PRIMARY KEY,customer_id BIGINT NOT NULL,status TEXT NOT NULL);
CREATE TABLE sites(id BIGINT PRIMARY KEY,subscription_id BIGINT NOT NULL,customer_id BIGINT NOT NULL,desired_status TEXT NOT NULL);
CREATE TABLE reseller_accounts(id BIGINT PRIMARY KEY,status TEXT NOT NULL);
CREATE TABLE reseller_subscriptions(reseller_id BIGINT NOT NULL,status TEXT NOT NULL);
CREATE TABLE river_job(kind TEXT NOT NULL,state TEXT NOT NULL,args JSONB NOT NULL);
CREATE TABLE php_applications(
 id BIGINT PRIMARY KEY,subscription_id BIGINT NOT NULL,site_id BIGINT NOT NULL UNIQUE,
 hosting_mode TEXT NOT NULL DEFAULT 'managed',desired_state TEXT NOT NULL DEFAULT 'active',
 desired_revision BIGINT NOT NULL DEFAULT 1,active_deployment_id BIGINT,previous_deployment_id BIGINT,
 observed_state TEXT NOT NULL DEFAULT 'pending',observed_message TEXT NOT NULL DEFAULT '',
 applied_revision BIGINT NOT NULL DEFAULT 0,convergence_status TEXT NOT NULL DEFAULT 'pending',
 last_error TEXT NOT NULL DEFAULT '',last_reconciled_at TIMESTAMPTZ,updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE php_workers(id BIGINT PRIMARY KEY,subscription_id BIGINT NOT NULL,application_id BIGINT NOT NULL,
 processes INTEGER NOT NULL,desired_state TEXT NOT NULL DEFAULT 'running',observed_state TEXT NOT NULL DEFAULT 'unknown',
 desired_revision BIGINT NOT NULL DEFAULT 1,applied_revision BIGINT NOT NULL DEFAULT 0,
 convergence_status TEXT NOT NULL DEFAULT 'pending',last_error TEXT NOT NULL DEFAULT '',
 last_reconciled_at TIMESTAMPTZ,updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE php_deployments(
 id BIGINT PRIMARY KEY,subscription_id BIGINT NOT NULL,application_id BIGINT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
 resolved_revision TEXT NOT NULL DEFAULT '',composer_audit JSONB NOT NULL DEFAULT '{}'::jsonb,
 health_message TEXT NOT NULL DEFAULT '',last_error TEXT NOT NULL DEFAULT '',
 started_at TIMESTAMPTZ,activated_at TIMESTAMPTZ,finished_at TIMESTAMPTZ
);
CREATE TABLE php_environment_bindings(id BIGINT PRIMARY KEY,subscription_id BIGINT NOT NULL,application_id BIGINT NOT NULL);
CREATE TABLE notifications(id BIGSERIAL PRIMARY KEY,recipient_user_id BIGINT,customer_id BIGINT,reseller_id BIGINT,
 subscription_id BIGINT,kind TEXT NOT NULL,severity TEXT NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,
 dedupe_key TEXT NOT NULL,resolved_at TIMESTAMPTZ,updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE UNIQUE INDEX notifications_active_dedupe ON notifications(dedupe_key) WHERE resolved_at IS NULL;
CREATE TABLE notification_deliveries(notification_id BIGINT NOT NULL,channel TEXT NOT NULL,recipient TEXT NOT NULL,
 UNIQUE(notification_id,channel,recipient));
CREATE TABLE audit_events(
 actor_user_id BIGINT,actor_label TEXT,customer_id BIGINT,subscription_id BIGINT,action TEXT,
 target_type TEXT,target_id BIGINT,metadata JSONB
);
INSERT INTO billing_accounts VALUES(4,'active');
INSERT INTO customers(id,reseller_id,email,status) VALUES(5,NULL,'owner@example.test','active');
INSERT INTO subscriptions VALUES(4,5,'active');
INSERT INTO sites VALUES(7,4,5,'active'),(8,4,5,'active'),(17,4,5,'active'),(18,4,5,'active'),
 (19,4,5,'active'),(20,4,5,'active'),(21,4,5,'active');
INSERT INTO php_applications(id,subscription_id,site_id,desired_revision,applied_revision) VALUES
 (9,4,7,2,1),(10,4,8,1,1),(11,4,17,2,1),(12,4,18,2,1),(13,4,19,3,1),
 (14,4,20,4,3),(15,4,21,5,4);
INSERT INTO php_workers(id,subscription_id,application_id,processes) VALUES(15,4,9,2),(16,4,10,2);
INSERT INTO php_deployments(id,subscription_id,application_id,status,resolved_revision) VALUES
 (91,4,9,'pending',''),(111,4,11,'preparing',''),(121,4,12,'preparing',''),
 (131,4,13,'pending',''),(140,4,14,'healthy','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
 (141,4,14,'retired','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),(142,4,14,'pending','');
UPDATE php_applications SET active_deployment_id=140 WHERE id=14;
UPDATE php_applications SET applied_revision=desired_revision,convergence_status='in_sync',last_reconciled_at=now()
 WHERE id>=11;
`)
	if err != nil {
		t.Fatal(err)
	}

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	processes, err := configuredSubscriptionWorkerProcessesTx(context.Background(), tx, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if processes != 4 {
		t.Fatalf("two-site subscription processes = %d, want 4", processes)
	}
	if _, err = db.Exec(`INSERT INTO river_job VALUES('reconcile_php_application','running','{"application_id":9,"desired_revision":2}')`); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(sweepApplicationCandidatesSQL)
	if err != nil {
		t.Fatalf("execute managed-application drift sweep: %v", err)
	}
	defer rows.Close()
	var candidates []int64
	for rows.Next() {
		var applicationID, revision int64
		if err = rows.Scan(&applicationID, &revision); err != nil {
			t.Fatal(err)
		}
		candidates = append(candidates, applicationID)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(candidates) != "[10]" {
		t.Fatalf("fair sweep candidates = %v, want queued application 9 excluded and application 10 selected", candidates)
	}
	policy := types.HostingPolicy{Permissions: types.HostingPermissionPolicy{PHPWorkers: true}, Resources: types.HostingResourcePolicy{MaxPHPWorkers: 4}}
	if err = validateSubscriptionWorkerProcesses(policy, processes); err != nil {
		t.Fatalf("finite worker limit rejected exact allocation: %v", err)
	}
	policy.Resources.MaxPHPWorkers = 3
	if err = validateSubscriptionWorkerProcesses(policy, processes); !errors.Is(err, controlquota.ErrExceeded) {
		t.Fatalf("finite over-allocation error = %v, want ErrExceeded", err)
	}
	policy.Resources.MaxPHPWorkers = 0
	if err = validateSubscriptionWorkerProcesses(policy, processes); !errors.Is(err, controlquota.ErrExceeded) {
		t.Fatalf("zero worker limit error = %v, want ErrExceeded", err)
	}
	policy.Resources.MaxPHPWorkers = -1
	if err = validateSubscriptionWorkerProcesses(policy, processes); err != nil {
		t.Fatalf("unlimited worker allocation rejected: %v", err)
	}

	installProductionPHPMutationGuards(t, db)
	store := &SQLStore{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	claimed, err := store.markDeploymentRunning(ctx, DeployPHPReleaseArgs{ApplicationID: 9, DeploymentID: 91, DesiredRevision: 2}, "preparing")
	if err != nil || !claimed {
		t.Fatalf("guarded deployment claim: claimed=%v err=%v", claimed, err)
	}
	if err = store.retryDeployment(ctx, 11, 111, 2, "temporary transport failure"); err != nil {
		t.Fatalf("guarded retry persistence: %v", err)
	}
	var retryStatus string
	if err = db.QueryRow(`SELECT status FROM php_deployments WHERE id=111`).Scan(&retryStatus); err != nil {
		t.Fatal(err)
	}
	if retryStatus != "pending" {
		t.Fatalf("retryable failure status = %q, want pending", retryStatus)
	}
	claimed, err = store.markDeploymentRunning(ctx, DeployPHPReleaseArgs{ApplicationID: 11, DeploymentID: 111, DesiredRevision: 2}, "preparing")
	if err != nil || !claimed {
		t.Fatalf("reclaim retryable deployment: claimed=%v err=%v", claimed, err)
	}
	retryLoaded := loadedApplication{record: applicationRecord{spec: types.PHPApplicationSpec{
		ApplicationID: 11, SubscriptionID: 4,
	}, customerID: 5}}
	if err = store.completeDeployment(ctx, DeployPHPReleaseArgs{ApplicationID: 11, DeploymentID: 111, DesiredRevision: 2}, retryLoaded,
		types.DeployPHPReleaseResult{DeploymentID: 111, ResolvedRevision: strings.Repeat("c", 40), HealthMessage: "healthy"}); err != nil {
		t.Fatalf("guarded retry success: %v", err)
	}
	if err = store.failDeployment(ctx, 12, 121, 2, "terminal deployment failure"); err != nil {
		t.Fatalf("guarded terminal failure: %v", err)
	}
	if err = store.settleSupersededDeployment(ctx, 13, 131, 2); err != nil {
		t.Fatalf("guarded superseded settlement: %v", err)
	}
	claimed, err = store.markRollbackRunning(ctx, RollbackPHPReleaseArgs{
		ApplicationID: 14, DeploymentID: 142, TargetDeploymentID: 141, DesiredRevision: 4,
	}, "preparing")
	if err != nil || !claimed {
		t.Fatalf("guarded rollback claim: claimed=%v err=%v", claimed, err)
	}
	loaded := loadedApplication{record: applicationRecord{spec: types.PHPApplicationSpec{
		ApplicationID: 15, SubscriptionID: 4, HostingMode: types.PHPHostingModeManaged, DesiredState: "active",
	}, customerID: 5}}
	if err = store.completeReconcile(ctx, ReconcilePHPApplicationArgs{ApplicationID: 15, DesiredRevision: 5}, loaded,
		types.ReconcilePHPApplicationResult{ApplicationID: 15, ObservedState: "pending", Message: "waiting for release"}); err != nil {
		t.Fatalf("guarded reconcile completion: %v", err)
	}
	var failedStatus, supersededStatus, rollbackStatus string
	if err = db.QueryRow(`SELECT
 (SELECT status FROM php_deployments WHERE id=111),
 (SELECT status FROM php_deployments WHERE id=121),
 (SELECT status FROM php_deployments WHERE id=131),
 (SELECT status FROM php_deployments WHERE id=142)`).Scan(&retryStatus, &failedStatus, &supersededStatus, &rollbackStatus); err != nil {
		t.Fatal(err)
	}
	if retryStatus != "healthy" || failedStatus != "failed" || supersededStatus != "failed" || rollbackStatus != "preparing" {
		t.Fatalf("guarded transition states = %q/%q/%q/%q", retryStatus, failedStatus, supersededStatus, rollbackStatus)
	}
}

func installProductionPHPMutationGuards(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
CREATE OR REPLACE FUNCTION nakpanel_assert_account_mutable(subscription_id_value BIGINT)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE provisioning_state_value TEXT;
BEGIN
    IF subscription_id_value IS NULL THEN RETURN; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('nakpanel:subscription:' || subscription_id_value::TEXT,0));
    SELECT provisioning_state INTO provisioning_state_value FROM billing_accounts
      WHERE subscription_id=subscription_id_value FOR SHARE;
    IF provisioning_state_value IN ('terminating','terminated') THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='billing account teardown has started';
    END IF;
END;
$$;
CREATE OR REPLACE FUNCTION nakpanel_guard_php_account_teardown()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE old_subscription_id BIGINT; new_subscription_id BIGINT;
BEGIN
    IF current_setting('nakpanel.account_teardown',true)='on' THEN
        IF TG_OP='DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    IF TG_OP<>'INSERT' THEN old_subscription_id:=NULLIF(to_jsonb(OLD)->>'subscription_id','')::BIGINT; END IF;
    IF TG_OP<>'DELETE' THEN new_subscription_id:=NULLIF(to_jsonb(NEW)->>'subscription_id','')::BIGINT; END IF;
    IF old_subscription_id IS NOT NULL AND new_subscription_id IS NOT NULL AND old_subscription_id<>new_subscription_id THEN
        IF old_subscription_id<new_subscription_id THEN
            PERFORM nakpanel_assert_account_mutable(old_subscription_id);
            PERFORM nakpanel_assert_account_mutable(new_subscription_id);
        ELSE
            PERFORM nakpanel_assert_account_mutable(new_subscription_id);
            PERFORM nakpanel_assert_account_mutable(old_subscription_id);
        END IF;
    ELSE
        PERFORM nakpanel_assert_account_mutable(COALESCE(new_subscription_id,old_subscription_id));
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER php_applications_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON php_applications
 FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_php_account_teardown();
CREATE TRIGGER php_deployments_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON php_deployments
 FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_php_account_teardown();
CREATE TRIGGER php_environment_bindings_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON php_environment_bindings
 FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_php_account_teardown();
CREATE TRIGGER php_workers_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON php_workers
 FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_php_account_teardown();`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPostgresManagedPendingAndObservedMarkerRecovery(t *testing.T) {
	db := phpApplicationPostgres(t)
	_, err := db.Exec(`
CREATE TABLE php_applications(
 id BIGINT PRIMARY KEY,desired_revision BIGINT NOT NULL,active_deployment_id BIGINT,previous_deployment_id BIGINT,
 observed_state TEXT NOT NULL,observed_message TEXT NOT NULL DEFAULT '',applied_revision BIGINT NOT NULL,
 convergence_status TEXT NOT NULL,last_error TEXT NOT NULL DEFAULT '',last_reconciled_at TIMESTAMPTZ,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE php_deployments(
 id BIGINT PRIMARY KEY,application_id BIGINT NOT NULL,status TEXT NOT NULL,resolved_revision TEXT NOT NULL DEFAULT '',
 health_message TEXT NOT NULL DEFAULT '',last_error TEXT NOT NULL DEFAULT '',activated_at TIMESTAMPTZ,finished_at TIMESTAMPTZ
);
CREATE TABLE php_workers(id BIGINT PRIMARY KEY,application_id BIGINT NOT NULL,desired_state TEXT,observed_state TEXT,
 desired_revision BIGINT,applied_revision BIGINT,convergence_status TEXT,last_error TEXT,last_reconciled_at TIMESTAMPTZ,updated_at TIMESTAMPTZ);
CREATE TABLE notifications(dedupe_key TEXT,resolved_at TIMESTAMPTZ,updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE audit_events(actor_user_id BIGINT,actor_label TEXT,customer_id BIGINT,subscription_id BIGINT,
 action TEXT,target_type TEXT,target_id BIGINT,metadata JSONB);
INSERT INTO php_applications VALUES(9,2,NULL,NULL,'pending','',1,'pending','',NULL,now());
`)
	if err != nil {
		t.Fatal(err)
	}
	store := &SQLStore{db: db}
	loaded := loadedApplication{record: applicationRecord{
		spec:       types.PHPApplicationSpec{ApplicationID: 9, SubscriptionID: 4, HostingMode: types.PHPHostingModeManaged, DesiredState: "active"},
		customerID: 5,
	}}
	args := ReconcilePHPApplicationArgs{ApplicationID: 9, DesiredRevision: 2}
	if err = store.completeReconcile(context.Background(), args, loaded, types.ReconcilePHPApplicationResult{
		ApplicationID: 9, ObservedState: "pending", Message: "waiting for first release",
	}); err != nil {
		t.Fatal(err)
	}
	var applied int64
	var convergence string
	if err = db.QueryRow(`SELECT applied_revision,convergence_status FROM php_applications WHERE id=9`).Scan(&applied, &convergence); err != nil {
		t.Fatal(err)
	}
	if applied != 1 || convergence != "pending" {
		t.Fatalf("pre-release convergence = applied %d status %q, want 1/pending", applied, convergence)
	}

	if _, err = db.Exec(`INSERT INTO php_deployments(id,application_id,status) VALUES(22,9,'preparing')`); err != nil {
		t.Fatal(err)
	}
	resolved := strings.Repeat("a", 40)
	if err = store.completeReconcile(context.Background(), args, loaded, types.ReconcilePHPApplicationResult{
		ApplicationID: 9, ActiveDeploymentID: 22, ResolvedRevision: resolved,
		ObservedState: "healthy", Message: "recovered marker",
	}); err != nil {
		t.Fatal(err)
	}
	var active int64
	if err = db.QueryRow(`SELECT COALESCE(active_deployment_id,0),applied_revision,convergence_status FROM php_applications WHERE id=9`).Scan(&active, &applied, &convergence); err != nil {
		t.Fatal(err)
	}
	if active != 22 || applied != 1 || convergence != "pending" {
		t.Fatalf("marker recovery = active %d applied %d status %q, want 22/1/pending", active, applied, convergence)
	}
	var status, storedRevision string
	if err = db.QueryRow(`SELECT status,resolved_revision FROM php_deployments WHERE id=22`).Scan(&status, &storedRevision); err != nil {
		t.Fatal(err)
	}
	if status != "healthy" || storedRevision != resolved {
		t.Fatalf("recovered deployment = %q %q", status, storedRevision)
	}
}

func phpApplicationPostgres(t *testing.T) *sql.DB {
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
	var admin *sql.DB
	var dsn string
	for _, candidateDSN := range candidates {
		candidate, openErr := sql.Open("pgx", candidateDSN)
		if openErr == nil {
			openErr = candidate.PingContext(ctx)
		}
		if openErr == nil {
			admin, dsn = candidate, candidateDSN
			break
		}
		if candidate != nil {
			candidate.Close()
		}
	}
	if admin == nil {
		t.Skip("PostgreSQL is unavailable and NAKPANEL_TEST_DATABASE_URL is not usable")
	}
	schema := fmt.Sprintf("phase30_task4_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = schema
	config.RuntimeParams["statement_timeout"] = "750ms"
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(8)
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`)
		admin.Close()
	})
	return db
}
