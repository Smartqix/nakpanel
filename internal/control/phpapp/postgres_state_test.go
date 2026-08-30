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

func TestPostgresSubscriptionWorkerBudgetAndApplicationFence(t *testing.T) {
	db := phpApplicationPostgres(t)
	_, err := db.Exec(`
CREATE TABLE billing_accounts(subscription_id BIGINT PRIMARY KEY,provisioning_state TEXT NOT NULL);
CREATE TABLE customers(id BIGINT PRIMARY KEY,reseller_id BIGINT,status TEXT NOT NULL);
CREATE TABLE subscriptions(id BIGINT PRIMARY KEY,customer_id BIGINT NOT NULL,status TEXT NOT NULL);
CREATE TABLE sites(id BIGINT PRIMARY KEY,desired_status TEXT NOT NULL);
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
CREATE TABLE php_workers(id BIGINT PRIMARY KEY,subscription_id BIGINT NOT NULL,application_id BIGINT NOT NULL,processes INTEGER NOT NULL);
CREATE TABLE php_deployments(
 id BIGINT PRIMARY KEY,application_id BIGINT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
 resolved_revision TEXT NOT NULL DEFAULT '',health_message TEXT NOT NULL DEFAULT '',last_error TEXT NOT NULL DEFAULT '',
 activated_at TIMESTAMPTZ,finished_at TIMESTAMPTZ
);
CREATE TABLE notifications(dedupe_key TEXT,resolved_at TIMESTAMPTZ,updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE audit_events(
 actor_user_id BIGINT,actor_label TEXT,customer_id BIGINT,subscription_id BIGINT,action TEXT,
 target_type TEXT,target_id BIGINT,metadata JSONB
);
INSERT INTO billing_accounts VALUES(4,'active');
INSERT INTO customers VALUES(5,NULL,'active');
INSERT INTO subscriptions VALUES(4,5,'active');
INSERT INTO sites VALUES(7,'active'),(8,'active');
INSERT INTO php_applications(id,subscription_id,site_id,desired_revision,applied_revision) VALUES(9,4,7,2,1),(10,4,8,1,1);
INSERT INTO php_workers VALUES(15,4,9,2),(16,4,10,2);
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

	store := &SQLStore{db: db}
	fence, missing, err := store.acquirePHPApplicationFence(context.Background(), 9)
	if err != nil || missing {
		t.Fatalf("acquire application fence: missing=%v err=%v", missing, err)
	}
	mutationFinished := make(chan error, 1)
	go func() {
		tx, beginErr := db.BeginTx(context.Background(), nil)
		if beginErr != nil {
			mutationFinished <- beginErr
			return
		}
		defer tx.Rollback()
		if lockErr := controlquota.LockSubscriptionMutationTx(context.Background(), tx, 4); lockErr != nil {
			mutationFinished <- lockErr
			return
		}
		if lockErr := lockPHPApplicationMutationTx(context.Background(), tx, 9); lockErr != nil {
			mutationFinished <- lockErr
			return
		}
		mutationFinished <- tx.Commit()
	}()
	select {
	case err = <-mutationFinished:
		t.Fatalf("mutation crossed the in-flight agent fence: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if err = fence.Release(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-mutationFinished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mutation did not resume after the agent fence was released")
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
