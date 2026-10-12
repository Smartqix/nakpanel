package phpapp

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

func workerLoadRows(values ...driver.Value) *sqlmock.Rows {
	columns := make([]string, len(values))
	for i := range columns {
		columns[i] = "column" + strconv.Itoa(i)
	}
	return sqlmock.NewRows(columns).AddRow(values...)
}

func expectWorkerPolicyLoad(t *testing.T, mock sqlmock.Sqlmock, policy types.HostingPolicy, siteState string, desiredWorkerState ...string) {
	t.Helper()
	expectWorkerPolicyLoadBeforeRuntime(t, mock, policy, siteState, desiredWorkerState...)
	mock.ExpectQuery(`SELECT binding.name`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"name", "value", "scope", "secret"}))
	mock.ExpectCommit()
}

func expectWorkerPolicyLoadBeforeRuntime(t *testing.T, mock sqlmock.Sqlmock, policy types.HostingPolicy, siteState string, desiredWorkerState ...string) {
	t.Helper()
	workerState := "running"
	processes := 2
	if len(desiredWorkerState) > 0 {
		workerState = desiredWorkerState[0]
	}
	if workerState == "stopped" {
		processes = 0
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT application.id`).WithArgs(int64(7)).WillReturnRows(workerLoadRows(
		7, 4, 9, 5, "nps4", "example.test", "managed", "8.4", 3, "main", "plain", "", "/", "[]", false, false, false, 3,
		"active", "healthy", 0, 0, 2, 1, "pending", "", "", "active", "active", siteState, true,
	))
	mock.ExpectQuery(`SELECT site.subscription_id`).WithArgs(int64(9)).WillReturnRows(workerLoadRows(4, "{}"))
	mock.ExpectQuery(`SELECT subscription_id,plan_name`).WithArgs(int64(4)).WillReturnRows(workerLoadRows(
		4, "test", 1024, 2, 2, 1024, 2, false, true, 7, "8.4", 5, 128, 1024, 2, 1024, 1, "warn", 80, 80, 2, 2, 2, 0, true, "8.4", true, true, true, "{}", raw,
	))
	mock.ExpectQuery(`SELECT e.hosting_policy`).WithArgs(int64(4)).WillReturnRows(workerLoadRows(raw, "{}"))
	mock.ExpectQuery(`SELECT id,subscription_id,application_id,name,script,arguments,processes`).WithArgs(int64(7)).WillReturnRows(workerLoadRows(
		11, 4, 7, "queue", "artisan", "[]", 2, workerState, "running", 2, 1, "pending", "", time.Now(),
	))
	mock.ExpectQuery(`SELECT COALESCE\(SUM\(processes\),0\)::int FROM php_workers`).WithArgs(int64(4), int64(0)).WillReturnRows(workerLoadRows(processes))
}

func TestWorkerStopOnlyLoadingDoesNotBypassStartOrDeployReadiness(t *testing.T) {
	for _, workersOnly := range []bool{false, true} {
		t.Run(strconv.FormatBool(workersOnly), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			state := "stopped"
			if workersOnly {
				state = "running"
			}
			expectWorkerPolicyLoadBeforeRuntime(t, mock, managedPolicy(), "active", state)
			mock.ExpectRollback()
			_, stale, err := (&SQLStore{db: db}).loadForWorkerOperation(context.Background(), 7, 2, nil, workersOnly)
			if stale || !errors.Is(err, ErrRuntimeUnavailable) {
				t.Fatalf("start/deploy bypassed readiness: stale=%v err=%v", stale, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWorkerStopDoesNotRequireRuntimeOrManagedPermission(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(strconv.FormatBool(revoked), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			policy := managedPolicy()
			policy.Permissions.ManagedPHPDeployments = !revoked
			expectWorkerPolicyLoad(t, mock, policy, "active", "stopped")
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT id,subscription_id,application_id,name,script,arguments,processes`).WithArgs(int64(7)).WillReturnRows(workerLoadRows(
				11, 4, 7, "queue", "artisan", "[]", 2, "stopped", "running", 2, 1, "pending", "", time.Now(),
			))
			mock.ExpectCommit()
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT desired_revision FROM php_applications`).WithArgs(int64(7)).WillReturnRows(workerLoadRows(2))
			mock.ExpectExec(`UPDATE php_workers SET observed_state`).WithArgs(int64(11), int64(7), "stopped").WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec(`UPDATE php_applications SET convergence_status='pending'`).WithArgs(int64(7), int64(2)).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec(`UPDATE notifications`).WithArgs(workerFailureKey(7)).WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectCommit()
			agent := &revokedWorkerShutdownAgent{t: t}
			w := NewReconcilePHPWorkersWorker(&SQLStore{db: db}, agent, nil)
			err = w.Work(context.Background(), &river.Job[ReconcilePHPWorkersArgs]{Args: ReconcilePHPWorkersArgs{ApplicationID: 7, DesiredRevision: 2}})
			if err != nil || !agent.stopped {
				t.Fatalf("stop-only reconciliation failed: stopped=%v err=%v", agent.stopped, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWorkerPolicyRevocationDoesNotPreventLifecycleLoad(t *testing.T) {
	for _, siteState := range []string{"active", "suspended"} {
		for _, revoked := range []bool{true, false} {
			t.Run(siteState+strconv.FormatBool(revoked), func(t *testing.T) {
				db, mock, err := sqlmock.New()
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				policy := managedPolicy()
				policy.Permissions.PHPWorkers = !revoked
				policy.Resources.MaxPHPWorkers = 1
				expectWorkerPolicyLoad(t, mock, policy, siteState)
				loaded, stale, err := (&SQLStore{db: db}).loadForWorker(context.Background(), 7, 2, nil)
				if err != nil || stale {
					t.Fatalf("cleanup load failed: stale=%v err=%v", stale, err)
				}
				if loaded.record.spec.DesiredState != siteState {
					t.Fatalf("website state = %q, want %q", loaded.record.spec.DesiredState, siteState)
				}
				if len(loaded.record.spec.Workers) != 0 {
					t.Fatal("restricted workers remain in the start specification")
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestWorkerRuntimeSpecStopsRevokedWorkersAndReactivates(t *testing.T) {
	loaded := loadedApplication{record: applicationRecord{spec: types.PHPApplicationSpec{
		HostingMode: types.PHPHostingModeManaged, DesiredState: "active", Policy: managedPolicy(),
		Workers: []types.PHPWorkerSpec{{WorkerID: 11, DesiredState: "running", Processes: 1}, {WorkerID: 12, DesiredState: "stopped", Processes: 64}},
	}}}
	if got := workerRuntimeSpec(loaded); len(got.Workers) != 1 || got.Workers[0].WorkerID != 11 {
		t.Fatalf("stopped worker remains in runtime budget: %#v", got.Workers)
	}
	loaded.record.spec.Policy.Permissions.PHPWorkers = false
	if got := workerRuntimeSpec(loaded); got.DesiredState != "suspended" {
		t.Fatal("revoked workers may start")
	}
	if !shouldCallWorkerAgent(loaded) {
		t.Fatal("revoked workers bypass cleanup without a release")
	}
	loaded.record.spec.Policy.Permissions.PHPWorkers = true
	if got := workerRuntimeSpec(loaded); got.DesiredState != "active" {
		t.Fatal("restored permission did not reactivate workers")
	}
	if loaded.record.spec.DesiredState != "active" || len(loaded.record.spec.Workers) != 2 {
		t.Fatal("worker cleanup mutated desired intent")
	}
}

type revokedWorkerShutdownAgent struct {
	t       *testing.T
	stopped bool
}

func (a *revokedWorkerShutdownAgent) DeployPHPRelease(context.Context, types.DeployPHPReleaseReq) (types.DeployPHPReleaseResult, error) {
	a.t.Fatal("unexpected deploy")
	return types.DeployPHPReleaseResult{}, nil
}
func (a *revokedWorkerShutdownAgent) RollbackPHPRelease(context.Context, types.RollbackPHPReleaseReq) (types.RollbackPHPReleaseResult, error) {
	a.t.Fatal("unexpected rollback")
	return types.RollbackPHPReleaseResult{}, nil
}
func (a *revokedWorkerShutdownAgent) ReconcilePHPWorkers(_ context.Context, req types.ReconcilePHPWorkersReq) (types.ReconcilePHPWorkersResult, error) {
	if req.Application.DesiredState != "suspended" {
		a.t.Fatal("worker shutdown attempted a start")
	}
	a.stopped = true
	return types.ReconcilePHPWorkersResult{ApplicationID: 7}, nil
}
func (a *revokedWorkerShutdownAgent) ReconcilePHPApplication(_ context.Context, req types.ReconcilePHPApplicationReq) (types.ReconcilePHPApplicationResult, error) {
	if !a.stopped {
		a.t.Fatal("website reconciliation ran before worker shutdown")
	}
	if req.Application.DesiredState != "active" {
		a.t.Fatal("worker revocation suspended the website")
	}
	return types.ReconcilePHPApplicationResult{}, errors.New("temporary web runtime failure")
}

func TestRevokedWorkerShutdownPrecedesFailedWebsiteReconcile(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	policy := managedPolicy()
	policy.Permissions.PHPWorkers = false
	expectWorkerPolicyLoad(t, mock, policy, "active")
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT application.subscription_id,site.customer_id,application.desired_revision`).WithArgs(int64(7)).WillReturnRows(workerLoadRows(4, 5, 2))
	mock.ExpectExec(`UPDATE php_applications SET convergence_status='pending'`).WithArgs(int64(7), int64(2), "temporary web runtime failure").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	agent := &revokedWorkerShutdownAgent{t: t}
	w := NewReconcilePHPApplicationWorker(&SQLStore{db: db}, agent, nil)
	err = w.Work(context.Background(), &river.Job[ReconcilePHPApplicationArgs]{Args: ReconcilePHPApplicationArgs{ApplicationID: 7, DesiredRevision: 2}})
	if err == nil || !agent.stopped {
		t.Fatalf("shutdown not performed before web failure: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRedactedPHPFailureNeverPersistsEnvironmentValues(t *testing.T) {
	environment := []types.PHPEnvironmentPayload{
		{Name: "APP_KEY", Secret: "top-secret-value"},
		{Name: "APP_NAME", Value: "private application name"},
	}
	got := redactPHPFailure(errors.New("failed with top-secret-value for private application name\nnext"), environment)
	if strings.Contains(got, "top-secret-value") || strings.Contains(got, "private application name") {
		t.Fatalf("redacted failure leaked an environment value: %q", got)
	}
	if strings.ContainsAny(got, "\r\n\x00") || len(got) > maxPersistedErrorBytes {
		t.Fatalf("redacted failure is not bounded and single-line: %q", got)
	}
}

func TestMarkDeploymentRunningRejectsStaleRevisionBeforeRPC(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectExec(`UPDATE php_deployments`).
		WithArgs(int64(11), int64(7), int64(13), "preparing").
		WillReturnResult(sqlmock.NewResult(0, 0))
	claimed, err := (&SQLStore{db: db}).markDeploymentRunning(context.Background(), DeployPHPReleaseArgs{
		ApplicationID: 7, DeploymentID: 11, DesiredRevision: 13,
	}, "preparing")
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("stale deployment revision was claimed")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPHPApplicationWorkerLockSerializesJobKinds(t *testing.T) {
	releaseFirst := lockPHPApplicationWorker(77)
	acquired := make(chan func(), 1)
	go func() { acquired <- lockPHPApplicationWorker(77) }()
	select {
	case releaseSecond := <-acquired:
		releaseSecond()
		releaseFirst()
		t.Fatal("second job acquired the same application lock concurrently")
	case <-time.After(25 * time.Millisecond):
	}
	releaseFirst()
	select {
	case releaseSecond := <-acquired:
		releaseSecond()
	case <-time.After(time.Second):
		t.Fatal("second job did not acquire the released application lock")
	}
}

func TestTerminalPHPPolicyFailuresCancelWithoutRetry(t *testing.T) {
	for _, message := range []string{
		"managed PHP deployments are disabled by policy",
		"PHP application subscription is inactive",
		"PHP release candidate failed readiness: HTTP health probe returned 500",
		"live PHP health probe returned 502",
	} {
		err := terminalPHPJobError(errors.New(message))
		var cancel *river.JobCancelError
		if !errors.As(err, &cancel) {
			t.Fatalf("terminal policy failure %q = %T, want JobCancelError", message, err)
		}
	}
	transport := errors.New("dial agent socket: connection refused")
	if got := terminalPHPJobError(transport); !errors.Is(got, transport) {
		t.Fatalf("transport error lost retryable identity: %v", got)
	}
	var cancel *river.JobCancelError
	if errors.As(terminalPHPJobError(transport), &cancel) {
		t.Fatal("transport error was made terminal")
	}
}

func TestRetryableDeploymentFailureRemainsClaimable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT application.subscription_id,site.customer_id,application.desired_revision
FROM php_applications application JOIN sites site ON site.id=application.site_id WHERE application.id=$1 FOR UPDATE OF application`)).
		WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"subscription_id", "customer_id", "desired_revision"}).AddRow(3, 5, 13))
	mock.ExpectExec(`UPDATE php_deployments SET status='pending'`).
		WithArgs(int64(11), int64(7), "dial agent socket: connection refused").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE php_applications SET convergence_status='pending'`).
		WithArgs(int64(7), int64(13), "dial agent socket: connection refused").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	transport := errors.New("dial agent socket: connection refused")
	worker := &DeployPHPReleaseWorker{store: &SQLStore{db: db}}
	got := worker.fail(context.Background(), DeployPHPReleaseArgs{
		ApplicationID: 7, DeploymentID: 11, DesiredRevision: 13,
	}, nil, transport, false)
	if !errors.Is(got, transport) {
		t.Fatalf("retryable failure = %v, want original transport error", got)
	}
	var cancel *river.JobCancelError
	if errors.As(got, &cancel) {
		t.Fatal("retryable transport failure was cancelled")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinalRetryableDeploymentAttemptPersistsTerminalFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT application.subscription_id,site.customer_id,application.desired_revision
FROM php_applications application JOIN sites site ON site.id=application.site_id WHERE application.id=$1 FOR UPDATE OF application`)).
		WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"subscription_id", "customer_id", "desired_revision"}).AddRow(3, 5, 13))
	mock.ExpectExec(`UPDATE php_deployments SET status='failed'`).
		WithArgs(int64(11), int64(7), "dial agent socket: connection refused").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE php_applications SET convergence_status='failed'`).
		WithArgs(int64(7), int64(13), "dial agent socket: connection refused").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`WITH recipient AS`).
		WithArgs(int64(5), int64(3), "php_deployment_failed", "critical", "PHP deployment failed",
			"dial agent socket: connection refused", deploymentFailureKey(7)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).
		WithArgs(int64(0), int64(5), int64(3), "php.convergence.failed", "php_application", int64(7), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	transport := errors.New("dial agent socket: connection refused")
	worker := &DeployPHPReleaseWorker{store: &SQLStore{db: db}}
	got := worker.fail(context.Background(), DeployPHPReleaseArgs{
		ApplicationID: 7, DeploymentID: 11, DesiredRevision: 13,
	}, nil, transport, true)
	var cancel *river.JobCancelError
	if !errors.As(got, &cancel) {
		t.Fatalf("final transport failure = %T %v, want JobCancelError", got, got)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinalPHPJobAttemptUsesRiverAttemptBudget(t *testing.T) {
	job := &river.Job[DeployPHPReleaseArgs]{JobRow: &rivertype.JobRow{Attempt: 4, MaxAttempts: 5}}
	if finalPHPJobAttempt(job) {
		t.Fatal("penultimate River attempt was treated as final")
	}
	job.Attempt = job.MaxAttempts
	if !finalPHPJobAttempt(job) {
		t.Fatal("exhausted River attempt was not treated as final")
	}
	if finalPHPJobAttempt(&river.Job[DeployPHPReleaseArgs]{}) {
		t.Fatal("synthetic job without attempt metadata was treated as final")
	}
}

func TestPHPFailureNotificationsUseDistinctPublicCategories(t *testing.T) {
	worker := phpFailureNotification(phpFailureWorker, 7, errors.New("worker exited"))
	if worker.kind != "php_worker_failed" || worker.key != workerFailureKey(7) {
		t.Fatalf("worker failure notification = %#v", worker)
	}
	composer := phpFailureNotification(phpFailureDeployment, 7, errors.New("Composer audit found a blocking security advisory"))
	if composer.kind != "php_composer_security" || composer.key != composerSecurityKey(7) {
		t.Fatalf("Composer failure notification = %#v", composer)
	}
	reconcile := phpFailureNotification(phpFailureReconcile, 7, errors.New("socket drift"))
	if reconcile.kind != "php_reconciliation_failed" || reconcile.key != reconcileFailureKey(7) {
		t.Fatalf("reconciliation failure notification = %#v", reconcile)
	}
}

func TestComposerAuditNotificationResolvesOnlyAfterCleanAudit(t *testing.T) {
	if kind, _, resolve := composerAuditNotification("low=2, abandoned=1"); kind != "php_composer_security" || resolve {
		t.Fatalf("Composer findings notification = kind %q resolve %v", kind, resolve)
	}
	for _, summary := range []string{"clean", "not required", `{"summary":"clean"}`} {
		if kind, _, resolve := composerAuditNotification(summary); kind != "" || !resolve {
			t.Fatalf("clean Composer audit %q = kind %q resolve %v", summary, kind, resolve)
		}
	}
}

func TestSupersededDeploymentIntentIsTerminalized(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectExec(`UPDATE php_deployments SET status='failed'`).
		WithArgs(int64(11), int64(7), int64(13)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err = (&SQLStore{db: db}).settleSupersededDeployment(context.Background(), 7, 11, 13); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRollbackIntentRequiresAtomicRevisionClaim(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectExec(`UPDATE php_deployments`).
		WithArgs(int64(12), int64(7), int64(11), int64(14), "preparing").
		WillReturnResult(sqlmock.NewResult(0, 1))
	claimed, err := (&SQLStore{db: db}).markRollbackRunning(context.Background(), RollbackPHPReleaseArgs{
		ApplicationID: 7, DeploymentID: 12, TargetDeploymentID: 11, DesiredRevision: 14,
	}, "preparing")
	if err != nil {
		t.Fatal(err)
	}
	if !claimed {
		t.Fatal("eligible rollback intent was not claimed")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedReconcileWithoutHealthyReleaseRemainsPending(t *testing.T) {
	record := applicationRecord{spec: types.PHPApplicationSpec{
		HostingMode: types.PHPHostingModeManaged, DesiredState: "active",
	}}
	if reconcileCanApply(record, types.ReconcilePHPApplicationResult{ObservedState: "pending"}) {
		t.Fatal("managed application without a healthy release was considered applied")
	}
	if !reconcileCanApply(record, types.ReconcilePHPApplicationResult{ActiveDeploymentID: 9, ObservedState: "healthy"}) {
		t.Fatal("healthy managed release was not considered applied")
	}
	record.spec.HostingMode = types.PHPHostingModeClassic
	if !reconcileCanApply(record, types.ReconcilePHPApplicationResult{ObservedState: "classic"}) {
		t.Fatal("classic application reconciliation was not considered applied")
	}
}

func TestWorkerObservedStateRequiresRunningApplication(t *testing.T) {
	if got := workerObservedState("running", true); got != "running" {
		t.Fatalf("running = %q", got)
	}
	if got := workerObservedState("running", false); got != "stopped" {
		t.Fatalf("suspended running worker = %q", got)
	}
	if got := workerObservedState("stopped", true); got != "stopped" {
		t.Fatalf("stopped = %q", got)
	}
}

func TestWorkerReconcileWaitsForFirstHealthyManagedRelease(t *testing.T) {
	loaded := loadedApplication{record: applicationRecord{spec: types.PHPApplicationSpec{
		HostingMode: types.PHPHostingModeManaged, DesiredState: "active",
	}}}
	if shouldCallWorkerAgent(loaded) {
		t.Fatal("worker reconciliation called the agent before the first healthy release")
	}
	loaded.active = &types.PHPDeployment{ID: 7}
	if !shouldCallWorkerAgent(loaded) {
		t.Fatal("worker reconciliation skipped an active managed release")
	}
	loaded.active = nil
	loaded.record.spec.DesiredState = "suspended"
	if !shouldCallWorkerAgent(loaded) {
		t.Fatal("suspension skipped the agent cleanup path")
	}
}
