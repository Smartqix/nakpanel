package phpapp

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

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
