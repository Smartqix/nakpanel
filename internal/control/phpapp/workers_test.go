package phpapp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
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
	err := terminalPHPJobError(errors.New("managed PHP deployments are disabled by policy"))
	var cancel *river.JobCancelError
	if !errors.As(err, &cancel) {
		t.Fatalf("terminal policy failure = %T, want JobCancelError", err)
	}
	transport := errors.New("dial agent socket: connection refused")
	if got := terminalPHPJobError(transport); !errors.Is(got, transport) {
		t.Fatalf("transport error lost retryable identity: %v", got)
	}
	if errors.As(terminalPHPJobError(transport), &cancel) {
		t.Fatal("transport error was made terminal")
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
