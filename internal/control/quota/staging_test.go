package quota

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type stagingAgentStub struct {
	result types.RunStagingOperationResult
	err    error
	calls  int
}

func (a *stagingAgentStub) RunStagingOperation(_ context.Context, _ types.RunStagingOperationReq) (types.RunStagingOperationResult, error) {
	a.calls++
	return a.result, a.err
}

func TestStagingOperationRetriesReturnClaimToPending(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE staging_operations").
		WithArgs(int64(41), 1).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectLoadedStagingOperation(mock, 41)
	mock.ExpectExec("UPDATE staging_operations").
		WithArgs(int64(41), "pending", "agent unavailable").
		WillReturnResult(sqlmock.NewResult(0, 1))

	agent := &stagingAgentStub{err: errors.New("agent unavailable")}
	worker := NewStagingOperationWorker(db, agent)
	job := &river.Job[StagingOperationArgs]{
		JobRow: &rivertype.JobRow{Attempt: 1, MaxAttempts: 5},
		Args:   StagingOperationArgs{OperationID: 41},
	}
	if err = worker.Work(context.Background(), job); err == nil || err.Error() != "agent unavailable" {
		t.Fatalf("Work error = %v", err)
	}
	if agent.calls != 1 {
		t.Fatalf("agent calls = %d, want 1", agent.calls)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStagingOperationFinalAttemptMarksFailed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE staging_operations SET status='running'").
		WithArgs(int64(42), 5).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectLoadedStagingOperation(mock, 42)
	mock.ExpectExec("UPDATE staging_operations").
		WithArgs(int64(42), "failed", "terminal failure").
		WillReturnResult(sqlmock.NewResult(0, 1))

	worker := NewStagingOperationWorker(db, &stagingAgentStub{err: errors.New("terminal failure")})
	job := &river.Job[StagingOperationArgs]{
		JobRow: &rivertype.JobRow{Attempt: 5, MaxAttempts: 5},
		Args:   StagingOperationArgs{OperationID: 42},
	}
	if err = worker.Work(context.Background(), job); err == nil {
		t.Fatal("expected terminal failure")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStagingOperationRequiresClaimedRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE staging_operations SET status='running'").
		WithArgs(int64(43), 1).
		WillReturnResult(sqlmock.NewResult(0, 0))
	agent := &stagingAgentStub{}
	worker := NewStagingOperationWorker(db, agent)
	err = worker.Work(context.Background(), &river.Job[StagingOperationArgs]{Args: StagingOperationArgs{OperationID: 43}})
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("Work error = %v, want sql.ErrNoRows", err)
	}
	if agent.calls != 0 {
		t.Fatalf("agent calls = %d, want 0", agent.calls)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStagingOperationRechecksLifecycleBeforeAgentMutation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE staging_operations").
		WithArgs(int64(45), 1).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("FROM staging_operations operation").
		WithArgs(int64(45)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "source_site_id", "target_site_id", "username", "source_domain", "target_domain",
			"direction", "include_database", "source_subscription_id", "target_subscription_id",
			"lifecycle_active", "source_allowed", "target_allowed",
		}).AddRow(int64(45), int64(10), int64(20), "siteusr", "source.test", "target.test",
			"promote", false, int64(7), int64(7), false, true, true))
	mock.ExpectExec("UPDATE staging_operations").
		WithArgs(int64(45), "pending", "staging customer, provider, or subscription was suspended before execution").
		WillReturnResult(sqlmock.NewResult(0, 1))

	agent := &stagingAgentStub{}
	worker := NewStagingOperationWorker(db, agent)
	err = worker.Work(context.Background(), &river.Job[StagingOperationArgs]{
		JobRow: &rivertype.JobRow{Attempt: 1, MaxAttempts: 5},
		Args:   StagingOperationArgs{OperationID: 45},
	})
	if err == nil || !strings.Contains(err.Error(), "suspended before execution") {
		t.Fatalf("Work error = %v", err)
	}
	if agent.calls != 0 {
		t.Fatalf("agent calls = %d, want 0", agent.calls)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStagingOperationRequiresSuccessfulStatusTransition(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE staging_operations").
		WithArgs(int64(44), 1).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectLoadedStagingOperation(mock, 44)
	mock.ExpectExec("UPDATE staging_operations").
		WithArgs(int64(44), "/rollback/snapshot.tar.gz", sqlmock.AnyArg(), int64(12)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	worker := NewStagingOperationWorker(db, &stagingAgentStub{result: types.RunStagingOperationResult{
		SnapshotPath: "/rollback/snapshot.tar.gz", CopiedBytes: 12,
	}})
	err = worker.Work(context.Background(), &river.Job[StagingOperationArgs]{Args: StagingOperationArgs{OperationID: 44}})
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("Work error = %v, want sql.ErrNoRows", err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStagingOperationHasMultipleAttempts(t *testing.T) {
	if attempts := (StagingOperationArgs{}).InsertOpts().MaxAttempts; attempts <= 1 {
		t.Fatalf("MaxAttempts = %d, want more than one", attempts)
	}
}

func TestManualGitRepositoryOnlyConvergesForExplicitDeployment(t *testing.T) {
	if run, deploy := gitConvergenceAction("remote", false, false); !run || deploy {
		t.Fatal("manual remote repository should reconcile metadata without deploying")
	}
	if run, deploy := gitConvergenceAction("remote", false, true); !run || !deploy {
		t.Fatal("manual repository ignored an explicit deployment")
	}
	if run, deploy := gitConvergenceAction("remote", true, false); !run || !deploy {
		t.Fatal("automatic repository did not converge")
	}
	if run, deploy := gitConvergenceAction("hosted", false, false); !run || deploy {
		t.Fatal("manual hosted repository should initialize without deploying")
	}
}

func expectLoadedStagingOperation(mock sqlmock.Sqlmock, operationID int64) {
	mock.ExpectQuery("FROM staging_operations operation").
		WithArgs(operationID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "source_site_id", "target_site_id", "username", "source_domain", "target_domain",
			"direction", "include_database", "source_subscription_id", "target_subscription_id",
			"lifecycle_active", "source_allowed", "target_allowed",
		}).AddRow(operationID, int64(10), int64(20), "siteusr", "source.test", "target.test",
			"copy_to_staging", false, int64(7), int64(7), true, true, true))
}
