package provisioningapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

func TestAccountChildJobPredicateCoversIndirectResourceJobs(t *testing.T) {
	for _, key := range []string{
		"subscription_id",
		"site_id",
		"database_id",
		"backup_id",
		"restore_id",
		"webmail_id",
		"zone_id",
		"application_id",
		"operation_id",
		"run_id",
		"billing_account_id",
	} {
		if !strings.Contains(accountChildJobPredicate, "j.args->>'"+key+"'") {
			t.Fatalf("account child-job predicate does not cover %s", key)
		}
	}
	for _, qualified := range []string{
		"j.kind='restore_backup' AND j.args->>'restore_id'",
		"j.kind='configure_webmail' AND j.args->>'webmail_id'",
		"j.kind='configure_dns_zone' AND j.args->>'zone_id'",
		"j.kind='converge_application' AND j.args->>'application_id'",
		"j.kind='run_staging_operation' AND j.args->>'operation_id'",
		"j.kind='run_scheduled_task' AND j.args->>'run_id'",
		"j.kind='finalize_billing_account' AND j.args->>'billing_account_id'",
		"j.kind='reconcile_system'",
		"j.args->'sites'",
		"j.args->'databases'",
	} {
		if !strings.Contains(accountChildJobPredicate, qualified) {
			t.Fatalf("account child-job predicate is not kind-qualified: %s", qualified)
		}
	}
}

func TestMarkAccountTerminatingClosesSubscriptionMutationGate(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WithArgs(int64(83)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT b\.provisioning_state`).
		WithArgs(int64(7), int64(83)).
		WillReturnRows(sqlmock.NewRows([]string{"provisioning_state"}).AddRow("active"))
	mock.ExpectExec(`UPDATE subscriptions SET status='cancelled'`).
		WithArgs(int64(83)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE billing_accounts`).
		WithArgs(int64(7)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	state, err := markAccountTerminatingTx(context.Background(), tx, 7, 83)
	if err != nil {
		t.Fatal(err)
	}
	if state != "terminating" {
		t.Fatalf("purge state = %q", state)
	}
	mock.ExpectRollback()
	_ = tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

type teardownAgentStub struct{}

func (teardownAgentStub) TeardownSubscription(context.Context, types.TeardownSubscriptionReq) error {
	return nil
}

func (teardownAgentStub) DeleteBackup(context.Context, types.DeleteBackupReq) (types.Response, error) {
	return types.Response{OK: true}, nil
}

func (teardownAgentStub) EnsureFTPS(context.Context, types.EnsureFTPSReq) (types.EnsureFTPSResult, error) {
	return types.EnsureFTPSResult{}, nil
}

func TestTeardownStopsWhenChildJobIsClaimedDuringCancellation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery(`SELECT b\.subscription_id`).
		WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"subscription_id", "provisioning_state", "username", "home_path"}).
			AddRow(int64(83), "terminating", "npaccount", "/home/npaccount"))
	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs(int64(83)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec(`UPDATE river_job`).
		WithArgs(int64(83)).
		WillReturnResult(sqlmock.NewResult(0, 4))
	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs(int64(83)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	worker := NewTeardownAccountWorker(db, teardownAgentStub{})
	err = worker.Work(context.Background(), &river.Job[TeardownAccountArgs]{
		Args: TeardownAccountArgs{BillingAccountID: 7},
	})
	if err == nil || !strings.Contains(err.Error(), "claimed during teardown") {
		t.Fatalf("Work error = %v; want claimed-during-teardown failure", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("Work returned unrelated cancellation: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
