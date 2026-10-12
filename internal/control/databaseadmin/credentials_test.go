package databaseadmin

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

func TestRotationCommitUncertaintyRechecksDurableSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const id = "op_123456789012345678901234"
	request := mutationRequest{Action: types.DatabaseAdminRotatePassword, Target: types.DatabaseAdminTarget{DatabaseID: 42, Name: "np_demo", Principal: "np_demo_user"}, CredentialScope: pendingSecretScope, CredentialName: "rotation-" + id}
	payload, _ := json.Marshal(request)
	store := &fakeAdminStore{operation: serveradmin.Operation{OperationID: id, TargetKey: "42", Request: payload, Status: serveradmin.OperationPending, ActorUserID: 7}, plaintext: []byte("desired_password_2026")}
	agent := &fakeAgent{}
	manager := NewManager(db, agent, store, nil)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE server_operations").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO audit_events").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit().WillReturnError(errors.New("commit acknowledgement lost"))
	job := &river.Job[MutationArgs]{Args: MutationArgs{OperationID: id, DatabaseID: 42}}
	err = NewMutationWorker(manager).Work(context.Background(), job)
	var snooze *river.JobSnoozeError
	if !errors.As(err, &snooze) {
		t.Fatalf("expected reconciliation: %v", err)
	}
	if len(store.updates) != 1 || store.updates[0].Status != serveradmin.OperationRunning {
		t.Fatal("ambiguous commit overwrote possible success")
	}
	// Simulate a transaction which committed despite losing its acknowledgement.
	store.operation.Status = serveradmin.OperationSucceeded
	if err := NewMutationWorker(manager).Work(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if agent.calls != 1 {
		t.Fatal("completed revision was reapplied")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRotationRejectsConcurrentReplacementWithoutChangingSecret(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &fakeAdminStore{}
	manager := NewManager(db, &fakeAgent{}, store, &fakeRiver{})
	mock.ExpectQuery("SELECT id, engine, db_name, db_user").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"id", "engine", "db_name", "db_user"}).AddRow(42, "mariadb", "np_demo", "np_demo_user"))
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT operation_id, action, request").WillReturnRows(sqlmock.NewRows([]string{"operation_id", "action", "request"}).AddRow("op_existing", "rotate_password", []byte(`{}`)))
	mock.ExpectRollback()
	if _, err := manager.RotatePassword(context.Background(), 7, 42, "another_password_2026"); !errors.Is(err, ErrOperationInProgress) {
		t.Fatalf("expected conflict: %v", err)
	}
	if len(store.secretWrites) != 0 {
		t.Fatal("concurrent replacement changed desired revision")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
