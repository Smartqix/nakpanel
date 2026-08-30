package databaseadmin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type fakeAgent struct {
	request types.ManageDatabaseAdminReq
	calls   int
	err     error
}

type fakeAdminStore struct {
	secretParams    serveradmin.PutSecretParams
	secretWrites    []serveradmin.PutSecretParams
	deletedSecrets  [][2]string
	operationParams serveradmin.CreateOperationParams
	operation       serveradmin.Operation
	plaintext       []byte
	updates         []serveradmin.UpdateOperationParams
}

func (f *fakeAdminStore) PutSecretTx(_ context.Context, _ *sql.Tx, params serveradmin.PutSecretParams) (serveradmin.SecretReference, error) {
	f.secretParams = params
	f.secretParams.Plaintext = append([]byte(nil), params.Plaintext...)
	copied := params
	copied.Plaintext = append([]byte(nil), params.Plaintext...)
	f.secretWrites = append(f.secretWrites, copied)
	return serveradmin.SecretReference{SecretID: "sec_123456789012345678901234"}, nil
}

func (f *fakeAdminStore) DeleteSecretTx(_ context.Context, _ *sql.Tx, scope, name string) error {
	f.deletedSecrets = append(f.deletedSecrets, [2]string{scope, name})
	return nil
}

func (f *fakeAdminStore) GetSecret(context.Context, string, string) ([]byte, serveradmin.SecretReference, error) {
	return append([]byte(nil), f.plaintext...), serveradmin.SecretReference{SecretID: "sec_pending"}, nil
}

func (f *fakeAdminStore) CreateOperationTx(_ context.Context, _ *sql.Tx, params serveradmin.CreateOperationParams) (serveradmin.Operation, error) {
	f.operationParams = params
	return serveradmin.Operation{
		OperationID: params.OperationID, Status: serveradmin.OperationPending,
		ActorUserID: params.ActorUserID,
	}, nil
}

func (f *fakeAdminStore) GetOperation(context.Context, string) (serveradmin.Operation, error) {
	if f.operation.OperationID == "" {
		return serveradmin.Operation{}, sql.ErrNoRows
	}
	return f.operation, nil
}

func (f *fakeAdminStore) UpdateOperation(_ context.Context, params serveradmin.UpdateOperationParams) (serveradmin.Operation, error) {
	f.updates = append(f.updates, params)
	return f.operation, nil
}

type fakeRiver struct {
	args MutationArgs
}

func (f *fakeRiver) InsertTx(_ context.Context, _ *sql.Tx, args river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	f.args = args.(MutationArgs)
	return &rivertype.JobInsertResult{}, nil
}

func (f *fakeAgent) InspectDatabaseAdmin(context.Context, types.InspectDatabaseAdminReq) (types.DatabaseAdminSnapshot, error) {
	return types.DatabaseAdminSnapshot{}, nil
}

func (f *fakeAgent) ManageDatabaseAdmin(_ context.Context, req types.ManageDatabaseAdminReq) (types.ManageDatabaseAdminResult, error) {
	f.calls++
	f.request = req
	return types.ManageDatabaseAdminResult{
		DatabaseID: req.Target.DatabaseID, Action: req.Action, Role: req.Role,
	}, f.err
}

func TestCheckResolvesTrackedNamesInsteadOfAcceptingCallerIdentifiers(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	agent := &fakeAgent{}
	manager := NewManager(db, agent, nil, nil)

	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT id, engine, db_name, db_user
FROM databases
WHERE id=$1`)).
		WithArgs(int64(42)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "engine", "db_name", "db_user"}).
			AddRow(42, "mariadb", "np_customer", "np_customer_user"))

	_, err = manager.Check(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if agent.calls != 1 || agent.request.Target.Name != "np_customer" ||
		agent.request.Target.Principal != "np_customer_user" ||
		agent.request.Action != types.DatabaseAdminCheck {
		t.Fatalf("unexpected agent request: %#v", agent.request)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestUnsupportedTrackedEngineNeverReachesMariaDBAgent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	agent := &fakeAgent{}
	manager := NewManager(db, agent, nil, nil)

	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT id, engine, db_name, db_user
FROM databases
WHERE id=$1`)).
		WithArgs(int64(8)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "engine", "db_name", "db_user"}).
			AddRow(8, "pgsql", "np_pg", "np_pg_user"))

	if _, err := manager.Check(context.Background(), 8); err == nil {
		t.Fatal("expected unsupported engine error")
	}
	if agent.calls != 0 {
		t.Fatalf("agent calls = %d, want 0", agent.calls)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRotatePasswordQueuesOnlyEncryptedSecretReference(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &fakeAdminStore{}
	queue := &fakeRiver{}
	manager := NewManager(db, &fakeAgent{}, store, queue)
	const replacement = "new_rotation_password_2026"

	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT id, engine, db_name, db_user
FROM databases
WHERE id=$1`)).
		WithArgs(int64(42)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "engine", "db_name", "db_user"}).
			AddRow(42, "mariadb", "np_customer", "np_customer_user"))
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock($1)")).
		WithArgs(int64(26000042)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT operation_id, action, request
FROM server_operations`)).
		WithArgs("42").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()

	result, err := manager.RotatePassword(context.Background(), 7, 42, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "queued" || result.OperationID == "" || queue.args.OperationID != result.OperationID ||
		queue.args.DatabaseID != 42 {
		t.Fatalf("unexpected queued result=%#v args=%#v", result, queue.args)
	}
	if string(store.secretParams.Plaintext) != replacement ||
		store.secretParams.Scope != pendingSecretScope ||
		!strings.HasPrefix(store.secretParams.Name, "rotation_op_") ||
		store.secretParams.Name != strings.ToLower(store.secretParams.Name) {
		t.Fatalf("unexpected staged secret: %#v", store.secretParams)
	}
	if strings.Contains(string(store.operationParams.Request), replacement) {
		t.Fatal("plaintext password entered the durable operation request")
	}
	var persisted mutationRequest
	if err := json.Unmarshal(store.operationParams.Request, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.CredentialName != store.secretParams.Name || persisted.CredentialScope != pendingSecretScope {
		t.Fatalf("persisted credential reference = %#v", persisted)
	}
	if store.operationParams.ActorUserID != 7 ||
		store.operationParams.Category != serveradmin.CategoryApplicationsDatabases ||
		store.operationParams.TargetKey != "42" {
		t.Fatalf("operation params = %#v", store.operationParams)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotRedactsPersistedErrorText(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	agent := &fakeSnapshotAgent{snapshot: types.DatabaseAdminSnapshot{
		Server: types.DatabaseServerHealth{Available: true},
		Databases: []types.TrackedDatabaseState{{
			DatabaseID: 3, DatabaseExists: true, PrincipalExists: true,
		}},
	}}
	manager := NewManager(db, agent, nil, nil)
	mock.ExpectQuery("SELECT id, customer_id").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "customer_id", "subscription_id", "site_id", "engine",
			"db_name", "db_user", "status", "has_error",
		}).AddRow(3, 4, 5, 0, "mariadb", "np_demo", "np_demo_user", "failed", true))

	snapshot, err := manager.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Databases) != 1 || snapshot.Databases[0].LastError != "Provisioning requires attention." {
		t.Fatalf("snapshot error was not redacted: %#v", snapshot)
	}
}

func TestMutationWorkerPromotesCredentialAndScrubsPendingReference(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const (
		operationID = "op_123456789012345678901234"
		replacement = "new_rotation_password_2026"
	)
	request := mutationRequest{
		Action:          types.DatabaseAdminRotatePassword,
		Target:          types.DatabaseAdminTarget{DatabaseID: 42, Name: "np_demo", Principal: "np_demo_user"},
		CredentialScope: pendingSecretScope, CredentialName: pendingCredentialName(operationID),
	}
	payload, _ := json.Marshal(request)
	store := &fakeAdminStore{
		operation: serveradmin.Operation{
			OperationID: operationID, TargetKey: "42", Request: payload,
			Status: serveradmin.OperationPending, ActorUserID: 7,
		},
		plaintext: []byte(replacement),
	}
	agent := &fakeAgent{}
	manager := NewManager(db, agent, store, nil)
	worker := NewMutationWorker(manager)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE server_operations")).
		WithArgs(operationID, serveradmin.OperationSucceeded, sqlmock.AnyArg(), "", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_events")).
		WithArgs(int64(7), "database.rotate_password_succeeded", int64(42), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = worker.Work(context.Background(), &river.Job[MutationArgs]{
		Args: MutationArgs{OperationID: operationID, DatabaseID: 42},
	})
	if err != nil {
		t.Fatal(err)
	}
	if agent.calls != 1 || agent.request.Password != replacement {
		t.Fatalf("agent password rotation was not invoked: %#v", agent.request)
	}
	if len(store.secretWrites) != 1 ||
		store.secretWrites[0].Scope != canonicalSecretScope ||
		store.secretWrites[0].Name != "provision-42" ||
		string(store.secretWrites[0].Plaintext) != replacement {
		t.Fatalf("canonical credential promotion = %#v", store.secretWrites)
	}
	if len(store.deletedSecrets) != 1 ||
		store.deletedSecrets[0] != [2]string{pendingSecretScope, pendingCredentialName(operationID)} {
		t.Fatalf("staged secret cleanup = %#v", store.deletedSecrets)
	}
	if len(store.updates) != 1 || store.updates[0].Status != serveradmin.OperationRunning {
		t.Fatalf("operation updates = %#v", store.updates)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMutationWorkerScrubsPendingCredentialAndAuditsTerminalFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const operationID = "op_123456789012345678901234"
	request := mutationRequest{
		Action:          types.DatabaseAdminRotatePassword,
		Target:          types.DatabaseAdminTarget{DatabaseID: 42, Name: "np_demo", Principal: "np_demo_user"},
		CredentialScope: pendingSecretScope, CredentialName: pendingCredentialName(operationID),
	}
	payload, _ := json.Marshal(request)
	store := &fakeAdminStore{
		operation: serveradmin.Operation{
			OperationID: operationID, TargetKey: "42", Request: payload,
			Status: serveradmin.OperationPending, ActorUserID: 7,
		},
		plaintext: []byte("new_rotation_password_2026"),
	}
	agent := &fakeAgent{err: errors.New("mariadb unavailable")}
	manager := NewManager(db, agent, store, nil)
	worker := NewMutationWorker(manager)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE server_operations")).
		WithArgs(operationID, serveradmin.OperationFailed, sqlmock.AnyArg(),
			"Database administration operation failed.", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_events")).
		WithArgs(int64(7), "database.rotate_password_failed", int64(42), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = worker.Work(context.Background(), &river.Job[MutationArgs]{
		Args:   MutationArgs{OperationID: operationID, DatabaseID: 42},
		JobRow: &rivertype.JobRow{Attempt: 3, MaxAttempts: 3},
	})
	if err == nil {
		t.Fatal("expected terminal agent failure")
	}
	if len(store.secretWrites) != 0 {
		t.Fatalf("terminal failure promoted a credential: %#v", store.secretWrites)
	}
	if len(store.deletedSecrets) != 1 ||
		store.deletedSecrets[0] != [2]string{pendingSecretScope, pendingCredentialName(operationID)} {
		t.Fatalf("terminal failure did not scrub staged credential: %#v", store.deletedSecrets)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

type fakeSnapshotAgent struct {
	snapshot types.DatabaseAdminSnapshot
}

func (f *fakeSnapshotAgent) InspectDatabaseAdmin(context.Context, types.InspectDatabaseAdminReq) (types.DatabaseAdminSnapshot, error) {
	return f.snapshot, nil
}

func (*fakeSnapshotAgent) ManageDatabaseAdmin(context.Context, types.ManageDatabaseAdminReq) (types.ManageDatabaseAdminResult, error) {
	return types.ManageDatabaseAdminResult{}, nil
}
