package serveradmin

import (
	"context"
	"database/sql"
	"encoding/json"
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

func TestSystemJobsUseIsolatedSinglePurposeQueue(t *testing.T) {
	if opts := (RefreshInventoryArgs{}).InsertOpts(); opts.Queue != SystemQueue || !opts.UniqueOpts.ByArgs {
		t.Fatalf("refresh inventory opts = %#v", opts)
	}
	if opts := (ControlServiceArgs{OperationID: "op_12345678901234567890"}).InsertOpts(); opts.Queue != SystemQueue || opts.MaxAttempts != 1 || !opts.UniqueOpts.ByArgs {
		t.Fatalf("control service opts = %#v", opts)
	}
}

func TestManagerRejectsUnattributedServiceMutation(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	_, err := manager.ControlManagedService(context.Background(), types.ControlManagedServiceReq{
		ServiceID: "web", Action: "restart", OperationID: "op_12345678901234567890",
	})
	if err == nil {
		t.Fatal("unconfigured or unattributed service mutation unexpectedly succeeded")
	}
}

type testRiverInserter struct {
	err         error
	sawTx       bool
	operationID string
}

func (f *testRiverInserter) InsertTx(_ context.Context, tx *sql.Tx, args river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	f.sawTx = tx != nil
	if typed, ok := args.(ControlServiceArgs); ok {
		f.operationID = typed.OperationID
	}
	return &rivertype.JobInsertResult{}, f.err
}

type testServerAdminAgent struct {
	inventory types.ServerInventory
	err       error
}

func (a testServerAdminAgent) InspectServer(context.Context) (types.ServerInventory, error) {
	return a.inventory, a.err
}

func (testServerAdminAgent) ControlManagedService(context.Context, types.ControlManagedServiceReq) (types.ControlManagedServiceResult, error) {
	return types.ControlManagedServiceResult{}, nil
}

func TestControlManagedServicePersistsIntentAndJobAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const operationID = "op_12345678901234567890"
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO server_operations")).
		WithArgs(operationID, "services", "restart", "server_service", "web",
			sqlmock.AnyArg(), int64(0), operationID, int64(7)).
		WillReturnRows(operationTestRows(now).AddRow(
			int64(1), operationID, "services", "restart", "server_service", "web",
			[]byte(`{"action":"restart","operation_id":"`+operationID+`","service_id":"web"}`),
			[]byte(`{}`), "pending", nil, operationID, nil, nil, "", int64(7),
			nil, nil, now, now,
		))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_events")).
		WithArgs(int64(7), "server.service_restart_requested", "server_service", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	inserter := &testRiverInserter{}
	manager := &Manager{store: NewStore(db, nil), river: inserter, now: time.Now}

	_, err = manager.ControlManagedService(context.Background(), types.ControlManagedServiceReq{
		ServiceID: "web", Action: "restart", OperationID: operationID, ActorUserID: 7,
	})
	if err != nil {
		t.Fatalf("ControlManagedService error = %v", err)
	}
	if !inserter.sawTx || inserter.operationID != operationID {
		t.Fatalf("River insert = tx:%t operation:%q", inserter.sawTx, inserter.operationID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestControlManagedServiceRollsBackIntentWhenQueueInsertFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const operationID = "op_12345678901234567890"
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO server_operations")).
		WillReturnRows(operationTestRows(now).AddRow(
			int64(1), operationID, "services", "reload", "server_service", "web",
			[]byte(`{"action":"reload"}`), []byte(`{}`), "pending", nil,
			operationID, nil, nil, "", int64(7), nil, nil, now, now,
		))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_events")).
		WithArgs(int64(7), "server.service_reload_requested", "server_service", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectRollback()
	manager := &Manager{
		store: NewStore(db, nil),
		river: &testRiverInserter{err: errors.New("river unavailable")},
		now:   time.Now,
	}

	_, err = manager.ControlManagedService(context.Background(), types.ControlManagedServiceReq{
		ServiceID: "web", Action: "reload", OperationID: operationID, ActorUserID: 7,
	})
	if err == nil || !strings.Contains(err.Error(), "queue managed service operation") {
		t.Fatalf("ControlManagedService error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestInspectServerFallsBackToCachedInventoryAndMarksItUnknown(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	cached := types.ServerInventory{
		Hostname: "cached.test", Status: types.ServerStateHealthy, CheckedAt: now,
	}
	payload, _ := json.Marshal(cached)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id,kind,resource_key,health_status,payload,last_error,")).
		WithArgs("server", "host").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "kind", "resource_key", "health_status", "payload", "last_error",
			"checked_at", "expires_at", "created_at", "updated_at",
		}).AddRow(int64(1), "server", "host", "healthy", payload, "", now, now.Add(time.Minute), now, now))

	manager := &Manager{
		store: NewStore(db, nil),
		agent: testServerAdminAgent{err: errors.New("agent offline")},
		now:   func() time.Time { return now },
	}
	inventory, err := manager.InspectServer(context.Background())
	if !errors.Is(err, ErrInventoryCacheFallback) {
		t.Fatalf("InspectServer error = %v, want cache fallback", err)
	}
	if inventory.Hostname != "cached.test" || inventory.Status != types.ServerStateUnknown ||
		!strings.Contains(inventory.LastError, "cached inventory") {
		t.Fatalf("cached inventory = %#v", inventory)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestInspectServerReturnsInventoryPersistenceFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	inventory := types.ServerInventory{
		Hostname: "live.test", Status: types.ServerStateHealthy, CheckedAt: now,
	}
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO server_inventory")).
		WillReturnError(errors.New("database unavailable"))
	manager := &Manager{
		store: NewStore(db, nil),
		agent: testServerAdminAgent{inventory: inventory},
		now:   func() time.Time { return now },
	}

	got, err := manager.InspectServer(context.Background())
	if err == nil || !strings.Contains(err.Error(), "persist server inventory") {
		t.Fatalf("InspectServer error = %v", err)
	}
	if got.Hostname != inventory.Hostname {
		t.Fatalf("InspectServer inventory = %#v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func operationTestRows(_ time.Time) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "operation_id", "category", "action", "target_type", "target_key",
		"request", "result", "status", "desired_revision", "idempotency_key",
		"confirmation_deadline", "confirmed_at", "last_error", "actor_user_id",
		"started_at", "completed_at", "created_at", "updated_at",
	})
}
