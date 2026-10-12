package quota

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type lifecycleHostingAgent struct{}

func (lifecycleHostingAgent) SetHostingState(context.Context, types.SetHostingStateReq) (types.Response, error) {
	return types.Response{OK: true}, nil
}

type managedLifecycleAgent struct{ states []string }

func (a *managedLifecycleAgent) SetHostingState(_ context.Context, req types.SetHostingStateReq) (types.Response, error) {
	a.states = append(a.states, req.State)
	return types.Response{OK: true}, nil
}

type managedRuntimeLifecycleAgent struct{ *managedLifecycleAgent }

func (a *managedRuntimeLifecycleAgent) ApplySiteRuntime(_ context.Context, req types.ApplySiteRuntimeReq) (types.Response, error) {
	a.states = append(a.states, req.State)
	return types.Response{OK: true}, nil
}

func TestManagedActiveHostingStateSkipsClassicRuntime(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT CASE WHEN s.desired_status='active'`).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("active"))
	mock.ExpectQuery(`SELECT COALESCE.*hosting_mode FROM php_applications`).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"mode"}).AddRow("managed"))
	mock.ExpectExec(`UPDATE sites SET settings_status='pending'`).WithArgs(int64(42)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT settings_status FROM sites`).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"settings_status"}).AddRow("pending"))
	mock.ExpectQuery(`SELECT CASE WHEN s.desired_status='active'`).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("active"))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(int64(42), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	agent := &managedRuntimeLifecycleAgent{managedLifecycleAgent: &managedLifecycleAgent{}}
	reconciler := &lifecycleApplicationReconciler{}
	reconciler.onCall = func() error {
		var status string
		if err := db.QueryRow(`SELECT settings_status FROM sites WHERE id=$1`, int64(42)).Scan(&status); err != nil {
			return err
		}
		if status != "pending" {
			return errors.New("owner handoff preceded pending intent")
		}
		return nil
	}
	w := NewSetHostingStateWorker(agent, db)
	w.SetApplicationReconciler(reconciler)
	err = w.Work(context.Background(), &river.Job[SetHostingStateArgs]{Args: SetHostingStateArgs{SiteID: 42, State: "active"}})
	if err != nil || len(agent.states) != 0 || len(reconciler.siteIDs) != 1 {
		t.Fatalf("managed runtime not preserved: generic=%v reconciled=%v err=%v", agent.states, reconciler.siteIDs, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedActiveHostingStateFailsClosedWithoutReconciler(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT CASE WHEN s.desired_status='active'`).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("active"))
	mock.ExpectQuery(`SELECT COALESCE.*hosting_mode FROM php_applications`).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"mode"}).AddRow("managed"))
	mock.ExpectExec(`UPDATE sites SET last_error`).WithArgs(int64(42), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(int64(42), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	agent := &managedLifecycleAgent{}
	err = NewSetHostingStateWorker(agent, db).Work(context.Background(), &river.Job[SetHostingStateArgs]{Args: SetHostingStateArgs{SiteID: 42, State: "active"}})
	if err == nil || len(agent.states) != 0 {
		t.Fatalf("unconfigured managed handoff wrote classic runtime: generic=%v err=%v", agent.states, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedSuspensionStillStopsGenericRuntimeBeforeHandoff(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for range 2 {
		mock.ExpectQuery(`SELECT CASE WHEN s.desired_status='active'`).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("suspended"))
	}
	mock.ExpectExec(`UPDATE sites SET status=\$2`).WithArgs(int64(42), "suspended").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).WithArgs(int64(42), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	agent := &managedLifecycleAgent{}
	w := NewSetHostingStateWorker(agent, db)
	w.SetApplicationReconciler(lifecycleReconcilerFunc(func(context.Context, int64) error {
		if len(agent.states) != 1 || agent.states[0] != "suspended" {
			return errors.New("PHP handoff ran before generic shutdown")
		}
		return nil
	}))
	if err := w.Work(context.Background(), &river.Job[SetHostingStateArgs]{Args: SetHostingStateArgs{SiteID: 42, State: "suspended"}}); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

type lifecycleReconcilerFunc func(context.Context, int64) error

func (f lifecycleReconcilerFunc) ReconcileSiteApplication(ctx context.Context, siteID int64) error {
	return f(ctx, siteID)
}

type lifecycleApplicationReconciler struct {
	siteIDs []int64
	onCall  func() error
}

func (r *lifecycleApplicationReconciler) ReconcileSiteApplication(_ context.Context, siteID int64) error {
	if r.onCall != nil {
		if err := r.onCall(); err != nil {
			return err
		}
	}
	r.siteIDs = append(r.siteIDs, siteID)
	return nil
}

func TestHostingStateConvergenceImmediatelyReconcilesPHPApplication(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery(`SELECT CASE WHEN s.desired_status='active'`).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("active"))
	mock.ExpectQuery(`SELECT COALESCE.*hosting_mode FROM php_applications`).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"mode"}).AddRow("classic"))
	mock.ExpectQuery(`SELECT CASE WHEN s.desired_status='active'`).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("active"))
	mock.ExpectExec(`UPDATE sites SET status=\$2`).
		WithArgs(int64(42), "active").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_events`).
		WithArgs(int64(42), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	reconciler := &lifecycleApplicationReconciler{}
	worker := NewSetHostingStateWorker(lifecycleHostingAgent{}, db)
	worker.SetApplicationReconciler(reconciler)
	err = worker.Work(context.Background(), &river.Job[SetHostingStateArgs]{Args: SetHostingStateArgs{
		SiteID: 42, Username: "nps42", Domain: "managed.example", PHPVersion: "8.4", State: "active",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(reconciler.siteIDs) != 1 || reconciler.siteIDs[0] != 42 {
		t.Fatalf("reconciled site IDs = %v, want [42]", reconciler.siteIDs)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
