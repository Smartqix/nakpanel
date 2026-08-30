package quota

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type lifecycleHostingAgent struct{}

func (lifecycleHostingAgent) SetHostingState(context.Context, types.SetHostingStateReq) (types.Response, error) {
	return types.Response{OK: true}, nil
}

type lifecycleApplicationReconciler struct {
	siteIDs []int64
}

func (r *lifecycleApplicationReconciler) ReconcileSiteApplication(_ context.Context, siteID int64) error {
	r.siteIDs = append(r.siteIDs, siteID)
	return nil
}

func TestHostingStateConvergenceImmediatelyReconcilesPHPApplication(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for range 2 {
		mock.ExpectQuery(`SELECT CASE WHEN s.desired_status='active'`).
			WithArgs(int64(42)).
			WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("active"))
	}
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
