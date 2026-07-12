package quota

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestUpsertClientUserReusesCaseInsensitiveIdentity(t *testing.T) {
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
	mock.ExpectQuery(`SELECT id, role FROM users WHERE lower\(email\) = lower\(\$1\)`).
		WithArgs("client@example.test").
		WillReturnRows(sqlmock.NewRows([]string{"id", "role"}).AddRow(int64(17), "client"))
	mock.ExpectQuery(`UPDATE users`).
		WithArgs(int64(17), "client@example.test", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(17)))
	mock.ExpectRollback()

	id, err := upsertClientUserTx(context.Background(), tx, "client@example.test", "SecurePass!2026")
	if err != nil || id != 17 {
		t.Fatalf("upsertClientUserTx = %d, %v; want 17, nil", id, err)
	}
	_ = tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestLockedSubscriptionEditPreservesSnapshotOnlyForSamePlan(t *testing.T) {
	if !shouldPreserveLockedSnapshot(4, 8, "locked", 8, "locked") {
		t.Fatal("same-plan locked edit should preserve its entitlement snapshot")
	}
	for _, test := range []struct {
		requestedPlan int64
		requestedMode string
		currentPlan   int64
		currentMode   string
	}{{9, "locked", 8, "locked"}, {8, "synced", 8, "locked"}, {8, "locked", 8, "synced"}} {
		if shouldPreserveLockedSnapshot(4, test.requestedPlan, test.requestedMode, test.currentPlan, test.currentMode) {
			t.Fatalf("unexpected snapshot preservation for %+v", test)
		}
	}
}
