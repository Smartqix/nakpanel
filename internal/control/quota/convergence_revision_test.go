package quota

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestEnqueueSubscriptionConvergenceAdvancesDurableRevision(t *testing.T) {
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
	mock.ExpectQuery(`UPDATE subscription_system_accounts\s+SET desired_revision=desired_revision\+1`).
		WithArgs(int64(42)).
		WillReturnRows(sqlmock.NewRows([]string{"desired_revision"}).AddRow(int64(9)))
	revision, err := EnqueueSubscriptionConvergenceTx(context.Background(), tx, nil, 42)
	if err != nil {
		t.Fatal(err)
	}
	if revision != 9 {
		t.Fatalf("revision = %d, want 9", revision)
	}
	mock.ExpectCommit()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAccountConvergenceOnlyAcknowledgesLoadedRevision(t *testing.T) {
	for _, test := range []struct {
		name     string
		affected int64
		want     bool
	}{
		{name: "exact snapshot", affected: 1, want: true},
		{name: "newer desired state", affected: 0, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			mock.ExpectExec(`UPDATE subscription_system_accounts\s+SET linux_uid=.*desired_revision=\$2`).
				WithArgs(int64(42), int64(7), "active", "in_sync", 1001, "").
				WillReturnResult(sqlmock.NewResult(0, test.affected))
			applied, err := updateAccountConvergenceTx(context.Background(), tx, 42, 7, "in_sync", "", 1001)
			if err != nil {
				t.Fatal(err)
			}
			if applied != test.want {
				t.Fatalf("applied = %t, want %t", applied, test.want)
			}
			mock.ExpectRollback()
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
