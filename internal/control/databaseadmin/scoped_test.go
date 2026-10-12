package databaseadmin

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestCredentialStateIsScopedAndSafe(t *testing.T) {
	for _, test := range []struct{ stored, want string }{{"pending", "updating"}, {"running", "updating"}, {"succeeded", "active"}, {"failed", "failed"}, {"cancelled", "failed"}} {
		t.Run(test.stored, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			m := &Manager{db: db}
			mock.ExpectQuery(`SELECT COALESCE`).WithArgs(int64(30), int64(7)).WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow(test.stored))
			got, err := m.DatabaseCredentialState(context.Background(), 30, 7)
			if err != nil || got != test.want {
				t.Fatalf("state=%s err=%v", got, err)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestScopedPasswordGuardRejectsInactiveOrMismatchedTarget(t *testing.T) {
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
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs(int64(7)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT provisioning_state`).WithArgs(int64(7)).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT d.id FROM databases d`).WithArgs(int64(30), int64(7)).WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	err = guardScopedDatabaseMutation(context.Background(), tx, 30, 7)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("error=%v", err)
	}
	_ = tx.Rollback()
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
