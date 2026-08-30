package phpapp

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRequireExistingWorkerRejectsUnknownBrowserSuppliedID(t *testing.T) {
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
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(int64(9), int64(15)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if err = requireExistingWorkerTx(context.Background(), tx, 9, 15); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown worker error = %v, want ErrNotFound", err)
	}
	mock.ExpectRollback()
	_ = tx.Rollback()
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
