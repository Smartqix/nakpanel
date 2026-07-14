package quota

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestEnsureSiteBelongsTxRejectsCrossSubscriptionDomain(t *testing.T) {
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
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(int64(49), int64(83)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if err := ensureSiteBelongsTx(context.Background(), tx, 83, 49); err == nil {
		t.Fatal("cross-subscription domain was accepted")
	}
	mock.ExpectRollback()
	_ = tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteExternalServicesMarksCleanupBeforeConvergence(t *testing.T) {
	for _, test := range []struct {
		name  string
		query string
		call  func(*SQLStore) error
	}{
		{name: "mail", query: `UPDATE mail_domains SET enabled=false,delete_requested=true`, call: func(store *SQLStore) error { return store.DeleteMailDomain(context.Background(), 83, 7) }},
		{name: "application", query: `UPDATE application_instances SET delete_requested=true`, call: func(store *SQLStore) error { return store.DeleteApplication(context.Background(), 83, 7) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			mock.ExpectExec(test.query).WithArgs(int64(7), int64(83)).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec(`UPDATE subscription_system_accounts SET convergence_status='pending'`).WithArgs(int64(83)).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()
			if err := test.call(NewSQLStore(db)); err != nil {
				t.Fatal(err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
