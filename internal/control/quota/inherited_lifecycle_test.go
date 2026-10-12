package quota

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func expectInheritedAccountQueue(mock sqlmock.Sqlmock, customerID int64, accounts ...int64) {
	rows := sqlmock.NewRows([]string{"subscription_id"})
	for _, id := range accounts {
		rows.AddRow(id)
	}
	mock.ExpectQuery(`(?s)SELECT account.subscription_id.*account.desired_state IN.*provisioning_state IN.*ORDER BY`).WithArgs(customerID).WillReturnRows(rows)
	for _, id := range accounts {
		mock.ExpectQuery(`UPDATE subscription_system_accounts\s+SET desired_revision=desired_revision\+1`).WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"revision"}).AddRow(9))
	}
	mock.ExpectQuery(`SELECT r.id,r.username`).WithArgs(customerID).WillReturnRows(sqlmock.NewRows([]string{"empty"}))
}

func TestCustomerLifecycleQueuesAccountsEvenWithoutSites(t *testing.T) {
	for _, status := range []string{"suspended", "active"} {
		t.Run(status, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			mock.ExpectExec(`UPDATE customers SET status=\$2`).WithArgs(int64(4), status).WillReturnResult(sqlmock.NewResult(0, 1))
			expectInheritedAccountQueue(mock, 4, 42, 43)
			mock.ExpectCommit()
			if err := NewSQLStore(db, nil).SetCustomerStatus(context.Background(), 4, status); err != nil {
				t.Fatal(err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSubscriptionLifecycleQueuesAccountServices(t *testing.T) {
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
	mock.ExpectQuery(`SELECT customer_id FROM subscriptions`).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"customer_id"}).AddRow(4))
	expectInheritedAccountQueue(mock, 4, 42)
	mock.ExpectCommit()
	if err := NewSQLStore(db, nil).enqueueSubscriptionHostingStateTx(context.Background(), tx, 42); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestResellerLifecycleQueuesAllCustomerAccounts(t *testing.T) {
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
	mock.ExpectQuery(`SELECT id FROM customers WHERE reseller_id`).WithArgs(int64(2)).WillReturnRows(sqlmock.NewRows([]string{"customer_id"}).AddRow(4).AddRow(5))
	expectInheritedAccountQueue(mock, 4, 42)
	expectInheritedAccountQueue(mock, 5, 43)
	mock.ExpectCommit()
	if err := NewSQLStore(db, nil).enqueueResellerHostingStateTx(context.Background(), tx, 2); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCustomerLifecycleRollsBackWhenAccountQueueFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE customers SET status=\$2`).WithArgs(int64(4), "suspended").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT account.subscription_id`).WithArgs(int64(4)).WillReturnRows(sqlmock.NewRows([]string{"subscription_id"}).AddRow(42))
	mock.ExpectQuery(`UPDATE subscription_system_accounts`).WithArgs(int64(42)).WillReturnError(errors.New("queue failure"))
	mock.ExpectRollback()
	if err := NewSQLStore(db, nil).SetCustomerStatus(context.Background(), 4, "suspended"); err == nil {
		t.Fatal("lifecycle status committed without account convergence")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestExplicitSubscriptionLifecycleUpdatesAccountIntent(t *testing.T) {
	for _, status := range []string{"active", "suspended", "cancelled"} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectBegin()
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectExec(`(?s)UPDATE subscription_system_accounts SET desired_state=CASE WHEN \$2='active' THEN 'active' ELSE 'suspended' END`).WithArgs(int64(42), status).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		if err := setSubscriptionAccountIntentTx(context.Background(), tx, 42, status); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
}

func TestCustomerProviderTransferQueuesInheritedLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE customers SET reseller_id=\$2`).WithArgs(int64(4), nil).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE subscriptions SET sync_mode='locked'`).WithArgs(int64(4)).WillReturnResult(sqlmock.NewResult(0, 1))
	expectInheritedAccountQueue(mock, 4, 42)
	mock.ExpectCommit()
	if err := NewSQLStore(db, nil).TransferCustomer(context.Background(), 4, 0); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
