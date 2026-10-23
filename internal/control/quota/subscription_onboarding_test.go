package quota

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

func onboardingRows(values ...driver.Value) *sqlmock.Rows {
	columns := make([]string, len(values))
	for i := range columns {
		columns[i] = fmt.Sprintf("column%d", i)
	}
	return sqlmock.NewRows(columns).AddRow(values...)
}

func expectOnboardingCustomer(mock sqlmock.Sqlmock, login bool) {
	var loginID driver.Value
	if login {
		loginID = int64(17)
		mock.ExpectQuery(`SELECT id, role FROM users`).WithArgs("owner@example.test").WillReturnRows(sqlmock.NewRows([]string{"id", "role"}))
		mock.ExpectQuery(`INSERT INTO users`).WithArgs("owner@example.test", sqlmock.AnyArg()).WillReturnRows(onboardingRows(int64(17)))
	}
	now := time.Now()
	mock.ExpectQuery(`INSERT INTO customers`).WithArgs(loginID, "owner@example.test", "Owner", "", "", nil).
		WillReturnRows(onboardingRows(int64(88), loginID, "owner@example.test", "Owner", "", "active", "", now, now, int64(0)))
}

func expectOnboardingPlan(mock sqlmock.Sqlmock, active bool) {
	now := time.Now()
	mock.ExpectQuery(`FROM plans p LEFT JOIN`).WithArgs(int64(10)).WillReturnRows(onboardingRows(
		int64(10), "Starter", "", 0, 20, 1, 1, 100, 0, false, true, 0, "8.3", 2, 64, 20,
		1, 20, active, now, now, int64(0), 1, "block", 90, 90, 0, 0, 0, -1, true, "8.3", true, true, true,
		[]byte(`{}`), "active", nil, "", []byte(`{}`)))
}

func TestNewCustomerSubscriptionRollsBackRejectedPlan(t *testing.T) {
	for _, login := range []bool{false, true} {
		for _, reason := range []string{"inactive", "capacity"} {
			t.Run(fmt.Sprintf("%s/login=%v", reason, login), func(t *testing.T) {
				db, mock, err := sqlmock.New()
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				store := NewSQLStore(db)
				mock.ExpectBegin()
				expectOnboardingCustomer(mock, login)
				expectOnboardingPlan(mock, reason != "inactive")
				if reason == "capacity" {
					now := time.Now()
					mock.ExpectQuery(`SELECT oversell_policy`).WillReturnRows(onboardingRows(OversellPolicyCap, 100, 256, now, now))
					mock.ExpectQuery(`FROM subscriptions s`).WithArgs(int64(0)).WillReturnRows(onboardingRows(int64(90), false))
				}
				mock.ExpectRollback()
				_, err = store.CreateSubscription(context.Background(), types.CreateSubscriptionReq{PlanID: 10, NewCustomer: &types.CreateCustomerReq{Email: "owner@example.test", DisplayName: "Owner", EnableLogin: login, Password: "SecurePass!2026"}})
				if (reason == "inactive" && (err == nil || !strings.Contains(err.Error(), "inactive"))) || (reason == "capacity" && !errors.Is(err, ErrOversellCap)) {
					t.Fatalf("error = %v", err)
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestNewCustomerSubscriptionRejectsExistingIdentitiesBeforeWrites(t *testing.T) {
	for _, req := range []types.CreateSubscriptionReq{{ID: 7}, {CustomerID: 88}} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		req.NewCustomer = &types.CreateCustomerReq{Email: "owner@example.test"}
		_, err = NewSQLStore(db).CreateSubscription(context.Background(), req)
		if err == nil {
			t.Fatal("expected ambiguous identity rejection")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
}

func TestNewCustomerSubscriptionCanRetryAfterCapacityFailure(t *testing.T) {
	for _, login := range []bool{false, true} {
		t.Run(fmt.Sprintf("login=%v", login), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			store := NewSQLStore(db)
			req := types.CreateSubscriptionReq{PlanID: 10, NewCustomer: &types.CreateCustomerReq{Email: "owner@example.test", DisplayName: "Owner", EnableLogin: login, Password: "SecurePass!2026"}}
			for attempt := 0; attempt < 2; attempt++ {
				mock.ExpectBegin()
				expectOnboardingCustomer(mock, login)
				expectOnboardingPlan(mock, true)
				now := time.Now()
				mock.ExpectQuery(`SELECT oversell_policy`).WillReturnRows(onboardingRows(OversellPolicyCap, 100, 256, now, now))
				committed := int64(90)
				if attempt == 1 {
					committed = 0
				}
				mock.ExpectQuery(`FROM subscriptions s`).WithArgs(int64(0)).WillReturnRows(onboardingRows(committed, false))
				if attempt == 0 {
					mock.ExpectRollback()
					if _, err := store.CreateSubscription(context.Background(), req); !errors.Is(err, ErrOversellCap) {
						t.Fatalf("first attempt = %v", err)
					}
					continue
				}
				var loginID driver.Value
				customerUserID := int64(0)
				if login {
					loginID, customerUserID = int64(17), 17
				}
				mock.ExpectQuery(`INSERT INTO subscriptions`).WithArgs(int64(88), loginID, int64(10), "Starter subscription", "active", "synced", 1, -1).WillReturnRows(onboardingRows(int64(77)))
				mock.ExpectQuery(`SELECT EXISTS`).WithArgs("nps77").WillReturnRows(onboardingRows(false))
				mock.ExpectExec(`INSERT INTO subscription_system_accounts`).WithArgs(int64(77), "nps77", "active").WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`INSERT INTO subscription_entitlements`).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectQuery(`SELECT COALESCE\(\(SELECT policy_patch FROM subscription_policy_overrides`).WithArgs(int64(77)).WillReturnRows(onboardingRows([]byte(`{}`)))
				mock.ExpectExec(`UPDATE mail_domains domain SET effective_enabled=false`).WithArgs(int64(77)).WillReturnResult(sqlmock.NewResult(0, 0))
				for _, table := range []string{"sites", "databases", "backups"} {
					mock.ExpectExec(`UPDATE `+table+` SET customer_id`).WithArgs(int64(77), int64(88)).WillReturnResult(sqlmock.NewResult(0, 0))
				}
				mock.ExpectQuery(`WHERE s.id = \$1`).WithArgs(int64(77)).WillReturnRows(onboardingRows(
					int64(77), int64(88), customerUserID, "owner@example.test", "Owner", "", int64(10), "Starter", "Starter subscription", "active",
					1, 1, 20, 1, 20, 0, 0, 0, 0, 0, int64(0), now, now, int64(0), "synced", "in_sync", 1, "", "compliant", "", now,
					true, false, "8.3", 2, 64, 20, 100, 0, 0, 0, 0, 0, -1, true, "8.3", true, true, true, "block", 90, 90, []byte(`{}`), int64(0)))
				mock.ExpectCommit()
				sub, err := store.CreateSubscription(context.Background(), req)
				if err != nil || sub.ID != 77 || sub.CustomerID != 88 || sub.CustomerUserID != customerUserID {
					t.Fatalf("retry = %+v, %v", sub, err)
				}
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
