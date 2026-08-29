package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

func expectSubscriptionMutationLock(mock sqlmock.Sqlmock, subscriptionID int64) {
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs(subscriptionID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT provisioning_state`).WithArgs(subscriptionID).
		WillReturnError(sql.ErrNoRows)
}

func TestMergeAndResetSitePolicyScopes(t *testing.T) {
	merged, err := mergeSitePolicyPatch(
		json.RawMessage(`{"web":{"compression":true}}`),
		json.RawMessage(`{"php":{"memory_limit_mb":256}}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	var patch map[string]json.RawMessage
	if err := json.Unmarshal(merged, &patch); err != nil {
		t.Fatal(err)
	}
	if len(patch["web"]) == 0 || len(patch["php"]) == 0 {
		t.Fatalf("merged patch lost a scope: %s", merged)
	}
	reset, err := removeSitePolicyScope(merged, "php")
	if err != nil {
		t.Fatal(err)
	}
	patch = nil
	if err := json.Unmarshal(reset, &patch); err != nil {
		t.Fatal(err)
	}
	if _, ok := patch["php"]; ok {
		t.Fatalf("PHP scope survived reset: %s", reset)
	}
	if _, ok := patch["web"]; !ok {
		t.Fatalf("web scope was removed by PHP reset: %s", reset)
	}
}

func TestEnforceServiceCountAcceptsFTPTableAndHonorsFiniteLimit(t *testing.T) {
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
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM ftp_accounts`).
		WithArgs(int64(83)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	if err := enforceServiceCountTx(context.Background(), tx, "ftp_accounts", 83, 2); !errors.Is(err, ErrExceeded) {
		t.Fatalf("enforceServiceCountTx error = %v, want ErrExceeded", err)
	}
	mock.ExpectRollback()
	_ = tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

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

func TestEnsureApplicationIdentityRejectsSiteOrNameMutation(t *testing.T) {
	for _, input := range []types.ApplicationInput{
		{ID: 7, SiteID: 50, Name: "stable-name"},
		{ID: 7, SiteID: 49, Name: "renamed"},
	} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectBegin()
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectQuery(`SELECT site_id,name FROM application_instances`).
			WithArgs(int64(7), int64(83)).
			WillReturnRows(sqlmock.NewRows([]string{"site_id", "name"}).AddRow(int64(49), "stable-name"))
		err = ensureApplicationIdentityTx(context.Background(), tx, 83, input)
		if err == nil || !strings.Contains(err.Error(), "cannot be changed") {
			t.Fatalf("ensureApplicationIdentityTx(%+v) error = %v", input, err)
		}
		mock.ExpectRollback()
		_ = tx.Rollback()
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
	}
}

func TestDeleteExternalServicesMarksCleanupBeforeConvergence(t *testing.T) {
	for _, test := range []struct {
		name                  string
		query                 string
		returning             bool
		convergesSubscription bool
		call                  func(*SQLStore) error
	}{
		{name: "mail", query: `UPDATE mail_domains SET enabled=false,delete_requested=true`, convergesSubscription: true, call: func(store *SQLStore) error { return store.DeleteMailDomain(context.Background(), 83, 7) }},
		{name: "application", query: `UPDATE application_instances`, returning: true, call: func(store *SQLStore) error { return store.DeleteApplication(context.Background(), 83, 7) }},
		{name: "ftp", query: `DELETE FROM ftp_accounts`, convergesSubscription: true, call: func(store *SQLStore) error { return store.DeleteFTPAccount(context.Background(), 83, 7) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			expectSubscriptionMutationLock(mock, 83)
			mock.ExpectQuery(`SELECT subscription\.status,customer\.status,customer\.reseller_id`).
				WithArgs(int64(83)).
				WillReturnRows(sqlmock.NewRows([]string{"subscription_status", "customer_status", "reseller_id"}).
					AddRow("active", "active", nil))
			if test.returning {
				mock.ExpectQuery(test.query).WithArgs(int64(7), int64(83)).
					WillReturnRows(sqlmock.NewRows([]string{"desired_revision"}).AddRow(int64(5)))
			} else {
				mock.ExpectExec(test.query).WithArgs(int64(7), int64(83)).WillReturnResult(sqlmock.NewResult(0, 1))
			}
			if test.convergesSubscription {
				mock.ExpectQuery(`UPDATE subscription_system_accounts\s+SET desired_revision=desired_revision\+1`).
					WithArgs(int64(83)).
					WillReturnRows(sqlmock.NewRows([]string{"desired_revision"}).AddRow(int64(4)))
			}
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

func TestLockActiveSubscriptionRejectsSuspendedCustomerOrSubscription(t *testing.T) {
	for _, test := range []struct {
		name, subscriptionStatus, customerStatus string
	}{
		{name: "subscription", subscriptionStatus: "suspended", customerStatus: "active"},
		{name: "customer", subscriptionStatus: "active", customerStatus: "suspended"},
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
			expectSubscriptionMutationLock(mock, 83)
			mock.ExpectQuery(`SELECT subscription\.status,customer\.status,customer\.reseller_id`).
				WithArgs(int64(83)).
				WillReturnRows(sqlmock.NewRows([]string{"subscription_status", "customer_status", "reseller_id"}).
					AddRow(test.subscriptionStatus, test.customerStatus, nil))
			err = lockActiveSubscriptionTx(context.Background(), tx, 83)
			if err == nil || !strings.Contains(err.Error(), "customer or subscription is suspended") {
				t.Fatalf("lockActiveSubscriptionTx() error = %v", err)
			}
			mock.ExpectRollback()
			_ = tx.Rollback()
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLockActiveSubscriptionRejectsSuspendedResellerOrMissingAllocation(t *testing.T) {
	for _, test := range []struct {
		name         string
		resellerRows *sqlmock.Rows
		resellerErr  error
		wantError    string
	}{
		{
			name:         "suspended reseller",
			resellerRows: sqlmock.NewRows([]string{"status"}).AddRow("suspended"),
			wantError:    "owning reseller is suspended",
		},
		{
			name:        "missing allocation",
			resellerErr: sql.ErrNoRows,
			wantError:   "owning reseller is suspended or has no active allocation",
		},
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
			expectSubscriptionMutationLock(mock, 83)
			mock.ExpectQuery(`SELECT subscription\.status,customer\.status,customer\.reseller_id`).
				WithArgs(int64(83)).
				WillReturnRows(sqlmock.NewRows([]string{"subscription_status", "customer_status", "reseller_id"}).
					AddRow("active", "active", int64(17)))
			resellerQuery := mock.ExpectQuery(`SELECT reseller\.status`).WithArgs(int64(17))
			if test.resellerErr != nil {
				resellerQuery.WillReturnError(test.resellerErr)
			} else {
				resellerQuery.WillReturnRows(test.resellerRows)
			}
			err = lockActiveSubscriptionTx(context.Background(), tx, 83)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("lockActiveSubscriptionTx() error = %v, want containing %q", err, test.wantError)
			}
			mock.ExpectRollback()
			_ = tx.Rollback()
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestQueueGitDeploymentRejectsSuspendedSubscriptionBeforeMutation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	expectSubscriptionMutationLock(mock, 83)
	mock.ExpectQuery(`SELECT subscription\.status,customer\.status,customer\.reseller_id`).
		WithArgs(int64(83)).
		WillReturnRows(sqlmock.NewRows([]string{"subscription_status", "customer_status", "reseller_id"}).
			AddRow("suspended", "active", nil))
	mock.ExpectRollback()
	if _, err := NewSQLStore(db).QueueGitDeployment(context.Background(), 83, 49); err == nil {
		t.Fatal("suspended subscription queued a Git deployment")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRequireGitPermissionRejectsRevokedEntitlement(t *testing.T) {
	var policy types.HostingPolicy
	if err := requireGitPermission(policy); err == nil {
		t.Fatal("revoked Git entitlement was accepted")
	}
	policy.Permissions.Git = true
	if err := requireGitPermission(policy); err != nil {
		t.Fatalf("enabled Git entitlement was rejected: %v", err)
	}
}
