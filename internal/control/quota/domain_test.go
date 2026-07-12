package quota

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestSiteConvergenceKeyChangesWithDesiredSettings(t *testing.T) {
	baseLimits := types.SiteResourceLimits{DiskQuotaMB: 64, PHPFPMMaxChildren: 2, PHPMemoryMB: 128}
	base := siteSettingsKey("active", "8.3", false, baseLimits)
	for _, changed := range []string{
		siteSettingsKey("suspended", "8.3", false, baseLimits),
		siteSettingsKey("active", "8.2", false, baseLimits),
		siteSettingsKey("active", "8.3", true, baseLimits),
		siteSettingsKey("active", "8.3", false, types.SiteResourceLimits{DiskQuotaMB: 128, PHPFPMMaxChildren: 2, PHPMemoryMB: 128}),
	} {
		if changed == base {
			t.Fatalf("settings key %q did not reflect a desired-state change", changed)
		}
	}
}

func TestChangeSubscriptionSubscriberRollsBackWholeBatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery("FROM customers").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{
		"id", "login_user_id", "email", "display_name", "company", "status", "notes", "created_at", "updated_at", "reseller_id",
	}).AddRow(int64(42), nil, "new@example.test", "New owner", "", "active", "", now, now, int64(9)))
	mock.ExpectQuery("FROM subscriptions s JOIN customers c").WithArgs(int64(10)).WillReturnRows(
		sqlmock.NewRows([]string{"reseller_id"}).AddRow(int64(9)),
	)
	mock.ExpectExec("UPDATE subscriptions SET customer_id").WithArgs(int64(10), int64(42), nil).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE sites SET customer_id").WithArgs(int64(10), int64(42)).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec("UPDATE databases SET customer_id").WithArgs(int64(10), int64(42)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE backups SET customer_id").WithArgs(int64(10), int64(42)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("FROM subscriptions s JOIN customers c").WithArgs(int64(11)).WillReturnError(errors.New("injected second-subscription failure"))
	mock.ExpectRollback()

	err = NewSQLStore(db).ChangeSubscriptionSubscriber(context.Background(), []int64{11, 10}, 42)
	if err == nil {
		t.Fatal("ChangeSubscriptionSubscriber returned nil, want rollback error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestUniqueSortedIDs(t *testing.T) {
	got := uniqueSortedIDs([]int64{4, 2, 4, 0, -1, 3})
	want := []int64{2, 3, 4}
	if len(got) != len(want) {
		t.Fatalf("uniqueSortedIDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("uniqueSortedIDs = %v, want %v", got, want)
		}
	}
}
