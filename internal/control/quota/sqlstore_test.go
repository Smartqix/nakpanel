package quota

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestUpsertLimitsHonorsOversellCap(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	store := NewSQLStore(db)
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	limits := Limits{
		UserID:            2,
		MaxSites:          1,
		MaxDatabases:      1,
		StorageMB:         20,
		MaxBackups:        1,
		BackupStorageMB:   20,
		SiteDiskQuotaMB:   20,
		PHPFPMMaxChildren: 2,
		PHPMemoryMB:       64,
	}

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO plans").
		WithArgs(
			"Custom quota user 2",
			"Compatibility plan generated from /quotas for user 2.",
			20,
			1,
			1,
			2,
			64,
			20,
			1,
			20,
		).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(10)))
	mock.ExpectQuery("SELECT oversell_policy").
		WillReturnRows(sqlmock.NewRows([]string{"oversell_policy", "server_disk_capacity_mb", "created_at", "updated_at"}).
			AddRow(OversellPolicyCap, 100, now, now))
	mock.ExpectQuery("FROM subscriptions s").
		WithArgs(int64(2)).
		WillReturnRows(sqlmock.NewRows([]string{"committed", "unlimited"}).AddRow(int64(90), false))
	mock.ExpectRollback()

	err = store.UpsertLimits(context.Background(), limits)
	if !errors.Is(err, ErrOversellCap) {
		t.Fatalf("UpsertLimits error = %v, want ErrOversellCap", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestGetLimitsForSubscriptionLoadsActivePlanBySubscription(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	store := NewSQLStore(db)
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery(regexp.QuoteMeta("WHERE s.id = $1")).
		WithArgs(int64(44)).
		WillReturnRows(sqlmock.NewRows([]string{
			"customer_id",
			"subscription_id",
			"plan_id",
			"plan_name",
			"max_sites",
			"max_databases",
			"disk_mb",
			"max_backups",
			"backup_storage_mb",
			"site_disk_quota_mb",
			"php_fpm_max_children",
			"php_memory_mb",
			"created_at",
			"updated_at",
		}).AddRow(int64(7), int64(44), int64(10), "Starter", 1, 2, 5120, 7, 5120, 5120, 3, 128, now, now))

	limits, ok, err := store.GetLimitsForSubscription(context.Background(), 44)
	if err != nil {
		t.Fatalf("GetLimitsForSubscription returned error: %v", err)
	}
	if !ok {
		t.Fatal("GetLimitsForSubscription ok=false, want true")
	}
	if limits.SubscriptionID != 44 || limits.CustomerID != 7 || limits.PlanName != "Starter" {
		t.Fatalf("limits = %#v, want subscription/customer/plan populated", limits)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestGetLimitsForSubscriptionRequiresActiveCustomer(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	store := NewSQLStore(db)
	mock.ExpectQuery(regexp.QuoteMeta("AND c.status = 'active'")).
		WithArgs(int64(44)).
		WillReturnError(sql.ErrNoRows)

	_, ok, err := store.GetLimitsForSubscription(context.Background(), 44)
	if err != nil {
		t.Fatalf("GetLimitsForSubscription returned error: %v", err)
	}
	if ok {
		t.Fatal("GetLimitsForSubscription ok=true for inactive/missing customer, want false")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestGetUsageForSubscriptionCountsOnlySelectedSubscription(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	store := NewSQLStore(db)
	mock.ExpectQuery("subscription_id = \\$1").
		WithArgs(int64(44)).
		WillReturnRows(sqlmock.NewRows([]string{"subscription_id", "sites", "databases", "backups", "backup_storage_bytes"}).
			AddRow(int64(44), 1, 2, 3, int64(4096)))

	usage, err := store.GetUsageForSubscription(context.Background(), 44)
	if err != nil {
		t.Fatalf("GetUsageForSubscription returned error: %v", err)
	}
	if usage.SubscriptionID != 44 || usage.Sites != 1 || usage.Databases != 2 || usage.Backups != 3 || usage.BackupStorageBytes != 4096 {
		t.Fatalf("usage = %#v, want selected subscription counts", usage)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}
