package quota

import (
	"context"
	"errors"
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
