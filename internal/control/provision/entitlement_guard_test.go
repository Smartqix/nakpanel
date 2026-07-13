package provision

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
)

func TestSiteIntentGuardRejectsCrossSubscriptionConflict(t *testing.T) {
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
	mock.ExpectQuery(`SELECT e.max_sites`).WithArgs(int64(7)).WillReturnRows(
		sqlmock.NewRows([]string{"max_sites", "max_databases", "max_backups", "backup_storage_mb", "overuse_policy", "hosting_enabled", "allow_backups"}).AddRow(2, 2, 2, 128, "block", true, true),
	)
	mock.ExpectQuery(`SELECT subscription_id FROM sites`).WithArgs("owned.test").WillReturnRows(
		sqlmock.NewRows([]string{"subscription_id"}).AddRow(int64(8)),
	)
	mock.ExpectRollback()

	if err := guardSiteIntentTx(context.Background(), tx, 7, "owned.test"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("guardSiteIntentTx error = %v, want ErrForbidden", err)
	}
	_ = tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSiteIntentGuardRechecksQuotaUnderSubscriptionLock(t *testing.T) {
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
	mock.ExpectQuery(`SELECT e.max_sites`).WithArgs(int64(7)).WillReturnRows(
		sqlmock.NewRows([]string{"max_sites", "max_databases", "max_backups", "backup_storage_mb", "overuse_policy", "hosting_enabled", "allow_backups"}).AddRow(1, 2, 2, 128, "block", true, true),
	)
	mock.ExpectQuery(`SELECT subscription_id FROM sites`).WithArgs("new.test").WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT COUNT\(\*\)::int FROM sites`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectRollback()

	if err := guardSiteIntentTx(context.Background(), tx, 7, "new.test"); !errors.Is(err, controlquota.ErrExceeded) {
		t.Fatalf("guardSiteIntentTx error = %v, want ErrExceeded", err)
	}
	_ = tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBackupIntentGuardAllowsOneReplacementAtLimit(t *testing.T) {
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
	mock.ExpectQuery(`SELECT e.max_sites`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"max_sites", "max_databases", "max_backups", "backup_storage_mb", "overuse_policy", "hosting_enabled", "allow_backups"}).AddRow(2, 2, 2, 128, "block", true, true))
	mock.ExpectQuery(`SELECT COUNT\(b.id\)`).WithArgs(int64(7), "owned.test").WillReturnRows(sqlmock.NewRows([]string{"used", "active_jobs"}).AddRow(2, 0))
	mock.ExpectQuery(`SELECT COALESCE\(SUM\(size_bytes\)`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"used"}).AddRow(int64(1024)))
	mock.ExpectRollback()
	if err = guardBackupIntentTx(context.Background(), tx, 7, "owned.test"); err != nil {
		t.Fatalf("guardBackupIntentTx error=%v, want bounded replacement", err)
	}
	_ = tx.Rollback()
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBackupIntentGuardBlocksReplacementWhileRetryIsActive(t *testing.T) {
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
	mock.ExpectQuery(`SELECT e.max_sites`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"max_sites", "max_databases", "max_backups", "backup_storage_mb", "overuse_policy", "hosting_enabled", "allow_backups"}).AddRow(2, 2, 2, 128, "block", true, true))
	mock.ExpectQuery(`SELECT COUNT\(b.id\)`).WithArgs(int64(7), "owned.test").WillReturnRows(sqlmock.NewRows([]string{"used", "active_jobs"}).AddRow(2, 1))
	mock.ExpectRollback()
	err = guardBackupIntentTx(context.Background(), tx, 7, "owned.test")
	if !errors.Is(err, controlquota.ErrExceeded) {
		t.Fatalf("guardBackupIntentTx error=%v, want ErrExceeded", err)
	}
	_ = tx.Rollback()
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
