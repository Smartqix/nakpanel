package workspace

import (
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestScanSiteUsageConvertsPostgresTimestamp(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	periodStart := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	collectedAt := time.Date(2026, time.July, 23, 12, 30, 0, 0, time.UTC)
	mock.ExpectQuery("SELECT site_id").WillReturnRows(sqlmock.NewRows([]string{
		"site_id", "period_start", "document_root_bytes", "traffic_bytes",
		"request_count", "error_count", "php_state", "collected_at", "last_error",
	}).AddRow(int64(8), periodStart, int64(1024), int64(2048), int64(10), int64(2), "active", collectedAt, ""))

	rows, err := db.Query("SELECT site_id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("expected a site usage row")
	}
	got, err := scanSiteUsage(rows)
	if err != nil {
		t.Fatalf("scanSiteUsage: %v", err)
	}
	if got.SiteID != 8 || !got.CollectedAt.Valid || !got.CollectedAt.Time.Equal(collectedAt) {
		t.Fatalf("scanSiteUsage = %#v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestScanSiteUsagePreservesNullCollectionTime(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT site_id").WillReturnRows(sqlmock.NewRows([]string{
		"site_id", "period_start", "document_root_bytes", "traffic_bytes",
		"request_count", "error_count", "php_state", "collected_at", "last_error",
	}).AddRow(int64(9), time.Now(), int64(0), int64(0), int64(0), int64(0), "unknown", nil, "not collected"))

	rows, err := db.Query("SELECT site_id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("expected a site usage row")
	}
	got, err := scanSiteUsage(rows)
	if err != nil {
		t.Fatalf("scanSiteUsage: %v", err)
	}
	if got.CollectedAt.Valid {
		t.Fatalf("CollectedAt = %#v; want invalid", got.CollectedAt)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

var _ rowScanner = (*sql.Row)(nil)
