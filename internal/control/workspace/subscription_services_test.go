package workspace

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/auth"
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

func TestSubscriptionServicesRetainsLaterInventoryAfterGitFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.MatchExpectationsInOrder(false)
	for _, table := range []string{"subscription_system_accounts", "sites", "sftp_access_identities", "scheduled_tasks", "ftp_accounts", "git_deployments", "protected_directories", "valkey_instances", "staging_operations", "mail_domains", "mail_aliases", "webmail_hosts", "application_instances", "application_generations", "scheduled_task_runs", "site_usage_current", "application_presets"} {
		mock.ExpectQuery("FROM " + table + " ").WillReturnRows(sqlmock.NewRows([]string{"unused"}))
	}
	mock.ExpectQuery("FROM git_repositories ").WillReturnError(errors.New("git unavailable"))
	mock.ExpectQuery("FROM mailboxes ").WillReturnRows(sqlmock.NewRows([]string{"id", "subscription_id", "mail_domain_id", "address", "quota_mb", "enabled"}).AddRow(1, 42, 2, "hello@example.test", 128, true))
	data, err := NewStore(db).ListSubscriptionServices(context.Background(), auth.SessionUser{Role: auth.RoleAdmin})
	if err == nil || !strings.Contains(err.Error(), "git_repositories") {
		t.Fatalf("partial load error = %v", err)
	}
	if len(data.Mailboxes) != 1 || data.Mailboxes[0].Address != "hello@example.test" {
		t.Fatal("unrelated Git query hid mail inventory")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
