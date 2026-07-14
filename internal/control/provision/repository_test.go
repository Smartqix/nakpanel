package provision

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/store"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

func TestSQLSiteRepositoryRejectsTLSForInactiveSites(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	repo := NewSQLSiteRepository(db, store.New(db), new(river.Client[*sql.Tx]))
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, owner_user_id.*FROM sites.*WHERE domain = \$1`).
		WithArgs("example.test").
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"owner_user_id",
			"username",
			"domain",
			"php_version",
			"status",
			"last_error",
			"created_at",
			"updated_at",
			"tls_status",
			"tls_issuer",
			"tls_cert_path",
			"tls_key_path",
			"tls_expires_at",
			"tls_last_error",
			"subscription_id",
			"customer_id",
			"desired_status",
			"desired_php_version",
			"https_redirect",
			"desired_https_redirect",
			"settings_status",
			"settings_error",
			"tls_auto_renew",
			"system_account_id",
			"document_root",
		}).AddRow(
			int64(7),
			int64(1),
			"npdemo",
			"example.test",
			"8.3",
			"pending",
			"",
			now,
			now,
			"none",
			"",
			"",
			"",
			nil,
			"",
			int64(12),
			int64(13),
			"active",
			"8.3",
			false,
			false,
			"in_sync",
			"",
			true,
			int64(4),
			"/home/npdemo/domains/example.test/public_html",
		))
	mock.ExpectRollback()

	_, err = repo.IssueCertificate(context.Background(), 1, "example.test", types.CertIssuerLocalSelfSigned)
	if err == nil {
		t.Fatal("IssueCertificate returned nil error")
	}
	if !strings.Contains(err.Error(), "site must be active before issuing tls") {
		t.Fatalf("IssueCertificate error = %q, want inactive site rejection", err.Error())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestGuardCertificateOperationRejectsCrossKindActiveJob(t *testing.T) {
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
	mock.ExpectQuery(`SELECT id FROM sites WHERE id = \$1 FOR UPDATE`).
		WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(7)))
	mock.ExpectQuery(`SELECT EXISTS`).
		WithArgs("7").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	if err := guardCertificateOperationTx(context.Background(), tx, 7); !errors.Is(err, ErrCertificateOperationInProgress) {
		t.Fatalf("guardCertificateOperationTx error = %v", err)
	}
	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSelectReconcileDNSRecordsUsesCurrentSchema(t *testing.T) {
	t.Parallel()
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
	mock.ExpectQuery(`SELECT id,zone_id,host,record_type,value,COALESCE\(priority,0\),ttl FROM dns_records`).
		WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "zone_id", "host", "record_type", "value", "priority", "ttl"}).
			AddRow(int64(11), int64(7), "@", "A", "192.0.2.10", 0, 3600))
	records, err := selectReconcileDNSRecords(context.Background(), tx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Type != "A" || records[0].Priority != 0 {
		t.Fatalf("records = %#v", records)
	}
	mock.ExpectRollback()
	_ = tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
