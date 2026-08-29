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

func TestNormalizeDNSRecordSupportsSRVAndRejectsTypedFieldOverflow(t *testing.T) {
	record, err := normalizeDNSRecord("example.test", types.DNSRecord{
		Host: "_sip._tcp", Type: "SRV", Value: "SIP.EXAMPLE.TEST.",
		Priority: 10, Weight: 5, Port: 5060, TTL: 3600,
	})
	if err != nil {
		t.Fatalf("normalize SRV record: %v", err)
	}
	if record.Value != "sip.example.test" {
		t.Fatalf("canonical SRV target = %q", record.Value)
	}

	invalid := []types.DNSRecord{
		{Host: "sip._tcp", Type: "SRV", Value: "sip.example.test", Priority: 10, Weight: 5, Port: 5060, TTL: 3600},
		{Host: "@", Type: "CAA", Value: `256 issue "letsencrypt.org"`, TTL: 3600},
		{Host: "@", Type: "DS", Value: "65536 13 2 " + strings.Repeat("A", 64), TTL: 3600},
		{Host: "@", Type: "DS", Value: "12345 0 2 " + strings.Repeat("A", 64), TTL: 3600},
	}
	for _, candidate := range invalid {
		if _, err := normalizeDNSRecord("example.test", candidate); err == nil {
			t.Fatalf("normalizeDNSRecord(%#v) succeeded, want validation error", candidate)
		}
	}
}

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
	mock.ExpectQuery(`SELECT id,zone_id,COALESCE\(owner_site_id,0\),host,record_type,value`).
		WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "zone_id", "owner_site_id", "host", "record_type", "value", "priority",
			"weight", "port", "ttl", "origin", "template_record_key", "template_revision", "locally_modified",
		}).AddRow(int64(11), int64(7), int64(3), "@", "A", "192.0.2.10", 0, 0, 0, 3600, "custom", "", 0, false))
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

func TestRefreshDNSSyncRunsBindsZoneID(t *testing.T) {
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
	mock.ExpectExec(`WITH affected AS \(\s*SELECT DISTINCT run_id FROM dns_template_sync_items WHERE zone_id=\$1`).
		WithArgs(int64(17)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := refreshDNSSyncRunsTx(context.Background(), tx, 17); err != nil {
		t.Fatal(err)
	}
	mock.ExpectRollback()
	_ = tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureSystemDNSRecordsReplacesProtectedDefaults(t *testing.T) {
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
	mock.ExpectExec(`DELETE FROM dns_records`).
		WithArgs(int64(17)).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(`INSERT INTO dns_records`).
		WithArgs(int64(17), int64(23), "ns1.example.test", "192.0.2.10").
		WillReturnResult(sqlmock.NewResult(0, 3))
	if err = ensureSystemDNSRecordsTx(context.Background(), tx, 17, 23, "example.test", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	mock.ExpectRollback()
	_ = tx.Rollback()
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMarkDNSActiveCompletesSupersededSyncRevisions(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE dns_zones SET status='active'`).
		WithArgs(int64(17), "/etc/bind/nakpanel/zones/db.example.test", int64(2026072405), int64(5)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE dns_template_sync_items\s+SET outcome='applied'.*desired_revision<=\$2`).
		WithArgs(int64(17), int64(5)).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(`WITH affected AS \(\s*SELECT DISTINCT run_id FROM dns_template_sync_items WHERE zone_id=\$1`).
		WithArgs(int64(17)).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectCommit()

	store := NewSQLPhase6StatusStore(db)
	err = store.MarkDNSActive(context.Background(), 17, types.ConfigureDNSZoneResult{
		ZonePath: "/etc/bind/nakpanel/zones/db.example.test", Serial: 2026072405,
		DesiredRevision: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
