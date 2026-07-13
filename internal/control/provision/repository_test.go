package provision

import (
	"context"
	"database/sql"
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
