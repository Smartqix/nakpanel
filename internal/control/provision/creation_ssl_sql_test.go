package provision

import (
	"context"
	"database/sql"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/store"
	"testing"
	"time"
)

func TestHTTPSOnlyRetryPreservesInstalledCertificateState(t *testing.T) {
	site := store.GetSiteByDomainRow{TlsStatus: "active", TlsIssuer: "acme", TlsExpiresAt: sql.NullTime{Time: time.Now().Add(time.Hour), Valid: true}, TlsCertPath: "/cert.pem", TlsKeyPath: "/key.pem"}
	if !reuseInstalledCreationCertificate(site, true) {
		t.Fatal("HTTPS recovery would erase installed certificate state")
	}
	if reuseInstalledCreationCertificate(site, false) {
		t.Fatal("ordinary issuance must remain explicit")
	}
	site.TlsExpiresAt.Time = time.Now().Add(-time.Hour)
	if reuseInstalledCreationCertificate(site, true) {
		t.Fatal("expired certificate reused")
	}
}

func TestCreationSSLTransactionRejectsExistingDomainOrRevokedTLS(t *testing.T) {
	for _, tc := range []struct {
		name            string
		exists, allowed bool
		want            error
	}{{"existing domain", true, true, ErrSiteAlreadyExists}, {"revoked TLS", false, false, controlquota.ErrExceeded}, {"new allowed domain", false, true, nil}} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			tx, _ := db.BeginTx(context.Background(), nil)
			defer tx.Rollback()
			mock.ExpectQuery("SELECT EXISTS").WithArgs("example.test").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(tc.exists))
			if !tc.exists {
				mock.ExpectQuery("SELECT allow_tls").WithArgs(int64(20)).WillReturnRows(sqlmock.NewRows([]string{"allow_tls"}).AddRow(tc.allowed))
			}
			err = guardCreationSSLTx(context.Background(), tx, 20, "example.test")
			if !errors.Is(err, tc.want) {
				t.Fatalf("guard=%v want=%v", err, tc.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
