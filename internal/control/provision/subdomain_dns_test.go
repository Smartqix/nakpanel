package provision

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

func TestMissingSubdomainAddressRecordsCreatesOnlyAbsentAddresses(t *testing.T) {
	existing := []types.DNSRecord{{Host: "blog", Type: "A", Value: "192.0.2.10"}}
	missing, err := missingSubdomainAddressRecords(existing, "blog", "192.0.2.10", "2001:db8::10")
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0].Host != "blog" || missing[0].Type != "AAAA" || missing[0].Value != "2001:db8::10" {
		t.Fatalf("missing records = %+v, want only the AAAA record", missing)
	}
	if again, err := missingSubdomainAddressRecords(append(existing, missing...), "blog", "192.0.2.10", "2001:db8::10"); err != nil || len(again) != 0 {
		t.Fatalf("idempotent records = %+v, %v", again, err)
	}
}

func TestAutoConfigureSubdomainDNSDetectsConflictInLegacyParentZone(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewSQLPhase6Repository(db, new(river.Client[*sql.Tx]))
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT parent_site_id,dns_zone_mode,domain`).WithArgs(int64(2)).
		WillReturnRows(sqlmock.NewRows([]string{"parent_site_id", "dns_zone_mode", "domain"}).AddRow(int64(1), "parent", "blog.example.test"))
	mock.ExpectQuery(`LEFT JOIN dns_template_revisions`).WithArgs(int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "domain", "mode", "address", "ipv6_address", "serial", "desired_revision", "serial_format"}).
			AddRow(int64(9), "example.test", "primary", "192.0.2.10", "", int64(123), int64(3), "unix"))
	mock.ExpectQuery(`SELECT host,record_type,value`).WithArgs(int64(9), "blog").
		WillReturnRows(sqlmock.NewRows([]string{"host", "record_type", "value"}).AddRow("blog", "CNAME", "other.example.test"))
	mock.ExpectRollback()
	if err := repo.AutoConfigureSubdomainDNS(context.Background(), 2); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("AutoConfigureSubdomainDNS error = %v, want conflict", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAutoConfigureSubdomainDNSSkipsSecondaryZone(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewSQLPhase6Repository(db, new(river.Client[*sql.Tx]))
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT parent_site_id,dns_zone_mode,domain`).WithArgs(int64(2)).
		WillReturnRows(sqlmock.NewRows([]string{"parent_site_id", "dns_zone_mode", "domain"}).AddRow(int64(1), "parent", "blog.example.test"))
	mock.ExpectQuery(`SELECT zone.id,zone.domain,zone.mode`).WithArgs(int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "domain", "mode", "address", "ipv6_address", "serial", "desired_revision", "serial_format"}).
			AddRow(int64(9), "example.test", "secondary", "192.0.2.10", "", int64(123), int64(3), "unix"))
	mock.ExpectRollback()
	if err := repo.AutoConfigureSubdomainDNS(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMissingSubdomainAddressRecordsRejectsConflictingDNS(t *testing.T) {
	for _, record := range []types.DNSRecord{
		{Host: "blog", Type: "A", Value: "192.0.2.99"},
		{Host: "blog", Type: "CNAME", Value: "other.example.test"},
		{Host: "blog", Type: "AAAA", Value: "2001:db8::99"},
	} {
		if _, err := missingSubdomainAddressRecords([]types.DNSRecord{record}, "blog", "192.0.2.10", "2001:db8::10"); err == nil || !strings.Contains(err.Error(), "conflict") {
			t.Fatalf("record %+v: error = %v, want conflict", record, err)
		}
	}
}
