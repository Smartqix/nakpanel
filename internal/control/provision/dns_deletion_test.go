package provision

import (
	"context"
	"testing"

	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
)

func TestDeletedTemplateRecordLeavesSuppression(t *testing.T) {
	db := removaldb.New(t, "")
	driver := riverdatabasesql.New(db)
	migrator, err := rivermigrate.New(driver, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = migrator.Migrate(context.Background(), rivermigrate.DirectionUp, nil); err != nil {
		t.Fatal(err)
	}
	client, err := river.NewClient(driver, &river.Config{})
	if err != nil {
		t.Fatal(err)
	}
	site := removaldb.Site(t, db, 1, "deleted.example.test", nil)
	var zone, record int64
	if err = db.QueryRow(`INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,status,template_revision) VALUES(1,$1,'deleted.example.test','192.0.2.1',1,'active',1) RETURNING id`, site).Scan(&zone); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin,template_record_key,template_revision) VALUES($1,$2,'www','A','192.0.2.1',3600,'template','www-a',1) RETURNING id`, zone, site).Scan(&record); err != nil {
		t.Fatal(err)
	}
	if err = NewSQLPhase6Repository(db, client).DeleteDNSRecord(context.Background(), site, record); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM dns_template_deletions WHERE zone_id=$1 AND owner_site_id=$2 AND template_record_key='www-a'`, zone, site).Scan(&count); err != nil || count != 1 {
		t.Fatalf("deletion history: %d %v", count, err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM dns_records WHERE id=$1`, record).Scan(&count); err != nil || count != 0 {
		t.Fatalf("record remained: %d %v", count, err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = instantiateDNSTemplateTx(context.Background(), tx, zone, site, 1, 1, "deleted.example.test", "", "192.0.2.1", ""); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND template_record_key='www-a'`, zone).Scan(&count); err != nil || count != 0 {
		t.Fatalf("reconciliation recreated a deleted record: %d %v", count, err)
	}
}

func TestNewZoneDoesNotInventNameserversOrWebmail(t *testing.T) {
	db := removaldb.New(t, "")
	site := removaldb.Site(t, db, 1, "provider.example.test", nil)
	var zone int64
	if err := db.QueryRow(`INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,status,template_revision) VALUES(1,$1,'provider.example.test','192.0.2.1',1,'active',1) RETURNING id`, site).Scan(&zone); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin) VALUES($1,$2,'@','NS','ns1.provider.test',3600,'custom'),($1,$2,'@','NS','ns2.provider.test',3600,'custom')`, zone, site); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = ensureSystemDNSRecordsTx(context.Background(), tx, zone, site, "provider.example.test", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND record_type='NS'`, zone).Scan(&count); err != nil || count != 2 {
		t.Fatalf("extra nameserver: %d %v", count, err)
	}
	if err = tx.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND host='webmail'`, zone).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unconfigured webmail published: %d %v", count, err)
	}
}
