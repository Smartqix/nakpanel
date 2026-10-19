package provision

import (
	"context"
	"database/sql"
	"testing"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
)

func serviceDNSFixture(t *testing.T, domain string) (*sql.DB, *SQLPhase6Repository, int64, int64) {
	t.Helper()
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
	site := removaldb.Site(t, db, 1, domain, nil)
	var zone int64
	if err = db.QueryRow(`INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,status,template_revision)
VALUES(1,$1,$2,'192.0.2.1',1,'active',1) RETURNING id`, site, domain).Scan(&zone); err != nil {
		t.Fatal(err)
	}
	return db, NewSQLPhase6Repository(db, client), site, zone
}

func TestMailDNSVerificationTXTDoesNotSuppressSPF(t *testing.T) {
	current := []types.DNSRecord{{ID: 1, Host: "@", Type: "TXT", Value: "vendor-verification=keep", TTL: 300, Origin: "custom"}}
	desired := []types.DNSRecord{{Host: "@", Type: "TXT", Value: "v=spf1 mx ~all", TTL: 3600}}
	add, remove, _ := PlanServiceDNSRecords(current, desired, func(record types.DNSRecord) bool { return record.Origin == "system" })
	if len(add) != 1 || len(remove) != 0 || add[0].Value != "v=spf1 mx ~all" {
		t.Fatalf("unrelated verification TXT suppressed SPF: add=%+v remove=%v", add, remove)
	}
}

func TestDisabledMailPreservesNameserverEndpoint(t *testing.T) {
	db, repository, site, zone := serviceDNSFixture(t, "mail-ns.test")
	if _, err := db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin,template_record_key) VALUES($1,$2,'mail','A','192.0.2.1',3600,'system','service-nameserver-mail')`, zone, site); err != nil {
		t.Fatal(err)
	}
	worker := NewConfigureMailWorker(db, nil)
	worker.phase6 = repository
	if err := worker.reconcileZoneRecords(context.Background(), mailDomainRow{Domain: "mail-ns.test", SiteID: site}, nil); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND template_record_key='service-nameserver-mail'`, zone).Scan(&count); err != nil || count != 1 {
		t.Fatalf("disabling mail removed nameserver address: %d %v", count, err)
	}
}

func TestMailDeletionDoesNotRequireActiveDNSZone(t *testing.T) {
	db, repository, site, zone := serviceDNSFixture(t, "disabled-mail.test")
	if _, err := db.Exec(`UPDATE dns_zones SET mode='disabled' WHERE id=$1`, zone); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mail_domains(subscription_id,site_id,domain,enabled,delete_requested) VALUES(1,$1,'disabled-mail.test',false,true)`, site); err != nil {
		t.Fatal(err)
	}
	worker := NewConfigureMailWorker(db, &mailConvergenceAgentStub{})
	worker.phase6 = repository
	if err := worker.Work(context.Background(), &river.Job[controlquota.ConfigureMailArgs]{Args: controlquota.NewConfigureMailArgs()}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM mail_domains WHERE site_id=$1`, site).Scan(&count); err != nil || count != 0 {
		t.Fatalf("mail deletion stuck without managed DNS: %d %v", count, err)
	}
}

func TestChildMailDNSUsesParentZoneWithoutChangingParentMail(t *testing.T) {
	db, repository, parent, zone := serviceDNSFixture(t, "parent-mail.test")
	child := removaldb.Site(t, db, 1, "child.parent-mail.test", &parent)
	if _, err := db.Exec(`UPDATE sites SET dns_zone_mode='parent' WHERE id=$1`, child); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,priority,ttl,origin) VALUES($1,$2,'@','MX','mail.parent-mail.test',10,3600,'system'),($1,$2,'@','TXT','v=spf1 mx ~all',NULL,3600,'system')`, zone, parent); err != nil {
		t.Fatal(err)
	}
	const fingerprint = `SELECT COALESCE(string_agg(row_to_json(r)::text,',' ORDER BY id),'') FROM dns_records r WHERE zone_id=$1 AND owner_site_id=$2`
	var before, after string
	if err := db.QueryRow(fingerprint, zone, parent).Scan(&before); err != nil {
		t.Fatal(err)
	}
	worker := NewConfigureMailWorker(db, nil)
	worker.phase6 = repository
	domain := mailDomainRow{SiteID: child, Domain: "child.parent-mail.test", Enabled: true, DMARCPolicy: "none"}
	if err := worker.reconcileZoneRecords(context.Background(), domain, mailZoneRecords(domain, "v=DKIM1; p=child")); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND owner_site_id=$2 AND host IN ('child','mail.child','_dmarc.child','nak1._domainkey.child')`, zone, child).Scan(&count); err != nil || count != 5 {
		t.Fatalf("child mail records missing or outside parent zone: %d %v", count, err)
	}
	if _, err := db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,priority,ttl,origin) VALUES($1,$2,'child','MX','mx.external.test',10,300,'custom'),($1,$2,'child','TXT','v=spf1 include:external.test -all',NULL,300,'custom')`, zone, child); err != nil {
		t.Fatal(err)
	}
	if err := worker.reconcileZoneRecords(context.Background(), domain, mailZoneRecords(domain, "v=DKIM1; p=child")); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND owner_site_id=$2 AND (record_type='MX' OR value LIKE 'v=spf1%')`, zone, child).Scan(&count); err != nil || count != 2 {
		t.Fatalf("child routing mixed local and external policies: %d %v", count, err)
	}
	if err := worker.reconcileZoneRecords(context.Background(), domain, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(fingerprint, zone, parent).Scan(&after); err != nil || after != before {
		t.Fatalf("child mail changed parent mail records: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND owner_site_id=$2 AND origin='custom'`, zone, child).Scan(&count); err != nil || count != 2 {
		t.Fatalf("disabled child mail changed external records: %d %v", count, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND owner_site_id=$2 AND origin='system'`, zone, child).Scan(&count); err != nil || count != 0 {
		t.Fatalf("disabled child mail left managed records: %d %v", count, err)
	}
}

func TestMailDNSReconciliationPreservesExternalRecords(t *testing.T) {
	db, repository, site, zone := serviceDNSFixture(t, "mail-preserve.test")
	if _, err := db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,priority,ttl,origin) VALUES
($1,$2,'@','MX','mx.external.test',10,300,'custom'),
($1,$2,'@','TXT','v=spf1 include:external.test -all',NULL,600,'custom'),
($1,$2,'_dmarc','TXT','v=DMARC1; p=reject',NULL,600,'custom'),
($1,$2,'external._domainkey','TXT','v=DKIM1; p=external-key',NULL,600,'custom'),
($1,$2,'mail','A','192.0.2.99',NULL,300,'custom'),
($1,$2,'nak1._domainkey','TXT','v=DKIM1; p=old-key',NULL,3600,'system'),
($1,$2,'@','MX','old.mail-preserve.test',10,3600,'system')`, zone, site); err != nil {
		t.Fatal(err)
	}
	var before string
	const fingerprint = `SELECT COALESCE(string_agg(row_to_json(record)::text,',' ORDER BY id),'') FROM dns_records record WHERE zone_id=$1 AND origin='custom'`
	if err := db.QueryRow(fingerprint, zone).Scan(&before); err != nil {
		t.Fatal(err)
	}
	worker := NewConfigureMailWorker(db, nil)
	worker.phase6 = repository
	domain := mailDomainRow{Domain: "mail-preserve.test", SiteID: site, Enabled: true, DMARCPolicy: "none"}
	if err := worker.reconcileZoneRecords(context.Background(), domain, mailZoneRecords(domain, "v=DKIM1; p=new-key")); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := db.QueryRow(fingerprint, zone).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("mail convergence changed custom/external DNS records")
	}
	var mx, spf int
	if err := db.QueryRow(`SELECT count(*) FILTER(WHERE record_type='MX'),count(*) FILTER(WHERE record_type='TXT' AND value LIKE 'v=spf1%') FROM dns_records WHERE zone_id=$1`, zone).Scan(&mx, &spf); err != nil || mx != 1 || spf != 1 {
		t.Fatalf("external mail was mixed with local policies: MX=%d SPF=%d error=%v", mx, spf, err)
	}
	if err := worker.reconcileZoneRecords(context.Background(), domain, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(fingerprint, zone).Scan(&after); err != nil || after != before {
		t.Fatalf("disabling local mail changed external DNS: %v", err)
	}
}

func TestServiceDNSDefaultsGenerateBothInZoneNameserverAddresses(t *testing.T) {
	db, _, site, zone := serviceDNSFixture(t, "provider.test")
	if _, err := db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin) VALUES($1,$2,'@','NS','ns1.provider.test',3600,'custom'),($1,$2,'@','NS','ns2.provider.test',3600,'custom')`, zone, site); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = ensureSystemDNSRecordsTx(context.Background(), tx, zone, site, "provider.test", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND host IN ('ns1','ns2') AND record_type='A' AND value='192.0.2.1' AND origin='system'`, zone).Scan(&count); err != nil || count != 2 {
		t.Fatalf("generated nameserver addresses=%d want 2: %v", count, err)
	}
}

func TestServiceDNSDefaultsPublishOnlyConfiguredAccessServices(t *testing.T) {
	db, _, site, zone := serviceDNSFixture(t, "access.test")
	if _, err := db.Exec(`INSERT INTO ftp_accounts(subscription_id,site_id,name,password_hash,convergence_status) VALUES(1,$1,'dns-test-ftp','$6$test','in_sync')`, site); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO webmail_hosts(owner_user_id,site_id,hostname,status) VALUES(1,$1,'webmail.access.test','active')`, site); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = ensureSystemDNSRecordsTx(context.Background(), tx, zone, site, "access.test", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND host IN ('ftp','webmail') AND record_type='A' AND value='192.0.2.1' AND origin='system'`, zone).Scan(&count); err != nil || count != 2 {
		t.Fatalf("access service records=%d want 2: %v", count, err)
	}
}

func TestConfiguredServiceQueuesDNSOnceAndPreservesCustomEndpoint(t *testing.T) {
	db, repository, site, zone := serviceDNSFixture(t, "converged.test")
	if _, err := db.Exec(`INSERT INTO webmail_hosts(owner_user_id,site_id,hostname,status) VALUES(1,$1,'webmail.converged.test','active')`, site); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin) VALUES($1,$2,'ftp','A','192.0.2.99',300,'custom')`, zone, site); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := repository.ReconcileSiteDNS(context.Background(), site); err != nil {
			t.Fatal(err)
		}
	}
	var count, jobs int
	if err := db.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND host='webmail' AND origin='system'`, zone).Scan(&count); err != nil || count != 1 {
		t.Fatalf("webmail DNS missing: %d %v", count, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM river_job WHERE kind='configure_dns_zone'`).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatalf("service convergence was not idempotent: %d %v", jobs, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND host='ftp' AND origin='custom' AND value='192.0.2.99' AND ttl=300`, zone).Scan(&count); err != nil || count != 1 {
		t.Fatalf("custom endpoint changed: %d %v", count, err)
	}
}

func TestRootDNSRefreshKeepsChildServiceEndpoints(t *testing.T) {
	db, _, site, zone := serviceDNSFixture(t, "parent.test")
	child := removaldb.Site(t, db, 1, "blog.parent.test", site)
	if _, err := db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin,template_record_key)
VALUES($1,$2,'webmail.blog','A','192.0.2.1',3600,'system','service-webmail'),($1,$2,'ftp.blog','A','192.0.2.1',3600,'system','service-ftp')`, zone, child); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = ensureSystemDNSRecordsTx(context.Background(), tx, zone, site, "parent.test", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND owner_site_id=$2`, zone, child).Scan(&count); err != nil || count != 2 {
		t.Fatalf("root refresh removed child service endpoints: %d %v", count, err)
	}
}
