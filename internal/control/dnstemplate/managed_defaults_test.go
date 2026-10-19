package dnstemplate

import (
	"context"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestAdoptionPreviewPersistsAndLeavesDifferentTTLUnchanged(t *testing.T) {
	db, manager := dnsFixture(t)
	site := removaldb.Site(t, db, 1, "adopt.test", nil)
	var zone int64
	if err := db.QueryRow(`INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,status,template_revision) VALUES(1,$1,'adopt.test','192.0.2.1',1,'active',1) RETURNING id`, site).Scan(&zone); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE sites SET dns_template_adoption_completed=true WHERE id=$1`, site); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin) VALUES($1,$2,'@','A','192.0.2.1',3600,'custom'),($1,$2,'www','A','192.0.2.1',300,'custom')`, zone, site); err != nil {
		t.Fatal(err)
	}
	preview, err := manager.ApplyZoneWithAdoption(context.Background(), 1, site, true)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := manager.loadRun(context.Background(), preview.ID)
	if err != nil || !loaded.AdoptMatching || loaded.Items[0].AdoptedCount != 1 {
		t.Fatalf("adoption absent from persisted preview: %+v %v", loaded, err)
	}
	if err = manager.ApplyPreview(context.Background(), 1, preview.ID, preview.PreviewToken, "APPLY DNS TEMPLATE"); err != nil {
		t.Fatal(err)
	}
	if err = manager.applyRun(context.Background(), preview.ID); err != nil {
		t.Fatal(err)
	}
	var origin string
	var ttl int
	if err = db.QueryRow(`SELECT origin,ttl FROM dns_records WHERE zone_id=$1 AND host='www'`, zone).Scan(&origin, &ttl); err != nil || origin != "custom" || ttl != 300 {
		t.Fatalf("local TTL changed: %s %d %v", origin, ttl, err)
	}
	if err = db.QueryRow(`SELECT origin,ttl FROM dns_records WHERE zone_id=$1 AND host='@' AND record_type='A'`, zone).Scan(&origin, &ttl); err != nil || origin != "template" || ttl != 3600 {
		t.Fatalf("matching record not adopted: %s %d %v", origin, ttl, err)
	}
}

func TestDNSPreviewRejectsServicesEnabledAfterReview(t *testing.T) {
	db, manager := dnsFixture(t)
	site := removaldb.Site(t, db, 1, "stale-service.test", nil)
	var zone int64
	if err := db.QueryRow(`INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,status,template_revision) VALUES(1,$1,'stale-service.test','192.0.2.1',1,'active',1) RETURNING id`, site).Scan(&zone); err != nil {
		t.Fatal(err)
	}
	preview, err := manager.ApplyZone(context.Background(), 1, site)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO webmail_hosts(owner_user_id,site_id,hostname,status) VALUES(1,$1,'webmail.stale-service.test','active')`, site); err != nil {
		t.Fatal(err)
	}
	if err = manager.ApplyPreview(context.Background(), 1, preview.ID, preview.PreviewToken, "APPLY DNS TEMPLATE"); err != nil {
		t.Fatal(err)
	}
	if err = manager.applyRun(context.Background(), preview.ID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1`, zone).Scan(&count); err != nil || count != 0 {
		t.Fatalf("stale service preview changed DNS: %d %v", count, err)
	}
}

func TestExplicitAdoptionPreservesMultiAddressCustomRRset(t *testing.T) {
	template := types.DNSTemplateRevision{Revision: 2, Records: []types.DNSTemplateRecord{{StableKey: "www", Scope: "root", HostTemplate: "www", Type: "A", ValueTemplate: "<ip.web>", TTL: 3600}}}
	zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{ID: 1, SiteID: 10, Domain: "example.test", Address: "192.0.2.1", Records: []types.DNSRecord{
		{ID: 1, OwnerSiteID: 10, Host: "www", Type: "A", Value: "192.0.2.1", TTL: 3600, Origin: "custom"},
		{ID: 2, OwnerSiteID: 10, Host: "www", Type: "A", Value: "192.0.2.2", TTL: 3600, Origin: "custom"},
	}}, AdoptionCompleted: true, AdoptMatching: true}
	plan := compareZone(template, zone)
	if len(plan.adopt)+len(plan.remove)+len(plan.add) != 0 {
		t.Fatalf("part of a multi-address RRset was adopted: %+v", plan)
	}
	zone.Records[0].Host = "webmail"
	zone.Records[1].Host = "webmail"
	zone.Services = &provision.DNSServiceState{Webmail: true}
	plan = compareZone(types.DNSTemplateRevision{Revision: 2}, zone)
	if len(plan.adopt)+len(plan.remove)+len(plan.add) != 0 {
		t.Fatalf("part of a custom service RRset was adopted: %+v", plan)
	}
}

func TestTemplateSyncDoesNotMixCustomAddressOrDMARCAnswers(t *testing.T) {
	zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{ID: 1, SiteID: 10, Domain: "example.test", Address: "192.0.2.1", Records: []types.DNSRecord{
		{ID: 1, OwnerSiteID: 10, Host: "ftp", Type: "A", Value: "192.0.2.99", TTL: 300, Origin: "custom"},
		{ID: 2, OwnerSiteID: 10, Host: "_dmarc", Type: "TXT", Value: "v=DMARC1; p=reject", TTL: 300, Origin: "custom"},
	}}, AdoptionCompleted: true}
	template := types.DNSTemplateRevision{Revision: 2, Records: []types.DNSTemplateRecord{
		{StableKey: "ftp", Scope: "root", HostTemplate: "ftp", Type: "A", ValueTemplate: "<ip.web>", TTL: 3600},
		{StableKey: "dmarc", Scope: "root", HostTemplate: "_dmarc", Type: "TXT", ValueTemplate: "v=DMARC1; p=none", TTL: 3600},
	}}
	plan := compareZone(template, zone)
	if len(plan.add)+len(plan.update)+len(plan.remove) != 0 || plan.item.OverrideCount != 2 {
		t.Fatalf("custom RRsets were not preserved: %+v", plan)
	}
}

func TestTemplateCannotReplaceServiceManagedAddress(t *testing.T) {
	zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{SiteID: 10, Domain: "example.test", Address: "192.0.2.1", Records: []types.DNSRecord{{ID: 1, OwnerSiteID: 10, Host: "webmail", Type: "A", Value: "192.0.2.1", TTL: 3600, Origin: "system", TemplateRecordKey: "service-webmail"}}}, Services: &provision.DNSServiceState{Webmail: true}}
	template := types.DNSTemplateRevision{Revision: 2, Records: []types.DNSTemplateRecord{{StableKey: "webmail", Scope: "root", HostTemplate: "webmail", Type: "A", ValueTemplate: "192.0.2.99", TTL: 3600}}}
	plan := compareZone(template, zone)
	if len(plan.remove)+len(plan.add)+len(plan.update) != 0 {
		t.Fatalf("template replaced a service-managed endpoint: %+v", plan)
	}
}

func TestTemplatePreviewIncludesConfiguredServiceDefaults(t *testing.T) {
	zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{ID: 1, SiteID: 10, Domain: "provider.test", Address: "192.0.2.1", Records: []types.DNSRecord{
		{ID: 1, OwnerSiteID: 10, Host: "@", Type: "NS", Value: "ns1.provider.test", TTL: 3600, Origin: "template", TemplateRecordKey: "primary"},
		{ID: 2, OwnerSiteID: 10, Host: "@", Type: "NS", Value: "ns2.provider.test", TTL: 3600, Origin: "template", TemplateRecordKey: "secondary"},
	}}, Services: &provision.DNSServiceState{FTPS: true, Webmail: true}}
	template := types.DNSTemplateRevision{Revision: 2, Records: []types.DNSTemplateRecord{
		{StableKey: "primary", Scope: "root", HostTemplate: "@", Type: "NS", ValueTemplate: "ns1.provider.test", TTL: 3600},
		{StableKey: "secondary", Scope: "root", HostTemplate: "@", Type: "NS", ValueTemplate: "ns2.provider.test", TTL: 3600},
	}}
	plan := compareWholeZone(template, zone)
	if plan.item.AddedCount != 4 || len(plan.add) != 4 {
		t.Fatalf("service records absent from exact preview: %+v", plan)
	}
	want := map[string]bool{"ftp": true, "webmail": true, "ns1": true, "ns2": true}
	for _, record := range plan.add {
		if !want[record.Host] || record.Origin != "system" || record.Value != "192.0.2.1" {
			t.Fatalf("wrong service default: %+v", record)
		}
		delete(want, record.Host)
	}
	if len(want) != 0 {
		t.Fatalf("missing defaults: %v", want)
	}
}

func TestExplicitAdoptionRequiresExactValuesAndTTL(t *testing.T) {
	template := types.DNSTemplateRevision{Revision: 2, Records: []types.DNSTemplateRecord{{StableKey: "www", Scope: "root", HostTemplate: "www", Type: "A", ValueTemplate: "<ip.web>", TTL: 3600}}}
	for _, test := range []struct {
		name  string
		ttl   int
		adopt bool
		want  int
	}{{"normal sync", 3600, false, 0}, {"explicit matching", 3600, true, 1}, {"custom TTL", 300, true, 0}} {
		t.Run(test.name, func(t *testing.T) {
			zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{SiteID: 10, Domain: "example.test", Address: "192.0.2.1", Records: []types.DNSRecord{{ID: 7, OwnerSiteID: 10, Host: "www", Type: "A", Value: "192.0.2.1", TTL: test.ttl, Origin: "custom"}}}, AdoptionCompleted: true, AdoptMatching: test.adopt}
			plan := compareZone(template, zone)
			if len(plan.adopt) != test.want || len(plan.add)+len(plan.update)+len(plan.remove) != 0 {
				t.Fatalf("adoption changed a local value: %+v", plan)
			}
		})
	}
}

func TestLegacyCustomRecordsRequireExplicitAdoption(t *testing.T) {
	template := types.DNSTemplateRevision{Revision: 2, Records: []types.DNSTemplateRecord{{StableKey: "www", Scope: "root", HostTemplate: "www", Type: "A", ValueTemplate: "<ip.web>", TTL: 3600}}}
	zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{SiteID: 10, Domain: "example.test", Address: "192.0.2.1", Records: []types.DNSRecord{{ID: 7, OwnerSiteID: 10, Host: "www", Type: "A", Value: "192.0.2.1", TTL: 3600, Origin: "custom"}}}}
	plan := compareZone(template, zone)
	if len(plan.adopt) != 0 {
		t.Fatalf("legacy custom record adopted without consent: %+v", plan)
	}
}

func TestDNSPreviewRejectsServiceChangeHiddenByCustomRecord(t *testing.T) {
	db, manager := dnsFixture(t)
	site := removaldb.Site(t, db, 1, "stale-custom-service.test", nil)
	var zone int64
	if err := db.QueryRow(`INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,status,template_revision) VALUES(1,$1,'stale-custom-service.test','192.0.2.1',1,'active',1) RETURNING id`, site).Scan(&zone); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin) VALUES($1,$2,'webmail','A','192.0.2.99',300,'custom')`, zone, site); err != nil {
		t.Fatal(err)
	}
	preview, err := manager.ApplyZone(context.Background(), 1, site)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO webmail_hosts(owner_user_id,site_id,hostname,status) VALUES(1,$1,'webmail.stale-custom-service.test','active')`, site); err != nil {
		t.Fatal(err)
	}
	if err = manager.ApplyPreview(context.Background(), 1, preview.ID, preview.PreviewToken, "APPLY DNS TEMPLATE"); err != nil {
		t.Fatal(err)
	}
	if err = manager.applyRun(context.Background(), preview.ID); err != nil {
		t.Fatal(err)
	}
	var outcome, detail string
	if err = db.QueryRow(`SELECT outcome,detail FROM dns_template_sync_items WHERE run_id=$1`, preview.ID).Scan(&outcome, &detail); err != nil {
		t.Fatal(err)
	}
	if outcome != "failed" {
		t.Fatalf("service change was not fenced: %s %s", outcome, detail)
	}
}

func TestTemplateReplacementKeepsNameserverAddress(t *testing.T) {
	db, _ := dnsFixture(t)
	site := removaldb.Site(t, db, 1, "replacement.test", nil)
	var zone, recordID int64
	if err := db.QueryRow(`INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,status,template_revision) VALUES(1,$1,'replacement.test','192.0.2.1',1,'active',1) RETURNING id`, site).Scan(&zone); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin,template_record_key,template_revision) VALUES($1,$2,'ns1','A','192.0.2.1',3600,'template','ns1-a',1) RETURNING id`, zone, site).Scan(&recordID); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	plan := zonePlan{remove: []int64{recordID}, add: []types.DNSRecord{{OwnerSiteID: site, Host: "ns1", Type: "A", Value: "192.0.2.1", TTL: 3600, Origin: "system", TemplateRecordKey: "service-nameserver-ns1"}}}
	if err = applyZonePlanMutationsTx(context.Background(), tx, zone, 2, plan); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND host='ns1' AND record_type='A' AND origin='system'`, zone).Scan(&count); err != nil || count != 1 {
		t.Fatalf("replacement removed nameserver address: %d %v", count, err)
	}
}

func TestServiceAdoptionCountsDistinctRecords(t *testing.T) {
	zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{SiteID: 10, Domain: "example.test", Address: "192.0.2.1", Records: []types.DNSRecord{{ID: 7, OwnerSiteID: 10, Host: "webmail", Type: "A", Value: "192.0.2.1", TTL: 3600, Origin: "custom"}}}, Services: &provision.DNSServiceState{Webmail: true}, AdoptMatching: true}
	template := types.DNSTemplateRevision{Revision: 2, Records: []types.DNSTemplateRecord{{StableKey: "webmail", Scope: "root", HostTemplate: "webmail", Type: "A", ValueTemplate: "<ip.web>", TTL: 3600}}}
	plan := compareZone(template, zone)
	if len(plan.adopt) != 1 || plan.item.AdoptedCount != 1 {
		t.Fatalf("preview double counted one record: %+v", plan)
	}
}
