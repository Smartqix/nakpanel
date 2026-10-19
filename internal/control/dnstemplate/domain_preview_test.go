package dnstemplate

import (
	"context"
	"reflect"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestDomainPreviewPreservesCustomMailAndTTLWithoutMutatingInput(t *testing.T) {
	zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{ID: 1, SiteID: 10, Domain: "example.test", Mode: "primary", Address: "192.0.2.1", Records: []types.DNSRecord{
		{ID: 1, OwnerSiteID: 10, Host: "@", Type: "MX", Value: "external.example.net", Priority: 10, TTL: 300, Origin: "custom"},
		{ID: 2, OwnerSiteID: 10, Host: "@", Type: "TXT", Value: "v=spf1 include:external.example.net -all", TTL: 600, Origin: "custom"},
		{ID: 3, OwnerSiteID: 10, Host: "webmail", Type: "A", Value: "192.0.2.99", TTL: 300, Origin: "custom"},
	}}, AuthoritativeSiteID: 10, Services: &provision.DNSServiceState{Webmail: true}}
	before := append([]types.DNSRecord(nil), zone.Records...)
	template := types.DNSTemplateRevision{Revision: 4, Records: []types.DNSTemplateRecord{{StableKey: "apex", Scope: "all", HostTemplate: "@", Type: "A", ValueTemplate: "<ip.web>", TTL: 3600}}}
	preview := buildDomainPreview(template, zone, 10, "example.test")
	if preview.TemplateRevision != 4 || len(preview.Records) != 4 {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	for _, want := range before {
		found := false
		for _, row := range preview.Records {
			if row.Record.ID == want.ID {
				found = reflect.DeepEqual(row.Record, want) && row.Action == "Preserved"
			}
		}
		if !found {
			t.Fatalf("custom record changed or omitted: %+v", want)
		}
	}
	if !reflect.DeepEqual(zone.Records, before) {
		t.Fatal("preview mutated source records")
	}
}

func TestDomainPreviewScopesParentZoneChildAndDoesNotInventServices(t *testing.T) {
	zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{ID: 1, SiteID: 10, Domain: "example.test", Mode: "primary", Address: "192.0.2.1", Records: []types.DNSRecord{
		{ID: 1, OwnerSiteID: 10, Host: "@", Type: "MX", Value: "mail.example.test", TTL: 3600, Origin: "system"},
		{ID: 2, OwnerSiteID: 11, Host: "shop", Type: "A", Value: "192.0.2.1", TTL: 300, Origin: "custom"},
		{ID: 3, OwnerSiteID: 10, Host: "webmail.shop", Type: "A", Value: "192.0.2.99", TTL: 300, Origin: "custom"},
	}}, AuthoritativeSiteID: 10, SubdomainSite: map[int64]siteExpansion{11: {Domain: "shop.example.test", Subdomain: "shop"}}}
	preview := buildDomainPreview(types.DNSTemplateRevision{Revision: 4}, zone, 11, "shop.example.test")
	if preview.ZoneDomain != "example.test" || len(preview.Records) != 2 || preview.Records[0].Record.Host != "shop" || preview.Records[1].Record.Value != "192.0.2.99" {
		t.Fatalf("child preview leaked parent or invented service: %+v", preview)
	}
	zone.Mode = "secondary"
	preview = buildDomainPreview(types.DNSTemplateRevision{Revision: 5}, zone, 10, "example.test")
	if len(preview.Warnings) == 0 || len(preview.Records) != 3 {
		t.Fatalf("secondary preview should retain current records and explain why: %+v", preview)
	}
}

func TestDomainPreviewIsReadOnlyAndHandlesMissingZone(t *testing.T) {
	db, manager := dnsFixture(t)
	site := removaldb.Site(t, db, 1, "preview.test", nil)
	preview, err := manager.DomainPreview(context.Background(), site)
	if err != nil || preview.Domain != "preview.test" || len(preview.Warnings) == 0 {
		t.Fatalf("missing-zone preview: %+v %v", preview, err)
	}
	if _, err = db.Exec(`INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,status,template_revision) VALUES(1,$1,'preview.test','192.0.2.1',1,'active',1)`, site); err != nil {
		t.Fatal(err)
	}
	preview, err = manager.DomainPreview(context.Background(), site)
	if err != nil || len(preview.Records) == 0 {
		t.Fatalf("preview: %+v %v", preview, err)
	}
	for _, table := range []string{"dns_records", "dns_template_sync_runs", "river_job"} {
		var count int
		if err = db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("preview wrote %s: %d %v", table, count, err)
		}
	}
	options, err := manager.PreviewDomains(context.Background())
	if err != nil || len(options) != 1 || options[0].SiteID != site {
		t.Fatalf("preview domains: %+v %v", options, err)
	}
}
