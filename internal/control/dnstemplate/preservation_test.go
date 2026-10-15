package dnstemplate

import (
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestApplyAllPreservesCustomMXTXTAndDKIM(t *testing.T) {
	zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{ID: 1, SiteID: 10, Domain: "example.test", Address: "192.0.2.1", Records: []types.DNSRecord{
		{ID: 1, OwnerSiteID: 10, Host: "@", Type: "MX", Value: "mail.external.test", Priority: 10, TTL: 3600, Origin: "custom"},
		{ID: 2, OwnerSiteID: 10, Host: "@", Type: "TXT", Value: "v=spf1 include:external.test -all", TTL: 3600, Origin: "custom"},
		{ID: 3, OwnerSiteID: 10, Host: "nak1._domainkey", Type: "TXT", Value: "v=DKIM1; p=actual-key", TTL: 3600, Origin: "system"},
	}}, AdoptionCompleted: true}
	plan := compareWholeZone(types.DNSTemplateRevision{Revision: 2}, zone)
	if len(plan.remove) != 0 || len(plan.update) != 0 || len(plan.adopt) != 0 {
		t.Fatalf("custom mail records changed: %+v", plan)
	}
}

func TestLocalDeletionStaysDeleted(t *testing.T) {
	template := types.DNSTemplateRevision{Revision: 2, Records: []types.DNSTemplateRecord{{StableKey: "www", HostTemplate: "www", Type: "A", ValueTemplate: "<ip.web>", TTL: 3600, Scope: "root"}}}
	zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{ID: 1, SiteID: 10, Domain: "example.test", Address: "192.0.2.1"}, SuppressedKeys: map[int64]map[string]bool{10: {"www": true}}}
	plan := compareWholeZone(template, zone)
	if len(plan.add) != 0 || plan.item.OverrideCount != 1 {
		t.Fatalf("explicit deletion restored: %+v", plan)
	}
}

func TestParentChangePreservesSibling(t *testing.T) {
	zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{ID: 1, SiteID: 10, Domain: "example.test", Records: []types.DNSRecord{{ID: 1, OwnerSiteID: 11, Host: "shop", Type: "A", Value: "192.0.2.11", Origin: "template", TemplateRecordKey: "old"}}}}
	plan := compareZone(types.DNSTemplateRevision{Revision: 2}, zone)
	if len(plan.remove) != 0 || len(plan.update) != 0 {
		t.Fatalf("parent edited sibling: %+v", plan)
	}
}
