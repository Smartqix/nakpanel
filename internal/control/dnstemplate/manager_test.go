package dnstemplate

import (
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestTemplateExpansionSupportsPleskPlaceholdersAndIPv6Omission(t *testing.T) {
	record := types.DNSTemplateRecord{
		StableKey: "apex", Scope: "all", HostTemplate: "@", Type: "A",
		ValueTemplate: "<ip.web>", TTL: 3600,
	}
	expanded, omit, err := expandTemplateRecord(record, expansionContext{
		domain: "example.test", subdomain: "shop", hostname: "panel.example.test", ipv4: "192.0.2.10",
	})
	if err != nil || omit {
		t.Fatalf("expand = %#v, omit=%v, err=%v", expanded, omit, err)
	}
	if expanded.Host != "shop" || expanded.Value != "192.0.2.10" {
		t.Fatalf("expanded = %#v, want parent-zone subdomain owner", expanded)
	}
	ipv6 := record
	ipv6.Type, ipv6.ValueTemplate = "AAAA", "<ipv6.web>"
	if _, omit, err = expandTemplateRecord(ipv6, expansionContext{domain: "example.test", ipv4: "192.0.2.10"}); err != nil || !omit {
		t.Fatalf("IPv6 expansion omit=%v err=%v, want omitted without zone IPv6", omit, err)
	}
}

func TestTemplateExpansionPrefixesNamedOwnersInsideParentZone(t *testing.T) {
	record := types.DNSTemplateRecord{
		StableKey: "www", Scope: "all", HostTemplate: "www", Type: "A",
		ValueTemplate: "<ip.web>", TTL: 3600,
	}
	expanded, omit, err := expandTemplateRecord(record, expansionContext{
		domain: "example.test", subdomain: "shop", hostname: "panel.example.test",
		ipv4: "192.0.2.10",
	})
	if err != nil || omit {
		t.Fatalf("expand = %#v, omit=%v, err=%v", expanded, omit, err)
	}
	if expanded.Host != "www.shop" {
		t.Fatalf("expanded host = %q, want www.shop", expanded.Host)
	}
}

func TestRootScopedTemplateRecordCanBeValidatedAndEdited(t *testing.T) {
	record, err := validateTemplateRecord(types.DNSTemplateRecord{
		StableKey: "primary-ns", Scope: "root", HostTemplate: "@", Type: "NS",
		ValueTemplate: "ns1.<domain>", TTL: 3600,
	})
	if err != nil {
		t.Fatalf("validateTemplateRecord returned error: %v", err)
	}
	if record.Scope != "root" {
		t.Fatalf("scope = %q, want root", record.Scope)
	}
}

func TestTemplateRevisionRejectsCNAMEConflictAcrossParentAndChildScopes(t *testing.T) {
	template := types.DNSTemplateRevision{Records: []types.DNSTemplateRecord{
		{StableKey: "shop-alias", Scope: "root", HostTemplate: "shop", Type: "CNAME", ValueTemplate: "target.example.test", TTL: 3600},
		{StableKey: "child-apex", Scope: "subdomain", HostTemplate: "@", Type: "A", ValueTemplate: "<ip.web>", TTL: 3600},
	}}
	if err := validateTemplateRevision(template); err == nil {
		t.Fatal("validateTemplateRevision succeeded, want parent-zone CNAME conflict")
	}
}

func TestCompareZoneAdoptsMatchesAndPreservesOverrides(t *testing.T) {
	template := types.DNSTemplateRevision{
		Revision: 2,
		Records: []types.DNSTemplateRecord{
			{StableKey: "apex", Scope: "all", HostTemplate: "@", Type: "A", ValueTemplate: "<ip.web>", TTL: 3600},
			{StableKey: "www", Scope: "root", HostTemplate: "www", Type: "A", ValueTemplate: "<ip.web>", TTL: 3600},
		},
	}
	zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{
		ID: 1, SiteID: 10, Domain: "example.test", Address: "192.0.2.10",
		Records: []types.DNSRecord{
			{ID: 1, OwnerSiteID: 10, Host: "@", Type: "A", Value: "192.0.2.10", TTL: 3600, Origin: "custom"},
			{ID: 2, OwnerSiteID: 10, Host: "www", Type: "A", Value: "192.0.2.99", TTL: 3600, Origin: "template", TemplateRecordKey: "www", LocallyModified: true},
			{ID: 3, OwnerSiteID: 10, Host: "old", Type: "TXT", Value: "retained", TTL: 3600, Origin: "template", TemplateRecordKey: "removed", LocallyModified: true},
		},
	}, Hostname: "panel.example.test", SubdomainSite: map[int64]siteExpansion{}}
	plan := compareZone(template, zone)
	if len(plan.adopt) != 1 || plan.adopt[1].TemplateRecordKey != "apex" {
		t.Fatalf("adopt = %#v, want exact custom match adopted", plan.adopt)
	}
	if plan.item.OverrideCount != 2 {
		t.Fatalf("override count = %d, want both local overrides preserved", plan.item.OverrideCount)
	}
	if len(plan.update) != 0 || len(plan.remove) != 0 {
		t.Fatalf("update=%#v remove=%#v, local overrides must survive", plan.update, plan.remove)
	}
}

func TestCompareZoneDoesNotReclassifyCustomMatchesAfterInitialAdoption(t *testing.T) {
	template := types.DNSTemplateRevision{
		Revision: 2,
		Records: []types.DNSTemplateRecord{{
			StableKey: "apex", Scope: "all", HostTemplate: "@", Type: "A",
			ValueTemplate: "<ip.web>", TTL: 3600,
		}},
	}
	zone := zoneSnapshot{
		DNSZoneView: types.DNSZoneView{
			ID: 1, SiteID: 10, Domain: "example.test", Address: "192.0.2.10",
			Records: []types.DNSRecord{{
				ID: 1, OwnerSiteID: 10, Host: "@", Type: "A",
				Value: "192.0.2.10", TTL: 3600, Origin: "custom",
			}},
		},
		Hostname: "panel.example.test", AdoptionCompleted: true,
		SubdomainSite: map[int64]siteExpansion{},
	}
	plan := compareZone(template, zone)
	if len(plan.adopt) != 0 || len(plan.add) != 0 {
		t.Fatalf("plan = %#v, want the later custom match preserved without duplicate or reclassification", plan)
	}
}

func TestCompareZoneUpdatesAndRemovesOnlyUnmodifiedTemplateRecords(t *testing.T) {
	template := types.DNSTemplateRevision{
		Revision: 3,
		Records: []types.DNSTemplateRecord{
			{StableKey: "apex", Scope: "all", HostTemplate: "@", Type: "A", ValueTemplate: "<ip.web>", TTL: 600},
		},
	}
	zone := zoneSnapshot{DNSZoneView: types.DNSZoneView{
		ID: 1, SiteID: 10, Domain: "example.test", Address: "192.0.2.10",
		Records: []types.DNSRecord{
			{ID: 1, OwnerSiteID: 10, Host: "@", Type: "A", Value: "192.0.2.20", TTL: 3600, Origin: "template", TemplateRecordKey: "apex"},
			{ID: 2, OwnerSiteID: 10, Host: "old", Type: "TXT", Value: "remove", TTL: 3600, Origin: "template", TemplateRecordKey: "old"},
			{ID: 3, OwnerSiteID: 11, Host: "sibling", Type: "TXT", Value: "keep", TTL: 3600, Origin: "template", TemplateRecordKey: "old"},
			{ID: 4, OwnerSiteID: 10, Host: "mail", Type: "A", Value: "192.0.2.10", TTL: 3600, Origin: "system"},
		},
	}, Hostname: "panel.example.test", SubdomainSite: map[int64]siteExpansion{}}
	plan := compareZone(template, zone)
	if len(plan.update) != 1 || len(plan.remove) != 1 || plan.remove[0] != 2 {
		t.Fatalf("plan update=%#v remove=%#v", plan.update, plan.remove)
	}
}

func TestCompareZoneAllowsMultipleRecordsOfTheSameTypeAtOneOwner(t *testing.T) {
	template := types.DNSTemplateRevision{
		Revision: 4,
		Records: []types.DNSTemplateRecord{
			{StableKey: "spf", Scope: "root", HostTemplate: "@", Type: "TXT", ValueTemplate: "v=spf1 -all", TTL: 3600},
			{StableKey: "verification", Scope: "root", HostTemplate: "@", Type: "TXT", ValueTemplate: "verification=abc", TTL: 3600},
		},
	}
	zone := zoneSnapshot{
		DNSZoneView: types.DNSZoneView{
			ID: 1, SiteID: 10, Domain: "example.test", Address: "192.0.2.10",
			Records: []types.DNSRecord{
				{ID: 1, OwnerSiteID: 10, Host: "@", Type: "TXT", Value: "customer=value", TTL: 3600, Origin: "custom"},
			},
		},
		Hostname: "panel.example.test", SubdomainSite: map[int64]siteExpansion{},
	}

	plan := compareZone(template, zone)
	if len(plan.add) != 2 || plan.item.ConflictCount != 0 {
		t.Fatalf("plan = %#v, want both TXT records added without conflict", plan)
	}
}

func TestCompareZonePreservesCustomTTLOverrideWithoutDuplicateInsert(t *testing.T) {
	template := types.DNSTemplateRevision{
		Revision: 4,
		Records: []types.DNSTemplateRecord{{
			StableKey: "apex", Scope: "all", HostTemplate: "@", Type: "A",
			ValueTemplate: "<ip.web>", TTL: 600,
		}},
	}
	zone := zoneSnapshot{
		DNSZoneView: types.DNSZoneView{
			ID: 1, SiteID: 10, Domain: "example.test", Address: "192.0.2.10",
			Records: []types.DNSRecord{{
				ID: 1, OwnerSiteID: 10, Host: "@", Type: "A",
				Value: "192.0.2.10", TTL: 3600, Origin: "custom",
			}},
		},
		Hostname: "panel.example.test", SubdomainSite: map[int64]siteExpansion{},
	}
	plan := compareZone(template, zone)
	if len(plan.add) != 0 || plan.item.ConflictCount != 1 {
		t.Fatalf("plan = %#v, want preserved TTL override and no duplicate insert", plan)
	}
}

func TestCompareWholeZoneBlocksConflictingCombinedCandidate(t *testing.T) {
	template := types.DNSTemplateRevision{
		Revision: 4,
		Records: []types.DNSTemplateRecord{
			{StableKey: "shop-alias", Scope: "root", HostTemplate: "shop", Type: "CNAME", ValueTemplate: "target.example.test", TTL: 3600},
			{StableKey: "child-apex", Scope: "subdomain", HostTemplate: "@", Type: "A", ValueTemplate: "<ip.web>", TTL: 3600},
		},
	}
	zone := zoneSnapshot{
		DNSZoneView: types.DNSZoneView{
			ID: 1, SiteID: 10, Domain: "example.test", Address: "192.0.2.10",
		},
		Hostname: "panel.example.test",
		SubdomainSite: map[int64]siteExpansion{
			11: {Domain: "shop.example.test", Subdomain: "shop"},
		},
	}
	plan := compareWholeZone(template, zone)
	if len(plan.add) != 0 || plan.item.ConflictCount == 0 {
		t.Fatalf("plan = %#v, want all invalid mutations blocked", plan)
	}
}

func TestCompareWholeZoneIncludesParentZoneSubdomains(t *testing.T) {
	template := types.DNSTemplateRevision{
		Revision: 2,
		Records: []types.DNSTemplateRecord{
			{StableKey: "apex", Scope: "all", HostTemplate: "@", Type: "A", ValueTemplate: "<ip.web>", TTL: 3600},
			{StableKey: "ns", Scope: "root", HostTemplate: "@", Type: "NS", ValueTemplate: "ns1.<domain>", TTL: 3600},
		},
	}
	zone := zoneSnapshot{
		DNSZoneView: types.DNSZoneView{ID: 1, SiteID: 10, Domain: "example.test", Address: "192.0.2.10"},
		Hostname:    "panel.example.test",
		SubdomainSite: map[int64]siteExpansion{
			11: {Domain: "shop.example.test", Subdomain: "shop"},
		},
	}
	plan := compareWholeZone(template, zone)
	if len(plan.add) != 3 {
		t.Fatalf("adds = %#v, want root A/NS and parent-zone child A", plan.add)
	}
	foundChild := false
	for _, record := range plan.add {
		if record.OwnerSiteID == 11 && record.Host == "shop" && record.Type == "A" {
			foundChild = true
		}
		if record.OwnerSiteID == 11 && record.Type == "NS" {
			t.Fatalf("root-scoped NS leaked into parent-zone child: %#v", record)
		}
	}
	if !foundChild {
		t.Fatalf("parent-zone child record missing: %#v", plan.add)
	}
}

func TestZoneApplyPlanMatchesPreviewScopeForParentAndChildWorkspaces(t *testing.T) {
	template := types.DNSTemplateRevision{
		Revision: 2,
		Records: []types.DNSTemplateRecord{{
			StableKey: "apex", Scope: "all", HostTemplate: "@", Type: "A",
			ValueTemplate: "<ip.web>", TTL: 3600,
		}},
	}
	root := zoneSnapshot{
		DNSZoneView: types.DNSZoneView{
			ID: 1, SiteID: 10, Domain: "example.test", Address: "192.0.2.10",
		},
		AuthoritativeSiteID: 10,
		Hostname:            "panel.example.test",
		SubdomainSite: map[int64]siteExpansion{
			11: {Domain: "shop.example.test", Subdomain: "shop"},
		},
	}
	full := zonePlanForApply(template, root, false)
	if len(full.add) != 2 {
		t.Fatalf("parent apply adds = %#v, want root and child records from its whole-zone preview", full.add)
	}

	child := root
	child.SiteID = 11
	partial := zonePlanForApply(template, child, true)
	if len(partial.add) != 1 || partial.add[0].OwnerSiteID != 11 || partial.add[0].Host != "shop" {
		t.Fatalf("child apply adds = %#v, want only the child-owned template slice", partial.add)
	}
}

func TestCompareZoneTreatsPinnedTemplateRevisionAsConvergenceWork(t *testing.T) {
	template := types.DNSTemplateRevision{Revision: 7}
	root := zoneSnapshot{
		DNSZoneView: types.DNSZoneView{
			ID: 1, SiteID: 10, Domain: "example.test", TemplateRevision: 6,
		},
		AuthoritativeSiteID: 10,
		SubdomainSite:       map[int64]siteExpansion{},
	}
	plan := compareZone(template, root)
	if !plan.settingsChanged || plan.item.UpdatedCount != 1 || plan.item.Outcome != "updated" {
		t.Fatalf("root plan = %#v, want settings-only template convergence", plan)
	}

	child := root
	child.SiteID = 11
	plan = compareZone(template, child)
	if plan.settingsChanged || plan.item.UpdatedCount != 0 {
		t.Fatalf("child plan = %#v, parent-zone child must not apply shared SOA settings", plan)
	}
}

func TestCompareZoneRetriesFailedAgentConvergenceWithoutDataMutation(t *testing.T) {
	template := types.DNSTemplateRevision{Revision: 7}
	zone := zoneSnapshot{
		DNSZoneView: types.DNSZoneView{
			ID: 1, SiteID: 10, Domain: "example.test", TemplateRevision: 7,
			Status: "failed", DesiredRevision: 8, AppliedRevision: 7,
		},
		AuthoritativeSiteID: 10,
		SubdomainSite:       map[int64]siteExpansion{},
	}
	plan := compareZone(template, zone)
	if !plan.retryConvergence || plan.item.Outcome != "updated" {
		t.Fatalf("plan = %#v, want failed agent convergence retried", plan)
	}
}

func TestDNSRecordValidationRejectsConflictsAndInjection(t *testing.T) {
	for _, record := range []types.DNSRecord{
		{Host: "@", Type: "CNAME", Value: "target.example", TTL: 3600},
		{Host: "www\nmalicious", Type: "A", Value: "192.0.2.10", TTL: 3600},
		{Host: "_sip._tcp", Type: "SRV", Value: "sip.example", Priority: 10, Weight: 5, Port: 0, TTL: 3600},
		{Host: "@", Type: "CAA", Value: "999 issue \"letsencrypt.org\"", TTL: 3600},
		{Host: "@", Type: "DS", Value: "12345 13 2 ABCD", TTL: 3600},
	} {
		if _, err := normalizeRecord("example.test", record); err == nil {
			t.Fatalf("normalizeRecord(%#v) succeeded, want rejection", record)
		}
	}
}

func TestNextDNSSerialIsMonotonicForBothFormats(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	if got, err := nextDNSSerial(now, 2026072400, "date-counter"); err != nil || got != 2026072401 {
		t.Fatalf("date counter = %d", got)
	}
	if got, err := nextDNSSerial(now, now.Unix()+10, "unix"); err != nil || got != now.Unix()+11 {
		t.Fatalf("monotonic unix = %d", got)
	}
	if _, err := nextDNSSerial(now, 2026072499, "date-counter"); err == nil {
		t.Fatal("exhausted date counter was accepted")
	}
}
