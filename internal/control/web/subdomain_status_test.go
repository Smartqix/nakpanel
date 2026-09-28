package web

import (
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestSubdomainDNSStateRequiresAnAddressRecordForTheChild(t *testing.T) {
	site := dashboard.Site{ID: 2, ParentSiteID: 1, Domain: "blog.example.test", DNSZoneMode: "parent"}
	zone := dashboard.DNSZone{ID: 9, SiteID: 1, Domain: "example.test", Address: "192.0.2.10", Mode: "primary", Status: "active"}
	if got := subdomainDNSState(site, zone, true, nil); got != "missing" {
		t.Fatalf("recordless child DNS = %q, want missing", got)
	}
	records := []types.DNSRecord{{ZoneID: 9, Host: "blog", Type: "A", Value: "192.0.2.10"}}
	if got := subdomainDNSState(site, zone, true, records); got != "active" {
		t.Fatalf("addressed child DNS = %q, want active", got)
	}
	zone.Status = "pending"
	if got := subdomainDNSState(site, zone, true, records); got != "pending" {
		t.Fatalf("unapplied child DNS = %q, want pending", got)
	}
}

func TestSubdomainDNSStateTreatsNonAuthoritativeZonesAsExternal(t *testing.T) {
	site := dashboard.Site{ID: 2, ParentSiteID: 1, Domain: "blog.example.test", DNSZoneMode: "parent"}
	zone := dashboard.DNSZone{ID: 9, SiteID: 1, Domain: "example.test", Mode: "secondary", Status: "active"}
	if got := subdomainDNSState(site, zone, true, nil); got != "external" {
		t.Fatalf("secondary DNS = %q, want external", got)
	}
	if got := subdomainDNSState(site, dashboard.DNSZone{}, false, nil); got != "external" {
		t.Fatalf("unmanaged DNS = %q, want external", got)
	}
}
