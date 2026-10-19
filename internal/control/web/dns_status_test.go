package web

import (
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestDNSStatusSeparatesLocalRecordsAndConvergence(t *testing.T) {
	zone := dashboard.DNSZone{ID: 1, SiteID: 1, Domain: "example.test", Mode: "primary", Status: "active", TemplateStatus: "customized", TemplateRevision: 4, CurrentTemplateRevision: 4, DesiredRevision: 15, AppliedRevision: 15}
	data := dashboard.Data{Sites: []dashboard.Site{{ID: 1, Domain: "example.test", SubscriptionID: 5, Status: "active"}}, Subscriptions: []types.SubscriptionSummary{{ID: 5, Status: "active", AllowDNS: true}}, Phase6: dashboard.Phase6Data{DNSZones: []dashboard.DNSZone{zone}, DNSRecords: []types.DNSRecord{{ID: 1, ZoneID: 1, OwnerSiteID: 1, Host: "custom", Type: "TXT", Value: "keep-me", TTL: 300, Origin: "custom"}, {ID: 2, ZoneID: 1, OwnerSiteID: 1, Host: "mail", Type: "A", Value: "192.0.2.1", TTL: 3600, Origin: "system"}}}}
	body := renderDNSPage(t, data, WorkspaceView{Route: "site-detail", DetailID: 1, Tab: "dns"})
	for _, want := range []string{"Up to date", "1 local record", "Service-managed", "Preview DNS changes", "Adopt matching records"} {
		if !strings.Contains(body, want) {
			t.Fatalf("DNS workspace missing %q", want)
		}
	}
	if strings.Contains(body, "template customized") {
		t.Fatal("local records presented as an unsuccessful template sync")
	}
	data.Phase6.DNSZones[0].CurrentTemplateRevision = 5
	body = renderDNSPage(t, data, WorkspaceView{Route: "site-detail", DetailID: 1, Tab: "dns"})
	if !strings.Contains(body, "Update available") {
		t.Fatal("newer provider template hidden by local records")
	}
	data.Phase6.DNSZones[0].Status = "failed"
	body = renderDNSPage(t, data, WorkspaceView{Route: "site-detail", DetailID: 1, Tab: "dns"})
	if !strings.Contains(body, "DNS update failed") {
		t.Fatal("failed DNS update shown as up to date")
	}
}
