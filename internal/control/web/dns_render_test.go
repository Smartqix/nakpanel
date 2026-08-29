package web

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestDNSSettingsRendersTemplateSOATransfersAndPreview(t *testing.T) {
	view := WorkspaceView{
		Route: "tools-settings", SettingsFocus: "dns", CSRFToken: "csrf",
		DNSSettings: types.DNSTemplateView{
			Template: types.DNSTemplateRevision{
				ID: 1, Revision: 4, OptimisticRevision: 9, ZoneStatus: "active", SubdomainPolicy: "parent",
				SOA: types.DNSSOASettings{
					PrimaryNameserver: "ns1.<domain>", ResponsibleMailbox: "hostmaster.<domain>",
					SerialFormat: "date-counter", DefaultTTL: 3600, RefreshSeconds: 3600,
					RetrySeconds: 900, ExpireSeconds: 604800, MinimumTTL: 300,
				},
				TransferCIDRs: []string{"192.0.2.0/24"},
				Records: []types.DNSTemplateRecord{{
					ID: 7, StableKey: "apex-a", Scope: "all", HostTemplate: "@",
					Type: "A", ValueTemplate: "<ip.web>", TTL: 3600,
				}},
			},
			Preview: &types.DNSSyncRun{
				ID: 8, Status: "preview", Scope: "all", PreviewToken: "dns_token",
				TotalZones: 1, ChangedZones: 1,
				Items: []types.DNSSyncItem{{ZoneID: 2, Domain: "example.test", Outcome: "overridden", Detail: "1 override preserved"}},
			},
		},
	}
	body := renderDNSPage(t, dashboard.Data{}, view)
	for _, want := range []string{
		"Zone Records Template", "SOA Template", "Transfer Restrictions", "Synchronization History",
		"ns1.&lt;domain&gt;", "&lt;ip.web&gt;", "192.0.2.0/24", "APPLY DNS TEMPLATE",
		"1 override preserved", "data-np-dns-settings-workspace", `role="tablist"`,
		`data-np-dns-settings-panel="records"`, "Search host, value, or key",
		"Advanced timing and transfers", "Synchronization impact", "Authorize DNS changes",
		`aria-labelledby="dns-tab-records"`, "No template records match this search.",
		`data-np-dns-result-count`, ">1 record</span>", `<span class="np-sr-only">Actions</span>`,
		`aria-labelledby="dns-template-record-title"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("DNS settings missing %q:\n%s", want, body)
		}
	}
}

func TestDomainDNSRendersParentZoneOriginsAndAllRecordTypes(t *testing.T) {
	site := dashboard.Site{
		ID: 2, Domain: "shop.example.test", SubscriptionID: 5, Status: "active",
		ParentSiteID: 1, DNSZoneMode: "parent",
	}
	data := dashboard.Data{
		Sites: []dashboard.Site{site},
		Subscriptions: []types.SubscriptionSummary{{
			ID: 5, SubscriptionName: "Hosting", Status: "active", AllowDNS: true,
		}},
		Phase6: dashboard.Phase6Data{
			DNSZones: []dashboard.DNSZone{{
				ID: 9, SiteID: 1, Domain: "example.test", Mode: "primary", Status: "active",
				TemplateRevision: 4, TemplateStatus: "customized", DesiredRevision: 7, AppliedRevision: 6,
			}},
			DNSRecords: []types.DNSRecord{
				{ID: 10, ZoneID: 9, OwnerSiteID: 2, Host: "shop", Type: "A", Value: "192.0.2.10", TTL: 3600, Origin: "template", TemplateRecordKey: "apex-a", LocallyModified: true},
				{ID: 11, ZoneID: 9, OwnerSiteID: 2, Host: "_sip._tcp.shop", Type: "SRV", Value: "sip.example.test", Priority: 10, Weight: 5, Port: 5060, TTL: 600, Origin: "custom"},
				{ID: 12, ZoneID: 9, OwnerSiteID: 2, Host: "_dmarc.shop", Type: "TXT", Value: "v=DMARC1; p=reject", TTL: 3600, Origin: "system"},
			},
		},
	}
	view := WorkspaceView{Route: "site-detail", DetailID: 2, Tab: "dns", CSRFToken: "csrf"}
	body := renderDNSPage(t, data, view)
	for _, want := range []string{
		"Parent zone", "Records are served from <strong>example.test</strong>",
		"Apply DNS Template", "local override", "system", "10 5 5060 sip.example.test",
		"Use separate zone", "Reset zone", "Advanced zone settings",
		`data-np-dns-record-form`, "System-managed record", "Changing placement moves",
		"Authorize zone changes", `aria-label="Search DNS records"`,
		"No DNS records match this search.", `aria-live="polite"`,
		`aria-labelledby="dns-record-dialog-2-title"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("domain DNS workspace missing %q:\n%s", want, body)
		}
	}
	if !strings.Contains(body, `<code>@</code>`) {
		t.Fatalf("parent-zone apex was not presented relative to the subdomain:\n%s", body)
	}
	if strings.Contains(body, "</tr><dialog") {
		t.Fatalf("DNS record dialogs must not be rendered inside the table body:\n%s", body)
	}
	if got := strings.Count(body, `name="host"`); got != 3 {
		t.Fatalf("domain DNS rendered %d host inputs, want one per editable record dialog (3)", got)
	}
}

func TestDomainDNSFindsParentZoneWithoutOwnedRecords(t *testing.T) {
	site := dashboard.Site{
		ID: 2, Domain: "empty.example.test", SubscriptionID: 5, Status: "active",
		ParentSiteID: 1, DNSZoneMode: "parent",
	}
	data := dashboard.Data{
		Sites: []dashboard.Site{site},
		Subscriptions: []types.SubscriptionSummary{{
			ID: 5, SubscriptionName: "Hosting", Status: "active", AllowDNS: true,
		}},
		Phase6: dashboard.Phase6Data{
			DNSZones: []dashboard.DNSZone{{
				ID: 9, SiteID: 1, Domain: "example.test", Mode: "primary", Status: "active",
			}},
		},
	}
	body := renderDNSPage(t, data, WorkspaceView{
		Route: "site-detail", DetailID: 2, Tab: "dns", CSRFToken: "csrf",
	})
	if !strings.Contains(body, "Parent zone") ||
		!strings.Contains(body, "Records are served from <strong>example.test</strong>") {
		t.Fatalf("recordless parent-zone child lost its authoritative zone:\n%s", body)
	}
}

func renderDNSPage(t *testing.T, data dashboard.Data, view WorkspaceView) string {
	t.Helper()
	var body bytes.Buffer
	user := auth.SessionUser{ID: 1, Email: "admin@example.test", Role: auth.RoleAdmin, AuthenticatedAt: time.Now()}
	if err := RoutedDashboardPage("DNS", user, data, DashboardActions{CanUsePhase6: true}, view).
		Render(context.Background(), &body); err != nil {
		t.Fatal(err)
	}
	return body.String()
}
