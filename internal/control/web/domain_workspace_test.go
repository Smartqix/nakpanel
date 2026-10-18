package web

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func domainDesignFixture() (dashboard.Data, DashboardActions) {
	return dashboard.Data{
		Sites: []dashboard.Site{
			{ID: 1, Domain: "example.test", SubscriptionID: 20, Status: "active", DesiredStatus: "active", PHPVersion: "8.4", TLSStatus: "active"},
			{ID: 7, Domain: "blog.example.test", ParentSiteID: 1, SubscriptionID: 20, Status: "active", DesiredStatus: "active", PHPVersion: "8.4", TLSStatus: "failed", TLSLastError: "HTTP validation returned 403"},
		},
		Subscriptions: []types.SubscriptionSummary{{ID: 20, PrimarySiteID: 1, CustomerID: 88, CustomerName: "Example customer", Status: "active", PlanName: "Business", SubscriptionName: "Main hosting", MaxSites: 5, DomainsUsed: 1, MaxSubdomains: 5, PHPAllowlist: "8.4", DefaultPHPVersion: "8.4", AllowTLS: true, AllowDNS: true, AllowBackups: true}},
		Capabilities:  types.RuntimeCapabilities{PHPVersions: []string{"8.4"}, ACMEAvailable: true},
	}, DashboardActions{CanCreateSite: true, CanUseWordPress: true, CanUseFileManager: true}
}

func TestDomainDesignHeaderGroupsActionsAndUsesOneStatusStrip(t *testing.T) {
	data, actions := domainDesignFixture()
	var out bytes.Buffer
	err := routedSiteDetail(auth.SessionUser{Role: auth.RoleAdmin}, data, actions, WorkspaceView{DetailID: 1, Tab: "overview", CSRFToken: "csrf"}).Render(context.Background(), &out)
	if err != nil {
		t.Fatal(err)
	}
	body := out.String()
	for _, want := range []string{"np-domain-header-actions", "data-np-domain-context", "np-domain-status-strip", "Files &amp; access", "Hosting &amp; security", "Applications &amp; data", "Domain services", "Resource usage", "Shared across this subscription", "data-np-domain-subdomains"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing design contract %q", want)
		}
	}
	for _, unwanted := range []string{"np-v2-domain-primary", "np-domain-commandbar"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("duplicated legacy status/actions: %s", unwanted)
		}
	}
	if strings.Count(body, "np-domain-status-strip") != 1 {
		t.Fatal("status strip must appear exactly once")
	}
	if !strings.Contains(body, "Example customer") {
		t.Fatal("customer context is missing")
	}
}

func TestDomainDesignChildContextAndSupportRoutes(t *testing.T) {
	data, actions := domainDesignFixture()
	var out bytes.Buffer
	err := routedSiteDetail(auth.SessionUser{Role: auth.RoleAdmin}, data, actions, WorkspaceView{DetailID: 7, Tab: "overview", SupportCustomerID: 88}).Render(context.Background(), &out)
	if err != nil {
		t.Fatal(err)
	}
	body := out.String()
	for _, want := range []string{"Parent domain:", "/support/customers/88/sites/1", "/support/customers/88/sites/7?tab=ssl", "np-domain-parent-context", "np-domain-overview-tools", "data-np-domain-ssl-review", "SSL validation", "HTTP validation returned 403", "/support/customers/88/sites/7/setup/retry-ssl"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "Add subdomain") || strings.Contains(body, "subdomain-dialog-7") {
		t.Fatal("nested child creation is exposed")
	}
	if strings.Contains(body, "Public DNS does not yet resolve") {
		t.Fatal("SSL cause must not be guessed")
	}
}

func TestDomainDesignSuspensionAndMissingUsageRemainHonest(t *testing.T) {
	data, actions := domainDesignFixture()
	data.Subscriptions[0].Status = "suspended"
	var out bytes.Buffer
	if err := routedSiteDetail(auth.SessionUser{Role: auth.RoleClient}, data, actions, WorkspaceView{DetailID: 1, Tab: "overview"}).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Add subdomain") {
		t.Fatal("inactive subscription offers creation")
	}
	if !strings.Contains(out.String(), "Not measured") {
		t.Fatal("unknown disk use must not be invented as zero")
	}
}

func TestDomainDesignCompactListPreservesFiltersAndHierarchy(t *testing.T) {
	data, actions := domainDesignFixture()
	var out bytes.Buffer
	if err := routedSites(auth.SessionUser{Role: auth.RoleAdmin}, data.Sites, data.Subscriptions, actions, WorkspaceView{}).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"np-domain-inventory", "Service status", "Find a domain", `data-np-list-filter="subscription"`, `data-subscription="20"`, "Subdomain of example.test", "data-np-list-row"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestDomainDesignCreationFieldsHaveFixedSuffixAndNoBrowserOwnership(t *testing.T) {
	data, _ := domainDesignFixture()
	var out bytes.Buffer
	if err := routedSubdomainDialog(data.Sites[0], data.Subscriptions[0], data.Capabilities, WorkspaceView{}).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"np-domain-create-dialog", "np-domain-name-field", "data-np-subdomain-suffix", "np-domain-form-body", "Parent domain", "np-domain-dialog-notice", "np-dialog-actions"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, forbidden := range []string{`name="subscription_id"`, `name="domain"`, `name="php_version"`} {
		if strings.Contains(out.String(), forbidden) {
			t.Errorf("ownership/runtime must remain derived: %s", forbidden)
		}
	}
}

func TestDomainDesignAssetsAreEmbeddedAndNeverListDirectories(t *testing.T) {
	for _, asset := range []string{"/domains.css", "/domains.js", "/fonts/inter-variable.woff2"} {
		out := httptest.NewRecorder()
		StaticHandler().ServeHTTP(out, httptest.NewRequest("GET", asset, nil))
		if out.Code != 200 {
			t.Errorf("%s: status %d", asset, out.Code)
		}
	}
	for _, asset := range []string{"/", "/fonts/", "/fonts/../domains.css"} {
		out := httptest.NewRecorder()
		StaticHandler().ServeHTTP(out, httptest.NewRequest("GET", asset, nil))
		if out.Code != 404 {
			t.Errorf("%s must not expose files: %d", asset, out.Code)
		}
	}
}

func TestDomainDesignDrawerGroupsScopedToolsWithIcons(t *testing.T) {
	var out bytes.Buffer
	if err := domainNavigation(7, "git", WorkspaceView{SupportCustomerID: 88}, true, "blog.example.test").Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"np-domain-drawer-group", "Hosting &amp; security", "Files &amp; access", "Applications &amp; data", "Developer tools", "/support/customers/88/sites/7/git", "aria-current=\"page\""} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing drawer contract %q", want)
		}
	}
}
