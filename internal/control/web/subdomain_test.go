package web

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestSubdomainDialogKeepsParentAndSubscriptionServerSelected(t *testing.T) {
	var out bytes.Buffer
	parent := dashboard.Site{ID: 9, Domain: "example.test", SubscriptionID: 44}
	subscription := types.SubscriptionSummary{ID: 44, MaxSubdomains: 2, SubdomainsUsed: 1, PHPAllowlist: "8.4", DefaultPHPVersion: "8.4"}
	capabilities := types.RuntimeCapabilities{PHPVersions: []string{"8.4"}}
	if err := routedSubdomainDialog(parent, subscription, capabilities, WorkspaceView{}).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`action="/sites/9/subdomains"`, `name="label"`, `data-np-subdomain-preview`, `example.test`, `1/2`, `Inherited from subscription`, `data-np-setup-tracker`, `data-np-setup-background`, `data-np-setup-message`, `aria-live="polite"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q from subdomain dialog", want)
		}
	}
	if strings.Contains(out.String(), `name="subscription_id"`) || strings.Contains(out.String(), `name="domain"`) || strings.Contains(out.String(), `name="php_version"`) {
		t.Fatal("browser must not select subdomain ownership, full domain, or PHP before creation")
	}
}

func TestChildDomainCannotOfferNestedSubdomainCreation(t *testing.T) {
	data := dashboard.Data{Sites: []dashboard.Site{{ID: 1, Domain: "example.test"}, {ID: 7, Domain: "blog.example.test", ParentSiteID: 1, SubscriptionID: 20, Status: "active", DesiredStatus: "active"}}, Subscriptions: []types.SubscriptionSummary{{ID: 20, Status: "active"}}}
	var out bytes.Buffer
	if err := routedSiteDetail(auth.SessionUser{Role: auth.RoleAdmin}, data, DashboardActions{CanCreateSite: true}, WorkspaceView{DetailID: 7, Tab: "overview"}).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Add subdomain") || strings.Contains(out.String(), "subdomain-dialog-7") {
		t.Fatal("child offers nested subdomain creation")
	}
	if !strings.Contains(out.String(), "Parent domain:") || !strings.Contains(out.String(), `href="/sites/1"`) {
		t.Fatal("child lost parent context")
	}
	if strings.Contains(out.String(), "<h2>Subdomain setup</h2>") || strings.Count(out.String(), "np-domain-status-strip") != 1 {
		t.Fatal("child must use one shared status strip, not duplicate setup summaries")
	}
}

func TestSubdomainCreationOffersPlanGatedFreeSSL(t *testing.T) {
	var out bytes.Buffer
	if err := routedSubdomainDialog(dashboard.Site{ID: 1, Domain: "example.test"}, types.SubscriptionSummary{AllowTLS: true, PHPAllowlist: "8.4", DefaultPHPVersion: "8.4"}, types.RuntimeCapabilities{PHPVersions: []string{"8.4"}, ACMEAvailable: true}, WorkspaceView{}).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `name="secure_with_ssl"`) || !strings.Contains(out.String(), "Secure with free SSL") {
		t.Fatal("no integrated SSL choice")
	}
}

func TestWebsiteSSLDefaultAndSubscriptionRootUsage(t *testing.T) {
	for _, tc := range []struct {
		name              string
		allow, available  bool
		choice            *bool
		checked, disabled bool
	}{
		{"default", true, true, nil, true, false}, {"no entitlement", false, true, nil, false, true}, {"no ACME", true, false, nil, false, true}, {"unchecked preserved", true, true, boolPtrForSSL(false), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			view := WorkspaceView{SiteCreateSSL: tc.choice}
			if err := siteCreatePage([]types.SubscriptionSummary{{ID: 20, AllowTLS: tc.allow, MaxSites: 5, DomainsUsed: 1, SitesUsed: 6}}, types.RuntimeCapabilities{ACMEAvailable: tc.available}, DashboardActions{}, view).Render(context.Background(), &out); err != nil {
				t.Fatal(err)
			}
			body := out.String()
			start := strings.Index(body, `name="secure_with_ssl"`)
			if start < 0 {
				t.Fatal("missing SSL choice")
			}
			input := body[start : start+strings.Index(body[start:], ">")]
			if strings.Contains(input, " checked") != tc.checked || strings.Contains(input, " disabled") != tc.disabled {
				t.Fatalf("choice=%s", input)
			}
			if !strings.Contains(body, `data-sites-used="1"`) {
				t.Fatal("subdomains incorrectly consume root-website UI allowance")
			}
		})
	}
}
func boolPtrForSSL(value bool) *bool { return &value }

func TestDialogSetupUsesOneVisibleHeading(t *testing.T) {
	var out bytes.Buffer
	if err := siteSetupProgress(types.SiteSetupStatus{SiteID: 7, Kind: "subdomain", State: "pending"}, WorkspaceView{}, true).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "<h3") || !strings.Contains(out.String(), `class="sr-only" data-np-setup-title`) {
		t.Fatal("dialog duplicates its visible heading")
	}
}

func TestDomainOrderKeepsSubdomainsNearParent(t *testing.T) {
	items := []dashboard.Site{
		{ID: 3, Domain: "shop.example.test", ParentSiteID: 1},
		{ID: 2, Domain: "other.test"},
		{ID: 1, Domain: "example.test"},
		{ID: 4, Domain: "api.shop.example.test", ParentSiteID: 3},
	}
	ordered := sitesInDomainOrder(items)
	for index, want := range []int64{1, 3, 4, 2} {
		if ordered[index].ID != want {
			t.Fatalf("site order = %#v", ordered)
		}
	}
}
