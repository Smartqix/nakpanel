package web

import (
	"bytes"
	"context"
	"strings"
	"testing"

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
	for _, want := range []string{`action="/sites/9/subdomains"`, `name="label"`, `data-np-subdomain-preview`, `example.test`, `1/2`, `PHP settings`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q from subdomain dialog", want)
		}
	}
	if strings.Contains(out.String(), `name="subscription_id"`) || strings.Contains(out.String(), `name="domain"`) || strings.Contains(out.String(), `name="php_version"`) {
		t.Fatal("browser must not select subdomain ownership, full domain, or PHP before creation")
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
