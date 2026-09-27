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

func TestSubscriptionOverviewAlwaysShowsPlanCompliance(t *testing.T) {
	data := dashboard.Data{Subscriptions: []types.SubscriptionSummary{{
		ID:                  42,
		CustomerName:        "Example Customer",
		PlanName:            "Production",
		SubscriptionName:    "example.test",
		Status:              "active",
		ComplianceStatus:    types.SubscriptionComplianceCompliant,
		ComplianceCheckedAt: types.PlanRevision{}.CreatedAt,
	}}}
	var body bytes.Buffer
	if err := routedSubscriptionDetail(
		auth.SessionUser{Role: auth.RoleAdmin},
		data,
		DashboardActions{},
		WorkspaceView{Route: "/subscriptions/42", DetailID: 42, Tab: "overview"},
	).Render(context.Background(), &body); err != nil {
		t.Fatal(err)
	}

	html := body.String()
	if !strings.Contains(html, "Compliance") || !strings.Contains(html, "compliant") {
		t.Fatalf("subscription overview must expose compliance state: %s", html)
	}
}

func TestServicePlanMobileCardsKeepCellLabels(t *testing.T) {
	css := string(appCSS)
	const selector = ".np-plan-list-panel .np-table td:not(.np-select-cell):not(:last-child):before"
	if !strings.Contains(css, selector) {
		t.Fatalf("service-plan mobile cards must expose their data-label values")
	}
	if !strings.Contains(css, ".np-bulk-bar input,.np-select-cell input{accent-color:var(--np-primary);height:18px;min-width:18px;width:18px}") {
		t.Fatalf("bulk-selection checkboxes must not inherit the form input minimum width")
	}
}
