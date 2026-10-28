package web

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestPlanDeletionActionOnlyForUnusedPlans(t *testing.T) {
	plan := controlquota.Plan{ID: 42, Name: "Disposable", LifecycleStatus: types.PlanLifecycleDraft}
	for _, status := range []string{"unused", "active", "suspended", "cancelled"} {
		t.Run(status, func(t *testing.T) {
			data := dashboard.Data{Plans: []controlquota.Plan{plan}}
			if status != "unused" {
				data.Subscriptions = []types.SubscriptionSummary{{ID: 9, PlanID: 42, Status: status}}
			}
			for _, page := range []string{"list", "detail"} {
				var out bytes.Buffer
				view := WorkspaceView{Route: "plan-detail", DetailID: 42, CSRFToken: "test-token"}
				component := routedPlanEditor(plan, data, view, false)
				if page == "list" {
					component = hostingPlanTable(data, view)
				}
				if err := component.Render(context.Background(), &out); err != nil {
					t.Fatal(err)
				}
				html := out.String()
				if status == "unused" {
					if !strings.Contains(html, `action="/plans/42/delete"`) || !strings.Contains(html, `data-np-confirm=`) {
						t.Fatalf("%s missing confirmed deletion for unused plan", page)
					}
				} else if strings.Contains(html, `action="/plans/42/delete"`) || !strings.Contains(html, "subscriptions") {
					t.Fatalf("%s exposes deletion for %s subscription", page, status)
				}
			}
		})
	}
}
