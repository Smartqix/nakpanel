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

func TestPlanWordPressPermissionAndCapacityStayTogether(t *testing.T) {
	var output bytes.Buffer
	p := controlquota.Plan{ID: 5, Name: "Hosting", IsActive: true,
		HostingPolicy: types.HostingPolicy{SchemaVersion: 5,
			Permissions: types.HostingPermissionPolicy{WordPressToolkit: true},
			Resources:   types.HostingResourcePolicy{MaxWordPressSites: 5}}}
	if err := routedPlanEditor(p, dashboard.Data{}, WorkspaceView{Route: "plan-detail", DetailID: 5}, false).
		Render(context.Background(), &output); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	start := strings.Index(html, `data-np-plan-panel="services"`)
	if start < 0 {
		t.Fatal("missing services section")
	}
	end := strings.Index(html[start:], `data-np-plan-panel="customer-permissions"`)
	if start < 0 || end < 0 {
		t.Fatal("missing service plan sections")
	}
	services := html[start : start+end]
	for _, name := range []string{`name="allow_wordpress_toolkit"`, `name="max_wordpress_sites"`} {
		if !strings.Contains(services, name) {
			t.Fatalf("%s is not beside WordPress service", name)
		}
	}
	if strings.Count(html, `name="max_wordpress_sites"`) != 1 {
		t.Fatal("duplicate capacity fields")
	}
	if !strings.Contains(html, "data-np-plan-sync") {
		t.Fatal("missing live plan synchronization status")
	}
	if planInputEnforcement("max_wordpress_sites") != string(types.PlanEnforcementHardLimit) {
		t.Fatal("WordPress installation count is a hard limit")
	}
}

func TestPlanSyncLabelDistinguishesFailureAndExclusions(t *testing.T) {
	items := []types.SubscriptionSummary{
		{PlanID: 5, SyncMode: "synced", SyncStatus: "out_of_sync"},
		{PlanID: 5, SyncMode: "locked", SyncStatus: "in_sync"},
		{PlanID: 9, SyncMode: "synced", SyncStatus: "pending"},
	}
	got := planSyncLabel(5, items)
	if !strings.Contains(strings.ToLower(got), "failed") || !strings.Contains(strings.ToLower(got), "excluded") {
		t.Fatalf("misleading synchronization label: %q", got)
	}
}
