package web

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestHostingAndResellerPlanEditorsRenderPHPV3Entitlements(t *testing.T) {
	policy := types.HostingPolicy{
		SchemaVersion: 3,
		Permissions:   types.HostingPermissionPolicy{Composer: true, ComposerCodeExecution: true, ManagedPHPDeployments: true, PHPWorkers: true},
		Resources:     types.HostingResourcePolicy{MaxPHPWorkers: 3, MaxPHPReleases: 6},
	}
	data := dashboard.Data{
		Plans:         []controlquota.Plan{{ID: 4, Name: "PHP Pro", IsActive: true, HostingPolicy: policy}},
		ResellerPlans: []types.ResellerPlan{{ID: 9, Name: "Provider PHP", IsActive: true, HostingPolicy: policy}},
		Capabilities:  types.RuntimeCapabilities{PHPVersions: []string{"8.4", "8.5"}},
	}
	for name, view := range map[string]WorkspaceView{
		"hosting":  {Route: "plan-detail", DetailID: 4, PlanTab: "php", Tab: "php", CSRFToken: "csrf"},
		"reseller": {Route: "reseller-plan-detail", DetailID: 9, PlanTab: "permissions", Tab: "permissions", CSRFToken: "csrf"},
	} {
		t.Run(name, func(t *testing.T) {
			body := renderPhase30Page(t, data, view)
			for _, want := range []string{"Managed PHP deployments", "Composer", "Composer code execution", "PHP workers", `name="max_php_workers"`, `name="max_php_releases"`, "Zero disables"} {
				if !strings.Contains(body, want) {
					t.Fatalf("%s plan editor missing %q:\n%s", name, want, body)
				}
			}
		})
	}
}

func TestPHPApplicationNavigationHelperAllowsOnlyKnownTabs(t *testing.T) {
	for input, want := range map[string]string{"": "overview", "DEPLOYMENT": "deployment", "environment": "environment", "../../secret": "overview", "containers": "overview"} {
		if got := phpApplicationTab(input); got != want {
			t.Fatalf("phpApplicationTab(%q) = %q, want %q", input, got, want)
		}
	}
	if !phpDeploymentRollbackEligible(types.PHPDeployment{ID: 4, Status: "healthy", ResolvedRevision: "abc"}, 5) ||
		phpDeploymentRollbackEligible(types.PHPDeployment{ID: 5, Status: "healthy", ResolvedRevision: "abc"}, 5) ||
		phpDeploymentRollbackEligible(types.PHPDeployment{ID: 4, Status: "failed", ResolvedRevision: "abc"}, 5) {
		t.Fatal("rollback eligibility does not protect active or unhealthy releases")
	}
}

func TestPHPApplicationAssetsCarryResponsiveAndProgressiveHooks(t *testing.T) {
	css := string(appCSS)
	javascript := string(appJS)
	for _, want := range []string{".np-php-app-tabs", ".np-php-runtime-list", ".np-php-release-list", "min-height:44px"} {
		if !strings.Contains(css, want) {
			t.Fatalf("compiled PHP workspace CSS missing %q", want)
		}
	}
	for _, want := range []string{"initializePHPApplicationWorkspace", "data-np-php-secret-toggle", "data-np-php-profile", "X-Nakpanel-SPA"} {
		if !strings.Contains(javascript, want) {
			t.Fatalf("PHP workspace JavaScript missing %q", want)
		}
	}
}

func renderPhase30Page(t *testing.T, data dashboard.Data, view WorkspaceView) string {
	t.Helper()
	var body bytes.Buffer
	user := auth.SessionUser{ID: 1, Email: "admin@example.test", Role: auth.RoleAdmin, AuthenticatedAt: time.Now()}
	if err := RoutedDashboardPage("PHP", user, data, DashboardActions{}, view).Render(context.Background(), &body); err != nil {
		t.Fatal(err)
	}
	return body.String()
}
