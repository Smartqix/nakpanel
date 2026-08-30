package web

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlphpapp "github.com/nakroteck/nakpanel/internal/control/phpapp"
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
	if !strings.Contains(css, ".np-php-setup:not(.is-enhanced) [data-np-php-step-next]") {
		t.Fatal("compiled PHP workspace CSS does not preserve the non-JavaScript setup submit fallback")
	}
	for _, want := range []string{"initializePHPApplicationWorkspace", "data-np-php-secret-toggle", "data-np-php-profile", "X-Nakpanel-SPA", "allowedSiteLogSources", "requestedLogSource", "data-np-php-step-panel", "reportValidity"} {
		if !strings.Contains(javascript, want) {
			t.Fatalf("PHP workspace JavaScript missing %q", want)
		}
	}
}

func TestPhase30LogLinksAndSelectorUsePublicSourceEnums(t *testing.T) {
	policy := types.HostingPolicy{Permissions: types.HostingPermissionPolicy{Logs: true}}
	data := dashboard.Data{
		Sites:                []dashboard.Site{{ID: 7, Domain: "owned.test", SubscriptionID: 20, CustomerID: 88}},
		Subscriptions:        []types.SubscriptionSummary{{ID: 20, CustomerID: 88, SubscriptionName: "Production", Status: "active"}},
		Customers:            []types.Customer{{ID: 88, Status: "active"}},
		SubscriptionServices: dashboard.SubscriptionServicesData{SitePolicies: []dashboard.SitePolicy{{SiteID: 7, SubscriptionID: 20, EffectivePolicy: policy}}},
	}
	logs := renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "logs", LogSource: "php_deployment", CSRFToken: "csrf"})
	for _, want := range []string{`value="php_deployment" selected`, `value="php_worker"`, `value="php_fpm"`} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log selector missing %q:\n%s", want, logs)
		}
	}

	workspace := phase30ManagedWorkspace()
	data.SubscriptionServices.Git = []types.GitRepository{{ID: 12, SiteID: 7, Branch: "main"}}
	application := renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "applications", ApplicationTab: "logs", PHPApplication: &workspace, CSRFToken: "csrf"})
	for _, want := range []string{"source=php_deployment", "source=php_worker", "source=php_fpm"} {
		if !strings.Contains(application, want) {
			t.Fatalf("PHP log shortcut missing %q:\n%s", want, application)
		}
	}
	for _, forbidden := range []string{"source=php-deployment", "source=php-worker", "source=php-fpm"} {
		if strings.Contains(application, forbidden) {
			t.Fatalf("PHP log shortcut used invalid enum %q", forbidden)
		}
	}
}

func TestPHPApplicationMutationGateIncludesInheritedLifecycleAndFirstRelease(t *testing.T) {
	workspace := phase30ManagedWorkspace()
	subscription := types.SubscriptionSummary{ID: 20, CustomerID: 88, ResellerID: 91, Status: "active"}
	data := dashboard.Data{Customers: []types.Customer{{ID: 88, Status: "active"}}, Resellers: []types.Reseller{{ID: 91, Status: "active"}}}

	gate := phpApplicationMutationGate(workspace, subscription, data)
	if !gate.CanConfigure || !gate.CanDeploy || !gate.CanEnvironment || !gate.CanReconcile || gate.CanWorkers {
		t.Fatalf("pre-release active gate = %#v", gate)
	}
	workspace.ActiveDeploymentID = 41
	gate = phpApplicationMutationGate(workspace, subscription, data)
	if !gate.CanWorkers || gate.Message != "" {
		t.Fatalf("healthy active gate = %#v", gate)
	}

	checks := []struct {
		name   string
		mutate func(*controlphpapp.Workspace, *types.SubscriptionSummary, *dashboard.Data)
	}{
		{"classic", func(w *controlphpapp.Workspace, _ *types.SubscriptionSummary, _ *dashboard.Data) {
			w.Application.HostingMode = types.PHPHostingModeClassic
		}},
		{"subscription suspended", func(_ *controlphpapp.Workspace, s *types.SubscriptionSummary, _ *dashboard.Data) {
			s.Status = "suspended"
		}},
		{"customer suspended", func(_ *controlphpapp.Workspace, _ *types.SubscriptionSummary, d *dashboard.Data) {
			d.Customers[0].Status = "suspended"
		}},
		{"provider suspended", func(_ *controlphpapp.Workspace, _ *types.SubscriptionSummary, d *dashboard.Data) {
			d.Resellers[0].Status = "suspended"
		}},
		{"runtime unavailable", func(w *controlphpapp.Workspace, _ *types.SubscriptionSummary, _ *dashboard.Data) {
			w.Runtime.Ready = false
		}},
		{"managed permission disabled", func(w *controlphpapp.Workspace, _ *types.SubscriptionSummary, _ *dashboard.Data) {
			w.Policy.Permissions.ManagedPHPDeployments = false
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			candidate, candidateSubscription, candidateData := workspace, subscription, data
			candidateData.Customers = append([]types.Customer(nil), data.Customers...)
			candidateData.Resellers = append([]types.Reseller(nil), data.Resellers...)
			check.mutate(&candidate, &candidateSubscription, &candidateData)
			got := phpApplicationMutationGate(candidate, candidateSubscription, candidateData)
			if got.CanDeploy || got.CanEnvironment || got.CanWorkers || got.CanReconcile || got.Message == "" {
				t.Fatalf("blocked gate = %#v", got)
			}
		})
	}
}

func TestManagedSetupIsLosslessAccessibleAndClassicActionsAreReadOnly(t *testing.T) {
	workspace := phase30ManagedWorkspace()
	workspace.Application.Composer = types.PHPComposerSpec{Install: true, AllowScripts: true, AllowPlugins: false}
	workspace.ActiveDeploymentID = 41
	data := phase30ApplicationData()
	body := renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "applications", PHPApplication: &workspace, CSRFToken: "csrf"})
	for _, want := range []string{
		"Application settings", `value="12" selected`, `value="laravel" selected`, `value="8.4" selected`,
		`name="repository_ref" value="main"`, `name="public_path" value="public"`, `name="health_path" value="/up"`,
		`name="release_retention" min="1" max="100" value="4"`, `name="composer_install" value="true" checked`,
		`name="composer_allow_scripts" value="true" checked`, `name="composer_allow_plugins" value="true"`,
		`aria-controls="php-managed-step-source"`, `data-np-php-step-panel="0"`, `data-np-php-step-next`, `data-np-php-step-back`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("managed settings missing persisted/accessibility field %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `name="composer_allow_plugins" value="true" checked`) || strings.Contains(body, `data-np-php-step-panel="0" hidden`) {
		t.Fatalf("managed settings reset stored values or hid the non-JS fallback:\n%s", body)
	}

	workspace.Application.HostingMode = types.PHPHostingModeClassic
	workspace.ActiveDeploymentID = 0
	body = renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "applications", ApplicationTab: "environment", PHPApplication: &workspace, CSRFToken: "csrf"})
	for _, forbidden := range []string{`data-np-dialog-open="php-environment-dialog"`, `id="php-environment-dialog"`, `php-application/reconcile`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("classic workspace exposed incompatible mutation %q:\n%s", forbidden, body)
		}
	}
}

func phase30ManagedWorkspace() controlphpapp.Workspace {
	return controlphpapp.Workspace{
		Application: types.PHPApplicationSpec{ApplicationID: 31, SiteID: 7, SubscriptionID: 20, HostingMode: types.PHPHostingModeManaged,
			PHPVersion: "8.4", RepositoryID: 12, RepositoryRef: "main", FrameworkProfile: types.PHPFrameworkLaravel,
			PublicPath: "public", HealthPath: "/up", SharedPaths: []string{"storage", "bootstrap/cache"}, ReleaseRetention: 4},
		Policy:  types.HostingPolicy{SchemaVersion: 3, Permissions: types.HostingPermissionPolicy{Git: true, Composer: true, ComposerCodeExecution: true, ManagedPHPDeployments: true, PHPWorkers: true}, Resources: types.HostingResourcePolicy{MaxPHPWorkers: 4, MaxPHPReleases: 5}},
		Runtime: types.PHPRuntimeCapability{Version: "8.4", Ready: true},
	}
}

func phase30ApplicationData() dashboard.Data {
	return dashboard.Data{
		Sites:                []dashboard.Site{{ID: 7, Domain: "owned.test", SubscriptionID: 20, CustomerID: 88}},
		Subscriptions:        []types.SubscriptionSummary{{ID: 20, CustomerID: 88, SubscriptionName: "Production", Status: "active"}},
		Customers:            []types.Customer{{ID: 88, Status: "active"}},
		SubscriptionServices: dashboard.SubscriptionServicesData{Git: []types.GitRepository{{ID: 12, SiteID: 7, Branch: "main", RemoteURL: "ssh://git.example/app.git"}}},
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
