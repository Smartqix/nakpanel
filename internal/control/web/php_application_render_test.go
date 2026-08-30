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
	for _, want := range []string{"initializePHPApplicationWorkspace", "data-np-php-secret-toggle", "data-np-php-profile", "X-Nakpanel-SPA", "allowedSiteLogSources", "requestedLogSource", "data-np-php-step-panel", "reportValidity", "syncPHPReview", "data-np-php-review-repository", "data-np-php-review-retention"} {
		if !strings.Contains(javascript, want) {
			t.Fatalf("PHP workspace JavaScript missing %q", want)
		}
	}
}

func TestPHPApplicationMobileControlsMeetMinimumTouchTarget(t *testing.T) {
	css := string(appCSS)
	assertDeclaration := func(selector, declaration string) {
		t.Helper()
		start := strings.Index(css, selector+"{")
		if start < 0 {
			t.Fatalf("compiled CSS missing %q", selector)
		}
		end := strings.Index(css[start:], "}")
		if end < 0 || !strings.Contains(css[start:start+end], declaration) {
			t.Fatalf("compiled CSS rule %q missing %q", selector, declaration)
		}
	}
	assertDeclaration(".np-avatar", "height:44px")
	assertDeclaration(".np-domain-tools-trigger", "min-height:44px")
	assertDeclaration(".np-php-app-head-actions button", "min-height:44px")
}

func TestErrorPageStylesKeepCopyReadableOnAuthenticationBackground(t *testing.T) {
	css := string(appCSS)
	for _, want := range []string{
		`.np-error-stage{align-items:center`,
		`.np-error-card{background:var(--np-surface)`,
		`.np-error-card h1{color:var(--np-ink)`,
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("embedded error-page CSS missing %q", want)
		}
	}
}

func TestPHPSettingsExposeSubscriptionLimitsAndInlineErrorHooks(t *testing.T) {
	policy := types.HostingPolicy{
		PHP: types.HostingPHPPolicy{
			AllowedVersions: []string{"8.4"}, FPMMode: "ondemand", FPMMaxChildren: 3,
			MemoryLimitMB: 128, OPcacheMemoryMB: 64,
		},
	}
	data := dashboard.Data{
		Sites:         []dashboard.Site{{ID: 7, Domain: "owned.test", Status: "active", DesiredStatus: "active", DesiredPHPVersion: "8.4", SubscriptionID: 20, CustomerID: 88}},
		Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, Status: "active", AllowPHPSettings: true, PHPAllowlist: "8.4"}},
		Capabilities:  types.RuntimeCapabilities{PHPVersions: []string{"8.4"}},
		SubscriptionServices: dashboard.SubscriptionServicesData{SitePolicies: []dashboard.SitePolicy{{
			SiteID: 7, SubscriptionID: 20, InheritedPolicy: policy, EffectivePolicy: policy,
		}}},
	}
	body := renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "php", CSRFToken: "csrf"})
	fieldNameAt := strings.Index(body, `name="site_php_memory"`)
	if fieldNameAt < 0 {
		t.Fatal("PHP memory field is missing")
	}
	fieldAt := strings.LastIndex(body[:fieldNameAt], "<input")
	if fieldAt < 0 {
		t.Fatal("PHP memory input does not start")
	}
	fieldEnd := strings.Index(body[fieldAt:], ">")
	if fieldEnd < 0 {
		t.Fatal("PHP memory field does not terminate")
	}
	field := body[fieldAt : fieldAt+fieldEnd]
	for _, want := range []string{`min="0"`, `max="128"`, `aria-describedby="site-php-memory-help"`} {
		if !strings.Contains(field, want) {
			t.Fatalf("PHP memory field %q missing %q", field, want)
		}
	}
	if !strings.Contains(body, "Subscription ceiling") || strings.Contains(body, "Provider ceiling") {
		t.Fatalf("PHP settings summary does not describe the subscription ceiling:\n%s", body)
	}
	for _, want := range []string{`max="3" name="site_fpm_children"`, `max="64" name="site_php_opcache_memory"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("PHP settings do not expose subscription ceiling %q:\n%s", want, body)
		}
	}
	for _, want := range []string{"submitSitePolicyForm", "data-np-form-error", "data-np-field-error", "aria-invalid", "X-Nakpanel-SPA", `submitter.hasAttribute("formaction")`, `var body = new URLSearchParams(new window.FormData(form));`} {
		if !strings.Contains(string(appJS), want) {
			t.Fatalf("settings JavaScript missing inline error hook %q", want)
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

	gate := phpApplicationMutationGate(workspace)
	if !gate.CanConfigure || !gate.CanDeploy || !gate.CanEnvironment || !gate.CanReconcile || gate.CanWorkers {
		t.Fatalf("pre-release active gate = %#v", gate)
	}
	workspace.ActiveDeploymentID = 41
	gate = phpApplicationMutationGate(workspace)
	if !gate.CanWorkers || gate.Message != "" {
		t.Fatalf("healthy active gate = %#v", gate)
	}

	checks := []struct {
		name   string
		mutate func(*controlphpapp.Workspace)
	}{
		{"classic", func(w *controlphpapp.Workspace) {
			w.Application.HostingMode = types.PHPHostingModeClassic
		}},
		{"subscription suspended", func(w *controlphpapp.Workspace) {
			w.Lifecycle.SubscriptionStatus = "suspended"
		}},
		{"customer suspended", func(w *controlphpapp.Workspace) {
			w.Lifecycle.CustomerStatus = "suspended"
		}},
		{"provider suspended", func(w *controlphpapp.Workspace) {
			w.Lifecycle.ProviderActive = false
		}},
		{"site suspended", func(w *controlphpapp.Workspace) {
			w.Lifecycle.SiteStatus = "suspended"
		}},
		{"managed permission disabled", func(w *controlphpapp.Workspace) {
			w.Policy.Permissions.ManagedPHPDeployments = false
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			candidate := workspace
			check.mutate(&candidate)
			got := phpApplicationMutationGate(candidate)
			if got.CanDeploy || got.CanEnvironment || got.CanWorkers || got.CanReconcile || got.Message == "" {
				t.Fatalf("blocked gate = %#v", got)
			}
		})
	}

	t.Run("unavailable selected runtime is recoverable", func(t *testing.T) {
		candidate := workspace
		candidate.Runtime.Ready = false
		candidate.Policy.PHP.AllowedVersions = []string{"8.4", "8.5"}
		candidate.Capabilities.PHPRuntimes = []types.PHPRuntimeCapability{{Version: "8.4", Ready: false}, {Version: "8.5", Ready: true}}
		got := phpApplicationMutationGate(candidate)
		if !got.CanConfigure || got.CanDeploy || got.CanEnvironment || got.CanWorkers || got.CanReconcile || got.Message == "" {
			t.Fatalf("recoverable runtime gate = %#v", got)
		}
	})
	t.Run("no ready allowed runtime is blocked", func(t *testing.T) {
		candidate := workspace
		candidate.Runtime.Ready = false
		candidate.Capabilities.PHPRuntimes = []types.PHPRuntimeCapability{{Version: "8.4", Ready: false}}
		got := phpApplicationMutationGate(candidate)
		if got.CanConfigure || got.CanDeploy || got.CanEnvironment || got.CanWorkers || got.CanReconcile || got.Message == "" {
			t.Fatalf("unrecoverable runtime gate = %#v", got)
		}
	})
}

func TestUnavailableSelectedRuntimeRendersRecoveryOnly(t *testing.T) {
	workspace := phase30ManagedWorkspace()
	workspace.Runtime.Ready = false
	workspace.Policy.PHP.AllowedVersions = []string{"8.4", "8.5"}
	workspace.Capabilities.PHPRuntimes = []types.PHPRuntimeCapability{{Version: "8.4", Ready: false}, {Version: "8.5", Ready: true}}
	body := renderPhase30Page(t, phase30ApplicationData(), WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "applications", PHPApplication: &workspace, CSRFToken: "csrf"})
	for _, want := range []string{"Application settings", `id="php-managed-setup-dialog"`, `value="8.5"`, "choose a ready runtime"} {
		if !strings.Contains(body, want) {
			t.Fatalf("runtime recovery workspace missing %q:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{`id="php-deploy-dialog"`, `id="php-environment-dialog"`, `id="php-worker-dialog"`, `php-application/reconcile`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("runtime recovery workspace exposed incompatible mutation %q:\n%s", forbidden, body)
		}
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
		`data-np-php-review-repository`, `data-np-php-review-php`, `data-np-php-review-profile`, `data-np-php-review-composer`,
		`data-np-php-review-public`, `data-np-php-review-health`, `data-np-php-review-shared`, `data-np-php-review-retention`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("managed settings missing persisted/accessibility field %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `name="composer_allow_plugins" value="true" checked`) || strings.Contains(body, `data-np-php-step-panel="0" hidden`) {
		t.Fatalf("managed settings reset stored values or hid the non-JS fallback:\n%s", body)
	}

	workspace.Application.Composer = types.PHPComposerSpec{Install: true, AllowScripts: true, AllowPlugins: true}
	workspace.Policy.Permissions.Composer = false
	workspace.Policy.Permissions.ComposerCodeExecution = false
	body = renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "applications", PHPApplication: &workspace, CSRFToken: "csrf"})
	for _, forbidden := range []string{`name="composer_install" value="true" disabled`, `name="composer_allow_scripts" value="true" disabled`, `type="hidden" name="composer_install"`, `type="hidden" name="composer_allow_scripts"`, `type="hidden" name="composer_allow_plugins"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("revoked Composer state cannot be cleared because of %q:\n%s", forbidden, body)
		}
	}
	if !strings.Contains(body, "This saved Composer setting is no longer allowed") {
		t.Fatalf("revoked Composer state lacks an operator-visible recovery message:\n%s", body)
	}

	workspace.Application.HostingMode = types.PHPHostingModeClassic
	workspace.ActiveDeploymentID = 0
	body = renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "applications", ApplicationTab: "environment", PHPApplication: &workspace, CSRFToken: "csrf"})
	for _, forbidden := range []string{`data-np-dialog-open="php-environment-dialog"`, `id="php-environment-dialog"`, `php-application/reconcile`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("classic workspace exposed incompatible mutation %q:\n%s", forbidden, body)
		}
	}

	workspace = phase30ManagedWorkspace()
	workspace.ActiveDeploymentID = 41
	workspace.Lifecycle.SiteStatus = "suspended"
	body = renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "applications", ApplicationTab: "environment", PHPApplication: &workspace, CSRFToken: "csrf"})
	for _, forbidden := range []string{`data-np-dialog-open="php-environment-dialog"`, `id="php-environment-dialog"`, `php-application/reconcile`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("suspended site exposed incompatible mutation %q:\n%s", forbidden, body)
		}
	}
	if !strings.Contains(body, "website is suspended") {
		t.Fatalf("suspended site lacks its authoritative lifecycle explanation:\n%s", body)
	}
}

func phase30ManagedWorkspace() controlphpapp.Workspace {
	return controlphpapp.Workspace{
		Application: types.PHPApplicationSpec{ApplicationID: 31, SiteID: 7, SubscriptionID: 20, HostingMode: types.PHPHostingModeManaged,
			PHPVersion: "8.4", RepositoryID: 12, RepositoryRef: "main", FrameworkProfile: types.PHPFrameworkLaravel,
			PublicPath: "public", HealthPath: "/up", SharedPaths: []string{"storage", "bootstrap/cache"}, ReleaseRetention: 4, DesiredState: "active"},
		Policy:       types.HostingPolicy{SchemaVersion: 3, Permissions: types.HostingPermissionPolicy{Hosting: true, Git: true, Composer: true, ComposerCodeExecution: true, ManagedPHPDeployments: true, PHPWorkers: true}, Resources: types.HostingResourcePolicy{MaxPHPWorkers: 4, MaxPHPReleases: 5}, PHP: types.HostingPHPPolicy{AllowedVersions: []string{"8.4"}}},
		Runtime:      types.PHPRuntimeCapability{Version: "8.4", Ready: true},
		Capabilities: types.RuntimeCapabilities{PHPRuntimes: []types.PHPRuntimeCapability{{Version: "8.4", Ready: true}}},
		Lifecycle:    controlphpapp.LifecycleState{SubscriptionStatus: "active", CustomerStatus: "active", SiteStatus: "active", ProviderActive: true},
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
