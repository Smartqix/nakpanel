package panelhttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlphpapp "github.com/nakroteck/nakpanel/internal/control/phpapp"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakePHPApplicationService struct {
	workspace       controlphpapp.Workspace
	capabilities    types.RuntimeCapabilities
	err             error
	called          string
	actor           auth.SessionUser
	siteID          int64
	deploymentID    int64
	workerID        int64
	configureInput  controlphpapp.ConfigureApplicationInput
	deploymentInput controlphpapp.DeploymentInput
	environment     controlphpapp.EnvironmentInput
	environmentName string
	worker          controlphpapp.WorkerInput
	workerState     string
}

func (f *fakePHPApplicationService) Workspace(_ context.Context, actor auth.SessionUser, siteID int64) (controlphpapp.Workspace, error) {
	f.called, f.actor, f.siteID = "workspace", actor, siteID
	return f.workspace, f.err
}
func (f *fakePHPApplicationService) RuntimeCapabilities(context.Context) (types.RuntimeCapabilities, error) {
	f.called = "capabilities"
	return f.capabilities, f.err
}
func (f *fakePHPApplicationService) ConfigureApplication(_ context.Context, actor auth.SessionUser, siteID int64, input controlphpapp.ConfigureApplicationInput) (types.PHPApplicationSpec, error) {
	f.called, f.actor, f.siteID, f.configureInput = "configure", actor, siteID, input
	return types.PHPApplicationSpec{ApplicationID: 31, SiteID: siteID}, f.err
}
func (f *fakePHPApplicationService) QueueDeployment(_ context.Context, actor auth.SessionUser, siteID int64, input controlphpapp.DeploymentInput) (types.PHPDeployment, error) {
	f.called, f.actor, f.siteID, f.deploymentInput = "deploy", actor, siteID, input
	return types.PHPDeployment{ID: 41, ApplicationID: 31, Status: "pending"}, f.err
}
func (f *fakePHPApplicationService) QueueRollback(_ context.Context, actor auth.SessionUser, siteID, deploymentID int64) (types.PHPDeployment, error) {
	f.called, f.actor, f.siteID, f.deploymentID = "rollback", actor, siteID, deploymentID
	return types.PHPDeployment{ID: 42, ApplicationID: 31, Status: "pending"}, f.err
}
func (f *fakePHPApplicationService) UpsertEnvironment(_ context.Context, actor auth.SessionUser, siteID int64, input controlphpapp.EnvironmentInput) (types.PHPEnvironmentVariable, error) {
	f.called, f.actor, f.siteID, f.environment = "environment", actor, siteID, input
	return types.PHPEnvironmentVariable{Name: input.Name, SecretID: 9}, f.err
}
func (f *fakePHPApplicationService) DeleteEnvironment(_ context.Context, actor auth.SessionUser, siteID int64, name string) error {
	f.called, f.actor, f.siteID, f.environmentName = "delete-environment", actor, siteID, name
	return f.err
}
func (f *fakePHPApplicationService) UpsertWorker(_ context.Context, actor auth.SessionUser, siteID int64, input controlphpapp.WorkerInput) (types.PHPWorker, error) {
	f.called, f.actor, f.siteID, f.worker = "worker", actor, siteID, input
	return types.PHPWorker{ID: 51, ApplicationID: 31, Name: input.Name}, f.err
}
func (f *fakePHPApplicationService) DeleteWorker(_ context.Context, actor auth.SessionUser, siteID, workerID int64) error {
	f.called, f.actor, f.siteID, f.workerID = "delete-worker", actor, siteID, workerID
	return f.err
}
func (f *fakePHPApplicationService) SetWorkerState(_ context.Context, actor auth.SessionUser, siteID, workerID int64, state string) error {
	f.called, f.actor, f.siteID, f.workerID, f.workerState = "worker-state", actor, siteID, workerID, state
	return f.err
}
func (f *fakePHPApplicationService) RequestReconcile(_ context.Context, actor auth.SessionUser, siteID int64) error {
	f.called, f.actor, f.siteID = "reconcile", actor, siteID
	return f.err
}

func phpApplicationDashboard(siteID int64) dashboard.Data {
	return dashboard.Data{Sites: []dashboard.Site{{ID: siteID, Domain: "owned.test", Status: "active", CustomerID: 88, SubscriptionID: 20}}}
}

func TestPHPApplicationWorkspaceLoadsAfterScopedSiteVisibility(t *testing.T) {
	reader := &fakeDashboardReader{data: phpApplicationDashboard(7)}
	service := &fakePHPApplicationService{workspace: controlphpapp.Workspace{Application: types.PHPApplicationSpec{ApplicationID: 31, SiteID: 7, HostingMode: types.PHPHostingModeClassic}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: reader, PHPApplications: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/applications", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || service.called != "workspace" || service.siteID != 7 {
		t.Fatalf("workspace GET = %d call=%q site=%d body=%s", rec.Code, service.called, service.siteID, rec.Body.String())
	}

	service.called = ""
	req = httptest.NewRequest(http.MethodGet, "https://panel.test/sites/8/applications", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || service.called != "" {
		t.Fatalf("cross-tenant GET = %d call=%q", rec.Code, service.called)
	}
}

func TestPHPApplicationWorkspaceUsesAuthoritativeLifecycleForClientDashboardShape(t *testing.T) {
	data := phpApplicationDashboard(7)
	data.Subscriptions = []types.SubscriptionSummary{{ID: 20, CustomerID: 88, SubscriptionName: "Production", Status: "active"}}
	if len(data.Customers) != 0 {
		t.Fatal("client dashboard fixture unexpectedly contains provider customer inventory")
	}
	workspace := controlphpapp.Workspace{
		Application:        types.PHPApplicationSpec{ApplicationID: 31, SiteID: 7, SubscriptionID: 20, HostingMode: types.PHPHostingModeManaged, PHPVersion: "8.4", RepositoryID: 12, RepositoryRef: "main", HealthPath: "/", ReleaseRetention: 4, DesiredState: "active"},
		Policy:             types.HostingPolicy{Permissions: types.HostingPermissionPolicy{Hosting: true, Git: true, ManagedPHPDeployments: true, PHPWorkers: true}, PHP: types.HostingPHPPolicy{AllowedVersions: []string{"8.4"}}},
		Runtime:            types.PHPRuntimeCapability{Version: "8.4", Ready: true},
		Capabilities:       types.RuntimeCapabilities{PHPRuntimes: []types.PHPRuntimeCapability{{Version: "8.4", Ready: true}}},
		Lifecycle:          controlphpapp.LifecycleState{SubscriptionStatus: "active", CustomerStatus: "active", SiteStatus: "active", ProviderActive: true},
		ActiveDeploymentID: 41,
	}
	data.SubscriptionServices.Git = []types.GitRepository{{ID: 12, SiteID: 7, Branch: "main"}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: &fakeDashboardReader{data: data}, PHPApplications: &fakePHPApplicationService{workspace: workspace}})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/applications?app_tab=environment", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="php-managed-setup-dialog"`) || !strings.Contains(rec.Body.String(), "Add variable") {
		t.Fatalf("active client PHP workspace = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPHPApplicationWorkspaceSupportsAllHostingRoles(t *testing.T) {
	const secret = "role-scoped-secret-must-not-render"
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller, auth.RoleClient} {
		t.Run(string(role), func(t *testing.T) {
			service := &fakePHPApplicationService{workspace: controlphpapp.Workspace{
				Application: types.PHPApplicationSpec{ApplicationID: 31, SiteID: 7, HostingMode: types.PHPHostingModeManaged},
				Environment: []types.PHPEnvironmentVariable{{Name: "APP_SECRET", Value: secret, SecretID: 99}},
			}}
			handler, _ := newTestHandlerWithOptions(t, role, ServerOptions{DashboardReader: &fakeDashboardReader{data: phpApplicationDashboard(7)}, PHPApplications: service})
			email, password := "admin@nakpanel.test", "NakpanelAdmin!2026"
			if role == auth.RoleReseller {
				email, password = "reseller@nakpanel.test", "NakpanelReseller!2026"
			} else if role == auth.RoleClient {
				email, password = "client@nakpanel.test", "NakpanelClient!2026"
			}
			cookie := login(t, handler, email, password)
			req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/applications", nil)
			addAuthenticatedCookie(req, cookie)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || service.actor.Role != role || strings.Contains(rec.Body.String(), secret) {
				t.Fatalf("role %s workspace = %d actor=%s", role, rec.Code, service.actor.Role)
			}
		})
	}
}

func TestPHPApplicationWorkspaceSupportScopeAndUnavailableService(t *testing.T) {
	const secret = "support-secret-must-not-render"
	reader := &fakeDashboardReader{data: dashboard.Data{
		Customers: []types.Customer{{ID: 88, DisplayName: "Owned"}, {ID: 99, DisplayName: "Other"}},
		Sites:     []dashboard.Site{{ID: 7, Domain: "owned.test", CustomerID: 88, SubscriptionID: 20}, {ID: 8, Domain: "other.test", CustomerID: 99, SubscriptionID: 21}},
		Subscriptions: []types.SubscriptionSummary{
			{ID: 20, CustomerID: 88, SubscriptionName: "Owned"},
			{ID: 21, CustomerID: 99, SubscriptionName: "Other"},
		},
	}}
	service := &fakePHPApplicationService{workspace: controlphpapp.Workspace{
		Application: types.PHPApplicationSpec{ApplicationID: 31, SiteID: 7, HostingMode: types.PHPHostingModeManaged},
		Environment: []types.PHPEnvironmentVariable{{Name: "APP_SECRET", Value: secret, SecretID: 99}},
	}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader, PHPApplications: service})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/support/customers/88/sites/7/applications?app_tab=environment", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), secret) ||
		!strings.Contains(rec.Body.String(), `/support/customers/88/sites/7/applications`) {
		t.Fatalf("support workspace = %d body=%s", rec.Code, rec.Body.String())
	}

	service.called = ""
	req = httptest.NewRequest(http.MethodGet, "https://panel.test/support/customers/88/sites/8/applications", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || service.called != "" {
		t.Fatalf("wrong support customer = %d call=%q", rec.Code, service.called)
	}

	handler, _ = newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: &fakeDashboardReader{data: phpApplicationDashboard(7)}})
	cookie = login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req = httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/applications", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "database") {
		t.Fatalf("unconfigured workspace = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPHPApplicationSupportMutationRejectsWrongCustomerBeforeService(t *testing.T) {
	service := &fakePHPApplicationService{}
	reader := &fakeDashboardReader{data: dashboard.Data{
		Customers: []types.Customer{{ID: 88, DisplayName: "Owned"}, {ID: 99, DisplayName: "Other"}},
		Sites:     []dashboard.Site{{ID: 8, Domain: "other.test", CustomerID: 99}},
	}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader, PHPApplications: service})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	form := url.Values{"support_customer_id": {"88"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/8/php-application/reconcile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || service.called != "" {
		t.Fatalf("wrong support mutation = %d call=%q body=%s", rec.Code, service.called, rec.Body.String())
	}
}

func TestPHPRuntimeToolsAreProviderOnlyAndScoped(t *testing.T) {
	service := &fakePHPApplicationService{capabilities: types.RuntimeCapabilities{
		PHPVersions: []string{"8.4"}, ComposerAvailable: true, ComposerVersion: "2.8.11", WPCLIAvailable: true, WPCLIVersion: "2.12.0",
		PHPRuntimes: []types.PHPRuntimeCapability{{Version: "8.4", Ready: true, SupportStatus: types.PHPSupportActive,
			CLIPath: "/usr/bin/php8.4", FPMPath: "/usr/sbin/php-fpm8.4", CLIAvailable: true, FPMAvailable: true,
			FPMConfigValid: true, OPcacheAvailable: true, Extensions: []string{"curl", "mysqli", "opcache"}}},
	}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: &fakeDashboardReader{}, PHPApplications: service})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/php", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || service.called != "capabilities" {
		t.Fatalf("admin PHP tools = %d call=%q", rec.Code, service.called)
	}
	for _, want := range []string{"PHP Runtime Inventory", "PHP 8.4", "Recommended default", "/usr/bin/php8.4", "Composer 2.8.11", "WP-CLI 2.12.0", "mysqli"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("runtime inventory missing %q: %s", want, rec.Body.String())
		}
	}

	service.called = ""
	handler, _ = newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: &fakeDashboardReader{}, PHPApplications: service})
	cookie = login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req = httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/php", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || service.called != "" {
		t.Fatalf("client PHP tools = %d call=%q", rec.Code, service.called)
	}
}

func TestSiteLogWorkspaceSelectsAllowlistedPhase30SourceFromQuery(t *testing.T) {
	data := phpApplicationDashboard(7)
	data.Subscriptions = []types.SubscriptionSummary{{ID: 20, CustomerID: 88, SubscriptionName: "Production", Status: "active"}}
	data.Customers = []types.Customer{{ID: 88, Status: "active"}}
	data.SubscriptionServices.SitePolicies = []dashboard.SitePolicy{{SiteID: 7, SubscriptionID: 20, EffectivePolicy: types.HostingPolicy{Permissions: types.HostingPermissionPolicy{Logs: true}}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: &fakeDashboardReader{data: data}})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	for _, source := range []string{"php_deployment", "php_worker", "php_fpm"} {
		req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/logs?source="+source, nil)
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `value="`+source+`" selected`) {
			t.Fatalf("log source %s = %d body=%s", source, rec.Code, rec.Body.String())
		}
	}
}

func TestPHPApplicationWorkspaceRendersManagedTabsWithoutSecretOrLegacyOCI(t *testing.T) {
	const secret = "distinctive-render-secret-621"
	data := phpApplicationDashboard(7)
	data.Subscriptions = []types.SubscriptionSummary{{ID: 20, CustomerID: 88, SubscriptionName: "Production", PlanName: "Business", Status: "active"}}
	data.Customers = []types.Customer{{ID: 88, Status: "active"}}
	data.SubscriptionServices.Git = []types.GitRepository{{ID: 12, SiteID: 7, Mode: "remote", Branch: "main", RemoteURL: "ssh://git.example/app.git"}}
	workspace := controlphpapp.Workspace{
		Application: types.PHPApplicationSpec{ApplicationID: 31, SiteID: 7, SubscriptionID: 20, HostingMode: types.PHPHostingModeManaged,
			PHPVersion: "8.4", RepositoryID: 12, RepositoryRef: "main", FrameworkProfile: types.PHPFrameworkLaravel,
			PublicPath: "public", HealthPath: "/up", SharedPaths: []string{"storage", "bootstrap/cache"}, ReleaseRetention: 4,
			Composer: types.PHPComposerSpec{Install: true}, DesiredState: "active"},
		Environment: []types.PHPEnvironmentVariable{{Name: "APP_ENV", Value: "production"}, {Name: "APP_KEY", Value: secret, SecretID: 9}},
		Workers: []types.PHPWorker{{ID: 51, ApplicationID: 31, Name: "queue", Script: "artisan", Arguments: []string{"queue:work", "--tries=3"},
			Processes: 2, DesiredState: "running", ObservedState: "running", ConvergenceStatus: "in_sync"}},
		Deployments: []types.PHPDeployment{
			{ID: 41, ApplicationID: 31, RequestedRevision: "main", ResolvedRevision: "abc123", Status: "healthy", CreatedAt: time.Now()},
			{ID: 40, ApplicationID: 31, RequestedRevision: "v1", ResolvedRevision: "def456", Status: "healthy", CreatedAt: time.Now().Add(-time.Hour)},
		},
		Policy: types.HostingPolicy{SchemaVersion: 3, Permissions: types.HostingPermissionPolicy{Hosting: true, Git: true, Composer: true, ManagedPHPDeployments: true, PHPWorkers: true},
			Resources: types.HostingResourcePolicy{MaxPHPWorkers: 4, MaxPHPReleases: 5}, PHP: types.HostingPHPPolicy{AllowedVersions: []string{"8.4"}}},
		Runtime: types.PHPRuntimeCapability{Version: "8.4", Ready: true, SupportStatus: types.PHPSupportActive, CLIAvailable: true, FPMAvailable: true,
			FPMConfigValid: true, OPcacheAvailable: true, CLIPath: "/usr/bin/php8.4", FPMPath: "/usr/sbin/php-fpm8.4", Extensions: []string{"curl", "mysqli"}},
		Capabilities:  types.RuntimeCapabilities{PHPRuntimes: []types.PHPRuntimeCapability{{Version: "8.4", Ready: true}}},
		Lifecycle:     controlphpapp.LifecycleState{SubscriptionStatus: "active", CustomerStatus: "active", SiteStatus: "active", ProviderActive: true},
		ObservedState: "healthy", ConvergenceStatus: "in_sync", ActiveDeploymentID: 41, PreviousDeploymentID: 40,
	}
	service := &fakePHPApplicationService{workspace: workspace}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: &fakeDashboardReader{data: data}, PHPApplications: service})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/applications?app_tab=environment", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("managed workspace = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"PHP Application", "Managed Deployment", "Environment", "APP_ENV", "APP_KEY", "Write-only secret", `type="password"`, `data-np-php-app-tab="environment"`, `id="php-environment-edit-APP_ENV"`, `id="php-environment-edit-APP_KEY"`, `id="php-worker-edit-51"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("managed workspace missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{secret, "Managed runtimes are not installed yet", "Deploy container"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("managed workspace exposed stale/secret content %q: %s", forbidden, body)
		}
	}
}

func TestPHPApplicationWorkspaceRendersClassicDiagnosticsAndEntitlementGate(t *testing.T) {
	data := phpApplicationDashboard(7)
	data.Sites[0].PHPVersion = "8.4"
	data.Sites[0].DocumentRoot = "/home/np7/domains/owned.test/public_html"
	data.Subscriptions = []types.SubscriptionSummary{{ID: 20, CustomerID: 88, SubscriptionName: "Classic", PlanName: "Starter", Status: "active"}}
	data.Customers = []types.Customer{{ID: 88, Status: "active"}}
	workspace := controlphpapp.Workspace{
		Application: types.PHPApplicationSpec{ApplicationID: 31, SiteID: 7, SubscriptionID: 20, HostingMode: types.PHPHostingModeClassic, PHPVersion: "8.4"},
		Policy:      types.HostingPolicy{SchemaVersion: 3, Permissions: types.HostingPermissionPolicy{Composer: true}},
		Runtime: types.PHPRuntimeCapability{Version: "8.4", Ready: true, SupportStatus: types.PHPSupportActive, CLIPath: "/usr/bin/php8.4",
			FPMPath: "/usr/sbin/php-fpm8.4", CLIAvailable: true, FPMAvailable: true, FPMConfigValid: true, OPcacheAvailable: true,
			Extensions: []string{"curl", "mysqli"}},
		Capabilities:  types.RuntimeCapabilities{ComposerAvailable: true, ComposerVersion: "2.8.11", WPCLIAvailable: true, WPCLIVersion: "2.12.0"},
		ObservedState: "healthy", ConvergenceStatus: "in_sync",
	}
	service := &fakePHPApplicationService{workspace: workspace, capabilities: types.RuntimeCapabilities{ComposerAvailable: true, ComposerVersion: "2.8.11", WPCLIAvailable: true, WPCLIVersion: "2.12.0"}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: &fakeDashboardReader{data: data}, PHPApplications: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/applications", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("classic workspace = %d body=%s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{"Classic Hosting", "mutable public_html", "/home/np7/domains/owned.test/public_html", "PHP 8.4", "/usr/sbin/php-fpm8.4", "OPcache", "Files", "Databases", "Backups"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("classic workspace missing %q: %s", want, rec.Body.String())
		}
	}
}

func TestPHPApplicationMutationRoutes(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		form       url.Values
		wantCall   string
		wantStatus int
	}{
		{"configure", "/sites/7/php-application", url.Values{"hosting_mode": {"managed"}, "php_version": {"8.4"}, "repository_id": {"12"}, "repository_ref": {"main"}, "framework_profile": {"laravel"}, "public_path": {"public"}, "health_path": {"/up"}, "shared_path": {"storage", "bootstrap/cache"}, "release_retention": {"4"}, "composer_install": {"true"}}, "configure", http.StatusOK},
		{"deploy", "/sites/7/php-application/deployments", url.Values{"revision": {"main"}}, "deploy", http.StatusAccepted},
		{"rollback", "/sites/7/php-application/deployments/41/rollback", url.Values{"confirm": {"rollback"}}, "rollback", http.StatusAccepted},
		{"environment", "/sites/7/php-application/environment", url.Values{"name": {"APP_ENV"}, "value": {"production"}}, "environment", http.StatusOK},
		{"delete environment", "/sites/7/php-application/environment/delete", url.Values{"name": {"APP_ENV"}, "confirm": {"delete"}}, "delete-environment", http.StatusOK},
		{"worker", "/sites/7/php-application/workers", url.Values{"worker_id": {"51"}, "name": {"queue"}, "script": {"artisan"}, "argument": {"queue:work", "--tries=3"}, "processes": {"2"}, "desired_state": {"running"}}, "worker", http.StatusOK},
		{"worker state", "/sites/7/php-application/workers/51/state", url.Values{"state": {"stopped"}}, "worker-state", http.StatusOK},
		{"delete worker", "/sites/7/php-application/workers/51/delete", url.Values{"confirm": {"delete"}}, "delete-worker", http.StatusOK},
		{"reconcile", "/sites/7/php-application/reconcile", url.Values{}, "reconcile", http.StatusAccepted},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakePHPApplicationService{}
			workspace := &fakeWorkspaceService{}
			handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{PHPApplications: service, Workspace: workspace})
			cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
			req := httptest.NewRequest(http.MethodPost, "https://panel.test"+tc.path, strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Nakpanel-SPA", "true")
			addAuthenticatedCookie(req, cookie)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus || service.called != tc.wantCall {
				t.Fatalf("%s = %d call=%q body=%s", tc.path, rec.Code, service.called, rec.Body.String())
			}
			if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") || len(workspace.audits) != 1 {
				t.Fatalf("response content-type=%q audits=%#v", rec.Header().Get("Content-Type"), workspace.audits)
			}
		})
	}
}

func TestPHPApplicationFormsUsePRGAndSupportRedirect(t *testing.T) {
	service := &fakePHPApplicationService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{PHPApplications: service, DashboardReader: &fakeDashboardReader{data: phpApplicationDashboard(7)}})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	form := url.Values{"revision": {"main"}, "support_customer_id": {"88"}, "return_to": {"https://attacker.test/steal"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/php-application/deployments", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/support/customers/88/sites/7/applications?notice=php-deployment-queued" {
		t.Fatalf("PRG = %d location=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestPHPApplicationCSRFConfirmationAndBoundsRejectBeforeService(t *testing.T) {
	service := &fakePHPApplicationService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{PHPApplications: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/php-application/reconcile", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || service.called != "" {
		t.Fatalf("missing CSRF = %d call=%q", rec.Code, service.called)
	}

	for _, path := range []string{"/sites/7/php-application/deployments/41/rollback", "/sites/7/php-application/environment/delete", "/sites/7/php-application/workers/51/delete"} {
		service.called = ""
		req = httptest.NewRequest(http.MethodPost, "https://panel.test"+path, strings.NewReader("confirm=no"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addAuthenticatedCookie(req, cookie)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || service.called != "" {
			t.Fatalf("confirmation %s = %d call=%q", path, rec.Code, service.called)
		}
	}

	service.called = ""
	form := url.Values{"name": {"worker"}, "script": {"artisan"}, "processes": {"1"}}
	for i := 0; i < 65; i++ {
		form.Add("argument", "value")
	}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/php-application/workers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || service.called != "" {
		t.Fatalf("argument bound = %d call=%q", rec.Code, service.called)
	}
}

func TestPHPApplicationScalarLimitsRejectBeforeServiceWithoutEcho(t *testing.T) {
	const marker = "Z9QX"
	over := func(limit int) string {
		return strings.Repeat("x", limit+1-len(marker)) + marker
	}
	configureBase := func() url.Values {
		return url.Values{"hosting_mode": {"managed"}, "php_version": {"8.4"}, "repository_id": {"12"},
			"repository_ref": {"main"}, "framework_profile": {"plain"}, "health_path": {"/"}, "release_retention": {"4"}}
	}
	tests := []struct {
		name string
		path string
		form url.Values
	}{
		{"hosting mode", "/sites/7/php-application", withFormValue(configureBase(), "hosting_mode", over(16))},
		{"PHP version", "/sites/7/php-application", withFormValue(configureBase(), "php_version", over(16))},
		{"repository ref", "/sites/7/php-application", withFormValue(configureBase(), "repository_ref", over(128))},
		{"framework profile", "/sites/7/php-application", withFormValue(configureBase(), "framework_profile", over(16))},
		{"public path", "/sites/7/php-application", withFormValue(configureBase(), "public_path", over(240))},
		{"health path", "/sites/7/php-application", withFormValue(configureBase(), "health_path", over(240))},
		{"shared path", "/sites/7/php-application", withFormValue(configureBase(), "shared_path", over(240))},
		{"composer install", "/sites/7/php-application", withFormValue(configureBase(), "composer_install", over(5))},
		{"composer scripts", "/sites/7/php-application", withFormValue(configureBase(), "composer_allow_scripts", over(5))},
		{"composer plugins", "/sites/7/php-application", withFormValue(configureBase(), "composer_allow_plugins", over(5))},
		{"deployment revision", "/sites/7/php-application/deployments", url.Values{"revision": {over(128)}}},
		{"environment name", "/sites/7/php-application/environment", url.Values{"name": {over(128)}, "value": {"safe"}}},
		{"environment plain value", "/sites/7/php-application/environment", url.Values{"name": {"APP_ENV"}, "value": {over(maxPHPEnvironmentValue)}}},
		{"environment secret value", "/sites/7/php-application/environment", url.Values{"name": {"APP_KEY"}, "secret": {"true"}, "secret_value": {over(maxPHPEnvironmentValue)}}},
		{"environment secret flag", "/sites/7/php-application/environment", url.Values{"name": {"APP_KEY"}, "secret": {over(5)}, "secret_value": {"safe"}}},
		{"delete environment name", "/sites/7/php-application/environment/delete", url.Values{"name": {over(128)}, "confirm": {"delete"}}},
		{"worker name", "/sites/7/php-application/workers", url.Values{"name": {over(48)}, "script": {"artisan"}, "processes": {"1"}, "desired_state": {"running"}}},
		{"worker script", "/sites/7/php-application/workers", url.Values{"name": {"queue"}, "script": {over(240)}, "processes": {"1"}, "desired_state": {"running"}}},
		{"worker desired state", "/sites/7/php-application/workers", url.Values{"name": {"queue"}, "script": {"artisan"}, "processes": {"1"}, "desired_state": {over(16)}}},
		{"worker argument", "/sites/7/php-application/workers", url.Values{"name": {"queue"}, "script": {"artisan"}, "processes": {"1"}, "desired_state": {"running"}, "argument": {over(4096)}}},
		{"worker state", "/sites/7/php-application/workers/51/state", url.Values{"state": {over(16)}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakePHPApplicationService{}
			workspace := &fakeWorkspaceService{}
			handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{PHPApplications: service, Workspace: workspace})
			cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
			req := httptest.NewRequest(http.MethodPost, "https://panel.test"+tc.path, strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Nakpanel-SPA", "true")
			addAuthenticatedCookie(req, cookie)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest || service.called != "" {
				t.Fatalf("overlong scalar = %d call=%q body=%s", rec.Code, service.called, rec.Body.String())
			}
			combined := rec.Body.String() + fmt.Sprint(rec.Header())
			for _, audit := range workspace.audits {
				combined += string(audit.Metadata)
			}
			if strings.Contains(combined, marker) {
				t.Fatalf("overlong scalar echoed: headers=%v body=%s audits=%#v", rec.Header(), rec.Body.String(), workspace.audits)
			}
		})
	}
}

func TestPHPApplicationRawListLimitsRejectBeforeServiceWithoutEcho(t *testing.T) {
	const marker = "L7NX"
	configureBase := func() url.Values {
		return url.Values{"hosting_mode": {"managed"}, "php_version": {"8.4"}, "repository_id": {"12"},
			"repository_ref": {"main"}, "framework_profile": {"plain"}, "health_path": {"/"}, "release_retention": {"4"}}
	}
	workerBase := func() url.Values {
		return url.Values{"name": {"queue"}, "script": {"artisan"}, "processes": {"1"}, "desired_state": {"running"}}
	}
	sharedDuplicate := configureBase()
	sharedDuplicate["shared_paths"] = []string{"storage", marker}
	argumentDuplicate := workerBase()
	argumentDuplicate["arguments"] = []string{"--safe", marker}
	tests := []struct {
		name string
		path string
		form url.Values
	}{
		{"whitespace shared item", "/sites/7/php-application", withFormValue(configureBase(), "shared_path", strings.Repeat(" ", 241))},
		{"whitespace worker argument", "/sites/7/php-application/workers", withFormValue(workerBase(), "argument", strings.Repeat(" ", 4097))},
		{"oversized shared textarea", "/sites/7/php-application", withFormValue(configureBase(), "shared_paths", strings.Repeat(" \n", 1921)+marker)},
		{"oversized arguments textarea", "/sites/7/php-application/workers", withFormValue(workerBase(), "arguments", strings.Repeat(" \n", 16385)+marker)},
		{"duplicate shared textarea", "/sites/7/php-application", sharedDuplicate},
		{"duplicate arguments textarea", "/sites/7/php-application/workers", argumentDuplicate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakePHPApplicationService{}
			workspace := &fakeWorkspaceService{}
			handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{PHPApplications: service, Workspace: workspace})
			cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
			req := httptest.NewRequest(http.MethodPost, "https://panel.test"+tc.path, strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Nakpanel-SPA", "true")
			addAuthenticatedCookie(req, cookie)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest || service.called != "" {
				t.Fatalf("raw list bound = %d call=%q body=%s", rec.Code, service.called, rec.Body.String())
			}
			combined := rec.Body.String() + fmt.Sprint(rec.Header())
			for _, audit := range workspace.audits {
				combined += string(audit.Metadata)
			}
			if strings.Contains(combined, marker) || len(workspace.audits) != 0 {
				t.Fatalf("raw list input echoed/audited: headers=%v body=%s audits=%#v", rec.Header(), rec.Body.String(), workspace.audits)
			}
		})
	}
}

func withFormValue(form url.Values, name, value string) url.Values {
	form.Set(name, value)
	return form
}

func TestPHPApplicationAcceptsFormCSRFAndRejectsUnconfiguredService(t *testing.T) {
	service := &fakePHPApplicationService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{PHPApplications: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	dummy := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/php-application/reconcile", nil)
	dummy.AddCookie(cookie)
	form := url.Values{"csrf_token": {csrfToken(dummy)}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/php-application/reconcile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || service.called != "reconcile" {
		t.Fatalf("form CSRF = %d call=%q body=%s", rec.Code, service.called, rec.Body.String())
	}

	handler, _ = newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{})
	cookie = login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/php-application/reconcile", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "unconfigured") {
		t.Fatalf("unconfigured mutation = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPHPApplicationSecretIsNeverReturnedOrAudited(t *testing.T) {
	const secret = "distinctive-secret-value-934"
	service := &fakePHPApplicationService{}
	workspace := &fakeWorkspaceService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{PHPApplications: service, Workspace: workspace})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	form := url.Values{"name": {"APP_KEY"}, "secret": {"true"}, "secret_value": {secret}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/php-application/environment", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Nakpanel-SPA", "true")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || service.environment.Value != secret || !service.environment.Secret {
		t.Fatalf("secret write = %d input=%#v", rec.Code, service.environment)
	}
	combined := rec.Body.String() + rec.Header().Get("Location")
	for _, audit := range workspace.audits {
		combined += string(audit.Metadata)
	}
	if strings.Contains(combined, secret) || rec.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("secret leaked or response cacheable: headers=%v body=%s audits=%#v", rec.Header(), rec.Body.String(), workspace.audits)
	}

	service.called = ""
	form = url.Values{"name": {"APP_KEY"}, "secret": {"true"}, "secret_value": {secret}, "value": {"plain"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/php-application/environment", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || service.called != "" || strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("mixed secret/plain = %d call=%q body=%s", rec.Code, service.called, rec.Body.String())
	}
}

func TestSanitizedPHPWorkspaceClearsDefensiveSecretValues(t *testing.T) {
	const secret = "must-not-enter-rendered-view"
	workspace := sanitizedPHPWorkspace(controlphpapp.Workspace{Environment: []types.PHPEnvironmentVariable{
		{Name: "SAFE", Value: "visible"}, {Name: "SECRET", Value: secret, SecretID: 9},
	}})
	if workspace.Environment[0].Value != "visible" || workspace.Environment[1].Value != "" {
		t.Fatalf("sanitized environment = %#v", workspace.Environment)
	}
}

func TestPHPApplicationErrorsAreMappedWithoutDetails(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{controlphpapp.ErrNotFound, http.StatusNotFound},
		{controlphpapp.ErrInactive, http.StatusConflict},
		{controlphpapp.ErrRuntimeUnavailable, http.StatusConflict},
		{controlphpapp.ErrRevisionConflict, http.StatusConflict},
		{controlphpapp.ErrInvalidInput, http.StatusBadRequest},
		{controlquota.ErrExceeded, http.StatusBadRequest},
		{errors.New("database password=never-render"), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		service := &fakePHPApplicationService{err: tc.err}
		handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{PHPApplications: service})
		cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
		req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/php-application/deployments", strings.NewReader("revision=main"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Nakpanel-SPA", "true")
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want || strings.Contains(rec.Body.String(), "password") || strings.Contains(rec.Body.String(), tc.err.Error()) {
			t.Fatalf("error %v = %d body=%s", tc.err, rec.Code, rec.Body.String())
		}
	}
}

func TestParsePlanIncludesPHPHostingV4Fields(t *testing.T) {
	form := url.Values{
		"name": {"Managed PHP"}, "allow_composer": {"true"}, "allow_composer_code_execution": {"true"},
		"allow_managed_php_deployments": {"true"}, "allow_php_workers": {"true"},
		"allow_wordpress_toolkit": {"true"}, "max_wordpress_sites": {"3"},
		"max_php_workers": {"4"}, "max_php_releases_unlimited": {"true"},
	}
	req := httptest.NewRequest(http.MethodPost, "/plans", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	plan, err := parsePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	permissions := plan.HostingPolicy.Permissions
	if plan.HostingPolicy.SchemaVersion != 5 || !permissions.Composer || !permissions.ComposerCodeExecution ||
		!permissions.ManagedPHPDeployments || !permissions.PHPWorkers || plan.HostingPolicy.Resources.MaxPHPWorkers != 4 ||
		!permissions.WordPressToolkit || plan.HostingPolicy.Resources.MaxWordPressSites != 3 ||
		plan.HostingPolicy.Resources.MaxPHPReleases != -1 {
		t.Fatalf("v4 hosting policy not parsed: %#v", plan.HostingPolicy)
	}
}

func TestApplyResellerPHPHostingFieldsIncludesPhase30Ceilings(t *testing.T) {
	form := url.Values{
		"allow_composer":                {"true"},
		"allow_composer_code_execution": {"true"},
		"allow_managed_php_deployments": {"true"},
		"allow_php_workers":             {"true"},
		"allow_wordpress_toolkit":       {"true"},
		"max_php_workers":               {"6"},
		"max_php_releases_unlimited":    {"true"},
		"max_wordpress_sites":           {"8"},
	}
	req := httptest.NewRequest(http.MethodPost, "/reseller-plans", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	var policy types.HostingPolicy
	if err := applyResellerPHPHostingFields(req, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.SchemaVersion != 4 || !policy.Permissions.Composer ||
		!policy.Permissions.ComposerCodeExecution || !policy.Permissions.ManagedPHPDeployments ||
		!policy.Permissions.PHPWorkers || policy.Resources.MaxPHPWorkers != 6 ||
		!policy.Permissions.WordPressToolkit || policy.Resources.MaxWordPressSites != 8 ||
		policy.Resources.MaxPHPReleases != -1 {
		t.Fatalf("phase 32 reseller ceilings not parsed: %#v", policy)
	}
}
