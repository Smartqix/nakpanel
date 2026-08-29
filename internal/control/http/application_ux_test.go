package panelhttp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func applicationWorkspaceData() dashboard.Data {
	policy := types.HostingPolicy{SchemaVersion: 2}
	policy.Permissions.Applications = true
	policy.Permissions.CustomOCIImages = true
	policy.Applications.Rootless = true
	policy.Applications.AllowedRuntimes = []string{"oci"}
	policy.Applications.AllowedRegistries = []string{"docker.io"}
	policy.Resources.MaxApplications = 3
	policy.Resources.ContainerStorageMB = 4096
	policy.Resources.MemoryMB = 512
	policy.Resources.CPUPercent = 100
	return dashboard.Data{
		Sites: []dashboard.Site{{
			ID: 31, Domain: "app-owned.test", Status: "active", SubscriptionID: 20, CustomerID: 88,
		}},
		Subscriptions: []types.SubscriptionSummary{{
			ID: 20, CustomerID: 88, CustomerName: "App Owner", SubscriptionName: "App Hosting", Status: "active",
		}},
		SubscriptionServices: dashboard.SubscriptionServicesData{
			SitePolicies: []dashboard.SitePolicy{{
				SiteID: 31, SubscriptionID: 20, EffectivePolicy: policy,
			}},
		},
	}
}

func TestContainerWorkspaceRendersUsableDeploymentDialog(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{
		DashboardReader: &fakeDashboardReader{data: applicationWorkspaceData()},
	})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/31/containers", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("container workspace status = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, marker := range []string{
		`class="np-dialog-form np-container-deploy-form"`,
		`aria-labelledby="deploy-container-title"`,
		`name="volume_name"`,
		`name="volume_target"`,
		`name="volume_size_mb"`,
		`data-np-container-route`,
		`data-np-container-health`,
		`Subscription container limits`,
		`>Deploy container</button>`,
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("container workspace missing %q:\n%s", marker, body)
		}
	}
	if strings.Contains(body, "Review and deploy") {
		t.Fatalf("container dialog promises a review step that does not exist:\n%s", body)
	}
}

func TestApplicationFormCarriesStructuredPersistentVolume(t *testing.T) {
	services := &fakeMailDomainServices{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DomainManager: services})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	form := url.Values{
		"site_id": {"31"}, "name": {"demo-app"}, "runtime": {"oci"},
		"image_ref":     {"docker.io/example/app@sha256:" + strings.Repeat("a", 64)},
		"desired_state": {"running"}, "route_mode": {"prefix"}, "route_prefix": {"/demo/"},
		"container_port": {"8080"}, "health_kind": {"http"}, "health_path": {"/healthz"},
		"health_timeout_seconds": {"30"}, "environment": {`{"APP_ENV":"production"}`},
		"volume_name": {"data"}, "volume_target": {"/var/lib/application"}, "volume_size_mb": {"1024"},
		"volume_read_only": {"true"}, "return_to": {"site-containers"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/subscriptions/20/applications", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther || !services.appCalled || services.subscriptionID != 20 {
		t.Fatalf("application form status=%d called=%v subscription=%d body=%s", rec.Code, services.appCalled, services.subscriptionID, rec.Body.String())
	}
	if len(services.application.Volumes) != 1 {
		t.Fatalf("application volumes = %#v", services.application.Volumes)
	}
	volume := services.application.Volumes[0]
	if volume.Name != "data" || volume.Target != "/var/lib/application" || volume.SizeMB != 1024 || !volume.ReadOnly {
		t.Fatalf("application volume = %#v", volume)
	}
}

func TestApplicationFormRejectsPartialPersistentVolume(t *testing.T) {
	services := &fakeMailDomainServices{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DomainManager: services})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	form := url.Values{"volume_name": {"data"}, "volume_size_mb": {"1024"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/subscriptions/20/applications", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || services.appCalled {
		t.Fatalf("partial volume status=%d called=%v body=%s", rec.Code, services.appCalled, rec.Body.String())
	}
}
