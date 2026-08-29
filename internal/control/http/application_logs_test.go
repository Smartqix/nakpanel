package panelhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeApplicationLogReader struct {
	request types.ApplicationLogReq
	result  types.ApplicationLogResult
	called  bool
}

func (r *fakeApplicationLogReader) ReadApplicationLog(_ context.Context, request types.ApplicationLogReq) (types.ApplicationLogResult, error) {
	r.request = request
	r.called = true
	return r.result, nil
}

func TestContainerLogsUseScopedSiteIdentityAndBounds(t *testing.T) {
	reader := &fakeDashboardReader{data: dashboard.Data{
		Sites: []dashboard.Site{{
			ID: 7, Username: "npowned", Domain: "owned.test", SubscriptionID: 20, CustomerID: 88,
		}},
		SubscriptionServices: dashboard.SubscriptionServicesData{
			Applications: []dashboard.Application{{
				ID: 41, SiteID: 7, SubscriptionID: 20, Runtime: "oci", Name: "owned-app",
			}},
		},
	}}
	logs := &fakeApplicationLogReader{result: types.ApplicationLogResult{
		Lines: []string{"ready"}, Truncated: true,
	}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{
		DashboardReader: reader, ApplicationLogs: logs,
	})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/containers/41/logs?lines=50&bytes=4096", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("container logs status = %d: %s", rec.Code, rec.Body.String())
	}
	if !logs.called || logs.request.ApplicationID != 41 || logs.request.SubscriptionID != 20 ||
		logs.request.Username != "npowned" || logs.request.Lines != 50 || logs.request.Bytes != 4096 {
		t.Fatalf("application log request = %#v", logs.request)
	}
	if !strings.Contains(rec.Body.String(), `"ready"`) || !strings.Contains(rec.Body.String(), `"truncated":true`) {
		t.Fatalf("container log response = %s", rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestContainerLogsHideCrossTenantApplication(t *testing.T) {
	reader := &fakeDashboardReader{data: dashboard.Data{
		Sites: []dashboard.Site{{
			ID: 7, Username: "npowned", Domain: "owned.test", SubscriptionID: 20, CustomerID: 88,
		}},
		SubscriptionServices: dashboard.SubscriptionServicesData{
			Applications: []dashboard.Application{{
				ID: 41, SiteID: 7, SubscriptionID: 20, Runtime: "oci",
			}},
		},
	}}
	logs := &fakeApplicationLogReader{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{
		DashboardReader: reader, ApplicationLogs: logs,
	})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/containers/99/logs", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant container logs status = %d, want 404", rec.Code)
	}
	if logs.called {
		t.Fatal("agent was called for a hidden container")
	}
}
