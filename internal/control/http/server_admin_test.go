package panelhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

type phase26ServerAdminFake struct {
	inventory     types.ServerInventory
	inspectErr    error
	inspectCalls  int
	controlReq    types.ControlManagedServiceReq
	controlResult types.ControlManagedServiceResult
	controlErr    error
	controlCalls  int
}

func (f *phase26ServerAdminFake) InspectServer(context.Context) (types.ServerInventory, error) {
	f.inspectCalls++
	return f.inventory, f.inspectErr
}

func (f *phase26ServerAdminFake) ControlManagedService(_ context.Context, req types.ControlManagedServiceReq) (types.ControlManagedServiceResult, error) {
	f.controlCalls++
	f.controlReq = req
	return f.controlResult, f.controlErr
}

func TestServerInventoryJSONContractIsAdminOnly(t *testing.T) {
	checkedAt := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	admin := &phase26ServerAdminFake{inventory: types.ServerInventory{
		Hostname: "panel.test", Status: types.ServerStateHealthy, CheckedAt: checkedAt,
	}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{ServerAdmin: admin})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/inventory", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET inventory = %d; body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		OK        bool                  `json:"ok"`
		Inventory types.ServerInventory `json:"inventory"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode inventory response: %v", err)
	}
	if !response.OK || response.Inventory.Hostname != "panel.test" || admin.inspectCalls != 1 {
		t.Fatalf("inventory response = %#v, calls=%d", response, admin.inspectCalls)
	}

	clientAdmin := &phase26ServerAdminFake{}
	clientHandler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{ServerAdmin: clientAdmin})
	clientCookie := login(t, clientHandler, "client@nakpanel.test", "NakpanelClient!2026")
	req = httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/inventory", nil)
	addAuthenticatedCookie(req, clientCookie)
	rec = httptest.NewRecorder()
	clientHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || clientAdmin.inspectCalls != 0 {
		t.Fatalf("client inventory = %d, calls=%d; want 403, 0", rec.Code, clientAdmin.inspectCalls)
	}
}

func TestServerInventoryFailureDoesNotExposeAgentError(t *testing.T) {
	admin := &phase26ServerAdminFake{inspectErr: errors.New("agent secret: " + strings.Repeat("x", 4096))}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{ServerAdmin: admin})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/status", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("GET status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "agent secret") || len(rec.Body.String()) > 256 {
		t.Fatalf("inventory error was not safely bounded: %q", rec.Body.String())
	}
}

func TestServerInventoryReturnsSafeCachedFallback(t *testing.T) {
	admin := &phase26ServerAdminFake{
		inventory: types.ServerInventory{
			Hostname: "cached.test", Status: types.ServerStateUnknown,
		},
		inspectErr: serveradmin.ErrInventoryCacheFallback,
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{ServerAdmin: admin})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/status", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET cached status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		OK        bool                  `json:"ok"`
		Cached    bool                  `json:"cached"`
		Inventory types.ServerInventory `json:"inventory"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || !response.Cached || response.Inventory.Hostname != "cached.test" {
		t.Fatalf("cached response = %#v", response)
	}
}

func TestInventoryRefreshRequiresCSRF(t *testing.T) {
	admin := &phase26ServerAdminFake{inventory: types.ServerInventory{Status: types.ServerStateHealthy}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{ServerAdmin: admin})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/inventory/refresh", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || admin.inspectCalls != 0 {
		t.Fatalf("refresh without CSRF = %d, calls=%d", rec.Code, admin.inspectCalls)
	}

	req = httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/inventory/refresh", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || admin.inspectCalls != 1 {
		t.Fatalf("refresh with CSRF = %d, calls=%d; body=%s", rec.Code, admin.inspectCalls, rec.Body.String())
	}
}

func TestManagedServiceActionUsesOnlyRegistryIdentifiers(t *testing.T) {
	admin := &phase26ServerAdminFake{controlResult: types.ControlManagedServiceResult{
		ServiceID: "web", Action: "reload", Changed: true,
	}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{ServerAdmin: admin})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	form := url.Values{"service_id": {"web"}, "action": {"reload"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/services/action", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("service action = %d; body=%s", rec.Code, rec.Body.String())
	}
	if admin.controlCalls != 1 || admin.controlReq.ServiceID != "web" || admin.controlReq.Action != "reload" ||
		!strings.HasPrefix(admin.controlReq.OperationID, "op_") || admin.controlReq.ActorUserID <= 0 {
		t.Fatalf("control request = %#v, calls=%d", admin.controlReq, admin.controlCalls)
	}

	for _, form := range []url.Values{
		{"service_id": {"../../nginx.service"}, "action": {"restart"}},
		{"service_id": {"web"}, "action": {"daemon-reload"}},
		{"service_id": {"web"}, "action": {"reload"}, "unit": {"nginx.service"}},
		{"service_id": {"web"}, "action": {"reload"}, "command": {"sh -c id"}},
	} {
		req = httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/services/action", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addAuthenticatedCookie(req, cookie)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("unsafe service action %#v = %d; body=%s", form, rec.Code, rec.Body.String())
		}
	}
	if admin.controlCalls != 1 {
		t.Fatalf("unsafe inputs invoked service controller: calls=%d", admin.controlCalls)
	}
}

func TestServiceRestartAndStopRequireRecentPasswordReauthentication(t *testing.T) {
	admin := &phase26ServerAdminFake{}
	handler, sessions := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{ServerAdmin: admin})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	sessions.user.AuthenticatedAt = time.Date(2026, 7, 7, 11, 49, 0, 0, time.UTC)

	var req *http.Request
	var rec *httptest.ResponseRecorder
	for _, action := range []string{"restart", "stop"} {
		form := url.Values{"service_id": {"web"}, "action": {action}}
		req = httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/services/action", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addAuthenticatedCookie(req, cookie)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusPreconditionRequired || admin.controlCalls != 0 {
			t.Fatalf("stale service %s = %d, calls=%d; body=%s", action, rec.Code, admin.controlCalls, rec.Body.String())
		}
	}

	reauthForm := url.Values{"password": {"NakpanelAdmin!2026"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/reauthenticate", strings.NewReader(reauthForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reauthenticate = %d; body=%s", rec.Code, rec.Body.String())
	}

	stopForm := url.Values{"service_id": {"web"}, "action": {"stop"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/services/action", strings.NewReader(stopForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || admin.controlCalls != 1 {
		t.Fatalf("recent service stop = %d, calls=%d; body=%s", rec.Code, admin.controlCalls, rec.Body.String())
	}
}

func TestCustomerCanReauthenticateForProtectedDomainChanges(t *testing.T) {
	handler, sessions := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	sessions.user.AuthenticatedAt = time.Date(2026, 7, 7, 11, 49, 0, 0, time.UTC)

	form := url.Values{"password": {"NakpanelClient!2026"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/reauthenticate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("customer reauthenticate = %d; body=%s", rec.Code, rec.Body.String())
	}
	if !sessions.RecentlyAuthenticated(sessions.user, 10*time.Minute) {
		t.Fatal("customer session was not marked recently authenticated")
	}
}

func TestServerReauthenticationThrottlesAndAuditsFailures(t *testing.T) {
	workspace := &fakeWorkspaceService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{Workspace: workspace})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	for attempt := 1; attempt <= reauthenticationFailureLimit; attempt++ {
		form := url.Values{"password": {"definitely-wrong"}}
		req := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/reauthenticate", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		want := http.StatusUnauthorized
		if attempt == reauthenticationFailureLimit {
			want = http.StatusTooManyRequests
			if rec.Header().Get("Retry-After") == "" {
				t.Fatal("locked reauthentication omitted Retry-After")
			}
		}
		if rec.Code != want {
			t.Fatalf("failed reauthentication %d = %d; body=%s", attempt, rec.Code, rec.Body.String())
		}
	}

	form := url.Values{"password": {"NakpanelAdmin!2026"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/reauthenticate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked correct password = %d; body=%s", rec.Code, rec.Body.String())
	}

	failures := 0
	for _, event := range workspace.audits {
		if event.Action == "server.reauthentication_failed" {
			failures++
		}
	}
	if failures != reauthenticationFailureLimit {
		t.Fatalf("reauthentication failure audits = %d, want %d", failures, reauthenticationFailureLimit)
	}
}

func TestFocusedServerAdminWorkspacesReuseAdminSettingsPage(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	for _, path := range []string{
		"/tools-settings/server",
		"/tools-settings/php",
		"/tools-settings/security",
		"/tools-settings/services",
		"/tools-settings/updates",
		"/tools-settings/logs",
		"/tools-settings/mail",
		"/tools-settings/databases",
		"/tools-settings/applications",
		"/tools-settings/operations",
	} {
		req := httptest.NewRequest(http.MethodGet, "https://panel.test"+path, nil)
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Tools &amp; Settings") {
			t.Fatalf("GET %s = %d; body=%s", path, rec.Code, rec.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/services", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, marker := range []string{
		"Service inventory summary",
		"Protected service controls",
		"data-np-service-refresh",
		"data-np-focus-services",
	} {
		if rec.Code != http.StatusOK || !strings.Contains(body, marker) {
			t.Fatalf("managed services page missing %q: status=%d; body=%s", marker, rec.Code, body)
		}
	}
	req = httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/updates", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body = rec.Body.String()
	for _, marker := range []string{
		"Update inventory summary",
		"Protected update controls",
		"data-np-update-search",
		"data-np-update-select-all",
		"data-np-update-install-form",
	} {
		if rec.Code != http.StatusOK || !strings.Contains(body, marker) {
			t.Fatalf("system updates page missing %q: status=%d; body=%s", marker, rec.Code, body)
		}
	}

	resellerHandler, _ := newTestHandlerWithOptions(t, auth.RoleReseller, ServerOptions{})
	resellerCookie := login(t, resellerHandler, "reseller@nakpanel.test", "NakpanelReseller!2026")
	req = httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/services", nil)
	addAuthenticatedCookie(req, resellerCookie)
	rec = httptest.NewRecorder()
	resellerHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("reseller focused workspace = %d, want 403", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "https://panel.test/tools-utilities", nil)
	addAuthenticatedCookie(req, resellerCookie)
	rec = httptest.NewRecorder()
	resellerHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Tools &amp; Utilities") ||
		strings.Contains(rec.Body.String(), "Service Management") {
		t.Fatalf("reseller utilities = %d; body=%s", rec.Code, rec.Body.String())
	}
}
