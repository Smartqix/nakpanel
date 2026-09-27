package panelhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlwordpress "github.com/nakroteck/nakpanel/internal/control/wordpress"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeWordPressService struct {
	workspace      controlwordpress.Workspace
	err            error
	preflightErr   error
	preflightCalls int
	called         string
	actor          auth.SessionUser
	siteID         int64
	install        controlwordpress.InstallInput
	operation      controlwordpress.OperationInput
	uninstall      controlwordpress.UninstallInput
	detach         bool
}

func (f *fakeWordPressService) PreflightNewSite(context.Context, auth.SessionUser, int64) error {
	f.preflightCalls++
	return f.preflightErr
}

func (f *fakeWordPressService) Workspace(_ context.Context, actor auth.SessionUser, siteID int64) (controlwordpress.Workspace, error) {
	f.called, f.actor, f.siteID = "workspace", actor, siteID
	return f.workspace, f.err
}

func (f *fakeWordPressService) Install(_ context.Context, actor auth.SessionUser, siteID int64, input controlwordpress.InstallInput) (controlwordpress.Instance, controlwordpress.Operation, error) {
	f.called, f.actor, f.siteID, f.install = "install", actor, siteID, input
	return controlwordpress.Instance{ID: 31, SiteID: siteID}, controlwordpress.Operation{ID: 41, Status: "pending"}, f.err
}

func (f *fakeWordPressService) QueueOperation(_ context.Context, actor auth.SessionUser, siteID int64, input controlwordpress.OperationInput) (controlwordpress.Operation, error) {
	f.called, f.actor, f.siteID, f.operation = "operation", actor, siteID, input
	return controlwordpress.Operation{ID: 42, Status: "pending"}, f.err
}

func (f *fakeWordPressService) Detach(_ context.Context, actor auth.SessionUser, siteID int64) error {
	f.called, f.actor, f.siteID, f.detach = "detach", actor, siteID, true
	return f.err
}

func (f *fakeWordPressService) Uninstall(_ context.Context, actor auth.SessionUser, siteID int64, input controlwordpress.UninstallInput) (controlwordpress.Operation, error) {
	f.called, f.actor, f.siteID, f.uninstall = "uninstall", actor, siteID, input
	return controlwordpress.Operation{ID: 43, Status: "waiting_backup", BackupID: 44}, f.err
}

func wordpressHTTPDashboard() dashboard.Data {
	return dashboard.Data{
		Sites:         []dashboard.Site{{ID: 7, Domain: "owned.test", Status: "active", DesiredStatus: "active", CustomerID: 88, SubscriptionID: 20}},
		Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, SubscriptionName: "Production", PlanName: "WordPress Pro", Status: "active"}},
		Customers:     []types.Customer{{ID: 88, DisplayName: "Owned customer", Email: "owner@owned.test", Status: "active"}},
	}
}

func TestWordPressWorkspaceLoadsOnlyAfterScopedSiteVisibility(t *testing.T) {
	service := &fakeWordPressService{workspace: controlwordpress.Workspace{Available: true, Policy: types.HostingPolicy{SchemaVersion: 4, Permissions: types.HostingPermissionPolicy{WordPressToolkit: true}, Resources: types.HostingResourcePolicy{MaxWordPressSites: 2}}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: &fakeDashboardReader{data: wordpressHTTPDashboard()}, WordPress: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/wordpress?wp_tab=security", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || service.called != "workspace" || service.siteID != 7 || !strings.Contains(rec.Body.String(), "WordPress Toolkit") {
		t.Fatalf("workspace = %d call=%q site=%d body=%s", rec.Code, service.called, service.siteID, rec.Body.String())
	}

	service.called = ""
	req = httptest.NewRequest(http.MethodGet, "https://panel.test/sites/8/wordpress", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || service.called != "" {
		t.Fatalf("cross-tenant workspace = %d call=%q", rec.Code, service.called)
	}
}

func TestWordPressInstallAndOperationsUseTypedInputsAndPRG(t *testing.T) {
	service := &fakeWordPressService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{WordPress: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	form := url.Values{"site_title": {"Owned site"}, "admin_user": {"siteadmin"}, "admin_email": {"admin@owned.test"}, "admin_password": {"a-secure-password-123"}, "version": {"latest"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/install", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sites/7/wordpress?notice=wordpress-install-queued" || service.called != "install" {
		t.Fatalf("install = %d location=%q call=%q body=%s", rec.Code, rec.Header().Get("Location"), service.called, rec.Body.String())
	}
	if service.install.AdminPassword != "a-secure-password-123" || service.install.AdminUser != "siteadmin" {
		t.Fatalf("install input = %#v", service.install)
	}
	if strings.Contains(rec.Body.String()+rec.Header().Get("Location"), service.install.AdminPassword) || rec.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("install secret leaked or response is cacheable: headers=%v body=%s", rec.Header(), rec.Body.String())
	}

	service.called = ""
	form = url.Values{"action": {"update"}, "target_type": {"plugin"}, "target_slug": {"akismet"}, "confirm": {"update"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/operations", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Nakpanel-SPA", "true")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || service.called != "operation" || service.operation.Action != types.WordPressActionUpdate || service.operation.TargetSlug != "akismet" {
		t.Fatalf("update = %d call=%q input=%#v body=%s", rec.Code, service.called, service.operation, rec.Body.String())
	}
}

func TestWordPressMutationsRejectCSRFConfirmationBoundsAndSecrets(t *testing.T) {
	service := &fakeWordPressService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{WordPress: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/operations", strings.NewReader("action=refresh"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || service.called != "" {
		t.Fatalf("missing CSRF = %d call=%q", rec.Code, service.called)
	}

	form := url.Values{"action": {"update"}, "target_type": {"all"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/operations", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sites/7/wordpress?notice=wordpress-input-error" || service.called != "" {
		t.Fatalf("missing confirmation = %d location=%q call=%q body=%s", rec.Code, rec.Header().Get("Location"), service.called, rec.Body.String())
	}

	service.called = ""
	form = url.Values{"action": {"update"}, "target_type": {"plugin"}, "target_slug": {strings.Repeat("a", 129)}, "confirm": {"update"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/operations", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sites/7/wordpress?notice=wordpress-input-error" || service.called != "" {
		t.Fatalf("oversized slug = %d location=%q call=%q", rec.Code, rec.Header().Get("Location"), service.called)
	}

	const secret = "distinct-wordpress-secret-947"
	service.err = errors.New("operation failed with " + secret)
	form = url.Values{"action": {"password_reset"}, "admin_password": {secret}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/operations", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Nakpanel-SPA", "true")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String()+rec.Header().Get("Location"), secret) {
		t.Fatalf("secret error response = %d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
}

func TestWordPressDetachRequiresConfirmationAndPreservesPRG(t *testing.T) {
	service := &fakeWordPressService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{WordPress: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	for _, test := range []struct {
		form url.Values
		want int
		call bool
	}{{url.Values{}, http.StatusSeeOther, false}, {url.Values{"confirm": {"detach"}}, http.StatusSeeOther, true}} {
		service.called, service.detach = "", false
		req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/detach", strings.NewReader(test.form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != test.want || service.detach != test.call {
			t.Fatalf("detach form=%v status=%d call=%v body=%s", test.form, rec.Code, service.detach, rec.Body.String())
		}
		wantLocation := "/sites/7/wordpress?notice=wordpress-input-error"
		if test.call {
			wantLocation = "/sites/7/wordpress?notice=wordpress-detached"
		}
		if rec.Header().Get("Location") != wantLocation {
			t.Fatalf("detach redirect = %q, want %q", rec.Header().Get("Location"), wantLocation)
		}
	}
}

func TestWordPressUninstallEnhancedResponseIsQueuedAndSecretFree(t *testing.T) {
	service := &fakeWordPressService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{WordPress: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	form := url.Values{"create_backup": {"true"}, "delete_database": {"true"}, "confirm_domain": {"owned.test"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/uninstall", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Nakpanel-SPA", "true")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || service.called != "uninstall" || !service.uninstall.CreateBackup ||
		!service.uninstall.DeleteDatabase || service.uninstall.ConfirmDomain != "owned.test" {
		t.Fatalf("uninstall = %d call=%q input=%#v body=%s", rec.Code, service.called, service.uninstall, rec.Body.String())
	}
	for _, forbidden := range []string{"db_name", "db_user", "archive_path", "password", "/home/"} {
		if strings.Contains(strings.ToLower(rec.Body.String()), forbidden) {
			t.Fatalf("uninstall response exposed %q: %s", forbidden, rec.Body.String())
		}
	}
}

func TestWordPressUninstallUsesPRGAndRequiresCSRF(t *testing.T) {
	service := &fakeWordPressService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{WordPress: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	form := url.Values{"create_backup": {"true"}, "confirm_domain": {"owned.test"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/uninstall", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || service.called != "" {
		t.Fatalf("missing CSRF = %d call=%q", rec.Code, service.called)
	}

	req = httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/uninstall", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sites/7/wordpress?notice=wordpress-uninstall-queued" {
		t.Fatalf("uninstall PRG = %d location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
}

func TestWordPressNativeErrorsReturnToWorkspaceWithSafeNotice(t *testing.T) {
	service := &fakeWordPressService{err: controlwordpress.ErrLimitReached}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{WordPress: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	form := url.Values{"site_title": {"Owned site"}, "admin_user": {"siteadmin"}, "admin_email": {"admin@owned.test"}, "admin_password": {"a-secure-password-123"}, "version": {"latest"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/install", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sites/7/wordpress?notice=wordpress-limit-reached" {
		t.Fatalf("native error = %d location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/install", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Nakpanel-SPA", "true")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "WordPress site limit") {
		t.Fatalf("enhanced error = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWordPressSupportViewKeepsScopedMutationContext(t *testing.T) {
	service := &fakeWordPressService{workspace: controlwordpress.Workspace{Available: true}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{
		DashboardReader: &fakeDashboardReader{data: wordpressHTTPDashboard()},
		WordPress:       service,
	})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/support/customers/88/sites/7/wordpress?notice=wordpress-limit-reached", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="support_customer_id" value="88"`) ||
		!strings.Contains(rec.Body.String(), "reached its WordPress site limit") || !strings.Contains(rec.Body.String(), "np-notice-error") {
		t.Fatalf("support workspace = %d body=%s", rec.Code, rec.Body.String())
	}

	form := url.Values{"action": {"refresh"}, "support_customer_id": {"88"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/operations", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/support/customers/88/sites/7/wordpress?notice=wordpress-operation-queued" || service.called != "operation" {
		t.Fatalf("support mutation = %d location=%q call=%q", rec.Code, rec.Header().Get("Location"), service.called)
	}

	service.called = ""
	form.Set("support_customer_id", "99")
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/wordpress/operations", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || service.called != "" {
		t.Fatalf("cross-customer support mutation = %d call=%q", rec.Code, service.called)
	}
}
