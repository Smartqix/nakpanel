package panelhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeSetupCreator struct {
	*fakeSiteCreator
	setup    types.SiteSetupStatus
	setupErr error
	retryErr error
	retries  int
}

func setupTestHandler(t *testing.T, role auth.Role, creator *fakeSetupCreator) (http.Handler, *http.Cookie) {
	t.Helper()
	handler, _ := newTestHandlerWithOptions(t, role, ServerOptions{SiteCreator: creator})
	email, password := "admin@nakpanel.test", "NakpanelAdmin!2026"
	if role == auth.RoleClient {
		email, password = "client@nakpanel.test", "NakpanelClient!2026"
	}
	if role == auth.RoleReseller {
		email, password = "reseller@nakpanel.test", "NakpanelReseller!2026"
	}
	return handler, login(t, handler, email, password)
}

func (f *fakeSetupCreator) SiteSetupStatus(_ context.Context, _ auth.SessionUser, _ int64) (types.SiteSetupStatus, error) {
	return f.setup, f.setupErr
}

func (f *fakeSetupCreator) RetryCreationSSLFor(_ context.Context, _ auth.SessionUser, _ int64) (int64, error) {
	f.retries++
	return f.setup.SiteID, f.retryErr
}

func TestSSLRetryFailurePreservesNonJavaScriptWorkspace(t *testing.T) {
	creator := &fakeSetupCreator{fakeSiteCreator: &fakeSiteCreator{}, setup: types.SiteSetupStatus{SiteID: 7, SubscriptionID: 20, Domain: "example.test", State: "failed"}, retryErr: errors.New("SSL setup is not awaiting retry")}
	handler, cookie := setupTestHandler(t, auth.RoleAdmin, creator)
	req := httptest.NewRequest("POST", "https://panel.test/sites/7/setup/retry-ssl", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 303 || rec.Header().Get("Location") != "/sites/7/setup" || creator.retries != 1 {
		t.Fatalf("retry response=%d location=%s calls=%d body=%s", rec.Code, rec.Header().Get("Location"), creator.retries, rec.Body.String())
	}
	var notice *http.Cookie
	for _, candidate := range rec.Result().Cookies() {
		if candidate.Name == FormErrorCookieName {
			notice = candidate
		}
	}
	if notice == nil {
		t.Fatal("no one-shot retry error")
	}
	get := httptest.NewRequest("GET", "https://panel.test/sites/7/setup", nil)
	get.AddCookie(cookie)
	get.AddCookie(notice)
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, get)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Could not retry SSL: SSL setup is not awaiting retry") || !strings.Contains(page.Body.String(), "data-np-setup-tracker") {
		t.Fatalf("retry error page=%d %s", page.Code, page.Body.String())
	}
	cleared := false
	for _, candidate := range page.Result().Cookies() {
		if candidate.Name == FormErrorCookieName && candidate.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("retry error cookie was not consumed")
	}
}

func TestSSLRetryEnhancedFailureAndSupportIsolation(t *testing.T) {
	creator := &fakeSetupCreator{fakeSiteCreator: &fakeSiteCreator{}, setup: types.SiteSetupStatus{SiteID: 7, SubscriptionID: 20, CustomerID: 88}, retryErr: errors.New("SSL setup is not awaiting retry")}
	handler, cookie := setupTestHandler(t, auth.RoleAdmin, creator)
	for _, path := range []string{"/sites/7/setup/retry-ssl", "/support/customers/99/sites/7/setup/retry-ssl"} {
		req := httptest.NewRequest("POST", "https://panel.test"+path, strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Nakpanel-SPA", "true")
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		want := 400
		if strings.Contains(path, "/support/") {
			want = 404
		}
		if rec.Code != want {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
	}
	if creator.retries != 1 {
		t.Fatalf("cross-customer retry reached service: %d", creator.retries)
	}
}

func (f *fakeSetupCreator) CreateSubdomainWithSSLFor(ctx context.Context, user auth.SessionUser, parent int64, label, php string, secure bool) (int64, error) {
	result, err := f.fakeSiteCreator.CreateSubdomainFor(ctx, user, parent, label, php)
	f.requests[len(f.requests)-1].SecureWithSSL = secure
	return result, err
}

func TestWebsiteSetupStatusAllowsOwnedRootAndCreationCarriesSSLChoice(t *testing.T) {
	creator := &fakeSetupCreator{fakeSiteCreator: &fakeSiteCreator{}, setup: types.SiteSetupStatus{SiteID: 7, SubscriptionID: 20, CustomerID: 88, Domain: "example.test", State: "pending"}}
	handler, cookie := setupTestHandler(t, auth.RoleAdmin, creator)
	req := httptest.NewRequest("GET", "https://panel.test/sites/7/setup/status", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("root setup status=%d", rec.Code)
	}
	for _, path := range []string{"/websites", "/sites/1/subdomains"} {
		form := "subscription_id=20&domain=example.test&website_type=php&label=blog&secure_with_ssl=true"
		req := httptest.NewRequest("POST", "https://panel.test"+path, strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Nakpanel-SPA", "true")
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 202 || !creator.requests[len(creator.requests)-1].SecureWithSSL || !strings.Contains(rec.Body.String(), `"status_url":"/sites/7/setup/status"`) {
			t.Fatalf("%s status=%d request=%#v response=%s", path, rec.Code, creator.requests, rec.Body.String())
		}
	}
}

func TestSubdomainSetupStatusIsScopedAndNeverCached(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller, auth.RoleClient} {
		t.Run(string(role), func(t *testing.T) {
			creator := &fakeSetupCreator{fakeSiteCreator: &fakeSiteCreator{}, setup: types.SiteSetupStatus{SiteID: 7, ParentID: 1, CustomerID: 88, Domain: "blog.example.test", State: "pending", Message: "Creating subdomain."}}
			handler, cookie := setupTestHandler(t, role, creator)
			req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/setup/status", nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"pending"`) || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
				t.Fatalf("status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "customer_id") {
				t.Fatal("status exposed internal ownership metadata")
			}
		})
	}
}

func TestSubdomainSetupStatusDeniesCrossTenantAndSupportScope(t *testing.T) {
	creator := &fakeSetupCreator{fakeSiteCreator: &fakeSiteCreator{}, setup: types.SiteSetupStatus{SiteID: 7, ParentID: 1, CustomerID: 88, Domain: "blog.example.test", State: "pending"}}
	handler, cookie := setupTestHandler(t, auth.RoleAdmin, creator)
	for _, path := range []string{"/support/customers/99/sites/7/setup/status", "/support/customers/99/sites/7/setup"} {
		req := httptest.NewRequest(http.MethodGet, "https://panel.test"+path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d", path, rec.Code)
		}
	}
	creator.setupErr = provision.ErrForbidden
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/setup/status", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross tenant status=%d", rec.Code)
	}
}

func TestSubdomainSetupPageWaitsWithoutJavaScriptAndStopsOnFailureOrTimeout(t *testing.T) {
	for _, tc := range []struct {
		state   string
		started time.Time
		refresh bool
	}{
		{"pending", time.Now(), true}, {"failed", time.Now(), false}, {"pending", time.Now().Add(-6 * time.Minute), false}, {"ready", time.Now(), false},
	} {
		t.Run(tc.state+tc.started.String(), func(t *testing.T) {
			creator := &fakeSetupCreator{fakeSiteCreator: &fakeSiteCreator{}, setup: types.SiteSetupStatus{SiteID: 7, ParentID: 1, Domain: "blog.example.test", State: tc.state, StartedAt: tc.started}}
			handler, cookie := setupTestHandler(t, auth.RoleAdmin, creator)
			req := httptest.NewRequest("GET", "https://panel.test/sites/7/setup", nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if tc.state == "ready" {
				if rec.Code != 303 || rec.Header().Get("Location") != "/sites/7?tab=overview&notice=subdomain-created" {
					t.Fatalf("ready response=%d %s", rec.Code, rec.Header().Get("Location"))
				}
				return
			}
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), "data-np-setup-tracker") {
				t.Fatalf("progress=%d %s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), `http-equiv="refresh"`) != tc.refresh {
				t.Fatalf("refresh does not match state %s", tc.state)
			}
		})
	}
}

func TestSubdomainCreationSupportScopeCannotTargetAnotherCustomer(t *testing.T) {
	creator := &fakeSiteCreator{}
	reader := &fakeDashboardReader{data: dashboard.Data{Sites: []dashboard.Site{{ID: 1, CustomerID: 88, Domain: "example.test"}}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{SiteCreator: creator, DashboardReader: reader})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest("POST", "https://panel.test/sites/1/subdomains", strings.NewReader("label=blog&support_customer_id=99"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 404 || len(creator.requests) > 0 {
		t.Fatalf("wrong support customer status=%d requests=%#v", rec.Code, creator.requests)
	}
}

func TestSubdomainSetupStatusRequiresAuthentication(t *testing.T) {
	handler, _ := setupTestHandler(t, auth.RoleAdmin, &fakeSetupCreator{fakeSiteCreator: &fakeSiteCreator{}})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "https://panel.test/sites/7/setup/status", nil))
	if rec.Code != 401 {
		t.Fatalf("anonymous status=%d", rec.Code)
	}
}

func TestSubdomainCreateJSONReturnsProgressInsteadOfParentRedirect(t *testing.T) {
	creator := &fakeSetupCreator{fakeSiteCreator: &fakeSiteCreator{}}
	handler, cookie := setupTestHandler(t, auth.RoleAdmin, creator)
	req := httptest.NewRequest("POST", "https://panel.test/sites/1/subdomains", strings.NewReader("label=blog"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Nakpanel-SPA", "true")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 202 || !strings.Contains(rec.Body.String(), `"status_url":"/sites/7/setup/status"`) || !strings.Contains(rec.Body.String(), `"setup_url":"/sites/7/setup"`) || !strings.Contains(rec.Body.String(), `"redirect":"/sites/7?tab=overview`) {
		t.Fatalf("accepted response = %d %s", rec.Code, rec.Body.String())
	}
}
