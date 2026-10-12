package panelhttp

import (
	"context"
	"encoding/json"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSupportGitStatusRequiresAdminAndMatchingCustomer(t *testing.T) {
	data := dashboard.Data{Sites: []dashboard.Site{{ID: 58, SubscriptionID: 39, CustomerID: 36}}, SubscriptionServices: dashboard.SubscriptionServicesData{Git: []types.GitRepository{{ID: 4, SiteID: 58}}}}
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleClient, auth.RoleReseller} {
		handler, _ := newTestHandlerWithOptions(t, role, ServerOptions{DashboardReader: &fakeDashboardReader{data: data}})
		email, password := "admin@nakpanel.test", "NakpanelAdmin!2026"
		if role == auth.RoleClient {
			email, password = "client@nakpanel.test", "NakpanelClient!2026"
		}
		if role == auth.RoleReseller {
			email, password = "reseller@nakpanel.test", "NakpanelReseller!2026"
		}
		cookie := login(t, handler, email, password)
		for _, customer := range []string{"36", "37", "0", "bad"} {
			path := "/support/customers/" + customer + "/sites/58/git/status?support_customer_id=36"
			r := httptest.NewRequest("GET", path, nil)
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			want := 404
			if role == auth.RoleAdmin && customer == "36" {
				want = 200
			}
			if w.Code != want {
				t.Errorf("%s %s status=%d, want %d", role, path, w.Code, want)
				continue
			}
			if want == 200 {
				var body struct {
					SiteID     int64 `json:"site_id"`
					Repository types.GitRepository
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.SiteID != 58 || body.Repository.ID != 4 {
					t.Fatalf("unexpected JSON: %s", w.Body.String())
				}
			}
		}
	}
}

type fakeGitWorkspace struct {
	fakeDomainManager
	calls              int
	subscription, site int64
	input              types.GitWorkspaceOperationInput
}

func (f *fakeGitWorkspace) QueueGitWorkspaceOperation(_ context.Context, _ auth.SessionUser, subscription, site int64, input types.GitWorkspaceOperationInput) (int64, error) {
	f.calls++
	f.subscription = subscription
	f.site = site
	f.input = input
	return 12, nil
}
func (f *fakeGitWorkspace) UpsertGitRepository(_ context.Context, _ auth.SessionUser, subscription, site int64, _ types.GitRepositoryInput) (int64, error) {
	f.calls++
	f.subscription = subscription
	f.site = site
	return 4, nil
}

func (f *fakeGitWorkspace) PrepareGitKey(_ context.Context, _ auth.SessionUser, subscription, site int64, _ string) (string, error) {
	f.calls++
	f.subscription, f.site = subscription, site
	return "ssh-ed25519 YWJj public-only", nil
}

func TestGitKeyRequiresCSRFAndOwnedSite(t *testing.T) {
	service := &fakeGitWorkspace{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DomainManager: service, DashboardReader: &fakeDashboardReader{data: dashboard.Data{Sites: []dashboard.Site{{ID: 58, SubscriptionID: 39, CustomerID: 36, Domain: "example.test"}}}}})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	for _, tc := range []struct {
		path   string
		csrf   bool
		status int
	}{{"/sites/58/git/key", true, 200}, {"/sites/59/git/key", true, 404}, {"/sites/58/git/key", false, 403}} {
		r := httptest.NewRequest("POST", tc.path, strings.NewReader("remote_url=git%40github.com%3Ateam%2Frepo.git"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Nakpanel-SPA", "true")
		if tc.csrf {
			addAuthenticatedCookie(r, cookie)
		} else {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%+v: %d %s", tc, w.Code, w.Body.String())
		}
		if w.Code == 200 && !strings.Contains(w.Body.String(), `"public_key"`) {
			t.Fatal("no public key")
		}
	}
	if service.calls != 1 || service.site != 58 || service.subscription != 39 {
		t.Fatal("key preparation bypassed scope")
	}
}

func TestGitWorkspaceStatusScopesRepositoryAndHistory(t *testing.T) {
	data := dashboard.Data{Sites: []dashboard.Site{{ID: 58, SubscriptionID: 39, CustomerID: 36}}, SubscriptionServices: dashboard.SubscriptionServicesData{Git: []types.GitRepository{{ID: 4, SiteID: 58}, {ID: 5, SiteID: 59}}, GitDeployments: []types.GitDeployment{{ID: 1, RepositoryID: 4}, {ID: 2, RepositoryID: 5}}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: &fakeDashboardReader{data: data}})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	for _, path := range []string{"/sites/58/git/status", "/sites/59/git/status", "/sites/58/git/status?support_customer_id=36"} {
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if path != "/sites/58/git/status" {
			if w.Code != 404 {
				t.Fatalf("%s = %d", path, w.Code)
			}
			continue
		}
		var body struct {
			Repository  types.GitRepository
			Deployments []types.GitDeployment
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || body.Repository.ID != 4 || len(body.Deployments) != 1 || body.Deployments[0].ID != 1 {
			t.Fatalf("unscoped response %s", w.Body.String())
		}
	}
}

func TestGitWorkspaceActionsRequireScopeRevisionAndConfirmation(t *testing.T) {
	service := &fakeGitWorkspace{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DomainManager: service, DashboardReader: &fakeDashboardReader{data: dashboard.Data{Sites: []dashboard.Site{{ID: 58, SubscriptionID: 39, CustomerID: 36}}}}})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	for _, tc := range []struct {
		action, sub, rev, confirm, support string
		status                             int
	}{{"fetch", "39", "2", "", "", 202}, {"deploy", "39", "2", "", "", 400}, {"deploy", "39", "2", "yes", "", 202}, {"rollback", "39", "2", "yes", "", 202}, {"disconnect", "39", "2", "", "", 400}, {"fetch", "40", "2", "", "", 404}, {"fetch", "39", "bad", "", "", 400}, {"fetch", "39", "2", "", "37", 404}} {
		form := url.Values{"subscription_id": {tc.sub}, "expected_revision": {tc.rev}, "confirm": {tc.confirm}, "revision": {strings.Repeat("a", 40)}, "support_customer_id": {tc.support}}
		r := httptest.NewRequest("POST", "/sites/58/git/"+tc.action, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Nakpanel-SPA", "true")
		addAuthenticatedCookie(r, cookie)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%+v got %d %s", tc, w.Code, w.Body.String())
		}
	}
	if service.calls != 3 || service.subscription != 39 {
		t.Fatalf("service calls=%d subscription=%d", service.calls, service.subscription)
	}
	r := httptest.NewRequest("POST", "/sites/58/git/fetch", strings.NewReader("expected_revision=2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("missing CSRF = %d", w.Code)
	}
}
