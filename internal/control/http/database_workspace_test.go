package panelhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeScopedDatabaseAdmin struct {
	fakeDatabaseAdminService
	subscriptionID int64
}

func (f *fakeScopedDatabaseAdmin) RotatePasswordForSubscription(ctx context.Context, actor, id, subscription int64, password string) (types.ManageDatabaseAdminResult, error) {
	f.subscriptionID = subscription
	return f.RotatePassword(ctx, actor, id, password)
}

func TestScopedPasswordRequiresOwnedActiveDatabaseAndConfirmation(t *testing.T) {
	service := &fakeScopedDatabaseAdmin{}
	reader := &fakeDashboardReader{data: dashboard.Data{Databases: []dashboard.Database{{ID: 30, SubscriptionID: 7, Status: "active"}, {ID: 31, SubscriptionID: 7, Status: "pending"}}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: reader, DatabaseAdmin: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	for _, test := range []struct {
		path, confirm string
		status        int
	}{{"/databases/30/password", "", 400}, {"/databases/31/password", "yes", 409}, {"/databases/32/password", "yes", 404}, {"/databases/30/password", "yes", 202}} {
		form := url.Values{"password": {"new_secret_password"}, "confirm": {test.confirm}}
		r := httptest.NewRequest("POST", test.path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Accept", "application/json")
		r.Header.Set("X-Nakpanel-SPA", "true")
		addAuthenticatedCookie(r, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		if rec.Code != test.status {
			t.Fatalf("%s confirm=%s: %d %s", test.path, test.confirm, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "new_secret_password") {
			t.Fatal("password leaked")
		}
	}
	if service.rotateCalls != 1 || service.subscriptionID != 7 || service.actorID != 1 {
		t.Fatalf("service=%+v", service)
	}
}

func TestDatabaseIdempotencyBindsSessionAndPassword(t *testing.T) {
	build := func(session, password string) types.CreateDatabaseReq {
		r := httptest.NewRequest("POST", "/databases", nil)
		r.Form = url.Values{"idempotency_key": {"test-key"}}
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
		req := types.CreateDatabaseReq{SubscriptionID: 7, SiteID: 8, DBName: "example", Password: password}
		if err := prepareDatabaseIdempotency(r, auth.SessionUser{ID: 1}, 1, &req); err != nil {
			t.Fatal(err)
		}
		return req
	}
	a, b, c := build("session-one", "password-one"), build("session-one", "password-two"), build("session-two", "password-one")
	if a.IdempotencyFingerprint == b.IdempotencyFingerprint {
		t.Fatal("password change not detected")
	}
	if a.IdempotencyScope == c.IdempotencyScope {
		t.Fatal("session scope not bound")
	}
	if a.IdempotencyFingerprint != build("session-one", "password-one").IdempotencyFingerprint {
		t.Fatal("matching request not stable")
	}
}

func TestDatabaseSupportScopeRequiresExactCustomer(t *testing.T) {
	for _, test := range []struct {
		raw     string
		role    auth.Role
		allowed bool
	}{
		{"88", auth.RoleAdmin, true}, {"89", auth.RoleAdmin, false}, {"88", auth.RoleClient, false}, {"oops", auth.RoleAdmin, false}, {"", auth.RoleClient, true},
	} {
		r := httptest.NewRequest("GET", "/databases/1/connection?support_customer_id="+test.raw, nil)
		if got := databaseSupportScopeAllowed(r, auth.SessionUser{Role: test.role}, 88); got != test.allowed {
			t.Fatalf("scope=%s role=%s allowed=%v", test.raw, test.role, got)
		}
	}
}

func TestDatabaseCreateDerivesSiteSubscription(t *testing.T) {
	s := &Server{dashboard: &fakeDashboardReader{data: dashboard.Data{Sites: []dashboard.Site{{ID: 7, SubscriptionID: 20, CustomerID: 88}}}}}
	for _, test := range []struct {
		name                     string
		site, subscription, want int64
		denied                   bool
	}{
		{"derive", 7, 0, 20, false}, {"matching", 7, 20, 20, false}, {"mismatch", 7, 21, 0, true}, {"foreign", 8, 20, 0, true}, {"subscription only", 0, 20, 20, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := types.CreateDatabaseReq{SiteID: test.site, SubscriptionID: test.subscription}
			err := s.prepareDatabaseCreate(httptest.NewRequest("POST", "/databases", nil), auth.SessionUser{ID: 1, Role: auth.RoleClient}, &req)
			if (err != nil) != test.denied {
				t.Fatalf("error=%v", err)
			}
			if !test.denied && req.SubscriptionID != test.want {
				t.Fatalf("subscription=%d", req.SubscriptionID)
			}
		})
	}
}

func TestDatabaseStatusIsScopedAndSanitized(t *testing.T) {
	reader := &fakeDashboardReader{data: dashboard.Data{
		Sites:     []dashboard.Site{{ID: 7, SubscriptionID: 20}},
		Databases: []dashboard.Database{{ID: 1, SiteID: 7, SubscriptionID: 20, Name: "owned", Status: "failed", LastError: "SQL password=secret"}, {ID: 2, SiteID: 8, SubscriptionID: 20, Name: "other", Status: "active"}, {ID: 3, SiteID: 7, SubscriptionID: 21, Name: "foreign", Status: "active"}},
	}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: reader})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	for _, path := range []string{"/sites/7/databases/status", "/sites/8/databases/status"} {
		req := httptest.NewRequest("GET", path, nil)
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if strings.Contains(path, "/8/") {
			if rec.Code != 404 {
				t.Fatalf("foreign=%d", rec.Code)
			}
			continue
		}
		if rec.Code != 200 {
			t.Fatalf("status=%d: %s", rec.Code, rec.Body.String())
		}
		var body struct {
			Databases []databaseStatusResponse `json:"databases"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Databases) != 1 || body.Databases[0].ID != 1 {
			t.Fatalf("rows=%+v", body.Databases)
		}
		if strings.Contains(rec.Body.String(), "secret") || strings.Contains(rec.Body.String(), "SQL") {
			t.Fatal("raw error leaked")
		}
		if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
			t.Fatal("status is cacheable")
		}
	}
}

func TestDatabaseConnectionNeverReturnsPassword(t *testing.T) {
	reader := &fakeDashboardReader{data: dashboard.Data{Databases: []dashboard.Database{{ID: 1, Name: "owned", User: "dbuser", Engine: "mariadb", Status: "active"}, {ID: 2, Status: "pending"}}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: reader})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	for _, test := range []struct {
		path string
		code int
	}{{"/databases/1/connection", 200}, {"/databases/2/connection", 409}, {"/databases/3/connection", 404}} {
		req := httptest.NewRequest("GET", test.path, nil)
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != test.code {
			t.Fatalf("%s=%d", test.path, rec.Code)
		}
		if rec.Code == 200 && (!strings.Contains(rec.Body.String(), "YOUR_DATABASE_PASSWORD") || strings.Contains(rec.Body.String(), `"password":`)) {
			t.Fatalf("unsafe details: %s", rec.Body.String())
		}
	}
}

func TestDatabaseRetryRequiresCSRF(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodPost, "/databases/1/retry", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
}
