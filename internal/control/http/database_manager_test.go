package panelhttp

import (
	"context"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeManagerService struct {
	denied bool
	calls  int
}

func (f *fakeManagerService) Launch(context.Context, auth.SessionUser, string, int64) (string, error) {
	return strings.Repeat("a", 43), nil
}
func (f *fakeManagerService) Access(context.Context, auth.SessionUser, string, string) (provision.DatabaseManagerAccess, error) {
	f.calls++
	if f.denied {
		return provision.DatabaseManagerAccess{}, provision.ErrDatabaseManagerDenied
	}
	return provision.DatabaseManagerAccess{Grant: strings.Repeat("b", 64), DatabaseID: 3}, nil
}
func (f *fakeManagerService) Logout(context.Context, auth.SessionUser, string, string) error {
	return nil
}

type managerRoundTripper func(*http.Request) (*http.Response, error)

func (f managerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDatabaseManagerPathBoundary(t *testing.T) {
	for _, path := range []string{"../index.php", "a/../b", "a\\b", "%2e%2e/index.php", "setup/index.php", "signon.php", "__bridge"} {
		if validManagerPath(path) {
			t.Errorf("accepted %q", path)
		}
	}
	for _, path := range []string{"", "index.php", "themes/pmahomme/css/theme.css"} {
		if !validManagerPath(path) {
			t.Errorf("rejected %q", path)
		}
	}
}

func TestDatabaseManagerLogoutConfirmationKeepsSameOriginForms(t *testing.T) {
	p := NewDatabaseManagerProxy(&fakeManagerService{}, strings.Repeat("k", 32))
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DatabaseManager: p})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	for _, method := range []string{"GET", "POST"} {
		r := httptest.NewRequest(method, "https://panel.test/database-manager/"+strings.Repeat("a", 43)+"/logout", nil)
		r.AddCookie(cookie)
		r.Header.Set("Origin", "https://panel.test")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Header().Get("Referrer-Policy") != "same-origin" {
			t.Fatal("manager forms must retain same-origin provenance")
		}
		if method == "GET" && (w.Code != 200 || !strings.Contains(w.Body.String(), "End database session")) {
			t.Fatal("missing logout confirmation")
		}
		if method == "POST" && (w.Code != 303 || w.Header().Get("Location") != "/databases") {
			t.Fatal("logout did not return to databases")
		}
	}
}

func TestDatabaseManagerLaunchRequiresCSRFAndReadyRuntime(t *testing.T) {
	service := &fakeManagerService{}
	p := NewDatabaseManagerProxy(service, strings.Repeat("k", 32))
	ready := true
	p.transport = managerRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "http://127.0.0.1:9082/__nakpanel_health" || r.Header.Get("X-Nakpanel-Manager-Key") != strings.Repeat("k", 32) {
			t.Fatal("invalid health request")
		}
		status := 204
		if !ready {
			status = 503
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DatabaseManager: p, DashboardReader: &fakeDashboardReader{data: dashboard.Data{Databases: []dashboard.Database{{ID: 3, CustomerID: 9, Status: "active"}}}}})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	for _, validCSRF := range []bool{false, true} {
		r := httptest.NewRequest("POST", "https://panel.test/databases/3/manager", nil)
		r.AddCookie(cookie)
		if validCSRF {
			r.Header.Set("X-Nakpanel-CSRF", csrfToken(r))
		}
		r.Header.Set("Origin", "https://panel.test")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		want := 403
		if validCSRF {
			want = 303
		}
		if w.Code != want {
			t.Fatalf("status %d want %d: %s", w.Code, want, w.Body.String())
		}
	}
	ready = false
	r := httptest.NewRequest("POST", "https://panel.test/databases/3/manager", nil)
	r.AddCookie(cookie)
	r.Header.Set("X-Nakpanel-CSRF", csrfToken(r))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "Back to databases") {
		t.Fatalf("runtime error %d %s", w.Code, w.Body.String())
	}
}
func TestDatabaseManagerCapabilitySingleUseAndExpiry(t *testing.T) {
	p := NewDatabaseManagerProxy(&fakeManagerService{}, strings.Repeat("k", 32))
	for _, expired := range []bool{false, true} {
		expires := time.Now().Add(time.Minute)
		if expired {
			expires = time.Now().Add(-time.Minute)
		}
		token, err := p.issueCapability(managerCapability{access: provision.DatabaseManagerAccess{Password: "private"}, expires: expires})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			r := httptest.NewRequest("POST", "http://unix/redeem", strings.NewReader(`{"capability":"`+token+`"}`))
			w := httptest.NewRecorder()
			p.BridgeHandler().ServeHTTP(w, r)
			want := 200
			if expired || i == 1 {
				want = 404
			}
			if w.Code != want {
				t.Fatalf("status %d want %d", w.Code, want)
			}
		}
	}
}
func TestDatabaseManagerProxyStripsAuthorityAndScopesCookies(t *testing.T) {
	service := &fakeManagerService{}
	p := NewDatabaseManagerProxy(service, strings.Repeat("k", 32))
	p.transport = managerRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "127.0.0.1:9082" || r.Header.Get("Authorization") != "" || strings.Contains(r.Header.Get("Cookie"), "nakpanel") || r.Header.Get("X-Nakpanel-DB-Password") != "" {
			t.Fatalf("unsafe request headers: %v", r.Header)
		}
		if r.URL.Path != "/index.php" || r.URL.Query().Get("route") != "/database/structure" {
			t.Fatal("manager landing request did not select database structure")
		}
		if r.Header.Get("X-Nakpanel-Manager-Grant") != strings.Repeat("b", 64) {
			t.Fatal("spoofed grant forwarded")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Security-Policy": []string{"script-src 'self' 'unsafe-inline'"}, "Set-Cookie": []string{"__Secure-phpMyAdmin_https=abc; Path=/; Domain=evil.test", "nakpanel_session=evil; Path=/"}}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	store := &fakeSessionStore{tokenHash: auth.TokenHash("session"), user: auth.SessionUser{ID: 1, Role: auth.RoleClient}, expiresAt: time.Now().Add(time.Hour)}
	s := &Server{sessions: auth.NewSessionManager(store, auth.SessionOptions{})}
	r := httptest.NewRequest("GET", "https://panel.test/database-manager/"+strings.Repeat("a", 43)+"/index.php", nil)
	r.SetPathValue("grantID", strings.Repeat("a", 43))
	r.SetPathValue("path", "")
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "session"})
	r.AddCookie(&http.Cookie{Name: "__Secure-phpMyAdmin_https", Value: "abc"})
	r.Header.Set("Authorization", "secret")
	r.Header.Set("X-Nakpanel-DB-Password", "spoof")
	r.Header.Set("X-Nakpanel-Manager-Grant", "spoof")
	w := httptest.NewRecorder()
	w.Header().Set("Content-Security-Policy", "script-src 'self'")
	s.serveDatabaseManager(p, w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if got := w.Header().Values("Content-Security-Policy"); len(got) != 1 || got[0] != "script-src 'self' 'unsafe-inline'" {
		t.Fatal("manager policy was combined with the panel policy")
	}
	if len(cookies) != 1 || cookies[0].Domain != "" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/database-manager/"+strings.Repeat("a", 43)+"/" {
		t.Fatalf("cookies: %v", cookies)
	}
	store.deleted = true
	w = httptest.NewRecorder()
	s.serveDatabaseManager(p, w, r)
	if w.Code != 401 {
		t.Fatal("revoked panel session accepted")
	}
}

func TestDatabaseManagerAssetBurstWaitsForCapacityBeforeRedeemingGrant(t *testing.T) {
	service := &fakeManagerService{}
	proxy := NewDatabaseManagerProxy(service, strings.Repeat("k", 32))
	for i := 0; i < cap(proxy.slots); i++ {
		proxy.slots <- struct{}{}
	}
	proxy.transport = managerRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("var CommonParams = {};"))}, nil
	})
	store := &fakeSessionStore{tokenHash: auth.TokenHash("session"), user: auth.SessionUser{ID: 1, Role: auth.RoleClient}, expiresAt: time.Now().Add(time.Hour)}
	server := &Server{sessions: auth.NewSessionManager(store, auth.SessionOptions{})}
	request := httptest.NewRequest(http.MethodGet, "https://panel.test/database-manager/"+strings.Repeat("a", 43)+"/js/dist/common.js", nil)
	request.SetPathValue("grantID", strings.Repeat("a", 43))
	request.SetPathValue("path", "js/dist/common.js")
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "session"})
	ctx, cancel := context.WithTimeout(request.Context(), time.Second)
	defer cancel()
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		server.serveDatabaseManager(proxy, response, request.WithContext(ctx))
		close(done)
	}()
	select {
	case <-done:
		t.Fatalf("asset request was rejected instead of waiting: status=%d grant reads=%d", response.Code, service.calls)
	case <-time.After(30 * time.Millisecond):
	}
	<-proxy.slots
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("asset did not resume when capacity became available")
	}
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "CommonParams") || service.calls != 1 {
		t.Fatalf("resumed asset status=%d grant reads=%d body=%s", response.Code, service.calls, response.Body.String())
	}
}

func TestDatabaseManagerCancelledQueueDoesNotRedeemGrant(t *testing.T) {
	service := &fakeManagerService{}
	proxy := NewDatabaseManagerProxy(service, strings.Repeat("k", 32))
	for i := 0; i < cap(proxy.slots); i++ {
		proxy.slots <- struct{}{}
	}
	store := &fakeSessionStore{tokenHash: auth.TokenHash("session"), user: auth.SessionUser{ID: 1, Role: auth.RoleClient}, expiresAt: time.Now().Add(time.Hour)}
	server := &Server{sessions: auth.NewSessionManager(store, auth.SessionOptions{})}
	request := httptest.NewRequest(http.MethodGet, "https://panel.test/database-manager/"+strings.Repeat("a", 43)+"/", nil)
	request.SetPathValue("grantID", strings.Repeat("a", 43))
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "session"})
	ctx, cancel := context.WithCancel(request.Context())
	cancel()
	response := httptest.NewRecorder()
	server.serveDatabaseManager(proxy, response, request.WithContext(ctx))
	if response.Code != http.StatusServiceUnavailable || service.calls != 0 {
		t.Fatalf("cancelled queue status=%d consumed grant reads=%d", response.Code, service.calls)
	}
}
