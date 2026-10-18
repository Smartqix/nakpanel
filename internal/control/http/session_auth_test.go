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
)

type unavailableSessionStore struct{ fakeSessionStore }

func (*unavailableSessionStore) GetSession(context.Context, string, time.Time) (auth.SessionUser, error) {
	return auth.SessionUser{}, errors.New("session database is unavailable")
}

func TestSessionBackendFailurePreservesCookie(t *testing.T) {
	sessions := auth.NewSessionManager(&unavailableSessionStore{}, auth.SessionOptions{})
	server := NewServer(nil, sessions)
	for _, tc := range []struct {
		name     string
		handler  http.Handler
		fragment bool
	}{
		{name: "full", handler: server.Handler()},
		{name: "fragment", handler: server.Handler(), fragment: true},
		{name: "direct", handler: http.HandlerFunc(server.handleDashboard)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://panel.test/dashboard", nil)
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "valid-session-token"})
			if tc.fragment {
				req.Header.Set("X-Nakpanel-Fragment", "main")
			}
			rec := httptest.NewRecorder()
			tc.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", rec.Code)
			}
			if cookies := rec.Result().Header.Values("Set-Cookie"); len(cookies) != 0 {
				t.Errorf("backend failure changed cookies: %v", cookies)
			}
			if location := rec.Header().Get("X-Nakpanel-Location"); location != "" {
				t.Errorf("backend failure requested login navigation: %q", location)
			}
			if location := rec.Header().Get("Location"); location != "" {
				t.Errorf("backend failure redirected to %q", location)
			}
			if body := rec.Body.String(); strings.Contains(body, `href="/login"`) {
				t.Errorf("backend failure included a login redirect body: %s", body)
			}
		})
	}
}

func TestPrefetchSessionBackendFailureRequiresLoginWithoutCookies(t *testing.T) {
	sessions := auth.NewSessionManager(&unavailableSessionStore{}, auth.SessionOptions{})
	handler := NewServer(nil, sessions).Handler()
	for _, header := range []string{"Purpose", "Sec-Purpose"} {
		t.Run(header, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://panel.test/dashboard", nil)
			req.Header.Set(header, "prefetch")
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "valid-session-token"})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized || rec.Header().Get("X-Nakpanel-Location") != "/login" {
				t.Errorf("prefetch auth response = %d %v, want 401 and login location", rec.Code, rec.Header())
			}
			if cookies := rec.Result().Header.Values("Set-Cookie"); len(cookies) != 0 {
				t.Errorf("prefetch changed cookies: %v", cookies)
			}
		})
	}
}

func TestInvalidSessionExpiresCookie(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, token string
		expiresAt   time.Time
	}{
		{name: "unknown", token: "unknown-token", expiresAt: now.Add(time.Hour)},
		{name: "expired", token: "known-token", expiresAt: now.Add(-time.Second)},
		{name: "empty", token: "", expiresAt: now.Add(time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeSessionStore{tokenHash: auth.TokenHash("known-token"), expiresAt: tc.expiresAt}
			sessions := auth.NewSessionManager(store, auth.SessionOptions{Now: func() time.Time { return now }})
			req := httptest.NewRequest(http.MethodGet, "https://panel.test/dashboard", nil)
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tc.token})
			rec := httptest.NewRecorder()
			NewServer(nil, sessions).Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
				t.Errorf("invalid session response = %d %v, want login redirect", rec.Code, rec.Header())
			}
			cookies := rec.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Name != SessionCookieName || cookies[0].Value != "" || cookies[0].MaxAge >= 0 {
				t.Errorf("invalid session cookies = %v, want expired session cookie", cookies)
			}
		})
	}
}

func TestPrefetchInvalidSessionDoesNotChangeCookies(t *testing.T) {
	sessions := auth.NewSessionManager(&fakeSessionStore{}, auth.SessionOptions{})
	handler := NewServer(nil, sessions).Handler()
	for _, header := range []string{"Purpose", "Sec-Purpose"} {
		for _, fragment := range []bool{false, true} {
			t.Run(header+map[bool]string{false: "/full", true: "/fragment"}[fragment], func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "https://panel.test/dashboard", nil)
				req.Header.Set(header, "prefetch")
				req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "invalid-token"})
				if fragment {
					req.Header.Set("X-Nakpanel-Fragment", "main")
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusUnauthorized || rec.Header().Get("X-Nakpanel-Location") != "/login" {
					t.Errorf("prefetch auth response = %d %v, want 401 and login location", rec.Code, rec.Header())
				}
				if cookies := rec.Result().Header.Values("Set-Cookie"); len(cookies) != 0 {
					t.Errorf("prefetch changed cookies: %v", cookies)
				}
			})
		}
	}
}

func TestPrefetchSuppressesCookiesOutsideSessionAuthentication(t *testing.T) {
	handler := NewServer(nil, auth.NewSessionManager(&fakeSessionStore{}, auth.SessionOptions{})).Handler()
	for _, header := range []string{"Purpose", "Sec-Purpose"} {
		t.Run(header, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://panel.test/logout", nil)
			req.Header.Set(header, "prefetch")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusSeeOther {
				t.Errorf("logout status = %d, want 303", rec.Code)
			}
			if cookies := rec.Result().Header.Values("Set-Cookie"); len(cookies) != 0 {
				t.Errorf("prefetch changed cookies: %v", cookies)
			}
		})
	}
}
