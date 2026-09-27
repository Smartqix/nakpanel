package panelhttp

import (
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestStatisticsReportHeadersEnforceOpaqueSandbox(t *testing.T) {
	header := http.Header{}
	header.Set("X-Frame-Options", "DENY")
	setStatisticsReportHeaders(header)
	csp := header.Get("Content-Security-Policy")
	for _, value := range []string{"sandbox allow-scripts;", "connect-src 'none'", "form-action 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, value) {
			t.Fatalf("CSP missing %q", value)
		}
	}
	if strings.Contains(csp, "allow-same-origin") || header.Get("X-Frame-Options") != "" || header.Get("Cache-Control") != "no-store, private" {
		t.Fatalf("unsafe headers %+v", header)
	}
}

func TestStatisticsAdminSettingsRejectClientBeforeService(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	dummy := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/web-statistics", nil)
	dummy.AddCookie(cookie)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		form := url.Values{"csrf_token": {csrfToken(dummy)}}
		req := httptest.NewRequest(method, "https://panel.test/tools-settings/web-statistics", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://panel.test")
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s status %d", method, rec.Code)
		}
	}
}

func TestStatisticsRefreshRequiresCSRF(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/statistics/refresh", nil)
	req.Header.Set("Origin", "https://panel.test")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
}
