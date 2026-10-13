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

func certificateNoticeBanner(body string) string {
	_, banner, found := strings.Cut(body, `<p class="np-notice `)
	if !found {
		return ""
	}
	banner, _, _ = strings.Cut(banner, "</p>")
	return banner
}

func TestCertificateQueuedNoticeUsesCurrentSiteTLSState(t *testing.T) {
	for _, tc := range []struct {
		name, status, lastError, class, message string
	}{
		{name: "pending", status: "pending", class: "np-notice-run", message: "Certificate request in progress"},
		{name: "failed", status: "failed", lastError: "issuer rejected <script>alert(1)</script>", class: "np-notice-fail", message: "Certificate request failed"},
		{name: "failed without details", status: "failed", class: "np-notice-fail", message: "Certificate request failed"},
		{name: "active", status: "active", class: "np-notice-ok", message: "Certificate installed"},
		{name: "none", status: "none"},
		{name: "empty state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &fakeDashboardReader{data: dashboard.Data{
				Sites:         []dashboard.Site{{ID: 7, Domain: "owned.test", CustomerID: 88, SubscriptionID: 20, Status: "active", TLSStatus: tc.status, TLSLastError: tc.lastError}},
				Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, Status: "active", AllowTLS: true}},
			}}
			issuer := &fakeCertificateIssuer{}
			handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader, CertificateIssuer: issuer})
			cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
			req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7?tab=ssl&notice=certificate-queued", nil)
			addAuthenticatedCookie(req, cookie)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET certificate workspace = %d", rec.Code)
			}
			banner := certificateNoticeBanner(rec.Body.String())
			if tc.message == "" {
				if banner != "" {
					t.Fatalf("stale queued notice for TLS state %q: %s", tc.status, banner)
				}
			} else if !strings.Contains(banner, tc.class) || !strings.Contains(banner, tc.message) {
				t.Fatalf("TLS state %q banner = %s, want %s and %q", tc.status, banner, tc.class, tc.message)
			}
			if tc.lastError != "" && !strings.Contains(banner, "issuer rejected &lt;script&gt;alert(1)&lt;/script&gt;") {
				t.Fatalf("failure banner must safely render current error: %s", banner)
			}
			if strings.Contains(banner, "Certificate requested.") || strings.Contains(banner, "<script>alert(1)</script>") {
				t.Fatalf("stale or unsafe certificate banner: %s", banner)
			}
			if issuer.domain != "" {
				t.Fatal("GET must not replay certificate issuance")
			}
			for _, action := range []string{`action="/certificates"`, `action="/sites/7/tls-auto-renew"`, `action="/sites/7/certificates/custom"`} {
				if !strings.Contains(rec.Body.String(), action) {
					t.Errorf("TLS form missing %s", action)
				}
			}
		})
	}
}

func TestCertificateQueuedSupportNoticeUsesOnlyVisibleSite(t *testing.T) {
	reader := &fakeDashboardReader{data: dashboard.Data{
		Customers: []types.Customer{{ID: 88, DisplayName: "Owned", Status: "active"}},
		Sites: []dashboard.Site{
			{ID: 7, Domain: "owned.test", CustomerID: 88, SubscriptionID: 20, Status: "active", TLSStatus: "failed", TLSLastError: "owned issuer failure"},
			{ID: 9, Domain: "other.test", CustomerID: 99, Status: "active", TLSStatus: "active"},
		},
		Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, Status: "active", AllowTLS: true}},
	}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader, CertificateIssuer: &fakeCertificateIssuer{}})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	for _, tc := range []struct {
		path   string
		status int
	}{
		{path: "/support/customers/88/sites/7?tab=ssl&notice=certificate-queued", status: http.StatusOK},
		{path: "/support/customers/88/sites/9?tab=ssl&notice=certificate-queued", status: http.StatusNotFound},
	} {
		req := httptest.NewRequest(http.MethodGet, "https://panel.test"+tc.path, nil)
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Fatalf("GET %s = %d, want %d", tc.path, rec.Code, tc.status)
		}
		if tc.status == http.StatusOK {
			banner := certificateNoticeBanner(rec.Body.String())
			if !strings.Contains(banner, "np-notice-fail") || !strings.Contains(banner, "owned issuer failure") {
				t.Errorf("support certificate failure banner = %s", banner)
			}
			if !strings.Contains(rec.Body.String(), `name="support_customer_id" value="88"`) {
				t.Error("support certificate forms lost their customer scope")
			}
		}
		if strings.Contains(rec.Body.String(), "other.test") {
			t.Fatal("certificate notice exposed another customer's site")
		}
	}
}

func TestCertificateQueuedNoticePreservesFormFailure(t *testing.T) {
	reader := &fakeDashboardReader{data: dashboard.Data{Sites: []dashboard.Site{{ID: 7, Domain: "owned.test", Status: "active", TLSStatus: "active"}}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7?tab=ssl&notice=certificate-queued", nil)
	addAuthenticatedCookie(req, cookie)
	req.AddCookie(&http.Cookie{Name: FormErrorCookieName, Value: url.QueryEscape("Could not update renewal settings")})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	banner := certificateNoticeBanner(rec.Body.String())
	if !strings.Contains(banner, "np-notice-fail") || !strings.Contains(banner, "Could not update renewal settings") {
		t.Fatalf("form failure overwritten by certificate state: %s", banner)
	}
}

func TestUnscopedCertificateQueuedNoticeIsNotSuccess(t *testing.T) {
	_, kind := dashboardNotice("certificate-queued")
	if kind != dashboard.NoticeInfo {
		t.Fatalf("unscoped certificate queued kind = %q, want informational", kind)
	}
}
