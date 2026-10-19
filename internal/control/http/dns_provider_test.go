package panelhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type providerDNSStub struct {
	DNSTemplateManager
	calls int
	input types.DNSProviderDefaults
}

func (s *providerDNSStub) SaveProviderDefaults(_ context.Context, _ int64, _ int64, input types.DNSProviderDefaults) (int64, error) {
	s.calls++
	s.input = input
	return 2, nil
}
func (s *providerDNSStub) View(context.Context, int64) (types.DNSTemplateView, error) {
	return types.DNSTemplateView{Preview: &types.DNSSyncRun{ID: 2, Status: "pending", PreviewToken: "secret-preview"}}, nil
}

func (s *providerDNSStub) PreviewDomains(context.Context) ([]types.DNSPreviewDomain, error) {
	return []types.DNSPreviewDomain{{SiteID: 1, Domain: "example.test"}}, nil
}
func (s *providerDNSStub) DomainPreview(_ context.Context, siteID int64) (types.DNSDomainPreview, error) {
	s.calls++
	return types.DNSDomainPreview{SiteID: siteID, Domain: "example.test", Records: []types.DNSPreviewRecord{{Record: types.DNSRecord{Host: "@", Type: "MX", Value: "external.example.net", TTL: 300, Origin: "custom"}, Action: "Preserved"}}}, nil
}

func TestDNSDomainPreviewIsAdminOnlyReadOnlyAndUncached(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleClient, auth.RoleReseller} {
		t.Run(string(role), func(t *testing.T) {
			stub := &providerDNSStub{}
			handler, _ := newTestHandlerWithOptions(t, role, ServerOptions{DNSTemplates: stub})
			email, password := "admin@nakpanel.test", "NakpanelAdmin!2026"
			if role == auth.RoleClient {
				email, password = "client@nakpanel.test", "NakpanelClient!2026"
			}
			if role == auth.RoleReseller {
				email, password = "reseller@nakpanel.test", "NakpanelReseller!2026"
			}
			cookie := login(t, handler, email, password)
			r := httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/dns/domain-preview?site_id=1", nil)
			addAuthenticatedCookie(r, cookie)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if role == auth.RoleAdmin {
				if w.Code != 200 || stub.calls != 1 || !strings.Contains(w.Body.String(), "external.example.net") || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
					t.Fatalf("preview: %d %s", w.Code, w.Body.String())
				}
			} else if w.Code != 403 || stub.calls != 0 {
				t.Fatalf("role bypass: %d calls=%d", w.Code, stub.calls)
			}
		})
	}
}

func TestProviderDNSDefaultsRequireAdminAndCSRF(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleClient, auth.RoleReseller} {
		t.Run(string(role), func(t *testing.T) {
			stub := &providerDNSStub{}
			handler, _ := newTestHandlerWithOptions(t, role, ServerOptions{DNSTemplates: stub})
			email, password := "admin@nakpanel.test", "NakpanelAdmin!2026"
			if role == auth.RoleClient {
				email, password = "client@nakpanel.test", "NakpanelClient!2026"
			}
			if role == auth.RoleReseller {
				email, password = "reseller@nakpanel.test", "NakpanelReseller!2026"
			}
			cookie := login(t, handler, email, password)
			r := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/dns/template/provider", strings.NewReader("primary_nameserver=ns1.example.com&secondary_nameserver=ns2.example.com&expected_revision=1"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			addAuthenticatedCookie(r, cookie)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if role == auth.RoleAdmin {
				if w.Code != 303 || stub.calls != 1 {
					t.Fatalf("admin save %d calls=%d body=%s", w.Code, stub.calls, w.Body.String())
				}
			} else if w.Code != 403 || stub.calls != 0 {
				t.Fatalf("role bypass %d calls=%d", w.Code, stub.calls)
			}
		})
	}
}

func TestDNSStatusDoesNotExposeApplyToken(t *testing.T) {
	stub := &providerDNSStub{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DNSTemplates: stub})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	r := httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/dns/sync/2", nil)
	addAuthenticatedCookie(r, cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret-preview") || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("unsafe status %d %s", w.Code, w.Body.String())
	}
}

func TestDNSProviderDefaultsRejectMissingCSRF(t *testing.T) {
	stub := &providerDNSStub{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DNSTemplates: stub})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	r := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/dns/template/provider", strings.NewReader("primary_nameserver=ns1.example.com&secondary_nameserver=ns2.example.com"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 || stub.calls != 0 {
		t.Fatalf("CSRF bypass %d calls=%d", w.Code, stub.calls)
	}
}
