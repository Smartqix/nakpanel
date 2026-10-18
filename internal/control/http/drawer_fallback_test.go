package panelhttp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestWorkspaceDrawerFallbackOpensRequestedSFTP(t *testing.T) {
	for _, tc := range []struct {
		name, drawer string
		blocked      bool
		wantOpen     bool
	}{
		{"requested", "subscription-sftp-dialog-42", false, true},
		{"other drawer", "subscription-ftps-dialog-42", false, false},
		{"unsafe id", "subscription-sftp-dialog-42\" open", false, false},
		{"policy blocked", "subscription-sftp-dialog-42", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := types.HostingPolicy{}
			policy.Permissions.SFTP = !tc.blocked
			reader := &fakeDashboardReader{data: dashboard.Data{
				Subscriptions:        []types.SubscriptionSummary{{ID: 42, SubscriptionName: "example.test", Status: "active"}},
				SubscriptionServices: dashboard.SubscriptionServicesData{Accounts: []types.SubscriptionSystemAccount{{SubscriptionID: 42, EffectivePolicy: policy}}},
			}}
			handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader})
			cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
			req := httptest.NewRequest(http.MethodGet, "https://panel.test/subscriptions/42?tab=access&drawer="+url.QueryEscape(tc.drawer), nil)
			addAuthenticatedCookie(req, cookie)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			head := regexp.MustCompile(`<dialog\b[^>]*\bid="subscription-sftp-dialog-42"[^>]*>`).FindString(rec.Body.String())
			open := regexp.MustCompile(`\sopen(?:[\s=>])`).MatchString(head)
			if open != tc.wantOpen {
				t.Fatalf("SFTP fallback open=%v, want %v: %s", open, tc.wantOpen, head)
			}
			if tc.blocked && head != "" {
				t.Fatalf("policy-blocked drawer rendered: %s", head)
			}
		})
	}
}
