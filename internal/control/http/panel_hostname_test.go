package panelhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
)

func TestDashboardSidebarUsesEscapedRequestHostnameWithoutPort(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleAdmin)
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	for _, path := range []string{"/dashboard", "/?legacy=1"} {
		for _, host := range []struct{ raw, escaped string }{
			{"Panel.Example:7443", "panel.example"},
			{`<panel.example>:7443`, "&lt;panel.example&gt;"},
		} {
			r := httptest.NewRequest(http.MethodGet, "https://panel.test"+path, nil)
			r.Host = host.raw
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("%s status=%d", path, w.Code)
			}
			body := w.Body.String()
			if !strings.Contains(body, "<small>"+host.escaped+"</small>") || strings.Contains(body, "ns1.nakroteck.com") || strings.Contains(body, "<panel.example>") {
				t.Errorf("%s did not render escaped request hostname %q", path, host.raw)
			}
		}
	}
}
