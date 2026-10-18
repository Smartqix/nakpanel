package panelhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

type timingCapabilityReader struct{}

func (timingCapabilityReader) RuntimeCapabilities(context.Context) (types.RuntimeCapabilities, error) {
	return types.RuntimeCapabilities{}, nil
}

func TestWorkspaceServerTiming(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller, auth.RoleClient} {
		t.Run(string(role), func(t *testing.T) {
			reader := dashboard.NewStore(nil, dashboard.WithCapabilityReader(timingCapabilityReader{}))
			// Admin needs its inventory queries; scoped roles can use the store directly.
			var dashboardReader DashboardReader = reader
			if role == auth.RoleAdmin {
				dashboardReader = &fakeDashboardReader{data: dashboard.Data{Customers: []types.Customer{{ID: 88, DisplayName: "Example"}}}}
			}
			handler, _ := newTestHandlerWithOptions(t, role, ServerOptions{DashboardReader: dashboardReader})
			email, password := "admin@nakpanel.test", "NakpanelAdmin!2026"
			if role == auth.RoleClient {
				email, password = "client@nakpanel.test", "NakpanelClient!2026"
			} else if role == auth.RoleReseller {
				email, password = "reseller@nakpanel.test", "NakpanelReseller!2026"
			}
			cookie := login(t, handler, email, password)
			paths := []string{"/dashboard", "/sites"}
			if role == auth.RoleAdmin {
				paths = append(paths, "/support/customers/88/dashboard")
			}
			for _, path := range paths {
				req := httptest.NewRequest(http.MethodGet, "https://panel.test"+path, nil)
				req.AddCookie(cookie)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("GET %s status = %d", path, rec.Code)
				}
				for _, metric := range []string{"caps", "load", "render", "total"} {
					if got := rec.Result().Header.Get("Server-Timing"); !strings.Contains(got, metric+";dur=") {
						t.Errorf("GET %s Server-Timing = %q, missing %s", path, got, metric)
					}
				}
			}
			for _, path := range []string{"/login", "/dashboard", "/support/customers/88/dashboard"} {
				req := httptest.NewRequest(http.MethodGet, "https://panel.test"+path, nil)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if got := rec.Result().Header.Get("Server-Timing"); got != "" {
					t.Errorf("unauthenticated GET %s Server-Timing = %q", path, got)
				}
			}
		})
	}
}
