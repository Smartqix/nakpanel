package panelhttp

import (
	"encoding/json"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTasksContractAndAuthorization(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller, auth.RoleClient} {
		t.Run(string(role), func(t *testing.T) {
			service := &fakeOperations{}
			handler, _ := newTestHandlerWithOptions(t, role, ServerOptions{Operations: service, DashboardReader: &fakeDashboardReader{}})
			cookie := login(t, handler, string(role)+"@nakpanel.test", "Nakpanel"+strings.ToUpper(string(role[:1]))+string(role[1:])+"!2026")
			request := func(path string, authenticated bool) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodGet, "https://panel.test"+path, nil)
				r.Header.Set("Accept", "application/json")
				if authenticated {
					addAuthenticatedCookie(r, cookie)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			rec := request("/api/workspace/tasks", true)
			if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("tasks: %d %s", rec.Code, rec.Body.String())
			}
			var payload struct {
				Active int              `json:"active"`
				Items  []map[string]any `json:"items"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Active != 5 || len(payload.Items) != 1 || payload.Items[0]["label"] != "Create backup" || payload.Items[0]["target"] != "owned.example" || payload.Items[0]["state"] != "failed" || service.actor.Role != role {
				t.Fatalf("scoped tasks: %#v", payload)
			}
			if payload.Items[0]["error"] != "" || strings.Contains(rec.Body.String(), "args") {
				t.Fatal("raw worker diagnostics exposed")
			}
			previous := service.calls
			if rec = request("/api/workspace/tasks", false); rec.Code != 401 || service.calls != previous {
				t.Fatal("anonymous read tasks")
			}
		})
	}
}
