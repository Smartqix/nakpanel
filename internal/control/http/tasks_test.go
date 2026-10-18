package panelhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
)

type fakeTaskDashboard struct {
	fakeDashboardReader
	calls int
}

func (r *fakeTaskDashboard) GetTasks(context.Context) (dashboard.Tasks, error) {
	r.calls++
	return dashboard.Tasks{Active: 5, Items: []dashboard.Job{{ID: 42, Kind: "create_site", State: "discarded", Target: "owned.test", LastError: "last failure", CreatedAt: time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC), FinalizedAt: dashboard.NullableTime{Time: time.Date(2026, 10, 18, 11, 0, 0, 0, time.UTC), Valid: true}}}}, nil
}
func TestTasksContractAndAuthorization(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller, auth.RoleClient} {
		t.Run(string(role), func(t *testing.T) {
			reader := &fakeTaskDashboard{}
			handler, _ := newTestHandlerWithOptions(t, role, ServerOptions{DashboardReader: reader})
			email, password := string(role)+"@nakpanel.test", "Nakpanel"+strings.ToUpper(string(role[:1]))+string(role[1:])+"!2026"
			cookie := login(t, handler, email, password)
			request := func(path string, authenticated bool) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodGet, "https://panel.test"+path, nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("X-Nakpanel-SPA", "true")
				if authenticated {
					addAuthenticatedCookie(req, cookie)
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				return rec
			}
			rec := request("/api/workspace/tasks", true)
			want := http.StatusForbidden
			if role == auth.RoleAdmin {
				want = http.StatusOK
			}
			if rec.Code != want || rec.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
				t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body.String())
			}
			if role == auth.RoleAdmin {
				var payload struct {
					Active int              `json:"active"`
					Items  []map[string]any `json:"items"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
					t.Fatal(err)
				}
				if payload.Active != 5 || len(payload.Items) != 1 || len(payload.Items[0]) != 9 {
					t.Fatalf("payload: %#v", payload)
				}
				item := payload.Items[0]
				for key, want := range map[string]any{"id": float64(42), "kind": "create_site", "label": "Create site", "target": "owned.test", "state": "discarded", "tone": "fail", "created_at": "2026-10-18T10:00:00Z", "finalized_at": "2026-10-18T11:00:00Z", "error": "last failure"} {
					if item[key] != want {
						t.Errorf("%s=%v want %v", key, item[key], want)
					}
				}
			} else if reader.calls != 0 {
				t.Fatal("non-admin read jobs")
			}
			if rec := request("/api/workspace/tasks", false); rec.Code != 401 {
				t.Fatalf("anonymous: %d", rec.Code)
			}
			rec = request("/dashboard", true)
			has := strings.Contains(rec.Body.String(), "data-np-tasks-toggle")
			if rec.Code != 200 || has != (role == auth.RoleAdmin) {
				t.Fatalf("tray for %s: status %d present %v", role, rec.Code, has)
			}
		})
	}
}
