package panelhttp

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeOperations struct {
	OperationsService
	actor auth.SessionUser
	calls int
	err   error
}

func (f *fakeOperations) Page(_ context.Context, a auth.SessionUser, _ string, _ operations.Filter) (operations.Page, error) {
	f.actor = a
	f.calls++
	return operations.Page{Counts: operations.Counts{ActiveTasks: 5}, Tasks: []operations.Operation{{ID: 42, Kind: "create_backup", Title: "Create backup", Target: "owned.example", State: operations.StateFailed}}}, f.err
}
func (f *fakeOperations) Feed(_ context.Context, a auth.SessionUser, _ int64, _ operations.Filter) (operations.Feed, error) {
	f.actor = a
	f.calls++
	return operations.Feed{Events: []operations.Event{}, Cursor: 12}, f.err
}
func (f *fakeOperations) Issue(_ context.Context, a auth.SessionUser, _ int64) (operations.Issue, error) {
	f.actor = a
	f.calls++
	return operations.Issue{}, operations.ErrNotFound
}
func (f *fakeOperations) MarkNotificationRead(_ context.Context, a auth.SessionUser, _ int64) error {
	f.actor = a
	f.calls++
	return f.err
}

func TestOperationsEndpointsAuthenticateAndBindTheViewer(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller, auth.RoleClient} {
		t.Run(string(role), func(t *testing.T) {
			service := &fakeOperations{}
			h, _ := newTestHandlerWithOptions(t, role, ServerOptions{Operations: service})
			cookie := login(t, h, string(role)+"@nakpanel.test", "Nakpanel"+strings.ToUpper(string(role[:1]))+string(role[1:])+"!2026")
			call := func(method, path string, authenticated, csrf bool) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, "https://panel.test"+path, nil)
				r.Header.Set("Accept", "application/json")
				if authenticated {
					r.AddCookie(cookie)
				}
				if csrf {
					r.Header.Set("X-Nakpanel-CSRF", csrfToken(r))
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			for _, path := range []string{"/api/workspace/operations?view=issues", "/api/workspace/operations/events?after=0", "/api/workspace/tasks"} {
				w := call("GET", path, true, false)
				if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || service.actor.Role != role || service.actor.ID <= 0 {
					t.Fatalf("%s role %s: %d %s", path, role, w.Code, w.Body.String())
				}
			}
			previous := service.calls
			if w := call("GET", "/api/workspace/operations", false, false); w.Code != 401 || service.calls != previous {
				t.Fatal("unauthenticated operations query")
			}
			if w := call("GET", "/api/workspace/operations?resource_id=42", true, false); w.Code != 400 {
				t.Fatal("ambiguous scope accepted")
			}
			if w := call("GET", "/api/workspace/operations?limit=201", true, false); w.Code != 400 {
				t.Fatal("unbounded page accepted")
			}
			if w := call("GET", "/api/workspace/operations/issues/99", true, false); w.Code != 404 {
				t.Fatal("foreign issue was not hidden")
			}
			if w := call("POST", "/api/workspace/operations/notifications/1/read", true, false); w.Code != 403 {
				t.Fatalf("receipt mutation without CSRF: %d", w.Code)
			}
			if w := call("POST", "/api/workspace/operations/notifications/1/read", true, true); w.Code != 204 {
				t.Fatalf("receipt: %d %s", w.Code, w.Body.String())
			}
			service.err = errors.New("database password=do-not-show")
			if w := call("GET", "/api/workspace/operations", true, false); w.Code != 503 || strings.Contains(w.Body.String(), "do-not-show") {
				t.Fatal("internal diagnostic exposed")
			}
		})
	}
}
