package panelhttp

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"github.com/nakroteck/nakpanel/internal/control/provision"
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

type recoveryOperations struct {
	fakeOperations
	confirms  string
	recovered bool
}

func (f *recoveryOperations) Preflight(context.Context, auth.SessionUser, int64) (provision.RecoveryPreflight, error) {
	return provision.RecoveryPreflight{Allowed: true, Confirmation: "fresh"}, nil
}
func (f *recoveryOperations) Recover(_ context.Context, _ auth.SessionUser, _ int64, c string) (provision.RecoveryStarted, error) {
	f.confirms = c
	f.recovered = true
	return provision.RecoveryStarted{OperationID: 42}, nil
}
func (f *recoveryOperations) RequestVerification(context.Context, auth.SessionUser, int64) error {
	return nil
}
func TestOperationsRecoveryRequiresAdminConfirmationAndCSRF(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleClient} {
		t.Run(string(role), func(t *testing.T) {
			svc := &recoveryOperations{}
			h, _ := newTestHandlerWithOptions(t, role, ServerOptions{Operations: svc})
			password := "NakpanelAdmin!2026"
			if role == auth.RoleClient {
				password = "NakpanelClient!2026"
			}
			cookie := login(t, h, string(role)+"@nakpanel.test", password)
			for _, tc := range []struct {
				body   string
				csrf   bool
				status int
			}{{`{"confirmation":"fresh","confirmed":true}`, false, 403}, {`{"confirmation":"fresh"}`, true, 400}, {`{"confirmation":"fresh","confirmed":true}`, true, 202}} {
				r := httptest.NewRequest("POST", "https://panel.test/api/workspace/operations/issues/7/recover", strings.NewReader(tc.body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Accept", "application/json")
				r.AddCookie(cookie)
				if tc.csrf {
					r.Header.Set("X-Nakpanel-CSRF", csrfToken(r))
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				want := tc.status
				if role == auth.RoleClient && tc.csrf {
					want = 404
				}
				if w.Code != want {
					t.Fatalf("status=%d want=%d %s", w.Code, want, w.Body.String())
				}
			}
			if role == auth.RoleClient && svc.recovered {
				t.Fatal("client triggered recovery")
			}
		})
	}
}

type preferencesOperations struct {
	fakeOperations
	mode    string
	enabled bool
}

func (f *preferencesOperations) Preferences(context.Context, auth.SessionUser) (operations.Preferences, error) {
	return operations.Preferences{EmailMode: f.mode, CriticalInApp: true, SecurityInApp: true}, nil
}
func (f *preferencesOperations) SavePreferences(_ context.Context, _ auth.SessionUser, p operations.Preferences) error {
	f.mode = p.EmailMode
	return nil
}
func (f *preferencesOperations) DeliveryPolicy(context.Context, auth.SessionUser) (operations.DeliveryPolicy, error) {
	return operations.DeliveryPolicy{Enabled: f.enabled}, nil
}
func (f *preferencesOperations) SaveDeliveryPolicy(_ context.Context, _ auth.SessionUser, p operations.DeliveryPolicy) error {
	f.enabled = p.Enabled
	return nil
}
func TestOperationsPreferenceMutationsCannotDisableMandatoryInbox(t *testing.T) {
	svc := &preferencesOperations{}
	h, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{Operations: svc})
	cookie := login(t, h, "admin@nakpanel.test", "NakpanelAdmin!2026")
	for _, tc := range []struct {
		path, body string
		code       int
	}{{"preferences", `{"email_mode":"digest","critical_in_app":false}`, 400}, {"delivery-policy", `{}`, 400}, {"preferences", `{"email_mode":"digest"}`, 204}, {"delivery-policy", `{"enabled":true}`, 204}} {
		r := httptest.NewRequest("POST", "https://panel.test/api/workspace/operations/"+tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json")
		r.AddCookie(cookie)
		r.Header.Set("X-Nakpanel-CSRF", csrfToken(r))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatal(tc.path, w.Code, w.Body.String())
		}
	}
	if svc.mode != "digest" || !svc.enabled {
		t.Fatal("policy not persisted")
	}
}
