package panelhttp

import (
	"context"
	"encoding/json"
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
	issue *operations.Issue
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
	if f.issue != nil {
		return *f.issue, f.err
	}
	return operations.Issue{}, operations.ErrNotFound
}

func TestIssueDetailsOfferCurrentRoleSettingsDestinations(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		role                      auth.Role
		resource, kind, condition string
		available                 bool
		want                      string
	}{
		{"site TLS", auth.RoleClient, "site", "tls", "certificate", true, "/sites/51?tab=ssl"},
		{"site backup", auth.RoleClient, "site", "backup", "protection", true, "/sites/51?tab=backups"},
		{"site mail", auth.RoleClient, "site", "mail", "readiness", true, "/sites/51?tab=mail"},
		{"site DNS", auth.RoleClient, "site", "dns", "configuration", true, "/sites/51?tab=dns"},
		{"site runtime", auth.RoleClient, "site", "hosting", "readiness", true, "/sites/51?tab=hosting"},
		{"site tasks", auth.RoleReseller, "site", "operation_failed", "run_scheduled_task:task:9", true, "/sites/51/scheduled-tasks"},
		{"site database", auth.RoleClient, "site", "operation_failed", "create_database:9", true, "/sites/51?tab=databases"},
		{"site application", auth.RoleClient, "site", "operation_failed", "deploy_php_release:9", true, "/sites/51/applications"},
		{"site WordPress", auth.RoleClient, "site", "operation_failed", "wordpress_operation:9", true, "/sites/51/wordpress"},
		{"site import", auth.RoleClient, "site", "operation_failed", "mail_import:fixture", true, "/sites/51?tab=mail-imports"},
		{"subscription backups", auth.RoleClient, "subscription", "backup", "protection", true, "/subscriptions/51?tab=backups"},
		{"server mail", auth.RoleAdmin, "server", "mail", "readiness", true, "/tools-settings/mail"},
		{"server backup", auth.RoleAdmin, "server", "operation_failed", "server_backup:destination:9", true, "/tools-settings/backups"},
		{"customer", auth.RoleReseller, "customer", "quota", "limit", true, "/customers/51"},
		{"customer unavailable to client", auth.RoleClient, "customer", "quota", "limit", true, ""},
		{"personal delivery", auth.RoleClient, "user", "notification_delivery", "smtp", true, "/activity?tab=preferences"},
		{"removed site", auth.RoleAdmin, "site", "tls", "certificate", false, ""},
		{"server unavailable to client", auth.RoleClient, "server", "mail", "readiness", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var issue operations.Issue
			data, _ := json.Marshal(map[string]any{"id": 9, "resource": map[string]any{"kind": tc.resource, "id": 51}, "kind": tc.kind, "condition": tc.condition, "resource_available": tc.available})
			if err := json.Unmarshal(data, &issue); err != nil {
				t.Fatal(err)
			}
			if tc.resource == "server" {
				issue.Resource.ID = 0
			}
			svc := &fakeOperations{issue: &issue}
			h, _ := newTestHandlerWithOptions(t, tc.role, ServerOptions{Operations: svc})
			password := "Nakpanel" + strings.ToUpper(string(tc.role[:1])) + string(tc.role[1:]) + "!2026"
			cookie := login(t, h, string(tc.role)+"@nakpanel.test", password)
			r := httptest.NewRequest("GET", "https://panel.test/api/workspace/operations/issues/9", nil)
			r.AddCookie(cookie)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var got struct {
				SettingsURL         string `json:"settings_url"`
				SettingsLabel       string `json:"settings_label"`
				SettingsUnavailable string `json:"settings_unavailable"`
			}
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.SettingsURL != tc.want || (tc.want != "" && got.SettingsLabel == "") || (tc.want == "" && got.SettingsUnavailable == "") {
				t.Fatalf("settings destination: %+v want %q", got, tc.want)
			}
		})
	}
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
			} else if !strings.Contains(w.Header().Get("Content-Type"), "application/json") || !json.Valid(w.Body.Bytes()) {
				t.Fatal("removed/denied issue is unreadable by the JSON client", w.Body.String())
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
