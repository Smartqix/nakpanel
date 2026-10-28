package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

// Fictional loopback fixture for real templates, menu controls, Tasks and
// navigation. It never connects to a database, agent or installed service.
func TestServicesBrowserPreview(t *testing.T) {
	if os.Getenv("NAKPANEL_SERVICES_UI_PREVIEW") != "1" {
		t.Skip("opt-in loopback service controls fixture")
	}
	var mu sync.Mutex
	var once sync.Once
	stop := make(chan struct{})
	mode := "normal"
	reauth := false
	accepted := 0
	items := []serveradmin.ServiceOperation{}
	services := []types.ManagedService{}
	for _, item := range []struct{ id, name string }{{"web", "nginx"}, {"dns", "BIND"}, {"mail", "Stalwart Mail"}, {"php-8.3", "PHP 8.3 FPM"}, {"php-8.4", "PHP 8.4 FPM"}, {"php-8.5", "PHP 8.5 FPM"}} {
		services = append(services, types.ManagedService{ID: item.id, DisplayName: item.name, Available: true, LoadState: "loaded", ActiveState: "active", SubState: "running", UnitFileState: "enabled", MainPID: 100, AllowedActions: []string{"reload", "restart", "start", "stop"}})
	}
	page := func() operations.Page {
		p := operations.Page{CheckedAt: time.Now(), Tasks: []operations.Operation{}, Notifications: []operations.Notification{}, Issues: []operations.Issue{}, History: []operations.Event{}}
		for _, item := range items {
			state := operations.State(item.Status)
			if item.Status == serveradmin.OperationPending {
				state = operations.StateQueued
			}
			if !state.Terminal() {
				p.Counts.ActiveTasks++
			}
			name := item.ServiceID
			for _, svc := range services {
				if svc.ID == item.ServiceID {
					name = svc.DisplayName
				}
			}
			verb := map[string]string{"restart": "Restart", "reload": "Reload", "start": "Start", "stop": "Stop"}[item.Action]
			p.Tasks = append(p.Tasks, operations.Operation{ID: item.TaskID, Kind: "system_control_service", Title: verb + " " + name, Resource: operations.Resource{Kind: operations.ResourceServer}, Target: "Server", Trigger: "manual", State: state, Stage: item.Stage, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt})
		}
		return p
	}
	mux := http.NewServeMux()
	mux.Handle("/assets/", http.StripPrefix("/assets", StaticHandler()))
	jsonOut := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("POST /__stop", func(w http.ResponseWriter, r *http.Request) { once.Do(func() { close(stop) }); w.WriteHeader(204) })
	mux.HandleFunc("POST /__fixture", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var in struct {
			Mode          string
			Reset, Reauth bool
			Status, Stage string
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			w.WriteHeader(400)
			return
		}
		if in.Reset {
			items = nil
			accepted = 0
			mode = "normal"
			for i := range services {
				services[i].ActiveState = "active"
				services[i].SubState = "running"
			}
		}
		if in.Mode != "" {
			mode = in.Mode
		}
		reauth = in.Reauth
		if in.Status != "" && len(items) > 0 {
			items[0].Status = serveradmin.OperationStatus(in.Status)
			items[0].Stage = in.Stage
			items[0].UpdatedAt = time.Now()
			if in.Status == "succeeded" {
				now := time.Now()
				items[0].CompletedAt = &now
				items[0].DurationMS = 123
				for i := range services {
					if services[i].ID == items[0].ServiceID {
						if items[0].Action == "stop" {
							services[i].ActiveState = "inactive"
							services[i].SubState = "dead"
						} else {
							services[i].ActiveState = "active"
							services[i].SubState = "running"
						}
					}
				}
			}
		}
		jsonOut(w, map[string]any{"accepted": accepted, "operations": items})
	})
	mux.HandleFunc("GET /__state", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		jsonOut(w, map[string]any{"accepted": accepted, "operations": items})
	})
	mux.HandleFunc("GET /tools-settings/inventory", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		jsonOut(w, map[string]any{"ok": true, "inventory": types.ServerInventory{Hostname: "services.fixture.example", Status: types.ServerStateHealthy, CheckedAt: time.Now(), Services: services}})
	})
	mux.HandleFunc("GET /tools-settings/services/operations", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		copy := append([]serveradmin.ServiceOperation{}, items...)
		jsonOut(w, map[string]any{"ok": true, "operations": copy})
	})
	mux.HandleFunc("POST /tools-settings/reauthenticate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		if r.ParseForm() != nil || r.Form.Get("password") != "fixture-password" {
			w.WriteHeader(401)
			jsonOut(w, map[string]any{"ok": false, "error": "Password verification failed"})
			return
		}
		reauth = false
		jsonOut(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /tools-settings/services/action", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		if r.ParseForm() != nil || r.Form.Get("service_id") == "" || r.Form.Get("action") == "" || r.Header.Get("X-Nakpanel-CSRF") != "fixture-token" {
			w.WriteHeader(400)
			jsonOut(w, map[string]any{"ok": false, "error": "Invalid service form"})
			return
		}
		if reauth {
			w.WriteHeader(428)
			jsonOut(w, map[string]any{"ok": false, "error": "Recent authentication is required"})
			return
		}
		if mode == "reject" {
			w.WriteHeader(400)
			jsonOut(w, map[string]any{"ok": false, "error": "Configuration validation failed"})
			return
		}
		accepted++
		now := time.Now()
		item := serveradmin.ServiceOperation{OperationID: fmt.Sprintf("op_fixture_service_%020d", accepted), TaskID: int64(40 + accepted), ServiceID: r.Form.Get("service_id"), Action: r.Form.Get("action"), Status: serveradmin.OperationPending, CreatedAt: now, UpdatedAt: now}
		if mode == "fast" {
			item.Status = serveradmin.OperationSucceeded
			item.CompletedAt = &now
		}
		items = append([]serveradmin.ServiceOperation{item}, items...)
		w.WriteHeader(202)
		jsonOut(w, map[string]any{"ok": true, "result": item})
	})
	mux.HandleFunc("/api/workspace/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p := page()
		switch r.URL.Path {
		case "/api/workspace/tasks":
			jsonOut(w, map[string]any{"active": p.Counts.ActiveTasks, "items": OperationTaskItems(p.Tasks), "cursor": 0})
		case "/api/workspace/operations/events":
			jsonOut(w, operations.Feed{Events: []operations.Event{}, Cursor: 0})
		case "/api/workspace/operations":
			jsonOut(w, p)
		default:
			if len(p.Tasks) > 0 {
				op := p.Tasks[0]
				attempts := []operations.Attempt{}
				if op.State != operations.StateQueued {
					attempts = append(attempts, operations.Attempt{Number: 1, State: op.State, StartedAt: op.CreatedAt, FinishedAt: items[0].CompletedAt})
				}
				jsonOut(w, operations.OperationDetail{Operation: op, Attempts: attempts})
			} else {
				w.WriteHeader(404)
			}
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		view := WorkspaceView{Route: "tools-settings", SettingsFocus: "services", CSRFToken: "fixture-token", Operations: page(), OperationsQuick: page()}
		if r.URL.Path == "/dashboard" {
			view.Route = "dashboard"
			view.SettingsFocus = ""
		}
		if r.URL.Path == "/activity" {
			view.Route = "activity"
			view.SettingsFocus = ""
			view.OperationsTab = "tasks"
		}
		user := auth.SessionUser{ID: 1, Role: auth.RoleAdmin, Email: "admin@fixture.example"}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		var err error
		if r.Header.Get("X-Nakpanel-Fragment") == "main" {
			err = RoutedFragment("Services fixture", user, dashboard.Data{}, DashboardActions{}, view).Render(r.Context(), w)
		} else {
			err = RoutedDashboardPage("Services fixture", user, dashboard.Data{}, DashboardActions{}, view).Render(r.Context(), w)
		}
		if err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	fmt.Println("SERVICES_PREVIEW_URL=" + server.URL)
	select {
	case <-stop:
	case <-time.After(20 * time.Minute):
		t.Fatal("service fixture timed out")
	}
}
