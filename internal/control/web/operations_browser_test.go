package web

import (
	"encoding/json"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Loopback-only fictional UI fixture. It never mutates a database or calls an agent.
func TestOperationsBrowserPreview(t *testing.T) {
	if os.Getenv("NAKPANEL_OPERATIONS_UI_PREVIEW") != "1" {
		t.Skip("opt-in loopback UI fixture")
	}
	var mu sync.Mutex
	now := time.Now()
	state := "open"
	emailMode := "off"
	emailEnabled := false
	issue := func() operations.Issue {
		return operations.Issue{ID: 9, OperationID: 41, Resource: operations.Resource{Kind: operations.ResourceSite, ID: 51}, ResourceAvailable: true, Kind: "backup", Condition: "protection", Title: "Scheduled backup failed", Target: "studio.example", Summary: "The scheduled backup could not finish. Existing archives are preserved.", Severity: "critical", State: state, Occurrences: 2, ObservedAt: now}
	}
	task := operations.Operation{ID: 41, Title: "Create backup", Target: "studio.example", State: operations.StateFailed, CreatedAt: now, UpdatedAt: now}
	page := func() operations.Page {
		return operations.Page{Counts: operations.Counts{OpenIssues: 2, ActiveTasks: 1, Unread: 3}, CheckedAt: now, Issues: []operations.Issue{issue(), {ID: 10, Kind: "tls", Title: "Certificate expires in 7 days", Target: "shop.example", Severity: "warning", State: "open", ObservedAt: now}}, Tasks: []operations.Operation{task}, Notifications: []operations.Notification{{ID: 17, IssueID: 9, Kind: "operation_failed", Title: "Scheduled backup failed", Severity: "critical", Summary: "Review the issue and its failed attempt.", CreatedAt: now}}, History: []operations.Event{{ID: 1, Summary: "Backup failed", Kind: "task.failed", OperationID: 41, CreatedAt: now}}}
	}
	stop := make(chan struct{})
	var once sync.Once
	mux := http.NewServeMux()
	mux.Handle("/assets/", http.StripPrefix("/assets", StaticHandler()))
	mux.HandleFunc("POST /__stop", func(w http.ResponseWriter, r *http.Request) { once.Do(func() { close(stop) }); w.WriteHeader(204) })
	mux.HandleFunc("/api/workspace/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		var result any = page()
		switch {
		case path == "/api/workspace/tasks":
			result = map[string]any{"active": 1, "items": OperationTaskItems([]operations.Operation{task})}
		case strings.HasSuffix(path, "/events"):
			result = operations.Feed{Events: []operations.Event{}, Cursor: 1}
		case strings.HasSuffix(path, "/preflight"):
			result = map[string]any{"allowed": true, "target": "studio.example", "confirmation": "fixture", "checks": []map[string]any{{"label": "Current ownership and active resource", "passed": true}, {"label": "Backup permission and quota", "passed": true}, {"label": "Agent reachable", "passed": true}}}
		case strings.HasSuffix(path, "/recover"):
			state = "checking"
			result = map[string]int64{"operation_id": 41}
		case strings.HasSuffix(path, "/acknowledge"):
			state = "acknowledged"
			w.WriteHeader(204)
			return
		case strings.HasSuffix(path, "/verify"):
			result = map[string]bool{"queued": true}
			w.WriteHeader(202)
		case strings.HasSuffix(path, "/preferences"):
			if r.Method == "POST" {
				var p struct {
					EmailMode string `json:"email_mode"`
				}
				if json.NewDecoder(r.Body).Decode(&p) != nil {
					w.WriteHeader(400)
					return
				}
				emailMode = p.EmailMode
				w.WriteHeader(204)
				return
			}
			result = map[string]any{"email_mode": emailMode, "delivery_health": "Fixture SMTP is disabled. Your inbox remains available."}
		case strings.HasSuffix(path, "/delivery-policy"):
			if r.Method == "POST" {
				var p struct {
					Enabled bool `json:"enabled"`
				}
				if json.NewDecoder(r.Body).Decode(&p) != nil {
					w.WriteHeader(400)
					return
				}
				emailEnabled = p.Enabled
				w.WriteHeader(204)
				return
			}
			result = map[string]any{"enabled": emailEnabled, "smtp_configured": false}
		case strings.Contains(path, "/issues/"):
			result = DescribeOperationIssue(auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, issue())
		case strings.Contains(path, "/tasks/"):
			result = operations.OperationDetail{Operation: task, Attempts: []operations.Attempt{{ID: 1, Number: 1, State: operations.StateFailed, StartedAt: now, FinishedAt: &now}}}
		case r.Method == "POST":
			w.WriteHeader(204)
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		tab := r.URL.Query().Get("tab")
		if tab == "" {
			tab = "issues"
		}
		p := page()
		if r.URL.Query().Get("notification_task") == "1" {
			p.Notifications[0].IssueID = 0
			p.Notifications[0].OperationID = 41
		}
		view := WorkspaceView{Route: "activity", Tab: tab, OperationsTab: tab, Operations: p, OperationsQuick: p, CSRFToken: "fixture", InstantNavDisabled: true}
		w.Header().Set("Content-Type", "text/html")
		if err := RoutedDashboardPage("Activity · Nakpanel", auth.SessionUser{ID: 1, Role: auth.RoleAdmin, Email: "admin@panel.example"}, dashboard.Data{}, DashboardActions{}, view).Render(r.Context(), w); err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	fmt.Println("OPERATIONS_PREVIEW_URL=" + server.URL)
	select {
	case <-stop:
	case <-time.After(15 * time.Minute):
	}
}
