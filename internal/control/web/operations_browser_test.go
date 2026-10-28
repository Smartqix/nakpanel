package web

import (
	"encoding/json"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
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
	fixtureMode := "default"
	notificationReads := map[int64]bool{}
	archived := map[int64]bool{}
	requests := []string{}
	var extra bool
	notifications := func() []operations.Notification {
		items := []operations.Notification{
			{ID: 18, Kind: "login_new_device", Title: "New sign-in address", Severity: "info", Target: "Your account", Summary: "The account owner@studio.example signed in from 203.0.113.24 using a new address.", CreatedAt: now.Add(-5 * time.Minute)},
			{ID: 17, IssueID: 9, Kind: "operation_failed", Title: "Scheduled backup failed", Severity: "critical", Target: "studio.example", Summary: "Review the issue and its failed attempt. Existing archives are preserved.", CreatedAt: now.Add(-22 * time.Minute)},
			{ID: 16, OperationID: 41, Kind: "operation_failed", Title: "Database task finished", Severity: "info", Target: "Studio subscription", Summary: "Open the task to review its result.", CreatedAt: now.Add(-45 * time.Minute)},
			{ID: 15, Kind: "threshold", Title: "Storage threshold", Severity: "warning", Target: "studio.example", Summary: "Storage is approaching the configured warning threshold.", ReadAt: &now, CreatedAt: now.Add(-2 * time.Hour)},
			{ID: 14, Kind: "unknown", Title: "Hosting update", Severity: "info", Target: "Studio subscription", Summary: "Open the affected resource to review its current status.", ReadAt: &now, CreatedAt: now.Add(-3 * time.Hour)},
			{ID: 13, Kind: "threshold", Title: "Traffic threshold", Severity: "warning", Target: "shop.example", Summary: "Review the current monthly traffic usage.", ReadAt: &now, CreatedAt: now.Add(-26 * time.Hour)},
		}
		if fixtureMode == "single" {
			items = items[:1]
		}
		if fixtureMode == "five" {
			items = items[:5]
		}
		if fixtureMode == "empty" {
			items = nil
		}
		if fixtureMode == "long" {
			items[0].Summary = strings.Repeat("Long safe message for very-long-subscription.studio.example and owner@studio.example via 2001:db8:85a3::8a2e:370:7334. ", 16)
			items[0].Target = strings.Repeat("a", 240) + ".example"
		}
		if fixtureMode == "many" {
			for i := int64(19); i <= 62; i++ {
				items = append([]operations.Notification{{ID: i, Kind: "threshold", Title: fmt.Sprintf("Usage update %d", i), Target: "studio.example", Summary: "Safe resource update", CreatedAt: now.Add(-time.Duration(i) * time.Minute)}}, items...)
			}
		}
		if extra {
			items = append([]operations.Notification{{ID: 99, Kind: "threshold", Title: "New update during mark all read", Target: "studio.example", Summary: "This arrived after the previous messages were marked read.", CreatedAt: now}}, items...)
		}
		out := []operations.Notification{}
		for _, n := range items {
			if archived[n.ID] {
				continue
			}
			if notificationReads[n.ID] {
				n.ReadAt = &now
			}
			out = append(out, n)
		}
		return out
	}
	issue := func() operations.Issue {
		return operations.Issue{ID: 9, OperationID: 41, Resource: operations.Resource{Kind: operations.ResourceSite, ID: 51}, ResourceAvailable: true, Kind: "backup", Condition: "protection", Title: "Scheduled backup failed", Target: "studio.example", Summary: "The scheduled backup could not finish. Existing archives are preserved.", Severity: "critical", State: state, Occurrences: 2, ObservedAt: now}
	}
	task := operations.Operation{ID: 41, Title: "Create backup", Target: "studio.example", State: operations.StateFailed, CreatedAt: now, UpdatedAt: now}
	page := func() operations.Page {
		p := operations.Page{Counts: operations.Counts{OpenIssues: 2, ActiveTasks: 1}, CheckedAt: now, Issues: []operations.Issue{issue(), {ID: 10, Kind: "tls", Title: "Certificate expires in 7 days", Target: "shop.example", Severity: "warning", State: "open", ObservedAt: now}}, Tasks: []operations.Operation{task}, Notifications: notifications(), History: []operations.Event{{ID: 1, Summary: "Backup failed", Kind: "task.failed", OperationID: 41, CreatedAt: now}}}
		for _, n := range p.Notifications {
			if n.ReadAt == nil {
				p.Counts.Unread++
			}
		}
		return p
	}
	filteredNotifications := func(p operations.Page, r *http.Request) operations.Page {
		before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 25
		}
		items := []operations.Notification{}
		for _, n := range p.Notifications {
			if before > 0 && n.ID >= before {
				continue
			}
			if r.URL.Query().Get("status") == "unread" && n.ReadAt != nil {
				continue
			}
			query := strings.ToLower(r.URL.Query().Get("q"))
			if query != "" && !strings.Contains(strings.ToLower(n.Title+" "+n.Summary+" "+n.Target), query) {
				continue
			}
			items = append(items, n)
		}
		if len(items) > limit {
			items = items[:limit]
			p.NextBefore = items[len(items)-1].ID
		}
		p.Notifications = items
		return p
	}
	stop := make(chan struct{})
	var once sync.Once
	mux := http.NewServeMux()
	mux.Handle("/assets/", http.StripPrefix("/assets", StaticHandler()))
	mux.HandleFunc("GET /plans/5/sync-status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"synchronization": types.PlanSynchronization{PlanID: 5, Revision: 1, State: "in_sync"}})
	})
	mux.HandleFunc("POST /__stop", func(w http.ResponseWriter, r *http.Request) { once.Do(func() { close(stop) }); w.WriteHeader(204) })
	mux.HandleFunc("POST /__reset", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fixtureMode = r.URL.Query().Get("mode")
		notificationReads = map[int64]bool{}
		archived = map[int64]bool{}
		requests = nil
		extra = false
		state = "open"
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /__state", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"mode": fixtureMode, "requests": requests, "unread": page().Counts.Unread, "issue_state": state})
	})
	mux.HandleFunc("/api/workspace/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		if fixtureMode == "error" && r.Method == "POST" && strings.Contains(path, "/notifications/") {
			w.WriteHeader(503)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Could not save notification status. Try again."})
			return
		}
		if fixtureMode == "offline" || fixtureMode == "session" {
			w.WriteHeader(map[bool]int{true: 401, false: 503}[fixtureMode == "session"])
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Fixture connection unavailable"})
			return
		}
		var result any = page()
		switch {
		case strings.Contains(path, "/notifications/"):
			last := strings.TrimPrefix(path, "/api/workspace/operations/notifications/")
			if last == "read-all" && r.Method == "POST" {
				for _, n := range notifications() {
					notificationReads[n.ID] = true
				}
				if fixtureMode == "race" {
					extra = true
				}
				w.WriteHeader(204)
				return
			}
			parts := strings.Split(last, "/")
			id, _ := strconv.ParseInt(parts[0], 10, 64)
			if r.Method == "POST" {
				if fixtureMode == "error" {
					w.WriteHeader(503)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": "Could not save notification status. Try again."})
					return
				}
				if len(parts) != 2 {
					w.WriteHeader(404)
					return
				}
				switch parts[1] {
				case "read":
					notificationReads[id] = true
				case "archive":
					archived[id] = true
				default:
					w.WriteHeader(404)
					return
				}
				w.WriteHeader(204)
				return
			}
			if fixtureMode == "slow" {
				select {
				case <-time.After(2500 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
			}
			if fixtureMode == "gone" {
				w.WriteHeader(404)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Not found"})
				return
			}
			var found bool
			for _, n := range notifications() {
				if n.ID == id {
					result = n
					found = true
					break
				}
			}
			if !found {
				w.WriteHeader(404)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Not found"})
				return
			}
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
		case path == "/api/workspace/operations":
			result = filteredNotifications(page(), r)
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
			for i := range p.Notifications {
				if p.Notifications[i].ID == 17 {
					p.Notifications[i].IssueID = 0
					p.Notifications[i].OperationID = 41
				}
			}
		}
		quick := p
		if tab == "inbox" {
			p = filteredNotifications(p, r)
		}
		view := WorkspaceView{Route: "activity", Tab: tab, OperationsTab: tab, Operations: p, OperationsQuick: quick, OperationsInbox: quick, SearchQuery: r.URL.Query().Get("q"), StatusFilter: r.URL.Query().Get("status"), CSRFToken: "fixture", InstantNavDisabled: os.Getenv("NAKPANEL_OPERATIONS_UI_NAVIGATION") != "1"}
		if strings.HasPrefix(r.URL.Path, "/support/customers/10/") {
			view.SupportCustomerID = 10
			view.SupportCustomerName = "Studio"
		}
		if value := r.URL.Query().Get("subscription_id"); value != "" {
			view.SelectedSubscription, _ = strconv.ParseInt(value, 10, 64)
		}
		data := dashboard.Data{}
		if r.URL.Path == "/service-plans/5" {
			plan := planEditorDefault(types.RuntimeCapabilities{PHPVersions: []string{"8.4"}})
			plan.ID = 5
			plan.Name = "Business"
			data.Plans = []quota.Plan{plan}
			view.Route = "plan-detail"
			view.DetailID = 5
			view.PlanTab = "overview"
		}
		if strings.HasPrefix(r.URL.Path, "/sites/51") {
			data.Sites = []dashboard.Site{{ID: 51, SubscriptionID: 42, Domain: "studio.example", Status: "active", PHPVersion: "8.4"}}
			data.Subscriptions = []types.SubscriptionSummary{{ID: 42, PrimarySiteID: 51, CustomerID: 10, CustomerName: "Studio", SubscriptionName: "Studio", PlanName: "Business", Status: "active"}}
			view.Route = "site-detail"
			view.DetailID = 51
			view.Tab = r.URL.Query().Get("tab")
		}
		actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin, Email: "admin@panel.example"}
		if role := auth.Role(r.URL.Query().Get("fixture_role")); role == auth.RoleClient || role == auth.RoleReseller {
			actor.Role = role
			actor.ID = 11
			actor.Email = "owner@studio.example"
		}
		w.Header().Set("Content-Type", "text/html")
		if r.Header.Get("X-Nakpanel-Fragment") == "main" {
			if err := RoutedFragment("Activity · Nakpanel", actor, data, DashboardActions{}, view).Render(r.Context(), w); err != nil {
				t.Error(err)
			}
			return
		}
		if err := RoutedDashboardPage("Activity · Nakpanel", actor, data, DashboardActions{}, view).Render(r.Context(), w); err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	fmt.Println("OPERATIONS_PREVIEW_URL=" + server.URL)
	select {
	case <-stop:
	case <-time.After(time.Hour):
	}
}
