package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

// Fictional, loopback-only UI fixture. Database and authorization behavior is
// covered by the HTTP and PostgreSQL deletion tests.
func TestPlanDeletionBrowserPreview(t *testing.T) {
	if os.Getenv("NAKPANEL_PLAN_DELETE_UI_PREVIEW") != "1" {
		t.Skip("opt-in loopback plan deletion fixture")
	}
	var mu sync.Mutex
	deleted := map[int64]int{}
	stop := make(chan struct{})
	var once sync.Once
	mux := http.NewServeMux()
	mux.Handle("/assets/", http.StripPrefix("/assets", StaticHandler()))
	mux.HandleFunc("POST /__stop", func(w http.ResponseWriter, r *http.Request) { once.Do(func() { close(stop) }); w.WriteHeader(204) })
	mux.HandleFunc("GET /__state", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(deleted)
	})
	mux.HandleFunc("POST /__reset", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		deleted = map[int64]int{}
		mu.Unlock()
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /plans/{id}/delete", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || (id != 42 && id != 43) {
			http.Error(w, "invalid fixture plan", 400)
			return
		}
		if err = r.ParseForm(); err != nil || r.Form.Get("csrf_token") != "fixture-token" {
			http.Error(w, "missing CSRF token", 403)
			return
		}
		mu.Lock()
		deleted[id]++
		mu.Unlock()
		http.Redirect(w, r, "/service-plans?notice=plan-deleted", 303)
	})
	mux.HandleFunc("GET /plans/{id}/sync-status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true,"synchronization":{"state":"in_sync","subscriptions":[]}}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		data := dashboard.Data{Subscriptions: []types.SubscriptionSummary{{ID: 9, PlanID: 44, Status: "suspended"}}}
		for _, plan := range []controlquota.Plan{{ID: 42, Name: "Unused list plan", LifecycleStatus: types.PlanLifecycleDraft}, {ID: 43, Name: "Unused detail plan", LifecycleStatus: types.PlanLifecycleActive}, {ID: 44, Name: "Used plan", LifecycleStatus: types.PlanLifecycleRetired}} {
			if deleted[plan.ID] == 0 {
				data.Plans = append(data.Plans, plan)
			}
		}
		view := WorkspaceView{Route: "service-plans", CSRFToken: "fixture-token", InstantNavDisabled: r.URL.Query().Get("native") == "1"}
		if r.URL.Path == "/service-plans/43" {
			view.Route = "plan-detail"
			view.DetailID = 43
		}
		if r.URL.Query().Get("notice") == "plan-deleted" {
			data.Notice = "Plan deleted."
			data.NoticeKind = dashboard.NoticeSuccess
		}
		user := auth.SessionUser{ID: 1, Role: auth.RoleAdmin, Email: "admin@fixture.example"}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		var err error
		if r.Header.Get("X-Nakpanel-Fragment") == "main" {
			err = RoutedFragment("Service Plans", user, data, DashboardActions{}, view).Render(r.Context(), w)
		} else {
			err = RoutedDashboardPage("Service Plans", user, data, DashboardActions{}, view).Render(r.Context(), w)
		}
		if err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	fmt.Println("PLAN_DELETE_PREVIEW_URL=" + server.URL)
	select {
	case <-stop:
	case <-time.After(5 * time.Minute):
		t.Fatal("plan deletion preview timed out")
	}
}
