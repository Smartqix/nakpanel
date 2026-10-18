package panelhttp

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/web"
)

type taskReader interface {
	GetTasks(context.Context) (dashboard.Tasks, error)
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, ok := s.currentUser(w, r, func() {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
	if !ok {
		return
	}
	if user.Role != auth.RoleAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var tasks dashboard.Tasks
	var err error
	if reader, ok := s.dashboard.(taskReader); ok {
		tasks, err = reader.GetTasks(r.Context())
	} else {
		var data dashboard.Data
		data, err = s.loadDashboard(r.Context(), user)
		tasks = dashboard.Tasks{Active: dashboard.ActiveJobs(data.Jobs), Items: data.Jobs}
	}
	if err != nil {
		http.Error(w, "Could not load tasks", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(struct {
		Active int            `json:"active"`
		Items  []web.TaskItem `json:"items"`
	}{tasks.Active, web.TaskItems(tasks.Items)})
}
