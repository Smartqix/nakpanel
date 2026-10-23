package panelhttp

import (
	"encoding/json"
	"github.com/nakroteck/nakpanel/internal/control/web"
	"net/http"
)

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.operationsUser(w, r)
	if !ok {
		return
	}
	f, err := operationsFilter(r)
	if err != nil {
		operationsError(w, err)
		return
	}
	f.Limit = 8
	f.ActiveFirst = true
	p, err := s.operations.Page(r.Context(), actor, "tasks", f)
	if err != nil {
		operationsError(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		Active int            `json:"active"`
		Items  []web.TaskItem `json:"items"`
		Cursor int64          `json:"cursor"`
	}{p.Counts.ActiveTasks, web.OperationTaskItems(p.Tasks), p.Cursor})
}
