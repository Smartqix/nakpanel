package panelhttp

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/nakroteck/nakpanel/internal/control/provision"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
)

func (s *Server) handleDeletePlan(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	if s.quotas == nil {
		http.Error(w, "Plan management is not configured", http.StatusServiceUnavailable)
		return
	}
	err = s.quotas.DeletePlan(r.Context(), actor, id)
	if errors.Is(err, provision.ErrForbidden) {
		http.NotFound(w, r)
		return
	}
	if errors.Is(err, controlquota.ErrPlanInUse) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "Could not delete plan", http.StatusInternalServerError)
		return
	}
	s.recordAudit(r.Context(), actor, 0, 0, "plan.deleted", "plan", id, nil)
	http.Redirect(w, r, "/service-plans?type=hosting&notice=plan-deleted", http.StatusSeeOther)
}
