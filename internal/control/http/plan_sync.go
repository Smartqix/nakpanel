package panelhttp

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (s *Server) handlePlanSynchronization(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	reader, ok := s.quotas.(interface {
		PlanSynchronization(context.Context, auth.SessionUser, int64) (types.PlanSynchronization, error)
	})
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Plan synchronization is unavailable")
		return
	}
	view, err := reader.PlanSynchronization(r.Context(), actor, id)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, provision.ErrForbidden) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeSPAError(w, http.StatusServiceUnavailable, "Could not load plan synchronization")
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "synchronization": view})
}
