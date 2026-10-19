package panelhttp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
)

type planPHPVersionsManager interface {
	PreviewPlanPHPVersions(context.Context, auth.SessionUser, int64, controlquota.PlanPHPVersionsInput) (controlquota.PlanPHPVersionsPreview, error)
	UpdatePlanPHPVersions(context.Context, auth.SessionUser, int64, controlquota.PlanPHPVersionsInput) (controlquota.PlanPHPVersionsResult, error)
}

func isPlanPHPVersionsRequest(r *http.Request) bool {
	parts := strings.Split(r.URL.Path, "/")
	return r.Method == http.MethodPost && (len(parts) == 4 || len(parts) == 5 && parts[4] == "preview") && parts[0] == "" && parts[1] == "plans" && parts[3] == "php-versions"
}

// Only the fixed, sanitized API envelopes may cross the generic 5xx UI mapper.
// Raw database errors, extra fields and recovered panics retain its protection.
func isSafePlanPHPFailure(r *http.Request, status int, body []byte) bool {
	if !isPlanPHPVersionsRequest(r) {
		return false
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(body, &value) != nil || len(value) != 3 || string(value["ok"]) != "false" {
		return false
	}
	var code, message string
	if json.Unmarshal(value["code"], &code) != nil || json.Unmarshal(value["error"], &message) != nil {
		return false
	}
	canonical, err := json.Marshal(map[string]any{"ok": false, "code": code, "error": message})
	if err != nil || !bytes.Equal(bytes.TrimSpace(body), canonical) {
		return false
	}
	switch code {
	case "unavailable":
		return status == 503 && (message == "Plan operation is unavailable" || message == "PHP plan maintenance is unavailable")
	case "readiness_unavailable":
		return status == 503 && message == "Authoritative PHP readiness is unavailable"
	case "plan_timeout":
		return status == 503 && message == "Plan operation exceeded its deadline"
	case "revision_integrity":
		return status == 500 && message == "Plan revision integrity check failed"
	}
	return false
}

func parsePlanPHPVersions(r *http.Request) (controlquota.PlanPHPVersionsInput, error) {
	invalid := errors.New("expected_revision, repeated php_versions, default_php_version and change_reason are the only accepted operation fields")
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		return controlquota.PlanPHPVersionsInput{}, invalid
	}
	if err = r.ParseForm(); err != nil {
		return controlquota.PlanPHPVersionsInput{}, invalid
	}
	for key, values := range r.PostForm {
		switch key {
		case "php_versions":
		case "expected_revision", "default_php_version", "change_reason", "csrf_token":
			if len(values) != 1 {
				return controlquota.PlanPHPVersionsInput{}, invalid
			}
		default:
			return controlquota.PlanPHPVersionsInput{}, invalid
		}
	}
	for _, key := range []string{"expected_revision", "default_php_version", "change_reason"} {
		if len(r.PostForm[key]) != 1 {
			return controlquota.PlanPHPVersionsInput{}, invalid
		}
	}
	revision, err := strconv.ParseInt(r.PostForm.Get("expected_revision"), 10, 32)
	if err != nil {
		return controlquota.PlanPHPVersionsInput{}, invalid
	}
	return controlquota.NormalizePlanPHPVersions(controlquota.PlanPHPVersionsInput{ExpectedRevision: int(revision), PHPVersions: r.PostForm["php_versions"], DefaultPHPVersion: r.PostForm.Get("default_php_version"), ChangeReason: r.PostForm.Get("change_reason")})
}

func (s *Server) handlePreviewPlanPHPVersions(w http.ResponseWriter, r *http.Request) {
	s.handlePlanPHPVersions(w, r, true)
}
func (s *Server) handleUpdatePlanPHPVersions(w http.ResponseWriter, r *http.Request) {
	s.handlePlanPHPVersions(w, r, false)
}

func (s *Server) handlePlanPHPVersions(w http.ResponseWriter, r *http.Request, preview bool) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	input, err := parsePlanPHPVersions(r)
	if err != nil {
		writePlanPHPError(w, http.StatusBadRequest, "invalid_php_versions", err.Error(), 0)
		return
	}
	manager, ok := s.quotas.(planPHPVersionsManager)
	if !ok {
		writePlanPHPError(w, 503, "unavailable", "PHP plan maintenance is unavailable", 0)
		return
	}
	if preview {
		view, err := manager.PreviewPlanPHPVersions(r.Context(), actor, id, input)
		if err != nil {
			writePlanPHPFailure(w, err)
			return
		}
		if view.Blockers == nil {
			view.Blockers = []controlquota.PlanPHPBlocker{}
		}
		writeSPAJSON(w, 200, map[string]any{"ok": true, "plan_id": view.PlanID, "revision": view.Revision, "no_change": view.NoChange, "preview": view.Preview, "blockers": view.Blockers})
		return
	}
	result, err := manager.UpdatePlanPHPVersions(r.Context(), actor, id, input)
	if err != nil {
		writePlanPHPFailure(w, err)
		return
	}
	writeSPAJSON(w, 200, map[string]any{"ok": true, "plan_id": result.PlanID, "revision": result.Revision, "changed": result.Changed, "sync_state": result.SyncState})
}

func writePlanPHPError(w http.ResponseWriter, status int, code, message string, current int) {
	response := map[string]any{"ok": false, "code": code, "error": message}
	if current > 0 {
		response["current_revision"] = current
	}
	writeSPAJSON(w, status, response)
}

func writePlanPHPFailure(w http.ResponseWriter, err error) {
	var conflict *controlquota.PlanPHPConflictError
	var readiness *controlquota.PlanPHPReadinessError
	var integrity *controlquota.PlanPHPIntegrityError
	var rejected *controlquota.PlanPHPRejectedError
	var state interface{ SQLState() string }
	switch {
	case errors.Is(err, provision.ErrForbidden) || errors.Is(err, controlquota.ErrProviderScope) || errors.Is(err, sql.ErrNoRows):
		writePlanPHPError(w, 404, "not_found", "Plan is unavailable", 0)
	case errors.As(err, &conflict):
		writePlanPHPError(w, 409, string(conflict.Code), "Plan changed, is busy, or has unfinished synchronization; refresh before retrying", conflict.CurrentRevision)
	case errors.As(err, &readiness):
		if readiness.Cause != nil {
			writePlanPHPError(w, 503, "readiness_unavailable", "Authoritative PHP readiness is unavailable", 0)
		} else {
			writePlanPHPError(w, 400, "php_version_unready", readiness.Error(), 0)
		}
	case errors.As(err, &integrity):
		writePlanPHPError(w, 500, "revision_integrity", "Plan revision integrity check failed", 0)
	case errors.As(err, &rejected) || errors.Is(err, controlquota.ErrResellerCapacity) || errors.Is(err, controlquota.ErrOversellCap) || errors.Is(err, controlquota.ErrSubscriptionTerminating):
		writePlanPHPError(w, 400, "plan_rejected", err.Error(), 0)
	case errors.Is(err, context.DeadlineExceeded):
		writePlanPHPError(w, 503, "plan_timeout", "Plan operation exceeded its deadline", 0)
	case errors.As(err, &state):
		if state.SQLState() == "57014" {
			writePlanPHPError(w, 503, "plan_timeout", "Plan operation exceeded its deadline", 0)
		} else {
			writePlanPHPError(w, 503, "unavailable", "Plan operation is unavailable", 0)
		}
	default:
		writePlanPHPError(w, 503, "unavailable", "Plan operation is unavailable", 0)
	}
}
