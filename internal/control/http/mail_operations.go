package panelhttp

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/platformadmin"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
)

type phase26DMailReader interface {
	SearchMailQueue(context.Context, auth.SessionUser, platformadmin.MailQueueFilter) (types.MailQueueQueryResult, error)
	InspectQueuedMail(context.Context, auth.SessionUser, string) (types.MailQueueMessage, error)
	ReadMailLogs(context.Context, auth.SessionUser, time.Time, string, int) (types.ReadJournalResult, error)
}

// registerPhase26DMailRoutes is kept separate from Server.Handler so the
// Phase 26 milestones can be integrated without widening the core router.
// Server.Handler should invoke s.registerPhase26DMailRoutes(mux).
func (s *Server) registerPhase26DMailRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /tools-settings/mail/queue", s.handleSearchMailQueue)
	mux.HandleFunc("GET /tools-settings/mail/queue/{id}", s.handleInspectQueuedMail)
	mux.HandleFunc("GET /tools-settings/mail/logs", s.handleReadMailLogs)
}

func (s *Server) handleSearchMailQueue(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	manager, ok := s.mail.(phase26DMailReader)
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Mail queue inspection is unavailable")
		return
	}
	if !mailQueryKeysAllowed(r, "state", "sender_domain", "recipient_domain", "older_than_minutes", "limit") {
		writeSPAError(w, http.StatusBadRequest, "Unsupported mail queue filter")
		return
	}
	filter := platformadmin.MailQueueFilter{
		State:           platformadmin.MailQueueState(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))),
		SenderDomain:    strings.TrimSpace(r.URL.Query().Get("sender_domain")),
		RecipientDomain: strings.TrimSpace(r.URL.Query().Get("recipient_domain")),
		Limit:           50,
	}
	var err error
	if value := strings.TrimSpace(r.URL.Query().Get("older_than_minutes")); value != "" {
		filter.OlderThanMins, err = strconv.Atoi(value)
	}
	if err == nil {
		if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
			filter.Limit, err = strconv.Atoi(value)
		}
	}
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, "Invalid mail queue filter")
		return
	}
	result, err := manager.SearchMailQueue(r.Context(), user, filter)
	if err != nil {
		writeMailOperationsError(w, err, "Mail queue could not be read")
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "queue": result})
}

func (s *Server) handleInspectQueuedMail(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	manager, ok := s.mail.(phase26DMailReader)
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Mail queue inspection is unavailable")
		return
	}
	message, err := manager.InspectQueuedMail(r.Context(), user, r.PathValue("id"))
	if err != nil {
		writeMailOperationsError(w, err, "Queued mail metadata could not be read")
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "message": message})
}

func (s *Server) handleReadMailLogs(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	manager, ok := s.mail.(phase26DMailReader)
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Mail log inspection is unavailable")
		return
	}
	if !mailQueryKeysAllowed(r, "since_minutes", "after_cursor", "limit") {
		writeSPAError(w, http.StatusBadRequest, "Unsupported mail log filter")
		return
	}
	sinceMinutes, limit := 60, 100
	var err error
	if value := strings.TrimSpace(r.URL.Query().Get("since_minutes")); value != "" {
		sinceMinutes, err = strconv.Atoi(value)
	}
	if err == nil {
		if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
			limit, err = strconv.Atoi(value)
		}
	}
	if err != nil || sinceMinutes < 1 || sinceMinutes > 7*24*60 {
		writeSPAError(w, http.StatusBadRequest, "Invalid mail log filter")
		return
	}
	logs, err := manager.ReadMailLogs(
		r.Context(), user, time.Now().UTC().Add(-time.Duration(sinceMinutes)*time.Minute),
		r.URL.Query().Get("after_cursor"), limit,
	)
	if err != nil {
		writeMailOperationsError(w, err, "Mail logs could not be read")
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "logs": logs})
}

func mailQueryKeysAllowed(r *http.Request, allowed ...string) bool {
	registry := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		registry[key] = struct{}{}
	}
	for key := range r.URL.Query() {
		if _, ok := registry[key]; !ok {
			return false
		}
	}
	return true
}

func writeMailOperationsError(w http.ResponseWriter, err error, safeMessage string) {
	switch {
	case errors.Is(err, provision.ErrForbidden):
		writeSPAError(w, http.StatusForbidden, "Forbidden")
	case strings.Contains(strings.ToLower(err.Error()), "invalid"),
		strings.Contains(strings.ToLower(err.Error()), "must be"),
		strings.Contains(strings.ToLower(err.Error()), "unsupported"):
		writeSPAError(w, http.StatusBadRequest, safeMessage)
	default:
		writeSPAError(w, http.StatusBadGateway, safeMessage)
	}
}
