package panelhttp

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

var serverJournalSources = map[string]struct{}{
	"panel": {}, "agent": {}, "web": {}, "dns": {}, "mail": {},
	"database": {}, "system": {},
}

type serverAdminCoreReader interface {
	ReadJournal(context.Context, types.ReadJournalReq) (types.ReadJournalResult, error)
	InspectUpdates(context.Context) (types.UpdateState, error)
}

type serverAdminUpdateQueue interface {
	InspectUpdates(context.Context) (types.UpdateState, error)
	ApplyUpdates(context.Context, types.ApplyUpdatesReq, int64) error
}

// registerPhase26CoreRoutes is kept separate so Phase 26 can be merged with
// concurrent route work using one registration call from Server.Handler.
func (s *Server) registerPhase26CoreRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /tools-settings/updates", s.handleServerAdminWorkspace)
	mux.HandleFunc("GET /tools-settings/journal", s.handleServerJournal)
	mux.HandleFunc("GET /tools-settings/updates/inventory", s.handleServerUpdateInventory)
	mux.HandleFunc("POST /tools-settings/updates/dry-run", s.handleServerUpdateDryRun)
}

func (s *Server) handleServerJournal(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	reader, ok := s.serverAdmin.(serverAdminCoreReader)
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Server journal access is unavailable")
		return
	}
	req, err := parseServerJournalRequest(r)
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, "Invalid journal request")
		return
	}
	result, err := reader.ReadJournal(r.Context(), req)
	if err != nil {
		writeSPAError(w, http.StatusBadGateway, "Server journal could not be read")
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

func (s *Server) handleServerUpdateInventory(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	reader, ok := s.serverAdmin.(serverAdminCoreReader)
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Server update inspection is unavailable")
		return
	}
	state, err := reader.InspectUpdates(r.Context())
	if err != nil {
		writeSPAError(w, http.StatusBadGateway, "Server updates could not be inspected")
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "updates": state})
}

func (s *Server) handleServerUpdateDryRun(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	queue, ok := s.serverAdmin.(serverAdminUpdateQueue)
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Server update inspection is unavailable")
		return
	}
	if err := rejectUpdateDryRunFields(r); err != nil {
		writeSPAError(w, http.StatusBadRequest, "Invalid update dry-run request")
		return
	}
	state, err := queue.InspectUpdates(r.Context())
	if err != nil {
		writeSPAError(w, http.StatusBadGateway, "Server updates could not be inspected")
		return
	}
	names := make([]string, 0, len(state.Packages))
	packages := make([]types.UpdatePackage, 0, len(state.Packages))
	for _, item := range state.Packages {
		if item.Name == "" || item.Held {
			continue
		}
		names = append(names, item.Name)
		packages = append(packages, item)
	}
	if len(names) == 0 {
		writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "updates": state, "dry_run": true})
		return
	}
	operationID, err := newServerAdminOperationID()
	if err != nil {
		writeSPAError(w, http.StatusInternalServerError, "Could not start update simulation")
		return
	}
	if err := queue.ApplyUpdates(r.Context(), types.ApplyUpdatesReq{
		PackageNames: names,
		Packages:     packages,
		DryRun:       true,
		OperationID:  operationID,
	}, user.ID); err != nil {
		if errors.Is(err, serveradmin.ErrOperationInProgress) {
			writeSPAError(w, http.StatusConflict, "A package operation is already active")
			return
		}
		writeSPAError(w, http.StatusBadGateway, "Server update simulation could not be queued")
		return
	}
	writeSPAJSON(w, http.StatusAccepted, map[string]any{
		"ok": true, "operation_id": operationID, "dry_run": true,
	})
}

func parseServerJournalRequest(r *http.Request) (types.ReadJournalReq, error) {
	query := r.URL.Query()
	for key := range query {
		switch key {
		case "source", "hours", "limit", "priority":
		default:
			return types.ReadJournalReq{}, errors.New("unknown journal query field")
		}
	}

	sources := query["source"]
	if len(sources) == 0 {
		sources = []string{"panel", "agent"}
	}
	if len(sources) > len(serverJournalSources) {
		return types.ReadJournalReq{}, errors.New("too many journal sources")
	}
	seen := make(map[string]struct{}, len(sources))
	normalizedSources := make([]string, 0, len(sources))
	for _, source := range sources {
		source = strings.ToLower(strings.TrimSpace(source))
		if _, allowed := serverJournalSources[source]; !allowed {
			return types.ReadJournalReq{}, errors.New("journal source is not allowed")
		}
		if _, exists := seen[source]; !exists {
			seen[source] = struct{}{}
			normalizedSources = append(normalizedSources, source)
		}
	}

	hours, err := registeredPositiveInt(query.Get("hours"), 1, 6, 24, 168, 720)
	if err != nil {
		return types.ReadJournalReq{}, err
	}
	if hours == 0 {
		hours = 1
	}
	limit, err := registeredPositiveInt(query.Get("limit"), 25, 50, 100, 200, 500, 1000)
	if err != nil {
		return types.ReadJournalReq{}, err
	}
	if limit == 0 {
		limit = 200
	}

	var priorities []int
	if values := query["priority"]; len(values) > 0 {
		if len(values) > 8 {
			return types.ReadJournalReq{}, errors.New("too many priorities")
		}
		prioritySeen := make(map[int]struct{}, len(values))
		for _, value := range values {
			priority, parseErr := strconv.Atoi(value)
			if parseErr != nil || priority < 0 || priority > 7 {
				return types.ReadJournalReq{}, errors.New("journal priority is invalid")
			}
			if _, exists := prioritySeen[priority]; !exists {
				prioritySeen[priority] = struct{}{}
				priorities = append(priorities, priority)
			}
		}
	}

	until := time.Now().UTC()
	return types.ReadJournalReq{
		SourceIDs:  normalizedSources,
		Priorities: priorities,
		Since:      until.Add(-time.Duration(hours) * time.Hour),
		Until:      until,
		Limit:      limit,
	}, nil
}

func registeredPositiveInt(raw string, allowed ...int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	for _, candidate := range allowed {
		if value == candidate {
			return value, nil
		}
	}
	return 0, errors.New("value is not registered")
}

func rejectUpdateDryRunFields(r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	for key := range r.Form {
		if key != "csrf_token" {
			return errors.New("unknown update dry-run field")
		}
	}
	return nil
}
