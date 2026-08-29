package panelhttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/databaseadmin"
	"github.com/nakroteck/nakpanel/internal/control/platformadmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

type DatabaseAdminService interface {
	Snapshot(context.Context) (databaseadmin.Snapshot, error)
	RotatePassword(context.Context, int64, int64, string) (types.ManageDatabaseAdminResult, error)
	SetRole(context.Context, int64, int64, platformadmin.DatabaseRole) (types.ManageDatabaseAdminResult, error)
	Check(context.Context, int64) (types.ManageDatabaseAdminResult, error)
}

// RegisterDatabaseAdminRoutes keeps Phase 26D route wiring separate from the
// large Server router. The caller must register these on the same mux before
// applying the existing CSRF, same-origin, body-limit, and security middleware.
func RegisterDatabaseAdminRoutes(mux *http.ServeMux, server *Server, service DatabaseAdminService) {
	mux.HandleFunc("GET /tools-settings/databases/status", func(w http.ResponseWriter, r *http.Request) {
		server.handleDatabaseAdminStatus(service, w, r)
	})
	mux.HandleFunc("POST /tools-settings/databases/{id}/password", func(w http.ResponseWriter, r *http.Request) {
		server.handleDatabasePasswordRotation(service, w, r)
	})
	mux.HandleFunc("POST /tools-settings/databases/{id}/role", func(w http.ResponseWriter, r *http.Request) {
		server.handleDatabaseRole(service, w, r)
	})
	mux.HandleFunc("POST /tools-settings/databases/{id}/check", func(w http.ResponseWriter, r *http.Request) {
		server.handleDatabaseCheck(service, w, r)
	})
}

func (s *Server) handleDatabaseAdminStatus(service DatabaseAdminService, w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if service == nil {
		writeSPAError(w, http.StatusServiceUnavailable, "Database administration is unavailable")
		return
	}
	snapshot, err := service.Snapshot(r.Context())
	if err != nil {
		writeSPAError(w, http.StatusBadGateway, databaseadmin.SafeError(err))
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "database_admin": snapshot})
}

func (s *Server) handleDatabasePasswordRotation(service DatabaseAdminService, w http.ResponseWriter, r *http.Request) {
	user, databaseID, ok := s.databaseMutationContext(service, w, r, true)
	if !ok {
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if err := decodeDatabaseAdminInput(r, &input, "password"); err != nil {
		writeSPAError(w, http.StatusBadRequest, "Invalid database password rotation request")
		return
	}
	result, err := service.RotatePassword(r.Context(), user.ID, databaseID, input.Password)
	input.Password = ""
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, databaseadmin.SafeError(err))
		return
	}
	writeSPAJSON(w, http.StatusAccepted, map[string]any{"ok": true, "result": result})
}

func (s *Server) handleDatabaseRole(service DatabaseAdminService, w http.ResponseWriter, r *http.Request) {
	user, databaseID, ok := s.databaseMutationContext(service, w, r, true)
	if !ok {
		return
	}
	var input struct {
		Role platformadmin.DatabaseRole `json:"role"`
	}
	if err := decodeDatabaseAdminInput(r, &input, "role"); err != nil {
		writeSPAError(w, http.StatusBadRequest, "Invalid database role request")
		return
	}
	result, err := service.SetRole(r.Context(), user.ID, databaseID, input.Role)
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, databaseadmin.SafeError(err))
		return
	}
	writeSPAJSON(w, http.StatusAccepted, map[string]any{"ok": true, "result": result})
}

func (s *Server) handleDatabaseCheck(service DatabaseAdminService, w http.ResponseWriter, r *http.Request) {
	user, databaseID, ok := s.databaseMutationContext(service, w, r, false)
	if !ok {
		return
	}
	if err := decodeDatabaseAdminInput(r, &struct{}{}); err != nil {
		writeSPAError(w, http.StatusBadRequest, "Invalid database check request")
		return
	}
	result, err := service.Check(r.Context(), databaseID)
	if err != nil {
		writeSPAError(w, http.StatusBadGateway, databaseadmin.SafeError(err))
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "database.integrity_checked", "database", databaseID, map[string]any{
		"tables": len(result.Checks),
	})
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

func (s *Server) databaseMutationContext(service DatabaseAdminService, w http.ResponseWriter, r *http.Request, recentAuth bool) (user auth.SessionUser, databaseID int64, ok bool) {
	sessionUser, allowed := s.requireAdmin(w, r)
	if !allowed {
		return user, 0, false
	}
	if service == nil {
		writeSPAError(w, http.StatusServiceUnavailable, "Database administration is unavailable")
		return user, 0, false
	}
	if recentAuth && !s.sessions.RecentlyAuthenticated(sessionUser, 10*time.Minute) {
		writeSPAError(w, http.StatusPreconditionRequired, "Recent authentication is required")
		return user, 0, false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return user, 0, false
	}
	return sessionUser, id, true
}

func decodeDatabaseAdminInput(r *http.Request, output any, allowedFields ...string) error {
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType == "application/json" {
		decoder := json.NewDecoder(io.LimitReader(r.Body, maxServerAdminJSONBytes+1))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(output); err != nil {
			return err
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return errors.New("request must contain one JSON object")
		}
		return nil
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	allowed := map[string]struct{}{"csrf_token": {}}
	for _, field := range allowedFields {
		allowed[field] = struct{}{}
	}
	for field := range r.Form {
		if _, ok := allowed[field]; !ok {
			return errors.New("unknown database administration field")
		}
	}
	encoded, err := json.Marshal(databaseAdminFormValues(r, allowedFields))
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(output)
}

func databaseAdminFormValues(r *http.Request, fields []string) map[string]string {
	result := make(map[string]string, len(fields))
	for _, field := range fields {
		result[field] = strings.TrimSpace(r.Form.Get(field))
	}
	return result
}
