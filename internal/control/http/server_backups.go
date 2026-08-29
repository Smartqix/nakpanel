package panelhttp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

// Server-level backup management routes (admin-only). Mutations that change
// destinations or expose the archive key require recent re-authentication.

type serverBackupService interface {
	ListBackupDestinations(context.Context) ([]serveradmin.BackupDestination, error)
	SaveBackupDestination(context.Context, serveradmin.SaveBackupDestinationParams) (serveradmin.BackupDestination, error)
	DeleteBackupDestination(context.Context, string, int64, string) error
	TestBackupDestinationByName(context.Context, string) (types.TestBackupDestinationResult, error)
	InitBackupKey(context.Context, int64, string, bool) (string, string, error)
	BackupKeyFingerprint(context.Context) (string, bool)
	QueueServerBackup(context.Context, string, int64, string, bool) (int64, error)
	ListServerBackups(context.Context, int) ([]serveradmin.ServerBackup, error)
}

func (s *Server) registerServerBackupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /tools-settings/backups/status", s.handleServerBackupStatus)
	mux.HandleFunc("POST /tools-settings/backups/destinations", s.handleServerBackupSaveDestination)
	mux.HandleFunc("POST /tools-settings/backups/destinations/delete", s.handleServerBackupDeleteDestination)
	mux.HandleFunc("POST /tools-settings/backups/destinations/test", s.handleServerBackupTestDestination)
	mux.HandleFunc("POST /tools-settings/backups/run", s.handleServerBackupRun)
	mux.HandleFunc("POST /tools-settings/backups/key/init", s.handleServerBackupKeyInit)
}

func (s *Server) serverBackups(w http.ResponseWriter) (serverBackupService, bool) {
	service, ok := s.serverAdmin.(serverBackupService)
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Server backups are unavailable")
		return nil, false
	}
	return service, true
}

func (s *Server) handleServerBackupStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	service, ok := s.serverBackups(w)
	if !ok {
		return
	}
	destinations, err := service.ListBackupDestinations(r.Context())
	if err != nil {
		writeSPAError(w, http.StatusBadGateway, "Backup destinations could not be listed")
		return
	}
	backups, err := service.ListServerBackups(r.Context(), 25)
	if err != nil {
		writeSPAError(w, http.StatusBadGateway, "Server backups could not be listed")
		return
	}
	fingerprint, keyPresent := service.BackupKeyFingerprint(r.Context())
	writeSPAJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"key_present":     keyPresent,
		"key_fingerprint": fingerprint,
		"destinations":    destinations,
		"backups":         backups,
		"smtp_configured": s.smtpConfigured,
	})
}

type serverBackupDestinationInput struct {
	Name            string          `json:"name"`
	Kind            string          `json:"kind"`
	Enabled         *bool           `json:"enabled,omitempty"`
	Settings        json.RawMessage `json:"settings,omitempty"`
	Credential      json.RawMessage `json:"credential,omitempty"`
	ScheduleCron    string          `json:"schedule_cron,omitempty"`
	RetentionCount  int             `json:"retention_count,omitempty"`
	RetentionDays   *int            `json:"retention_days,omitempty"`
	IncludeMailData *bool           `json:"include_mail_data,omitempty"`
	NotifyEmail     string          `json:"notify_email,omitempty"`
}

func decodeBackupJSON(r *http.Request, dst any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

func (s *Server) handleServerBackupSaveDestination(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	service, ok := s.serverBackups(w)
	if !ok {
		return
	}
	if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		writeSPAError(w, http.StatusPreconditionRequired, "Recent authentication is required")
		return
	}
	var input serverBackupDestinationInput
	if err := decodeBackupJSON(r, &input); err != nil {
		writeSPAError(w, http.StatusBadRequest, "Invalid backup destination payload")
		return
	}
	params := serveradmin.SaveBackupDestinationParams{
		Name:            input.Name,
		Kind:            input.Kind,
		Enabled:         true,
		Settings:        input.Settings,
		ScheduleCron:    input.ScheduleCron,
		RetentionCount:  input.RetentionCount,
		RetentionDays:   30,
		IncludeMailData: true,
		NotifyEmail:     input.NotifyEmail,
		ActorUserID:     user.ID,
	}
	if input.Enabled != nil {
		params.Enabled = *input.Enabled
	}
	if input.RetentionDays != nil {
		params.RetentionDays = *input.RetentionDays
	}
	if input.IncludeMailData != nil {
		params.IncludeMailData = *input.IncludeMailData
	}
	if params.RetentionCount == 0 {
		params.RetentionCount = 7
	}
	if len(input.Credential) > 0 && string(input.Credential) != "null" {
		params.Credential = []byte(input.Credential)
	}
	item, err := service.SaveBackupDestination(r.Context(), params)
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "server.backup_destination_saved_ui", "server_backup_destination", item.ID, map[string]any{"name": item.Name})
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "destination": item})
}

type serverBackupNameInput struct {
	Name string `json:"name"`
}

func (s *Server) handleServerBackupDeleteDestination(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	service, ok := s.serverBackups(w)
	if !ok {
		return
	}
	if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		writeSPAError(w, http.StatusPreconditionRequired, "Recent authentication is required")
		return
	}
	var input serverBackupNameInput
	if err := decodeBackupJSON(r, &input); err != nil || strings.TrimSpace(input.Name) == "" {
		writeSPAError(w, http.StatusBadRequest, "A destination name is required")
		return
	}
	if err := service.DeleteBackupDestination(r.Context(), input.Name, user.ID, ""); err != nil {
		writeSPAError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleServerBackupTestDestination(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	service, ok := s.serverBackups(w)
	if !ok {
		return
	}
	var input serverBackupNameInput
	if err := decodeBackupJSON(r, &input); err != nil || strings.TrimSpace(input.Name) == "" {
		writeSPAError(w, http.StatusBadRequest, "A destination name is required")
		return
	}
	result, err := service.TestBackupDestinationByName(r.Context(), input.Name)
	if err != nil {
		writeSPAError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

type serverBackupRunInput struct {
	Destination string `json:"destination"`
}

func (s *Server) handleServerBackupRun(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	service, ok := s.serverBackups(w)
	if !ok {
		return
	}
	var input serverBackupRunInput
	if err := decodeBackupJSON(r, &input); err != nil || strings.TrimSpace(input.Destination) == "" {
		writeSPAError(w, http.StatusBadRequest, "A destination name is required")
		return
	}
	backupID, err := service.QueueServerBackup(r.Context(), input.Destination, user.ID, "", false)
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "backup_id": backupID})
}

type serverBackupKeyInput struct {
	Force bool `json:"force,omitempty"`
}

func (s *Server) handleServerBackupKeyInit(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	service, ok := s.serverBackups(w)
	if !ok {
		return
	}
	if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		writeSPAError(w, http.StatusPreconditionRequired, "Recent authentication is required")
		return
	}
	var input serverBackupKeyInput
	if err := decodeBackupJSON(r, &input); err != nil && err != io.EOF {
		writeSPAError(w, http.StatusBadRequest, "Invalid payload")
		return
	}
	encoded, fingerprint, err := service.InitBackupKey(r.Context(), user.ID, "", input.Force)
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{
		"ok":  true,
		"key": encoded, "fingerprint": fingerprint,
		"notice": "Store this key offline now; it is shown exactly once and archives cannot be restored without it.",
	})
}
