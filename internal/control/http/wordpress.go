package panelhttp

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/control/web"
	controlwordpress "github.com/nakroteck/nakpanel/internal/control/wordpress"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (s *Server) loadWordPressWorkspace(w http.ResponseWriter, r *http.Request, actor auth.SessionUser, siteID int64, view *web.WorkspaceView) bool {
	if s.wordpress == nil {
		http.Error(w, "WordPress Toolkit is unavailable", http.StatusServiceUnavailable)
		return false
	}
	workspace, err := s.wordpress.Workspace(r.Context(), actor, siteID)
	if err != nil {
		if errors.Is(err, controlwordpress.ErrNotFound) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "WordPress workspace is unavailable", http.StatusServiceUnavailable)
		}
		return false
	}
	workspace.Reason = boundedSafeText(workspace.Reason, 320)
	if workspace.Instance != nil {
		workspace.Instance.LastError = boundedSafeText(workspace.Instance.LastError, 512)
	}
	for index := range workspace.Operations {
		workspace.Operations[index].Output = boundedSafeText(workspace.Operations[index].Output, 2048)
		workspace.Operations[index].LastError = boundedSafeText(workspace.Operations[index].LastError, 512)
	}
	view.WordPress = &workspace
	return true
}

func (s *Server) handleInstallWordPress(w http.ResponseWriter, r *http.Request) {
	actor, siteID, ok := s.wordpressMutationRequest(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := r.ParseForm(); err != nil {
		s.writeWordPressError(w, r, actor, siteID, err, "Invalid WordPress installation")
		return
	}
	title, titleErr := boundedFormString(r, "site_title", 200)
	adminUser, userErr := boundedFormString(r, "admin_user", 60)
	adminEmail, emailErr := boundedFormString(r, "admin_email", 254)
	adminPassword, passwordErr := boundedRawFormString(r, "admin_password", 256)
	version, versionErr := boundedFormString(r, "version", 64)
	if err := errors.Join(titleErr, userErr, emailErr, passwordErr, versionErr); err != nil {
		s.writeWordPressError(w, r, actor, siteID, err, "Invalid WordPress installation")
		return
	}
	instance, operation, err := s.wordpress.Install(r.Context(), actor, siteID, controlwordpress.InstallInput{
		Title: title, AdminUser: adminUser, AdminEmail: adminEmail, AdminPassword: adminPassword, Version: version,
	})
	adminPassword = ""
	if err != nil {
		s.writeWordPressError(w, r, actor, siteID, err, "WordPress installation could not be queued")
		return
	}
	s.writeWordPressSuccess(w, r, actor, siteID, http.StatusAccepted, "wordpress-install-queued", map[string]any{
		"ok": true, "instance_id": instance.ID, "operation_id": operation.ID, "status": "pending",
	})
}

func (s *Server) handleWordPressOperation(w http.ResponseWriter, r *http.Request) {
	actor, siteID, ok := s.wordpressMutationRequest(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := r.ParseForm(); err != nil {
		s.writeWordPressError(w, r, actor, siteID, err, "Invalid WordPress operation")
		return
	}
	action, actionErr := boundedFormString(r, "action", 32)
	targetType, targetErr := boundedFormString(r, "target_type", 16)
	targetSlug, slugErr := boundedFormString(r, "target_slug", 128)
	version, versionErr := boundedFormString(r, "version", 64)
	password, passwordErr := boundedRawFormString(r, "admin_password", 256)
	maintenance, maintenanceErr := boundedFormBool(r, "maintenance")
	if err := errors.Join(actionErr, targetErr, slugErr, versionErr, passwordErr, maintenanceErr); err != nil {
		s.writeWordPressError(w, r, actor, siteID, err, "Invalid WordPress operation")
		return
	}
	if action == string(types.WordPressActionUpdate) && strings.ToLower(strings.TrimSpace(r.Form.Get("confirm"))) != "update" {
		s.writeWordPressError(w, r, actor, siteID, errors.New("update confirmation required"), "Update confirmation is required")
		return
	}
	operation, err := s.wordpress.QueueOperation(r.Context(), actor, siteID, controlwordpress.OperationInput{
		Action: types.WordPressAction(action), TargetType: types.WordPressTargetType(targetType), TargetSlug: targetSlug,
		RequestedVersion: version, Maintenance: maintenance, AdminPassword: password,
	})
	password = ""
	if err != nil {
		s.writeWordPressError(w, r, actor, siteID, err, "WordPress operation could not be queued")
		return
	}
	s.writeWordPressSuccess(w, r, actor, siteID, http.StatusAccepted, "wordpress-operation-queued", map[string]any{
		"ok": true, "operation_id": operation.ID, "status": operation.Status,
	})
}

func (s *Server) handleDetachWordPress(w http.ResponseWriter, r *http.Request) {
	actor, siteID, ok := s.wordpressMutationRequest(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil || strings.ToLower(strings.TrimSpace(r.Form.Get("confirm"))) != "detach" {
		s.writeWordPressError(w, r, actor, siteID, errors.New("detach confirmation required"), "Detach confirmation is required")
		return
	}
	if err := s.wordpress.Detach(r.Context(), actor, siteID); err != nil {
		s.writeWordPressError(w, r, actor, siteID, err, "WordPress tracking could not be detached")
		return
	}
	s.writeWordPressSuccess(w, r, actor, siteID, http.StatusOK, "wordpress-detached", map[string]any{"ok": true, "detached": true})
}

func (s *Server) handleUninstallWordPress(w http.ResponseWriter, r *http.Request) {
	actor, siteID, ok := s.wordpressMutationRequest(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := r.ParseForm(); err != nil {
		s.writeWordPressError(w, r, actor, siteID, err, "Invalid WordPress uninstall request")
		return
	}
	createBackup, backupErr := boundedFormBool(r, "create_backup")
	deleteDatabase, databaseErr := boundedFormBool(r, "delete_database")
	confirmDomain, confirmErr := boundedFormString(r, "confirm_domain", 253)
	if err := errors.Join(backupErr, databaseErr, confirmErr); err != nil {
		s.writeWordPressError(w, r, actor, siteID, err, "Invalid WordPress uninstall request")
		return
	}
	operation, err := s.wordpress.Uninstall(r.Context(), actor, siteID, controlwordpress.UninstallInput{
		CreateBackup: createBackup, DeleteDatabase: deleteDatabase, ConfirmDomain: confirmDomain,
	})
	if err != nil {
		s.writeWordPressError(w, r, actor, siteID, err, "WordPress uninstall could not be queued")
		return
	}
	s.writeWordPressSuccess(w, r, actor, siteID, http.StatusAccepted, "wordpress-uninstall-queued", map[string]any{
		"ok": true, "operation_id": operation.ID, "status": operation.Status, "backup_id": operation.BackupID,
	})
}

func (s *Server) wordpressMutationRequest(w http.ResponseWriter, r *http.Request) (auth.SessionUser, int64, bool) {
	actor, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return auth.SessionUser{}, 0, false
	}
	siteID, err := parsePositivePathID(r, "id")
	if err != nil {
		http.NotFound(w, r)
		return auth.SessionUser{}, 0, false
	}
	if actor.Role == auth.RoleAdmin && !s.phpSupportMutationVisible(w, r, actor, siteID) {
		return auth.SessionUser{}, 0, false
	}
	if s.wordpress == nil {
		s.writeWordPressError(w, r, actor, siteID, errors.New("unconfigured"), "WordPress Toolkit is unavailable")
		return auth.SessionUser{}, 0, false
	}
	return actor, siteID, true
}

func (s *Server) writeWordPressSuccess(w http.ResponseWriter, r *http.Request, actor auth.SessionUser, siteID int64, status int, notice string, payload map[string]any) {
	if wantsSPAJSON(r) {
		writeSPAJSON(w, status, payload)
		return
	}
	target := "/sites/" + strconv.FormatInt(siteID, 10) + "/wordpress?notice=" + notice
	http.Redirect(w, r, supportRedirectPath(r, actor, target), http.StatusSeeOther)
}

func (s *Server) writeWordPressError(w http.ResponseWriter, r *http.Request, actor auth.SessionUser, siteID int64, err error, message string) {
	status := http.StatusBadRequest
	notice := "wordpress-input-error"
	switch {
	case errors.Is(err, controlwordpress.ErrNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, controlwordpress.ErrInactive), errors.Is(err, controlwordpress.ErrNotClassic), errors.Is(err, controlwordpress.ErrBusy):
		status = http.StatusConflict
		notice = "wordpress-conflict"
		message = "The WordPress operation conflicts with the site's current state"
	case errors.Is(err, controlwordpress.ErrDisabled), errors.Is(err, controlwordpress.ErrLimitReached), errors.Is(err, controlwordpress.ErrInvalidInput):
		status = http.StatusBadRequest
		if errors.Is(err, controlwordpress.ErrDisabled) {
			notice = "wordpress-disabled"
			message = "WordPress Toolkit is disabled by this subscription"
		} else if errors.Is(err, controlwordpress.ErrLimitReached) {
			notice = "wordpress-limit-reached"
			message = "This subscription has reached its WordPress site limit"
		} else {
			message = "The WordPress request was not valid"
		}
	case errors.Is(err, serveradmin.ErrSecretUnavailable), err != nil && err.Error() == "unconfigured":
		status = http.StatusServiceUnavailable
		notice = "wordpress-unavailable"
		message = "WordPress Toolkit is temporarily unavailable"
	default:
		if err == nil || !isPHPHTTPValidationError(err) {
			status = http.StatusInternalServerError
			message = "WordPress operation failed"
			notice = "wordpress-operation-failed"
		}
	}
	if wantsSPAJSON(r) {
		writeSPAError(w, status, message)
		return
	}
	target := "/sites/" + strconv.FormatInt(siteID, 10) + "/wordpress?notice=" + notice
	http.Redirect(w, r, supportRedirectPath(r, actor, target), http.StatusSeeOther)
}
