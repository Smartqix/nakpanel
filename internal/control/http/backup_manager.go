package panelhttp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/control/web"
	"github.com/nakroteck/nakpanel/internal/types"
)

type backupManagerService interface {
	PreviewBackupRemovalFor(context.Context, auth.SessionUser, int64, []int64) (types.BackupRemovalPreview, error)
	RemoveBackupsFor(context.Context, auth.SessionUser, int64, []int64, string, bool) error
	BackupStatusFor(context.Context, auth.SessionUser, int64) (map[int64]string, error)
}

type backupRemovalApproval struct {
	SubscriptionID int64   `json:"subscription"`
	CustomerID     int64   `json:"customer"`
	SupportID      int64   `json:"support"`
	IDs            []int64 `json:"ids"`
	Digest         string  `json:"digest"`
	Expires        int64   `json:"expires"`
}

func (s *Server) loadBackupManager(w http.ResponseWriter, r *http.Request, user auth.SessionUser, data *dashboard.Data, view *web.WorkspaceView) bool {
	if view.Route != "subscription-detail" || view.Tab != "backups" {
		return true
	}
	visible := false
	for _, sub := range data.Subscriptions {
		if sub.ID == view.DetailID {
			visible = true
			break
		}
	}
	if !visible {
		http.NotFound(w, r)
		return false
	}
	if store, ok := s.workspace.(interface {
		SubscriptionBackups(context.Context, auth.SessionUser, int64, int) ([]dashboard.Backup, bool, error)
	}); ok {
		view.BackupPage = parseBoundedQueryInt(r, "backup_page", 0, 0, 100000)
		backups, more, err := store.SubscriptionBackups(r.Context(), user, view.DetailID, view.BackupPage)
		if err != nil {
			http.Error(w, "Could not load subscription backups", 503)
			return false
		}
		data.Phase6.Backups = backups
		view.BackupHasMore = more
	}
	return true
}

func (s *Server) registerBackupManagerRoutes(mux *http.ServeMux) {
	for _, prefix := range []string{"", "/support/customers/{customerID}"} {
		mux.HandleFunc("GET "+prefix+"/subscriptions/{id}/backups/remove", s.handleBackupRemovalPreview)
		mux.HandleFunc("POST "+prefix+"/subscriptions/{id}/backups/remove", s.handleBackupRemoval)
		mux.HandleFunc("GET "+prefix+"/subscriptions/{id}/backups/status", s.handleBackupManagerStatus)
	}
}

func selectedBackupIDs(values []string) ([]int64, error) {
	if len(values) == 0 || len(values) > 50 {
		return nil, errors.New("Select between 1 and 50 backups.")
	}
	ids := make([]int64, 0, len(values))
	seen := map[int64]bool{}
	for _, value := range values {
		id, err := strconv.ParseInt(value, 10, 64)
		if err != nil || id <= 0 {
			return nil, errors.New("Invalid backup selection.")
		}
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

func (s *Server) backupManagerUser(w http.ResponseWriter, r *http.Request) (auth.SessionUser, int64, int64, backupManagerService, bool) {
	w.Header().Set("Cache-Control", "private, no-store")
	user, ok := s.currentUser(w, r)
	if !ok {
		return user, 0, 0, nil, false
	}
	id, err := parsePositivePathID(r, "id")
	service, ready := s.phase6.(backupManagerService)
	if err != nil {
		http.NotFound(w, r)
		return user, 0, 0, nil, false
	}
	if !ready {
		writeSPAError(w, 503, "Backup management is unavailable.")
		return user, 0, 0, nil, false
	}
	var support int64
	if raw := r.PathValue("customerID"); raw != "" {
		support, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || support <= 0 || user.Role != auth.RoleAdmin || s.workspace == nil {
			http.NotFound(w, r)
			return user, 0, 0, nil, false
		}
		customer, e := s.workspace.CustomerIDForSubscription(r.Context(), id)
		if e != nil || customer != support {
			http.NotFound(w, r)
			return user, 0, 0, nil, false
		}
	}
	return user, id, support, service, true
}

func backupManagementFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, provision.ErrForbidden) {
		http.NotFound(w, r)
		return
	}
	status, message := http.StatusBadRequest, "Could not prepare this backup operation. Refresh and try again."
	if errors.Is(err, provision.ErrBackupBusy) {
		status = 409
		message = "A selected backup is in use by a restore or website operation. Wait for it to finish."
	}
	if errors.Is(err, provision.ErrBackupPreviewChanged) {
		status = 409
		message = "The selection changed or confirmation expired. Review the backups again."
	}
	if removalWantsJSON(r) {
		writeSPAError(w, status, message)
	} else {
		formFailure(w, r, message)
	}
}

func (s *Server) handleBackupRemovalPreview(w http.ResponseWriter, r *http.Request) {
	user, id, support, service, ok := s.backupManagerUser(w, r)
	if !ok {
		return
	}
	ids, err := selectedBackupIDs(r.URL.Query()["backup_id"])
	if err != nil {
		backupManagementFailure(w, r, err)
		return
	}
	preview, err := service.PreviewBackupRemovalFor(r.Context(), user, id, ids)
	if err != nil {
		backupManagementFailure(w, r, err)
		return
	}
	if preview.SubscriptionID != id || (support > 0 && preview.CustomerID != support) {
		http.NotFound(w, r)
		return
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data, _ := json.Marshal(backupRemovalApproval{id, preview.CustomerID, support, ids, preview.Digest, time.Now().Add(10 * time.Minute).Unix()})
	payload := base64.RawURLEncoding.EncodeToString(data)
	token := payload + "." + base64.RawURLEncoding.EncodeToString(removalSignature(s.removalApprovalKey, cookie.Value, "backup:"+payload))
	model := web.BackupRemovalView{Preview: preview, Approval: token}
	view := web.WorkspaceView{Route: "backup-removal", Title: "Remove backups", Tab: "backups", DetailID: id, SupportCustomerID: support, CSRFToken: csrfToken(r), BackupRemoval: &model}
	if removalWantsJSON(r) {
		var html bytes.Buffer
		if err := web.BackupRemovalContent(view, model).Render(r.Context(), &html); err != nil {
			writeSPAError(w, 503, "Could not render backup confirmation.")
			return
		}
		writeSPAJSON(w, 200, map[string]any{"ok": true, "html": html.String(), "approval": token})
		return
	}
	s.renderRemovalWorkspaceStatus(w, r, user, view, 200)
}

func (s *Server) handleBackupRemoval(w http.ResponseWriter, r *http.Request) {
	user, id, support, service, ok := s.backupManagerUser(w, r)
	if !ok {
		return
	}
	if r.ParseForm() != nil {
		backupManagementFailure(w, r, provision.ErrBackupPreviewChanged)
		return
	}
	ids, err := selectedBackupIDs(r.Form["backup_id"])
	if err != nil {
		backupManagementFailure(w, r, err)
		return
	}
	token := r.Form.Get("approval")
	parts := strings.Split(token, ".")
	cookie, e := r.Cookie(SessionCookieName)
	if e != nil || len(token) > 8192 || len(parts) != 2 {
		backupManagementFailure(w, r, provision.ErrBackupPreviewChanged)
		return
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil || !hmac.Equal(sig, removalSignature(s.removalApprovalKey, cookie.Value, "backup:"+parts[0])) {
		backupManagementFailure(w, r, provision.ErrBackupPreviewChanged)
		return
	}
	var approval backupRemovalApproval
	data, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil || json.Unmarshal(data, &approval) != nil || approval.SubscriptionID != id || approval.SupportID != support || approval.Expires <= time.Now().Unix() || len(approval.IDs) != len(ids) || r.Form.Get("acknowledge_permanent") != "true" {
		backupManagementFailure(w, r, provision.ErrBackupPreviewChanged)
		return
	}
	for i := range ids {
		if ids[i] != approval.IDs[i] {
			backupManagementFailure(w, r, provision.ErrBackupPreviewChanged)
			return
		}
	}
	if err := service.RemoveBackupsFor(r.Context(), user, id, ids, approval.Digest, true); err != nil {
		backupManagementFailure(w, r, err)
		return
	}
	path := removalPath(support, "/subscriptions/"+strconv.FormatInt(id, 10)+"?tab=backups&notice=backups-removing")
	if removalWantsJSON(r) {
		writeSPAJSON(w, 202, map[string]any{"ok": true, "redirect": path})
		return
	}
	http.Redirect(w, r, path, 303)
}

func (s *Server) handleBackupManagerStatus(w http.ResponseWriter, r *http.Request) {
	user, id, _, service, ok := s.backupManagerUser(w, r)
	if !ok {
		return
	}
	states, err := service.BackupStatusFor(r.Context(), user, id)
	if err != nil {
		backupManagementFailure(w, r, err)
		return
	}
	writeSPAJSON(w, 200, map[string]any{"ok": true, "backups": states})
}
