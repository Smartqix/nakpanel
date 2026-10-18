package panelhttp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/control/web"
	"github.com/nakroteck/nakpanel/internal/types"
)

type SiteRemovalManager interface {
	PreviewSiteRemoval(context.Context, auth.SessionUser, int64) (types.SiteRemovalPreview, error)
	RemoveSiteFor(context.Context, auth.SessionUser, types.RemoveSiteReq) (types.SiteRemovalOperation, error)
	SiteRemovalFor(context.Context, auth.SessionUser, int64) (types.SiteRemovalOperation, error)
	SiteRemovalByRequestFor(context.Context, auth.SessionUser, string) (types.SiteRemovalOperation, error)
	RetrySiteRemovalFor(context.Context, auth.SessionUser, int64) (types.SiteRemovalOperation, error)
}

func removalWantsJSON(r *http.Request) bool {
	return wantsSPAJSON(r) || strings.Contains(r.Header.Get("Accept"), "application/json")
}

type removalApproval struct {
	SiteID         int64  `json:"site"`
	SubscriptionID int64  `json:"subscription"`
	CustomerID     int64  `json:"customer"`
	SupportID      int64  `json:"support"`
	Digest         string `json:"digest"`
	RequestID      string `json:"request"`
	Expires        int64  `json:"expires"`
}

func newSiteRemovalApprovalKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("could not initialize removal approval key")
	}
	return key
}
func removalSignature(key []byte, session, payload string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("nakpanel-removal-v1\x00"))
	m.Write([]byte(session))
	m.Write([]byte{0})
	m.Write([]byte(payload))
	return m.Sum(nil)
}
func signSiteRemovalApproval(key []byte, session string, p types.SiteRemovalPreview, supportID int64, now time.Time) (string, string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	id := hex.EncodeToString(nonce)
	data, err := json.Marshal(removalApproval{SiteID: p.SiteID, SubscriptionID: p.SubscriptionID, CustomerID: p.CustomerID, SupportID: supportID, Digest: p.Digest, RequestID: id, Expires: now.Add(10 * time.Minute).Unix()})
	if err != nil {
		return "", "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(data)
	return payload + "." + base64.RawURLEncoding.EncodeToString(removalSignature(key, session, payload)), id, nil
}
func verifySiteRemovalApproval(key []byte, session, token, requestID string, siteID, supportID int64, now time.Time) (removalApproval, error) {
	var approval removalApproval
	parts := strings.Split(token, ".")
	invalid := errors.New("This confirmation expired or changed. Review the removal impact again.")
	if len(token) > 2048 || len(parts) != 2 || session == "" {
		return approval, invalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, removalSignature(key, session, parts[0])) {
		return approval, invalid
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(data, &approval) != nil || approval.SiteID != siteID || approval.SupportID != supportID || approval.RequestID != requestID || approval.Expires <= now.Unix() || approval.Expires > now.Add(10*time.Minute).Unix()+1 {
		return approval, invalid
	}
	return approval, nil
}
func (s *Server) registerSiteRemovalRoutes(mux *http.ServeMux) {
	for _, prefix := range []string{"", "/support/customers/{customerID}"} {
		mux.HandleFunc("GET "+prefix+"/backups/{id}/download", s.handleBackupDownload)
		mux.HandleFunc("GET "+prefix+"/sites/{id}/removal/preview", s.handleRemovalPreview)
		mux.HandleFunc("GET "+prefix+"/sites/{id}/removal", s.handleRemovalPreview)
		mux.HandleFunc("POST "+prefix+"/sites/{id}/remove", s.handleRemoveSite)
		mux.HandleFunc("GET "+prefix+"/site-removals/lookup", s.handleRemovalLookup)
		mux.HandleFunc("GET "+prefix+"/site-removals/{id}/status", s.handleRemovalStatus)
		mux.HandleFunc("GET "+prefix+"/site-removals/{id}", s.handleRemovalPage)
		mux.HandleFunc("POST "+prefix+"/site-removals/{id}/retry", s.handleRemovalRetry)
	}
}
func (s *Server) removalUser(w http.ResponseWriter, r *http.Request) (auth.SessionUser, int64, bool) {
	w.Header().Set("Cache-Control", "no-store")
	user, ok := s.currentUser(w, r, func() {
		if removalWantsJSON(r) || strings.HasSuffix(r.URL.Path, "/status") || strings.HasSuffix(r.URL.Path, "/lookup") {
			writeSPAError(w, 401, "Sign in to check removal status. Do not submit removal again.")
		} else {
			http.Redirect(w, r, "/login", 303)
		}
	})
	if !ok {
		return user, 0, false
	}
	if s.siteRemoval == nil {
		writeSPAError(w, 503, "Website removal is unavailable.")
		return user, 0, false
	}
	var support int64
	if raw := r.PathValue("customerID"); raw != "" {
		var err error
		support, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || support <= 0 || user.Role != auth.RoleAdmin {
			http.NotFound(w, r)
			return user, 0, false
		}
	}
	return user, support, true
}
func removalScopeValid(w http.ResponseWriter, r *http.Request, support, customer int64, err error) bool {
	if errors.Is(err, provision.ErrForbidden) || errors.Is(err, sql.ErrNoRows) || (err == nil && support > 0 && support != customer) {
		http.NotFound(w, r)
		return false
	}
	return true
}
func removalPath(support int64, path string) string {
	if support > 0 {
		return "/support/customers/" + strconv.FormatInt(support, 10) + path
	}
	return path
}
func (s *Server) removalPreviewModel(r *http.Request, p types.SiteRemovalPreview, support int64) (web.SiteRemovalView, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return web.SiteRemovalView{}, err
	}
	token, id, err := signSiteRemovalApproval(s.removalApprovalKey, cookie.Value, p, support, time.Now())
	return web.SiteRemovalView{Preview: &p, Approval: token, RequestID: id}, err
}
func (s *Server) handleRemovalPreview(w http.ResponseWriter, r *http.Request) {
	user, support, ok := s.removalUser(w, r)
	if !ok {
		return
	}
	id, err := parsePositivePathID(r, "id")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p, err := s.siteRemoval.PreviewSiteRemoval(r.Context(), user, id)
	if !removalScopeValid(w, r, support, p.CustomerID, err) {
		return
	}
	if err != nil {
		writeSPAError(w, 503, "Could not load removal impact.")
		return
	}
	if p.SiteID != id {
		http.NotFound(w, r)
		return
	}
	if p.Operation != nil {
		op, loadErr := s.siteRemoval.SiteRemovalFor(r.Context(), user, p.Operation.ID)
		if !removalScopeValid(w, r, support, op.CustomerID, loadErr) {
			return
		}
		if loadErr != nil {
			writeSPAError(w, 503, "Could not resume removal progress.")
			return
		}
		if op.SiteID != id {
			http.NotFound(w, r)
			return
		}
		if removalWantsJSON(r) {
			s.writeRemovalStatus(w, r, user, op, support)
		} else {
			http.Redirect(w, r, removalPath(support, "/site-removals/"+strconv.FormatInt(op.ID, 10)), 303)
		}
		return
	}
	model, err := s.removalPreviewModel(r, p, support)
	if err != nil {
		writeSPAError(w, 503, "Could not prepare removal confirmation.")
		return
	}
	view := web.WorkspaceView{Route: "site-removal", Title: "Remove website", CSRFToken: csrfToken(r), SupportCustomerID: support, SiteRemoval: &model}
	if removalWantsJSON(r) {
		var html bytes.Buffer
		dialogView := view
		dialogView.Route = ""
		if err = web.SiteRemovalPreviewContent(dialogView, model).Render(r.Context(), &html); err != nil {
			writeSPAError(w, 503, "Could not render removal impact.")
			return
		}
		writeSPAJSON(w, 200, map[string]any{"ok": true, "html": html.String(), "approval": model.Approval, "request_id": model.RequestID, "allowed": p.Allowed})
		return
	}
	s.renderRemovalWorkspace(w, r, user, view)
}
func (s *Server) handleRemoveSite(w http.ResponseWriter, r *http.Request) {
	user, support, ok := s.removalUser(w, r)
	if !ok {
		return
	}
	id, err := parsePositivePathID(r, "id")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err = r.ParseForm(); err != nil {
		writeSPAError(w, 400, "Invalid removal form.")
		return
	}
	cookie, _ := r.Cookie(SessionCookieName)
	approval, err := verifySiteRemovalApproval(s.removalApprovalKey, cookie.Value, r.Form.Get("approval"), r.Form.Get("request_id"), id, support, time.Now())
	if err != nil {
		s.removalFormFailure(w, r, user, support, id, err.Error(), true)
		return
	}
	if support > 0 && approval.CustomerID != support {
		http.NotFound(w, r)
		return
	}
	req := types.RemoveSiteReq{SiteID: id, RequestID: approval.RequestID, PreviewDigest: approval.Digest, ConfirmDomain: strings.TrimSpace(r.Form.Get("confirm_domain")), AcknowledgePermanent: r.Form.Get("acknowledge_permanent") == "true", IncludeChildren: r.Form.Get("include_children") == "true"}
	for _, raw := range r.Form["delete_database_ids"] {
		value, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || value <= 0 {
			s.removalFormFailure(w, r, user, support, id, "Invalid database selection.", false)
			return
		}
		req.DeleteDatabaseIDs = append(req.DeleteDatabaseIDs, value)
	}
	op, err := s.siteRemoval.RemoveSiteFor(r.Context(), user, req)
	if !removalScopeValid(w, r, support, op.CustomerID, err) {
		return
	}
	if err != nil {
		s.removalFormFailure(w, r, user, support, id, err.Error(), errors.Is(err, provision.ErrRemovalPreviewChanged))
		return
	}
	s.respondRemovalAccepted(w, r, op, support)
}
func (s *Server) removalFormFailure(w http.ResponseWriter, r *http.Request, user auth.SessionUser, support, id int64, message string, refreshConsent bool) {
	if wantsSPAJSON(r) {
		writeSPAJSON(w, 400, map[string]any{"ok": false, "error": sanitizeNoticeText(message), "refresh_preview": refreshConsent})
		return
	}
	p, err := s.siteRemoval.PreviewSiteRemoval(r.Context(), user, id)
	if !removalScopeValid(w, r, support, p.CustomerID, err) {
		return
	}
	if err != nil {
		http.Error(w, "Could not reload removal impact", 503)
		return
	}
	model, err := s.removalPreviewModel(r, p, support)
	if err != nil {
		http.Error(w, "Could not prepare confirmation", 503)
		return
	}
	model.Error = sanitizeNoticeText(message)
	model.ConfirmDomain = r.Form.Get("confirm_domain")
	model.AcknowledgePermanent = !refreshConsent && r.Form.Get("acknowledge_permanent") == "true"
	model.IncludeChildren = !refreshConsent && r.Form.Get("include_children") == "true"
	view := web.WorkspaceView{Route: "site-removal", Title: "Review removal", CSRFToken: csrfToken(r), SupportCustomerID: support, SiteRemoval: &model}
	s.renderRemovalWorkspaceStatus(w, r, user, view, http.StatusBadRequest)
}
func (s *Server) respondRemovalAccepted(w http.ResponseWriter, r *http.Request, op types.SiteRemovalOperation, support int64) {
	path := removalPath(support, "/site-removals/"+strconv.FormatInt(op.ID, 10))
	if wantsSPAJSON(r) {
		writeSPAJSON(w, 202, map[string]any{"ok": true, "operation_id": op.ID, "status_url": path + "/status", "progress_url": path, "state": op.State})
		return
	}
	http.Redirect(w, r, path, 303)
}
func (s *Server) removalOperation(w http.ResponseWriter, r *http.Request, lookup bool) (auth.SessionUser, types.SiteRemovalOperation, int64, bool) {
	user, support, ok := s.removalUser(w, r)
	if !ok {
		return user, types.SiteRemovalOperation{}, support, false
	}
	var op types.SiteRemovalOperation
	var err error
	if lookup {
		id := r.URL.Query().Get("request_id")
		if len(id) != 32 {
			http.NotFound(w, r)
			return user, op, support, false
		}
		op, err = s.siteRemoval.SiteRemovalByRequestFor(r.Context(), user, id)
	} else {
		id, e := parsePositivePathID(r, "id")
		if e != nil {
			http.NotFound(w, r)
			return user, op, support, false
		}
		op, err = s.siteRemoval.SiteRemovalFor(r.Context(), user, id)
	}
	if !removalScopeValid(w, r, support, op.CustomerID, err) {
		return user, op, support, false
	}
	if err != nil {
		writeSPAError(w, 503, "Removal status is temporarily unavailable.")
		return user, op, support, false
	}
	return user, op, support, true
}
func (s *Server) handleRemovalLookup(w http.ResponseWriter, r *http.Request) {
	user, op, support, ok := s.removalOperation(w, r, true)
	if ok {
		if !removalWantsJSON(r) {
			http.Redirect(w, r, removalPath(support, "/site-removals/"+strconv.FormatInt(op.ID, 10)), 303)
			return
		}
		s.writeRemovalStatus(w, r, user, op, support)
	}
}
func (s *Server) handleRemovalStatus(w http.ResponseWriter, r *http.Request) {
	user, op, support, ok := s.removalOperation(w, r, false)
	if ok {
		s.writeRemovalStatus(w, r, user, op, support)
	}
}
func (s *Server) removalDestination(r *http.Request, user auth.SessionUser, op types.SiteRemovalOperation, support int64) string {
	path := "/subscriptions/" + strconv.FormatInt(op.SubscriptionID, 10) + "?tab=websites"
	if op.ParentSiteID > 0 {
		if data, err := s.loadDashboard(r.Context(), user); err == nil {
			for _, site := range data.Sites {
				if site.ID == op.ParentSiteID && site.SubscriptionID == op.SubscriptionID && site.CustomerID == op.CustomerID && site.RemovalState == "none" {
					path = "/sites/" + strconv.FormatInt(site.ID, 10) + "?tab=overview"
					break
				}
			}
		}
	}
	return removalPath(support, path) + "&notice=website-removed&removal_id=" + strconv.FormatInt(op.ID, 10)
}
func (s *Server) writeRemovalStatus(w http.ResponseWriter, r *http.Request, user auth.SessionUser, op types.SiteRemovalOperation, support int64) {
	redirect := ""
	if op.State == "completed" {
		redirect = s.removalDestination(r, user, op, support)
	}
	path := removalPath(support, "/site-removals/"+strconv.FormatInt(op.ID, 10))
	view := web.WorkspaceView{CSRFToken: csrfToken(r), SupportCustomerID: support}
	model := web.SiteRemovalView{Operation: &op, Redirect: redirect}
	var html bytes.Buffer
	if err := web.SiteRemovalProgressContent(view, model).Render(r.Context(), &html); err != nil {
		writeSPAError(w, 503, "Could not render removal progress.")
		return
	}
	writeSPAJSON(w, 200, map[string]any{"ok": true, "operation_id": op.ID, "domain": op.Domain, "state": op.State, "stage": op.Stage, "message": op.LastError, "checkpoints": op.Checkpoints, "status_url": path + "/status", "progress_url": path, "redirect": redirect, "html": html.String()})
}
func (s *Server) handleRemovalPage(w http.ResponseWriter, r *http.Request) {
	user, op, support, ok := s.removalOperation(w, r, false)
	if !ok {
		return
	}
	if op.State == "completed" {
		http.Redirect(w, r, s.removalDestination(r, user, op, support), 303)
		return
	}
	model := web.SiteRemovalView{Operation: &op}
	view := web.WorkspaceView{Route: "site-removal-progress", Title: "Website removal", CSRFToken: csrfToken(r), SupportCustomerID: support, SiteRemoval: &model}
	s.renderRemovalWorkspace(w, r, user, view)
}
func (s *Server) handleRemovalRetry(w http.ResponseWriter, r *http.Request) {
	user, current, support, ok := s.removalOperation(w, r, false)
	if !ok {
		return
	}
	op, err := s.siteRemoval.RetrySiteRemovalFor(r.Context(), user, current.ID)
	if !removalScopeValid(w, r, support, op.CustomerID, err) {
		return
	}
	if err != nil {
		if wantsSPAJSON(r) {
			writeSPAError(w, 400, sanitizeNoticeText(err.Error()))
		} else {
			redirectFormError(w, r, removalPath(support, "/site-removals/"+strconv.FormatInt(current.ID, 10)), sanitizeNoticeText(err.Error()))
		}
		return
	}
	s.respondRemovalAccepted(w, r, op, support)
}
func (s *Server) renderRemovalWorkspace(w http.ResponseWriter, r *http.Request, user auth.SessionUser, view web.WorkspaceView) {
	s.renderRemovalWorkspaceStatus(w, r, user, view, http.StatusOK)
}

func (s *Server) renderRemovalWorkspaceStatus(w http.ResponseWriter, r *http.Request, user auth.SessionUser, view web.WorkspaceView, status int) {
	siteID := int64(0)
	if view.SiteRemoval != nil {
		if view.SiteRemoval.Preview != nil {
			siteID = view.SiteRemoval.Preview.SiteID
		}
		if view.SiteRemoval.Operation != nil {
			siteID = view.SiteRemoval.Operation.SiteID
		}
	}
	data, err := s.loadDashboard(dashboard.WithServiceScope(r.Context(), 0, siteID), user)
	if err != nil {
		http.Error(w, "Could not load removal workspace", 503)
		return
	}
	if view.SupportCustomerID > 0 {
		data = filterDashboardForCustomer(data, view.SupportCustomerID)
		for _, c := range data.Customers {
			if c.ID == view.SupportCustomerID {
				view.SupportCustomerName = c.DisplayName
			}
		}
	}
	if data.Notice == "" {
		data.Notice, data.NoticeKind = workspaceNotice(w, r)
	}
	if status != http.StatusOK {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Nakpanel-Complete-Error-Page", "1")
		w.WriteHeader(status)
	}
	s.renderRoutedPage(w, r, view.Title, user, data, s.dashboardActions(user), view)
}

func (s *Server) applyRemovalNotice(r *http.Request, user auth.SessionUser, data *dashboard.Data, support int64) {
	if r.URL.Query().Get("notice") != "website-removed" {
		return
	}
	data.Notice = ""
	id := parseQueryInt64(r, "removal_id")
	if id <= 0 || s.siteRemoval == nil {
		return
	}
	op, err := s.siteRemoval.SiteRemovalFor(r.Context(), user, id)
	if err != nil || op.State != "completed" || support > 0 && op.CustomerID != support {
		return
	}
	data.Notice = fmt.Sprintf("%s was removed. %d databases and %d backups were kept under the subscription.", op.Domain, len(op.Snapshot.Databases)-len(op.DeleteDatabaseIDs), len(op.Snapshot.Backups))
	data.NoticeKind = dashboard.NoticeSuccess
}
