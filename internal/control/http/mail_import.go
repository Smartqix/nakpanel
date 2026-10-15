package panelhttp

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	mailimport "github.com/nakroteck/nakpanel/internal/control/mailimport"
	"github.com/nakroteck/nakpanel/internal/control/web"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (s *Server) registerMailImportRoutes(mux *http.ServeMux) {
	for _, prefix := range []string{"/sites/{id}/mail-imports", "/support/customers/{customerID}/sites/{id}/mail-imports"} {
		page := func(w http.ResponseWriter, r *http.Request) {
			if r.PathValue("customerID") != "" {
				clone := r.Clone(r.Context())
				clone.SetPathValue("tool", "mail-imports")
				s.handleSupportObject("sites", "tool")(w, clone)
				return
			}
			s.handleSiteTool("mail-imports")(w, r)
		}
		mux.HandleFunc("GET "+prefix, page)
		mux.HandleFunc("GET "+prefix+"/{importID}", page)
		mux.HandleFunc("POST "+prefix+"/preview", s.handleMailImportPreview)
		mux.HandleFunc("GET "+prefix+"/{importID}/status", s.handleMailImportStatus)
		for _, action := range []string{"start", "pause", "resume", "cancel"} {
			mux.HandleFunc("POST "+prefix+"/{importID}/"+action, s.handleMailImportAction(action))
		}
	}
}
func (s *Server) loadMailImportWorkspace(w http.ResponseWriter, r *http.Request, actor auth.SessionUser, siteID int64, view *web.WorkspaceView) bool {
	if actor.Role != auth.RoleAdmin && actor.Role != auth.RoleReseller {
		s.mailImportError(w, r, mailimport.ErrForbidden)
		return false
	}
	if s.mailImports == nil {
		http.Error(w, "Mail imports are unavailable", 503)
		return false
	}
	data, err := s.mailImports.Workspace(r.Context(), actor, siteID, r.PathValue("importID"))
	if err != nil {
		s.mailImportError(w, r, err)
		return false
	}
	view.MailImports = &data
	return true
}
func (s *Server) mailImportRequest(w http.ResponseWriter, r *http.Request) (auth.SessionUser, int64, types.MailImportWorkspace, bool) {
	actor, ok := s.requireProvider(w, r)
	if !ok {
		return actor, 0, types.MailImportWorkspace{}, false
	}
	id, err := parsePositivePathID(r, "id")
	if err != nil {
		http.NotFound(w, r)
		return actor, 0, types.MailImportWorkspace{}, false
	}
	if actor.Role == auth.RoleAdmin && !s.phpSupportMutationVisible(w, r, actor, id) {
		return actor, 0, types.MailImportWorkspace{}, false
	}
	if s.mailImports == nil {
		http.Error(w, "Mail imports are unavailable", 503)
		return actor, 0, types.MailImportWorkspace{}, false
	}
	workspace, err := s.mailImports.Workspace(r.Context(), actor, id, r.PathValue("importID"))
	if err != nil {
		s.mailImportError(w, r, err)
		return actor, 0, workspace, false
	}
	w.Header().Set("Cache-Control", "private, no-store")
	return actor, id, workspace, true
}
func isMailImportMultipartPreview(r *http.Request) bool {
	return r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/mail-imports/preview") && strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data")
}
func (s *Server) handleMailImportPreview(w http.ResponseWriter, r *http.Request) {
	actor, siteID, workspace, ok := s.mailImportRequest(w, r)
	if !ok {
		return
	}
	err := r.ParseMultipartForm(32 << 10)
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if err != nil && !errors.Is(err, http.ErrNotMultipart) {
		s.mailImportError(w, r, errors.New("invalid mail import form"))
		return
	}
	if subtle.ConstantTimeCompare([]byte(csrfToken(r)), []byte(r.FormValue("csrf_token"))) != 1 && subtle.ConstantTimeCompare([]byte(csrfToken(r)), []byte(r.Header.Get("X-Nakpanel-CSRF"))) != 1 {
		http.Error(w, "Forbidden", 403)
		return
	}
	box, _ := strconv.ParseInt(r.FormValue("mailbox_id"), 10, 64)
	found := false
	for _, entry := range workspace.Mailboxes {
		found = found || entry.ID == box
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	req := types.MailImportRequest{MailboxID: box, SourceKind: r.FormValue("source_kind"), SourceHost: r.FormValue("source_host"), SourceUser: r.FormValue("source_user"), SourcePassword: r.FormValue("source_password"), TargetPassword: r.FormValue("target_password")}
	if len(req.SourcePassword) > 4096 || len(req.TargetPassword) > 4096 || len(req.SourceUser) > 320 {
		s.mailImportError(w, r, errors.New("invalid mail import credentials"))
		return
	}
	if req.SourceKind == "maildir" {
		file, _, err := r.FormFile("archive")
		if err != nil {
			s.mailImportError(w, r, errors.New("a Maildir archive is required"))
			return
		}
		defer file.Close()
		staged, err := s.mailImports.Stage(r.Context(), actor, siteID, file)
		if err != nil {
			s.mailImportError(w, r, err)
			return
		}
		req.StagingID, req.ManifestSHA256 = staged.StagingID, staged.ManifestSHA256
	}
	preview, err := s.mailImports.Preview(r.Context(), actor, req)
	req.SourcePassword, req.TargetPassword = "", ""
	if err != nil {
		s.mailImportError(w, r, err)
		return
	}
	target := supportRedirectPath(r, actor, "/sites/"+strconv.FormatInt(siteID, 10)+"/mail-imports/"+preview.ID)
	if wantsSPAJSON(r) {
		writeSPAJSON(w, 200, map[string]any{"ok": true, "preview": preview, "redirect": target})
		return
	}
	http.Redirect(w, r, target, 303)
}
func (s *Server) handleMailImportStatus(w http.ResponseWriter, r *http.Request) {
	actor, _, _, ok := s.mailImportRequest(w, r)
	if !ok {
		return
	}
	item, err := s.mailImports.Status(r.Context(), actor, r.PathValue("importID"))
	if err != nil {
		s.mailImportError(w, r, err)
		return
	}
	writeSPAJSON(w, 200, map[string]any{"ok": true, "import": item})
}
func (s *Server) handleMailImportAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, siteID, _, ok := s.mailImportRequest(w, r)
		if !ok {
			return
		}
		if err := r.ParseForm(); err != nil {
			s.mailImportError(w, r, err)
			return
		}
		id := r.PathValue("importID")
		var item types.MailImport
		var err error
		if action == "start" {
			if r.FormValue("confirm") != "import" {
				s.mailImportError(w, r, errors.New("import confirmation is required"))
				return
			}
			if values := r.Form["folder_id"]; len(values) > 0 {
				mappings := make([]types.MailImportMapping, 0, len(values))
				for _, value := range values {
					folderID, parseErr := strconv.ParseInt(value, 10, 64)
					if parseErr != nil || folderID <= 0 {
						s.mailImportError(w, r, errors.New("invalid folder mapping"))
						return
					}
					mappings = append(mappings, types.MailImportMapping{FolderID: folderID, Target: r.Form.Get("target_" + value), Include: r.Form.Get("include_"+value) == "true"})
				}
				if err = s.mailImports.MapFolders(r.Context(), actor, id, mappings); err != nil {
					s.mailImportError(w, r, err)
					return
				}
			}
			item, err = s.mailImports.Start(r.Context(), actor, id)
		} else {
			if action == "cancel" && r.FormValue("confirm") != "cancel" {
				s.mailImportError(w, r, errors.New("cancellation confirmation is required"))
				return
			}
			item, err = s.mailImports.Transition(r.Context(), actor, id, action)
		}
		if err != nil {
			s.mailImportError(w, r, err)
			return
		}
		target := supportRedirectPath(r, actor, "/sites/"+strconv.FormatInt(siteID, 10)+"/mail-imports/"+id)
		if wantsSPAJSON(r) {
			writeSPAJSON(w, 200, map[string]any{"ok": true, "import": item, "redirect": target})
			return
		}
		http.Redirect(w, r, target, 303)
	}
}
func (s *Server) mailImportError(w http.ResponseWriter, r *http.Request, err error) {
	status, message := 400, "Mail import could not proceed. Check the credentials, source layout and destination quota."
	if errors.Is(err, mailimport.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if errors.Is(err, mailimport.ErrForbidden) {
		status, message = 403, "Mail imports are available to hosting providers only."
	}
	if errors.Is(err, mailimport.ErrInactive) {
		status, message = 409, mailimport.ErrInactive.Error()
	}
	if wantsSPAJSON(r) {
		writeSPAError(w, status, message)
		return
	}
	http.Error(w, message, status)
}
