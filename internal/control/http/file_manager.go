package panelhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlfiles "github.com/nakroteck/nakpanel/internal/control/filemanager"
	"github.com/nakroteck/nakpanel/internal/control/web"
	"github.com/nakroteck/nakpanel/internal/types"
)

const fileUploadOverhead int64 = 2 << 20

func (s *Server) registerFileManagerRoutes(mux *http.ServeMux) {
	for _, prefix := range []string{"/sites/{id}", "/support/customers/{customerID}/sites/{id}"} {
		mux.HandleFunc("GET "+prefix+"/files", s.handleFileList)
		mux.HandleFunc("GET "+prefix+"/files/edit", s.handleFileEdit)
		mux.HandleFunc("GET "+prefix+"/files/download", s.handleFileDownload)
		mux.HandleFunc("POST "+prefix+"/files/upload", s.handleFileUpload)
		mux.HandleFunc("POST "+prefix+"/files/create", s.handleFileCreate)
		mux.HandleFunc("POST "+prefix+"/files/save", s.handleFileSave)
		mux.HandleFunc("POST "+prefix+"/files/rename", s.handleFileRename)
		mux.HandleFunc("POST "+prefix+"/files/copy", s.handleFileCopy)
		mux.HandleFunc("POST "+prefix+"/files/move", s.handleFileMove)
		mux.HandleFunc("POST "+prefix+"/files/delete", s.handleFileDelete)
		mux.HandleFunc("POST "+prefix+"/files/archive", s.handleFileArchive)
		mux.HandleFunc("POST "+prefix+"/files/extract", s.handleFileExtract)
		mux.HandleFunc("POST "+prefix+"/files/permissions", s.handleFilePermissions)
	}
}

type fileRequest struct {
	user      auth.SessionUser
	site      controlfiles.Site
	siteID    int64
	supportID int64
}

func (s *Server) currentFileRequest(w http.ResponseWriter, r *http.Request) (fileRequest, bool) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return fileRequest{}, false
	}
	if s.files == nil {
		http.Error(w, "File Manager is unavailable", http.StatusServiceUnavailable)
		return fileRequest{}, false
	}
	siteID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || siteID <= 0 {
		http.NotFound(w, r)
		return fileRequest{}, false
	}
	site, err := s.files.Site(r.Context(), user, siteID)
	if err != nil {
		writeFileManagerError(w, r, err)
		return fileRequest{}, false
	}
	supportID := int64(0)
	if raw := strings.TrimSpace(r.PathValue("customerID")); raw != "" {
		if user.Role != auth.RoleAdmin {
			http.NotFound(w, r)
			return fileRequest{}, false
		}
		supportID, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || supportID <= 0 || site.CustomerID != supportID {
			http.NotFound(w, r)
			return fileRequest{}, false
		}
	}
	return fileRequest{user: user, site: site, siteID: siteID, supportID: supportID}, true
}

func (s *Server) handleFileList(w http.ResponseWriter, r *http.Request) {
	request, ok := s.currentFileRequest(w, r)
	if !ok {
		return
	}
	requestedPath := strings.TrimSpace(r.URL.Query().Get("path"))
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	viewData := &web.FileManagerView{
		SiteID: request.siteID, Domain: request.site.Domain, Username: request.site.Username,
		Path: requestedPath, Query: query, Sort: r.URL.Query().Get("sort"), Order: r.URL.Query().Get("order"),
		UploadMaxBytes: s.files.UploadMaxBytes(),
	}
	if query != "" {
		_, result, err := s.files.Search(r.Context(), request.user, request.siteID, types.FileSearchReq{Path: requestedPath, Query: query, Limit: 200, Sort: viewData.Sort, Order: viewData.Order})
		if err != nil {
			viewData.Error = publicFileManagerError(err)
		} else {
			viewData.Entries, viewData.Total, viewData.Page, viewData.PerPage = result.Entries, len(result.Entries), 1, 200
		}
	} else {
		pageNumber, _ := strconv.Atoi(r.URL.Query().Get("page"))
		_, result, err := s.files.List(r.Context(), request.user, request.siteID, types.FileListReq{Path: requestedPath, Page: pageNumber, PerPage: 100, Sort: viewData.Sort, Order: viewData.Order})
		if err != nil {
			viewData.Error = publicFileManagerError(err)
		} else {
			viewData.Path, viewData.Entries, viewData.Directories = result.Path, result.Entries, result.Directories
			viewData.Total, viewData.Page, viewData.PerPage = result.Total, result.Page, result.PerPage
		}
	}
	data, view, ok := s.fileWorkspaceData(w, r, request, "site-files")
	if !ok {
		return
	}
	view.FileManager = viewData
	w.Header().Set("Cache-Control", "no-store")
	renderPage(w, r, web.RoutedDashboardPage("File Manager · "+request.site.Domain, request.user, data, s.dashboardActions(request.user), view))
}

func (s *Server) handleFileEdit(w http.ResponseWriter, r *http.Request) {
	request, ok := s.currentFileRequest(w, r)
	if !ok {
		return
	}
	filePath := strings.TrimSpace(r.URL.Query().Get("path"))
	_, result, err := s.files.Read(r.Context(), request.user, request.siteID, filePath)
	if err != nil {
		writeFileManagerError(w, r, err)
		return
	}
	data, view, ok := s.fileWorkspaceData(w, r, request, "site-file-edit")
	if !ok {
		return
	}
	view.FileEditor = &web.FileEditorView{SiteID: request.siteID, Domain: request.site.Domain, Path: result.Path, Name: path.Base(result.Path), Content: result.Content, SHA256: result.SHA256, Mode: result.Mode}
	w.Header().Set("Cache-Control", "no-store")
	renderPage(w, r, web.RoutedDashboardPage("Edit "+path.Base(result.Path), request.user, data, s.dashboardActions(request.user), view))
}

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	request, ok := s.currentFileRequest(w, r)
	if !ok {
		return
	}
	_, transfer, stagedPath, err := s.files.Download(r.Context(), request.user, request.siteID, strings.TrimSpace(r.URL.Query().Get("path")))
	if err != nil {
		writeFileManagerError(w, r, err)
		return
	}
	defer s.files.CleanupTransfer(transfer.TransferToken)
	file, err := os.Open(stagedPath)
	if err != nil {
		http.Error(w, "Download is unavailable", http.StatusServiceUnavailable)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.Error(w, "Download is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", contentDisposition(transfer.Name))
	http.ServeContent(w, r, transfer.Name, transfer.ModifiedAt, file)
}

func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	request, ok := s.currentFileRequest(w, r)
	if !ok {
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(15 * time.Minute))
	currentPath := strings.TrimSpace(r.URL.Query().Get("path"))
	overwrite := r.URL.Query().Get("overwrite") == "true"
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Invalid upload", http.StatusBadRequest)
		return
	}
	results := make([]string, 0)
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeFileManagerError(w, r, err)
			return
		}
		filename := part.FileName()
		if filename == "" {
			_ = part.Close()
			continue
		}
		relativeName := filename
		if strings.HasPrefix(part.FormName(), "file:") {
			if decoded, err := url.QueryUnescape(strings.TrimPrefix(part.FormName(), "file:")); err == nil && decoded != "" {
				relativeName = decoded
			}
		}
		destination, err := joinManagedFilePath(currentPath, filepath.ToSlash(relativeName), true)
		if err != nil {
			_ = part.Close()
			writeFileManagerError(w, r, err)
			return
		}
		token, size, err := s.files.StageUpload(r.Context(), part)
		_ = part.Close()
		if err != nil {
			writeFileManagerError(w, r, err)
			return
		}
		_, err = s.files.Import(r.Context(), request.user, request.siteID, token, destination, overwrite, size)
		if err != nil {
			s.files.CleanupTransfer(token)
			writeFileManagerError(w, r, err)
			return
		}
		results = append(results, destination)
	}
	if len(results) == 0 {
		http.Error(w, "Select at least one file", http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "paths": results, "redirect": fileListURL(request, currentPath, "file-uploaded")})
}

func (s *Server) handleFileCreate(w http.ResponseWriter, r *http.Request) {
	request, ok := s.currentFileRequest(w, r)
	if !ok {
		return
	}
	kind := types.FileKind(strings.TrimSpace(r.FormValue("kind")))
	entryPath, err := joinManagedFilePath(r.FormValue("path"), strings.TrimSpace(r.FormValue("name")), false)
	if err == nil {
		_, err = s.files.Create(r.Context(), request.user, request.siteID, types.FileCreateReq{Path: entryPath, Kind: kind})
	}
	s.finishFileMutation(w, r, request, r.FormValue("path"), "file-created", err)
}

func (s *Server) handleFileSave(w http.ResponseWriter, r *http.Request) {
	request, ok := s.currentFileRequest(w, r)
	if !ok {
		return
	}
	filePath := r.FormValue("path")
	_, err := s.files.Write(r.Context(), request.user, request.siteID, types.FileWriteReq{Path: filePath, Content: r.FormValue("content"), ExpectedSHA256: r.FormValue("sha256")})
	if err != nil {
		writeFileManagerError(w, r, err)
		return
	}
	http.Redirect(w, r, fileListURL(request, path.Dir(filePath), "file-saved"), http.StatusSeeOther)
}

func (s *Server) handleFileRename(w http.ResponseWriter, r *http.Request) {
	request, ok := s.currentFileRequest(w, r)
	if !ok {
		return
	}
	filePath := r.FormValue("file_path")
	_, err := s.files.Move(r.Context(), request.user, request.siteID, types.FileBatchReq{Paths: []string{filePath}, Destination: path.Dir(filePath), NewName: strings.TrimSpace(r.FormValue("name"))})
	s.finishFileMutation(w, r, request, r.FormValue("path"), "file-renamed", err)
}

func (s *Server) handleFileCopy(w http.ResponseWriter, r *http.Request) {
	request, ok := s.currentFileRequest(w, r)
	if !ok {
		return
	}
	_, err := s.files.Copy(r.Context(), request.user, request.siteID, batchRequest(r))
	s.finishFileMutation(w, r, request, r.FormValue("path"), "file-copied", err)
}

func (s *Server) handleFileMove(w http.ResponseWriter, r *http.Request) {
	request, ok := s.currentFileRequest(w, r)
	if !ok {
		return
	}
	_, err := s.files.Move(r.Context(), request.user, request.siteID, batchRequest(r))
	s.finishFileMutation(w, r, request, r.FormValue("path"), "file-moved", err)
}

func (s *Server) handleFileDelete(w http.ResponseWriter, r *http.Request) {
	request, ok := s.currentFileRequest(w, r)
	if !ok {
		return
	}
	_, err := s.files.Delete(r.Context(), request.user, request.siteID, types.FileBatchReq{Paths: r.Form["paths"]})
	s.finishFileMutation(w, r, request, r.FormValue("path"), "file-deleted", err)
}

func (s *Server) handleFileArchive(w http.ResponseWriter, r *http.Request) {
	request, ok := s.currentFileRequest(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if !strings.HasSuffix(strings.ToLower(name), ".zip") {
		name += ".zip"
	}
	archivePath, err := joinManagedFilePath(r.FormValue("path"), name, false)
	if err == nil {
		_, err = s.files.Archive(r.Context(), request.user, request.siteID, types.FileArchiveReq{Paths: r.Form["paths"], Destination: archivePath})
	}
	s.finishFileMutation(w, r, request, r.FormValue("path"), "file-archived", err)
}

func (s *Server) handleFileExtract(w http.ResponseWriter, r *http.Request) {
	request, ok := s.currentFileRequest(w, r)
	if !ok {
		return
	}
	_, err := s.files.Extract(r.Context(), request.user, request.siteID, types.FileExtractReq{Path: r.FormValue("file_path"), Destination: r.FormValue("destination"), Overwrite: r.FormValue("overwrite") == "true"})
	s.finishFileMutation(w, r, request, r.FormValue("path"), "file-extracted", err)
}

func (s *Server) handleFilePermissions(w http.ResponseWriter, r *http.Request) {
	request, ok := s.currentFileRequest(w, r)
	if !ok {
		return
	}
	mode, err := strconv.ParseUint(strings.TrimSpace(r.FormValue("mode")), 8, 32)
	if err == nil {
		_, err = s.files.Chmod(r.Context(), request.user, request.siteID, types.FileModeReq{Path: r.FormValue("file_path"), Mode: uint32(mode), Recursive: r.FormValue("recursive") == "true"})
	} else {
		err = fmt.Errorf("%w: mode must be octal", controlfiles.ErrValidation)
	}
	s.finishFileMutation(w, r, request, r.FormValue("path"), "file-permissions", err)
}

func batchRequest(r *http.Request) types.FileBatchReq {
	return types.FileBatchReq{Paths: r.Form["paths"], Destination: strings.TrimSpace(r.FormValue("destination")), Overwrite: r.FormValue("overwrite") == "true"}
}

func joinManagedFilePath(base, name string, allowNested bool) (string, error) {
	if !utf8.ValidString(name) || strings.IndexByte(name, 0) >= 0 || name == "" || len(name) > 4096 || path.IsAbs(name) || filepath.IsAbs(name) {
		return "", fmt.Errorf("%w: invalid file name", controlfiles.ErrValidation)
	}
	parts := strings.Split(name, "/")
	if !allowNested && len(parts) != 1 {
		return "", fmt.Errorf("%w: file name must not contain folders", controlfiles.ErrValidation)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return "", fmt.Errorf("%w: invalid file name", controlfiles.ErrValidation)
		}
	}
	base = strings.TrimSpace(base)
	if !utf8.ValidString(base) || strings.IndexByte(base, 0) >= 0 || len(base) > 4096 || path.IsAbs(base) || filepath.IsAbs(base) {
		return "", fmt.Errorf("%w: invalid current folder", controlfiles.ErrValidation)
	}
	if base != "" {
		for _, part := range strings.Split(base, "/") {
			if part == "" || part == "." || part == ".." || len(part) > 255 {
				return "", fmt.Errorf("%w: invalid current folder", controlfiles.ErrValidation)
			}
		}
	}
	joined := path.Join(base, name)
	if len(joined) > 4096 {
		return "", fmt.Errorf("%w: file path is too long", controlfiles.ErrValidation)
	}
	return joined, nil
}

func (s *Server) finishFileMutation(w http.ResponseWriter, r *http.Request, request fileRequest, currentPath, notice string, err error) {
	if err != nil {
		writeFileManagerError(w, r, err)
		return
	}
	http.Redirect(w, r, fileListURL(request, currentPath, notice), http.StatusSeeOther)
}

func (s *Server) fileWorkspaceData(w http.ResponseWriter, r *http.Request, request fileRequest, route string) (dashboard.Data, web.WorkspaceView, bool) {
	data, err := s.loadDashboard(r.Context(), request.user)
	if err != nil {
		http.Error(w, "Could not load File Manager", http.StatusInternalServerError)
		return dashboard.Data{}, web.WorkspaceView{}, false
	}
	view := web.WorkspaceView{Route: route, Title: dashboardTitle(request.user.Role), DetailID: request.siteID, CSRFToken: csrfToken(r)}
	data.Notice = dashboardNotice(r.URL.Query().Get("notice"))
	if request.supportID > 0 {
		name := ""
		for _, customer := range data.Customers {
			if customer.ID == request.supportID {
				name = customer.DisplayName
				if name == "" {
					name = customer.Email
				}
				break
			}
		}
		if name == "" {
			http.NotFound(w, r)
			return dashboard.Data{}, web.WorkspaceView{}, false
		}
		data = filterDashboardForCustomer(data, request.supportID)
		view.Title, view.SupportCustomerID, view.SupportCustomerName = "Support view", request.supportID, name
	}
	return data, view, true
}

func fileListURL(request fileRequest, currentPath, notice string) string {
	base := "/sites/" + strconv.FormatInt(request.siteID, 10) + "/files"
	if request.supportID > 0 {
		base = "/support/customers/" + strconv.FormatInt(request.supportID, 10) + base
	}
	values := url.Values{}
	if cleaned := strings.Trim(strings.TrimSpace(currentPath), "/"); cleaned != "" && cleaned != "." {
		values.Set("path", cleaned)
	}
	if notice != "" {
		values.Set("notice", notice)
	}
	if encoded := values.Encode(); encoded != "" {
		return base + "?" + encoded
	}
	return base
}

func contentDisposition(name string) string {
	name = strings.ReplaceAll(strings.ReplaceAll(path.Base(name), "\"", ""), "\r", "")
	name = strings.ReplaceAll(name, "\n", "")
	return fmt.Sprintf("attachment; filename=\"%s\"; filename*=UTF-8''%s", name, url.PathEscape(name))
}

func writeFileManagerError(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError
	message := publicFileManagerError(err)
	switch {
	case errors.Is(err, controlfiles.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, controlfiles.ErrForbidden):
		status = http.StatusForbidden
	case errors.Is(err, controlfiles.ErrConflict):
		status = http.StatusConflict
	case errors.Is(err, controlfiles.ErrTooLarge):
		status = http.StatusRequestEntityTooLarge
	case errors.Is(err, controlfiles.ErrValidation):
		status = http.StatusUnprocessableEntity
	case errors.Is(err, controlfiles.ErrUnavailable):
		status = http.StatusServiceUnavailable
	}
	http.Error(w, message, status)
}

func publicFileManagerError(err error) string {
	switch {
	case errors.Is(err, controlfiles.ErrNotFound):
		return "File Manager site was not found."
	case errors.Is(err, controlfiles.ErrForbidden):
		return "You do not have permission to perform this file operation."
	case errors.Is(err, controlfiles.ErrConflict):
		return "The file changed or the destination already exists. Refresh and try again."
	case errors.Is(err, controlfiles.ErrTooLarge):
		return "The file or archive exceeds the configured limit."
	case errors.Is(err, controlfiles.ErrValidation):
		return "The requested file operation is not valid."
	case errors.Is(err, controlfiles.ErrUnavailable):
		return "File Manager is temporarily unavailable because the server agent is not ready."
	default:
		return "The file operation could not be completed."
	}
}
