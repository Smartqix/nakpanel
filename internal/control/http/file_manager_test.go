package panelhttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlfiles "github.com/nakroteck/nakpanel/internal/control/filemanager"
	"github.com/nakroteck/nakpanel/internal/control/web"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeFileManagerService struct {
	site      controlfiles.Site
	listing   types.FileListResult
	staged    bool
	imported  bool
	uploadMax int64
	siteErr   error
	listErr   error
}

func (f *fakeFileManagerService) UploadMaxBytes() int64 {
	if f.uploadMax > 0 {
		return f.uploadMax
	}
	return 2 << 20
}
func (f *fakeFileManagerService) Site(context.Context, auth.SessionUser, int64) (controlfiles.Site, error) {
	if f.siteErr != nil {
		return controlfiles.Site{}, f.siteErr
	}
	return f.site, nil
}
func (f *fakeFileManagerService) List(context.Context, auth.SessionUser, int64, types.FileListReq) (controlfiles.Site, types.FileListResult, error) {
	return f.site, f.listing, f.listErr
}

func TestFileManagerDisablesMutationsWhenAgentIsUnavailable(t *testing.T) {
	files := &fakeFileManagerService{site: controlfiles.Site{ID: 7, Username: "npdemo", Domain: "owned.test"}, listErr: controlfiles.ErrUnavailable}
	reader := &fakeDashboardReader{data: dashboard.Data{Sites: []dashboard.Site{{ID: 7, Username: "npdemo", Domain: "owned.test", Status: "active"}}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader, FileManager: files})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/files", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "data-np-file-unavailable") || !strings.Contains(rec.Body.String(), "File Manager unavailable") {
		t.Fatalf("unavailable page=%d body=%s", rec.Code, rec.Body.String())
	}
}
func (f *fakeFileManagerService) Search(context.Context, auth.SessionUser, int64, types.FileSearchReq) (controlfiles.Site, types.FileSearchResult, error) {
	return f.site, types.FileSearchResult{}, nil
}
func (f *fakeFileManagerService) Read(context.Context, auth.SessionUser, int64, string) (controlfiles.Site, types.FileReadResult, error) {
	return f.site, types.FileReadResult{Path: "index.php", Content: "hello", SHA256: "hash", Mode: 0o644}, nil
}
func (f *fakeFileManagerService) Write(context.Context, auth.SessionUser, int64, types.FileWriteReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeFileManagerService) Create(context.Context, auth.SessionUser, int64, types.FileCreateReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeFileManagerService) Copy(context.Context, auth.SessionUser, int64, types.FileBatchReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeFileManagerService) Move(context.Context, auth.SessionUser, int64, types.FileBatchReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeFileManagerService) Delete(context.Context, auth.SessionUser, int64, types.FileBatchReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeFileManagerService) Archive(context.Context, auth.SessionUser, int64, types.FileArchiveReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeFileManagerService) Extract(context.Context, auth.SessionUser, int64, types.FileExtractReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeFileManagerService) Chmod(context.Context, auth.SessionUser, int64, types.FileModeReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeFileManagerService) StageUpload(_ context.Context, reader io.Reader) (string, int64, error) {
	f.staged = true
	data, _ := io.ReadAll(reader)
	return "upload-0123456789abcdef0123456789abcdef", int64(len(data)), nil
}
func (f *fakeFileManagerService) Import(context.Context, auth.SessionUser, int64, string, string, bool, int64) (types.FileMutationResult, error) {
	f.imported = true
	return types.FileMutationResult{}, nil
}
func (f *fakeFileManagerService) Download(context.Context, auth.SessionUser, int64, string) (controlfiles.Site, types.FileTransferResult, string, error) {
	return f.site, types.FileTransferResult{}, "", controlfiles.ErrUnavailable
}
func (f *fakeFileManagerService) CleanupTransfer(string) {}

func TestFileManagerWorkspaceRendersPleskStyleControls(t *testing.T) {
	files := &fakeFileManagerService{
		site:    controlfiles.Site{ID: 7, Username: "npdemo", Domain: "owned.test", CustomerID: 88, SubscriptionID: 20},
		listing: types.FileListResult{Entries: []types.FileEntry{{Path: "assets", Name: "assets", Kind: types.FileKindDirectory, Mode: 0o755, Owner: "npdemo", Group: "npdemo", Writable: true}, {Path: "index.php", Name: "index.php", Kind: types.FileKindFile, Size: 42, Mode: 0o644, Owner: "npdemo", Group: "npdemo", Editable: true, Downloadable: true, Writable: true}}, Total: 2, Page: 1, PerPage: 100},
	}
	reader := &fakeDashboardReader{data: dashboard.Data{Sites: []dashboard.Site{{ID: 7, Username: "npdemo", Domain: "owned.test", Status: "active", CustomerID: 88, SubscriptionID: 20}}, Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, SubscriptionName: "Owned hosting", PlanName: "Business"}}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader, FileManager: files})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	for path, marker := range map[string]string{"/sites/7": "File Manager", "/sites/7/files": "Upload files", "/sites/7/files/edit?path=index.php": "data-np-code-editor"} {
		req := httptest.NewRequest(http.MethodGet, "https://panel.test"+path, nil)
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), marker) {
			t.Fatalf("GET %s = %d marker %q missing\n%s", path, rec.Code, marker, rec.Body.String())
		}
	}
	pageReq := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/files", nil)
	addAuthenticatedCookie(pageReq, cookie)
	pageRec := httptest.NewRecorder()
	handler.ServeHTTP(pageRec, pageReq)
	for _, marker := range []string{"public_html", "index.php", "Permissions", "Create ZIP archive", "/assets/ace/ace.js"} {
		if marker == "/assets/ace/ace.js" {
			continue
		}
		if !strings.Contains(pageRec.Body.String(), marker) {
			t.Fatalf("file manager marker %q missing", marker)
		}
	}
}

func TestFileUploadUsesHeaderCSRFAndLargerRouteLimit(t *testing.T) {
	files := &fakeFileManagerService{site: controlfiles.Site{ID: 7, Username: "npdemo", Domain: "owned.test"}, uploadMax: 2 << 20}
	reader := &fakeDashboardReader{data: dashboard.Data{Sites: []dashboard.Site{{ID: 7, Username: "npdemo", Domain: "owned.test", Status: "active"}}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader, FileManager: files})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("files", "large.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(bytes.Repeat([]byte("a"), maxFormBodyBytes+1024))
	_ = writer.Close()
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/files/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Origin", "https://panel.test")
	req.AddCookie(cookie)
	req.Header.Set("X-Nakpanel-CSRF", csrfToken(req))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !files.staged || !files.imported {
		t.Fatalf("upload=%d staged=%v imported=%v body=%s", rec.Code, files.staged, files.imported, rec.Body.String())
	}
}

func TestClientCannotOpenForeignFileManagerSite(t *testing.T) {
	files := &fakeFileManagerService{siteErr: controlfiles.ErrNotFound}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: &fakeDashboardReader{}, FileManager: files})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/999/files", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("foreign file manager = %d", rec.Code)
	}
}

func TestAceAssetsAreEmbeddedForFileEditor(t *testing.T) {
	handler := web.StaticHandler()
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/ace/ace.js", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ace.define") {
		t.Fatalf("ace asset = %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestJoinManagedFilePathRejectsTraversalAndAbsoluteNames(t *testing.T) {
	for _, name := range []string{"../secret", "folder/../secret", "/etc/passwd", "folder//file"} {
		if _, err := joinManagedFilePath("assets", name, true); !errors.Is(err, controlfiles.ErrValidation) {
			t.Fatalf("name %q error=%v", name, err)
		}
	}
	if _, err := joinManagedFilePath("assets", "nested/file.txt", false); !errors.Is(err, controlfiles.ErrValidation) {
		t.Fatalf("nested leaf error=%v", err)
	}
	if got, err := joinManagedFilePath("assets", "nested/file.txt", true); err != nil || got != "assets/nested/file.txt" {
		t.Fatalf("joined=%q err=%v", got, err)
	}
}
