package panelhttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	mailimport "github.com/nakroteck/nakpanel/internal/control/mailimport"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeMailImports struct {
	err   error
	calls int
	last  types.MailImportRequest
}

func (f *fakeMailImports) MapFolders(context.Context, auth.SessionUser, string, []types.MailImportMapping) error {
	return f.err
}

func (f *fakeMailImports) Workspace(context.Context, auth.SessionUser, int64, string) (types.MailImportWorkspace, error) {
	f.calls++
	return types.MailImportWorkspace{SiteID: 7, Domain: "owned.test", Mailboxes: []types.MailImportMailbox{{ID: 1, Address: "test@owned.test", Active: true}}}, f.err
}
func (f *fakeMailImports) Preview(_ context.Context, _ auth.SessionUser, req types.MailImportRequest) (types.MailImportPreview, error) {
	f.calls++
	f.last = req
	return types.MailImportPreview{ID: "imp_test", Request: req}, f.err
}
func (f *fakeMailImports) Start(context.Context, auth.SessionUser, string) (types.MailImport, error) {
	return types.MailImport{ID: "imp_test", State: "queued"}, f.err
}
func (f *fakeMailImports) Status(context.Context, auth.SessionUser, string) (types.MailImport, error) {
	return types.MailImport{ID: "imp_test", MailboxID: 1, State: "attention_required", LastError: "The append acknowledgement was lost. Reconcile before retrying."}, f.err
}
func (f *fakeMailImports) Transition(context.Context, auth.SessionUser, string, string) (types.MailImport, error) {
	return types.MailImport{}, f.err
}
func (f *fakeMailImports) Stage(context.Context, auth.SessionUser, int64, io.Reader) (types.StageMaildirResult, error) {
	return types.StageMaildirResult{}, f.err
}

func TestMailImportWorkspaceProviderAndClientAccess(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller, auth.RoleClient} {
		t.Run(string(role), func(t *testing.T) {
			service := &fakeMailImports{}
			handler, _ := newTestHandlerWithOptions(t, role, ServerOptions{DashboardReader: &fakeDashboardReader{data: wordpressHTTPDashboard()}, MailImports: service})
			email, password := "admin@nakpanel.test", "NakpanelAdmin!2026"
			if role == auth.RoleClient {
				email, password = "client@nakpanel.test", "NakpanelClient!2026"
			}
			if role == auth.RoleReseller {
				email, password = "reseller@nakpanel.test", "NakpanelReseller!2026"
			}
			cookie := login(t, handler, email, password)
			request := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/mail-imports", nil)
			addAuthenticatedCookie(request, cookie)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if role == auth.RoleClient {
				if response.Code != http.StatusForbidden {
					t.Fatalf("client access %d", response.Code)
				}
			} else if response.Code != 200 || !strings.Contains(response.Body.String(), "Import mail") {
				t.Fatalf("workspace %d %s", response.Code, response.Body.String())
			}
		})
	}
}
func TestMailImportForeignSiteIsNotFound(t *testing.T) {
	service := &fakeMailImports{err: mailimport.ErrNotFound}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: &fakeDashboardReader{data: wordpressHTTPDashboard()}, MailImports: service})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	request := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/mail-imports", nil)
	addAuthenticatedCookie(request, cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("got %d", response.Code)
	}
}
func TestMailImportPreviewRequiresCSRF(t *testing.T) {
	service := &fakeMailImports{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{MailImports: service})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	request := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/mail-imports/preview", strings.NewReader("mailbox_id=1"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 403 || service.calls != 0 {
		t.Fatalf("csrf bypass: %d %d", response.Code, service.calls)
	}
}

func TestMailImportEnhancedPreviewRedactsPasswords(t *testing.T) {
	service := &fakeMailImports{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{MailImports: service})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	form := url.Values{"mailbox_id": {"1"}, "source_kind": {"imap"}, "source_host": {"mail.example.com"}, "source_user": {"user"}, "source_password": {"source-hidden"}, "target_password": {"target-hidden"}}
	request := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/mail-imports/preview", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-Nakpanel-SPA", "true")
	addAuthenticatedCookie(request, cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 || strings.Contains(response.Body.String(), "hidden") || service.last.SourcePassword != "source-hidden" {
		t.Fatalf("preview response unsafe: %d %s", response.Code, response.Body.String())
	}
}
