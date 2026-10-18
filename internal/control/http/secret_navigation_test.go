package panelhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

type secretNavigationServices struct{ fakeMailDomainServices }

func (*secretNavigationServices) UpsertFTPAccount(context.Context, auth.SessionUser, int64, types.FTPAccountInput) (int64, string, error) {
	return 1, "secret<&password", nil
}
func (*secretNavigationServices) ConfigureValkey(context.Context, auth.SessionUser, int64, types.ValkeyInput) (string, error) {
	return "secret<&password", nil
}
func (*secretNavigationServices) UpsertProtectedDirectory(context.Context, auth.SessionUser, int64, types.ProtectedDirectoryInput) (int64, string, error) {
	return 1, "secret<&password", nil
}
func (*secretNavigationServices) QueueGitDeployment(context.Context, auth.SessionUser, int64, int64) (int64, error) {
	return 1, nil
}
func (*secretNavigationServices) RotateGitWebhook(context.Context, auth.SessionUser, int64, int64) (string, error) {
	return "secret<&password", nil
}
func (*secretNavigationServices) TriggerGitWebhook(context.Context, int64, string) error { return nil }

func TestSecretPOSTRepresentations(t *testing.T) {
	data := dashboard.Data{Sites: []dashboard.Site{{ID: 7, SubscriptionID: 20, Domain: "owned.test"}}, Subscriptions: []types.SubscriptionSummary{{ID: 20}}}
	service := &secretNavigationServices{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DomainManager: service, DashboardReader: &fakeDashboardReader{data: data}})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	for _, tc := range []struct {
		path, title string
		status      int
	}{
		{"/subscriptions/20/ftp", "FTPS account created", 201},
		{"/subscriptions/20/valkey", "Cache credential rotated", 200},
		{"/sites/7/git/webhook", "Webhook credential rotated", 201},
		{"/subscriptions/20/protected-directories", "Protected directory saved", 201},
	} {
		for _, representation := range []struct {
			fragment bool
			accept   string
		}{{false, "text/html"}, {true, "text/html"}, {true, "application/json"}} {
			fragment := representation.fragment
			t.Run(tc.path+map[bool]string{false: "/full/", true: "/fragment/"}[fragment]+representation.accept, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, "https://panel.test"+tc.path, strings.NewReader("site_id=7&username=test&path=private&password=test"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Accept", representation.accept)
				if fragment {
					req.Header.Set("X-Nakpanel-Fragment", "main")
				}
				addAuthenticatedCookie(req, cookie)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				body := rec.Body.String()
				if rec.Code != tc.status || rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("response: %d %v %s", rec.Code, rec.Header(), body)
				}
				for _, marker := range []string{tc.title, "shown once", "secret&lt;&amp;password", ">Continue</a>"} {
					if !strings.Contains(body, marker) {
						t.Errorf("missing %s: %s", marker, body)
					}
				}
				if fragment {
					for _, marker := range []string{`data-keep-shell="true"`, `data-np-fragment="main"`, `data-np-copy-secret`} {
						if !strings.Contains(body, marker) {
							t.Errorf("missing %s: %s", marker, body)
						}
					}
					if strings.Contains(body, "<!doctype") || strings.Contains(body, `data-np-shell="sidebar"`) {
						t.Fatal("fragment replaced shell")
					}
				} else if !strings.HasPrefix(body, "<!doctype html><meta name=\"robots\" content=\"noindex\">") || strings.Contains(body, "data-np-fragment") {
					t.Fatal("legacy full page changed")
				}
			})
		}
	}
}
