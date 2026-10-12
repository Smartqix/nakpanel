package panelhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
)

func TestSiteLogDataEncodesEmptyLinesAsArray(t *testing.T) {
	services := &fakeMailDomainServices{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DomainManager: services})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/logs/data?source=nginx_error&limit=20&bytes=4096", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"lines":[]`) {
		t.Fatalf("empty log API=%d %s", rec.Code, rec.Body.String())
	}
}
