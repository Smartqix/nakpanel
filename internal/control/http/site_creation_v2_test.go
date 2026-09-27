package panelhttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlwordpress "github.com/nakroteck/nakpanel/internal/control/wordpress"
)

func postWebsiteForTest(t *testing.T, handler http.Handler, cookie *http.Cookie, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/websites", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Nakpanel-SPA", "true")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func wordpressWebsiteForm() url.Values {
	return url.Values{
		"subscription_id": {"20"}, "domain": {"new.example.test"}, "website_type": {"wordpress"},
		"site_title": {"My site"}, "admin_email": {"owner@example.test"}, "admin_user": {"siteadmin"},
		"admin_password": {"a-strong-test-password"},
	}
}

func TestWordPressWebsitePreflightRejectsBeforeSiteCreation(t *testing.T) {
	creator := &fakeSiteCreator{}
	wordpress := &fakeWordPressService{preflightErr: controlwordpress.ErrDisabled}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{SiteCreator: creator, WordPress: wordpress})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	rec := postWebsiteForTest(t, handler, cookie, wordpressWebsiteForm())
	if rec.Code != http.StatusBadRequest || len(creator.requests) != 0 || wordpress.preflightCalls != 1 {
		t.Fatalf("preflight response=%d sites=%d calls=%d body=%s", rec.Code, len(creator.requests), wordpress.preflightCalls, rec.Body.String())
	}
}

func TestWordPressWebsiteRequiresDatabaseCapacityBeforeSiteCreation(t *testing.T) {
	creator := &fakeSiteCreator{}
	wordpress := &fakeWordPressService{preflightErr: controlwordpress.ErrDatabaseLimit}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{SiteCreator: creator, WordPress: wordpress})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	rec := postWebsiteForTest(t, handler, cookie, wordpressWebsiteForm())
	if rec.Code != http.StatusBadRequest || len(creator.requests) != 0 || !strings.Contains(rec.Body.String(), "database limit") {
		t.Fatalf("database limit response=%d requests=%d body=%s", rec.Code, len(creator.requests), rec.Body.String())
	}
}

func TestWordPressWebsiteCreatesSiteThenQueuesInstall(t *testing.T) {
	creator := &fakeSiteCreator{}
	wordpress := &fakeWordPressService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{SiteCreator: creator, WordPress: wordpress})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	rec := postWebsiteForTest(t, handler, cookie, wordpressWebsiteForm())
	if rec.Code != http.StatusAccepted || wordpress.called != "install" || wordpress.siteID != 7 || len(creator.requests) != 1 {
		t.Fatalf("creation response=%d wordpress=%q site=%d requests=%d body=%s", rec.Code, wordpress.called, wordpress.siteID, len(creator.requests), rec.Body.String())
	}
	if creator.requests[0].PHPVersion != "" || wordpress.install.Title != "My site" || wordpress.install.AdminPassword != "a-strong-test-password" {
		t.Fatalf("site=%#v wordpress=%#v", creator.requests[0], wordpress.install)
	}
	var body struct {
		Redirect    string `json:"redirect"`
		WebsiteType string `json:"website_type"`
		OperationID int64  `json:"operation_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Redirect != "/sites/7/wordpress" || body.WebsiteType != "wordpress" || body.OperationID != 41 {
		t.Fatalf("response = %#v", body)
	}
	if strings.Contains(rec.Body.String(), "a-strong-test-password") {
		t.Fatal("WordPress password leaked in response")
	}
}

func TestWordPressWebsiteReportsPartialCompletionWithoutDiscardingSite(t *testing.T) {
	creator := &fakeSiteCreator{}
	wordpress := &fakeWordPressService{err: errors.New("database unavailable")}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{SiteCreator: creator, WordPress: wordpress})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	rec := postWebsiteForTest(t, handler, cookie, wordpressWebsiteForm())
	if rec.Code != http.StatusAccepted || len(creator.requests) != 1 || !strings.Contains(rec.Body.String(), `"partial":true`) || !strings.Contains(rec.Body.String(), `"site_id":7`) {
		t.Fatalf("partial completion = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "database unavailable") || strings.Contains(rec.Body.String(), "a-strong-test-password") {
		t.Fatal("internal error or password leaked in partial response")
	}
}

func TestWordPressWebsiteValidatesBeforeCreatingSite(t *testing.T) {
	creator := &fakeSiteCreator{}
	wordpress := &fakeWordPressService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{SiteCreator: creator, WordPress: wordpress})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	form := wordpressWebsiteForm()
	form.Set("admin_password", "short")
	rec := postWebsiteForTest(t, handler, cookie, form)
	if rec.Code != http.StatusBadRequest || len(creator.requests) != 0 || wordpress.preflightCalls != 0 {
		t.Fatalf("invalid input = %d sites=%d preflight=%d", rec.Code, len(creator.requests), wordpress.preflightCalls)
	}
}

func TestWebsiteCreationPageShowsFocusedChoices(t *testing.T) {
	data := wordpressHTTPDashboard()
	service := &fakeWordPressService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: &fakeDashboardReader{data: data}, SiteCreator: &fakeSiteCreator{}, WordPress: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/new?type=wordpress&subscription_id=20", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Set up WordPress") || !strings.Contains(rec.Body.String(), `action="/websites"`) {
		t.Fatalf("creation page = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `href="/sites" class="np-routed-nav-item is-active"`) {
		t.Fatal("Add Website did not keep Websites active in the navigation")
	}
	if strings.Contains(rec.Body.String(), `name="php_version"`) && strings.Contains(rec.Body.String(), `class="np-v2-create-form"`) {
		// The legacy dialog may still be embedded elsewhere, but the focused form must not ask for PHP version.
		section := rec.Body.String()[strings.Index(rec.Body.String(), `class="np-v2-create-form"`):]
		section = section[:strings.Index(section, "</form>")]
		if strings.Contains(section, `name="php_version"`) {
			t.Fatal("focused WordPress form exposes PHP runtime selection")
		}
	}
}

func TestWebsiteCreationHidesUnavailableWordPressChoice(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{
		DashboardReader: &fakeDashboardReader{data: wordpressHTTPDashboard()}, SiteCreator: &fakeSiteCreator{},
	})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/new?type=wordpress", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `href="/sites/new?type=wordpress"`) || strings.Contains(rec.Body.String(), `name="website_type" value="wordpress"`) {
		t.Fatalf("unavailable WordPress was offered: status=%d", rec.Code)
	}
}

func TestWebsiteCreationWithoutJavaScriptReturnsUsableValidationForm(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{
		DashboardReader: &fakeDashboardReader{data: wordpressHTTPDashboard()}, SiteCreator: &fakeSiteCreator{},
	})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/websites", strings.NewReader(url.Values{
		"subscription_id": {"20"}, "website_type": {"php"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Review the website details") || !strings.Contains(rec.Body.String(), `action="/websites"`) {
		t.Fatalf("validation response status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCustomerNavigationKeepsAdvancedResourcesUnderWebsites(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{
		DashboardReader: &fakeDashboardReader{data: wordpressHTTPDashboard()}, SiteCreator: &fakeSiteCreator{},
	})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/new", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body := rec.Body.String()
	start, end := strings.Index(body, `<nav class="np-routed-nav"`), strings.Index(body, `</nav>`)
	if rec.Code != http.StatusOK || start < 0 || end < start {
		t.Fatalf("customer navigation missing: status=%d", rec.Code)
	}
	nav := body[start:end]
	for _, label := range []string{"Home", "Websites &amp; Domains", "Mail", "Backups", "Account &amp; Usage"} {
		if !strings.Contains(nav, label) {
			t.Fatalf("customer navigation missing %q: %s", label, nav)
		}
	}
	for _, path := range []string{`href="/databases"`, `href="/dns"`, `href="/certificates"`, `href="/activity"`} {
		if strings.Contains(nav, path) {
			t.Fatalf("advanced route %s should not crowd customer navigation: %s", path, nav)
		}
	}
}

func TestWebsiteCreationDoesNotOfferSuspendedSubscription(t *testing.T) {
	data := wordpressHTTPDashboard()
	data.Subscriptions[0].Status = "suspended"
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{
		DashboardReader: &fakeDashboardReader{data: data}, SiteCreator: &fakeSiteCreator{},
	})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/new", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "No active subscription") || strings.Contains(rec.Body.String(), `name="subscription_id"`) {
		t.Fatalf("suspended subscription offered for website creation: status=%d", rec.Code)
	}
}

func TestWebsiteCreationSuccessControlsHonorHiddenState(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{})
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/assets/app.css", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	css := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(css, ".np-v2-create-form[hidden]") || !strings.Contains(css, ".np-v2-type-list[hidden]") || !strings.Contains(css, ".np-v2-credential[hidden]") {
		t.Fatalf("V2 success controls lack hidden-state CSS: status=%d", rec.Code)
	}
}

func TestWordPressWebsiteNoJavaScriptShowsGeneratedPasswordOnce(t *testing.T) {
	creator := &fakeSiteCreator{}
	service := &fakeWordPressService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{SiteCreator: creator, WordPress: service, DashboardReader: &fakeDashboardReader{data: wordpressHTTPDashboard()}})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	form := wordpressWebsiteForm()
	form.Del("admin_password")
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/websites", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || rec.Header().Get("Cache-Control") != "private, no-store" || len(service.install.AdminPassword) < 20 {
		t.Fatalf("one-time response = %d cache=%q password length=%d", rec.Code, rec.Header().Get("Cache-Control"), len(service.install.AdminPassword))
	}
	if !strings.Contains(rec.Body.String(), service.install.AdminPassword) || !strings.Contains(rec.Body.String(), "Save this password now") {
		t.Fatal("one-time password was not available in the no-JavaScript response")
	}
}

func TestPHPWebsiteDoesNotRequireWordPressService(t *testing.T) {
	creator := &fakeSiteCreator{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{SiteCreator: creator})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	rec := postWebsiteForTest(t, handler, cookie, url.Values{"subscription_id": {"20"}, "domain": {"php.example.test"}, "website_type": {"php"}})
	if rec.Code != http.StatusAccepted || len(creator.requests) != 1 || creator.requests[0].PHPVersion != "" || !strings.Contains(rec.Body.String(), `"website_type":"php"`) {
		t.Fatalf("PHP creation = %d requests=%#v body=%s", rec.Code, creator.requests, rec.Body.String())
	}
}

func TestEnhancedWebsiteCreationAcceptsBrowserFormData(t *testing.T) {
	creator := &fakeSiteCreator{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{SiteCreator: creator})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range map[string]string{"subscription_id": "20", "domain": "multipart.example.test", "website_type": "php"} {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/websites", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Nakpanel-SPA", "true")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || len(creator.requests) != 1 {
		t.Fatalf("browser form-data response=%d requests=%d body=%s", rec.Code, len(creator.requests), rec.Body.String())
	}
}

func TestSupportViewWebsiteCreationKeepsCustomerContext(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{
		DashboardReader: &fakeDashboardReader{data: wordpressHTTPDashboard()}, SiteCreator: &fakeSiteCreator{}, WordPress: &fakeWordPressService{},
	})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/support/customers/88/sites", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/support/customers/88/site-new") {
		t.Fatalf("support launch = %d body=%s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "https://panel.test/support/customers/88/site-new?type=wordpress&subscription_id=20", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="support_customer_id" value="88"`) || !strings.Contains(rec.Body.String(), "Set up WordPress") {
		t.Fatalf("support creation page = %d body=%s", rec.Code, rec.Body.String())
	}
}
