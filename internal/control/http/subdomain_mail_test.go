package panelhttp

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

type subdomainMailHTTPServices struct {
	fakeMailDomainServices
	alias types.MailAliasInput
}

func (s *subdomainMailHTTPServices) UpsertMailDomain(_ context.Context, _ auth.SessionUser, subscriptionID int64, input types.MailDomainInput) (int64, error) {
	s.subscriptionID, s.input = subscriptionID, input
	return 42, nil
}

func (s *subdomainMailHTTPServices) UpsertMailbox(_ context.Context, _ auth.SessionUser, subscriptionID int64, input types.MailboxInput) (int64, error) {
	s.subscriptionID, s.mailbox = subscriptionID, input
	return 52, nil
}

func (s *subdomainMailHTTPServices) UpsertMailAlias(_ context.Context, _ auth.SessionUser, subscriptionID int64, input types.MailAliasInput) (int64, error) {
	s.subscriptionID, s.alias = subscriptionID, input
	return 62, nil
}

// Read this template's rendered inputs rather than constructing hidden IDs or CSRF.
func subdomainMailForm(t *testing.T, body, action string) (url.Values, string) {
	t.Helper()
	attributes := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_:-]*)="([^"]*)"`)
	attrs := func(tag string) map[string]string {
		values := make(map[string]string)
		for _, pair := range attributes.FindAllStringSubmatch(tag, -1) {
			values[pair[1]] = html.UnescapeString(pair[2])
		}
		return values
	}
	for _, form := range regexp.MustCompile(`(?s)<form\b[^>]*>.*?</form>`).FindAllString(body, -1) {
		head := form[:strings.IndexByte(form, '>')+1]
		if attrs(head)["action"] != action {
			continue
		}
		values := make(url.Values)
		for _, input := range regexp.MustCompile(`<input\b[^>]*>`).FindAllString(form, -1) {
			a := attrs(input)
			if a["name"] == "" || regexp.MustCompile(`\sdisabled(?:[=\s>])`).MatchString(input) {
				continue
			}
			if a["type"] == "checkbox" && !regexp.MustCompile(`\schecked(?:[=\s>])`).MatchString(input) {
				continue
			}
			values.Add(a["name"], a["value"])
		}
		return values, form
	}
	t.Fatalf("child mail form missing: %s", action)
	return nil, ""
}

func TestSubdomainMailFormsKeepChildContext(t *testing.T) {
	data := mailWorkspaceData(true)
	data.Sites = append(data.Sites, dashboard.Site{ID: 32, ParentSiteID: 31, Domain: "shop.mail-owned.test", Status: "active", DesiredStatus: "active", SubscriptionID: 20, CustomerID: 88})
	reader := &fakeDashboardReader{data: data}
	services := &subdomainMailHTTPServices{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DomainManager: services, DashboardReader: reader})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	get := func(path string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "https://panel.test"+path, nil)
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: HTTP %d", path, rec.Code)
		}
		return rec.Body.String()
	}
	post := func(path string, form url.Values) {
		t.Helper()
		if form.Get("site_id") != "32" || form.Get("return_to") != "site-mail" || form.Get("csrf_token") == "" {
			t.Fatal("rendered form lost child ownership, return context or CSRF")
		}
		req := httptest.NewRequest(http.MethodPost, "https://panel.test"+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addAuthenticatedCookie(req, cookie)
		req.Header.Del("X-Nakpanel-CSRF") // Ordinary browser form submission.
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sites/32?tab=mail&notice=service-saved" {
			t.Fatalf("POST %s: HTTP %d location=%q", path, rec.Code, rec.Header().Get("Location"))
		}
		if services.subscriptionID != 20 {
			t.Fatal("form left the child subscription")
		}
	}

	checkDialog := func(body, dialogID, action, domainID string) {
		t.Helper()
		if !strings.Contains(body, `data-np-dialog-open="`+dialogID+`"`) {
			t.Fatalf("missing child dialog action %s", dialogID)
		}
		dialog := regexp.MustCompile(`(?s)<dialog\b[^>]*\bid="` + regexp.QuoteMeta(dialogID) + `"[^>]*>.*?</dialog>`).FindString(body)
		form, _ := subdomainMailForm(t, dialog, action)
		if form.Get("site_id") != "32" || form.Get("return_to") != "site-mail" || form.Get("csrf_token") == "" || form.Get("mail_domain_id") != domainID {
			t.Fatalf("dialog %s lost child ownership or return context", dialogID)
		}
	}
	body := get("/sites/32?tab=mail")
	checkDialog(body, "mail-domain-20", "/subscriptions/20/mail-domains", "")
	body = get("/sites/32?tab=mail&mail_view=enable-domain")
	form, _ := subdomainMailForm(t, body, "/subscriptions/20/mail-domains")
	form.Set("dmarc_policy", "none")
	form.Set("domain", "forged.example.test")
	post("/subscriptions/20/mail-domains", form)
	if services.input.SiteID != 32 || services.input.Domain != "" || !services.input.Enabled {
		t.Fatal("enable mail did not use the child site identity")
	}

	reader.data.SubscriptionServices.MailDomains = append(reader.data.SubscriptionServices.MailDomains, dashboard.MailDomain{ID: 42, SubscriptionID: 20, SiteID: 32, Domain: "shop.mail-owned.test", Enabled: true, EffectiveEnabled: true, Status: "in_sync"})
	body = get("/sites/32?tab=mail")
	checkDialog(body, "mail-mailbox-20-42", "/subscriptions/20/mailboxes", "42")
	body = get("/sites/32?tab=mail&mail_view=aliases")
	checkDialog(body, "mail-alias-20-42", "/subscriptions/20/mail-aliases", "42")
	body = get("/sites/32?tab=mail&mail_view=create-address")
	form, rendered := subdomainMailForm(t, body, "/subscriptions/20/mailboxes")
	if form.Get("mail_domain_id") != "42" || !strings.Contains(rendered, "@shop.mail-owned.test") {
		t.Fatal("mailbox form used the parent mail domain")
	}
	form.Set("local_part", "hello")
	form.Set("password", "subdomain-mail-fixture-password")
	form.Set("quota_mb", "128")
	post("/subscriptions/20/mailboxes", form)
	if services.mailbox.MailDomainID != 42 || services.mailbox.LocalPart != "hello" || !services.mailbox.Enabled {
		t.Fatal("mailbox request lost child identity or enabled state")
	}

	body = get("/sites/32?tab=mail&mail_view=create-alias")
	form, _ = subdomainMailForm(t, body, "/subscriptions/20/mail-aliases")
	if form.Get("mail_domain_id") != "42" {
		t.Fatal("alias form used the parent mail domain")
	}
	form.Set("local_part", "sales")
	form.Set("destinations", "hello@shop.mail-owned.test")
	post("/subscriptions/20/mail-aliases", form)
	if services.alias.MailDomainID != 42 || services.alias.LocalPart != "sales" || len(services.alias.Destinations) != 1 || services.alias.Destinations[0] != "hello@shop.mail-owned.test" {
		t.Fatal("alias request lost child identity or destination")
	}
}
