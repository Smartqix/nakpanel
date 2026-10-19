package panelhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeMailDomainServices struct {
	fakeDomainManager
	input          types.MailDomainInput
	application    types.ApplicationInput
	subscriptionID int64
	appCalled      bool
	err            error
	resetSiteID    int64
	resetScope     string
	setSiteCalled  bool
	mailbox        types.MailboxInput
}

func (*fakeMailDomainServices) SetSubscriptionPolicy(context.Context, auth.SessionUser, int64, json.RawMessage) error {
	return nil
}
func (s *fakeMailDomainServices) SetSitePolicy(context.Context, auth.SessionUser, int64, json.RawMessage) error {
	s.setSiteCalled = true
	return nil
}
func (s *fakeMailDomainServices) ResetSitePolicy(_ context.Context, _ auth.SessionUser, siteID int64, scope string) error {
	s.resetSiteID, s.resetScope = siteID, scope
	return nil
}
func (*fakeMailDomainServices) UpsertSFTPIdentity(context.Context, auth.SessionUser, int64, types.SFTPIdentityInput) (int64, error) {
	return 0, nil
}
func (*fakeMailDomainServices) UpsertScheduledTask(context.Context, auth.SessionUser, int64, types.ScheduledTaskInput) (int64, error) {
	return 0, nil
}
func (s *fakeMailDomainServices) UpsertMailDomain(_ context.Context, _ auth.SessionUser, subscriptionID int64, input types.MailDomainInput) (int64, error) {
	s.subscriptionID, s.input = subscriptionID, input
	return 41, s.err
}
func (s *fakeMailDomainServices) UpsertMailbox(_ context.Context, _ auth.SessionUser, _ int64, input types.MailboxInput) (int64, error) {
	s.mailbox = input
	return 0, nil
}
func (*fakeMailDomainServices) UpsertMailAlias(context.Context, auth.SessionUser, int64, types.MailAliasInput) (int64, error) {
	return 0, nil
}
func (s *fakeMailDomainServices) UpsertApplication(_ context.Context, _ auth.SessionUser, subscriptionID int64, input types.ApplicationInput) (int64, error) {
	s.subscriptionID, s.application, s.appCalled = subscriptionID, input, true
	return 91, s.err
}
func (*fakeMailDomainServices) UpsertProtectedDirectory(context.Context, auth.SessionUser, int64, types.ProtectedDirectoryInput) (int64, string, error) {
	return 0, "", nil
}
func (*fakeMailDomainServices) DeleteSubscriptionService(context.Context, auth.SessionUser, int64, string, int64) error {
	return nil
}
func (*fakeMailDomainServices) UpsertFTPAccount(context.Context, auth.SessionUser, int64, types.FTPAccountInput) (int64, string, error) {
	return 0, "", nil
}
func (*fakeMailDomainServices) UpsertGitRepository(context.Context, auth.SessionUser, int64, int64, types.GitRepositoryInput) (int64, error) {
	return 0, nil
}
func (*fakeMailDomainServices) ConfigureValkey(context.Context, auth.SessionUser, int64, types.ValkeyInput) (string, error) {
	return "", nil
}
func (*fakeMailDomainServices) ReadSiteLog(context.Context, auth.SessionUser, int64, types.SiteLogRequest) (types.SiteLogResult, error) {
	return types.SiteLogResult{}, nil
}
func (*fakeMailDomainServices) RunScheduledTask(context.Context, auth.SessionUser, int64, int64) (types.ScheduledTaskRun, error) {
	return types.ScheduledTaskRun{}, nil
}

func TestSubscriptionTaskRunPreservesSupportContext(t *testing.T) {
	services := &fakeMailDomainServices{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DomainManager: services})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/subscriptions/20/scheduled-tasks/5/run", strings.NewReader("support_customer_id=88"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	want := "/support/customers/88/subscriptions/20?tab=tasks&notice=task-ran"
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
		t.Fatalf("task run status=%d location=%q, want %q", rec.Code, rec.Header().Get("Location"), want)
	}
}

type fakeMailManager struct {
	settings  types.MailSettingsView
	update    types.MailSettingsUpdate
	status    types.MailServerStatus
	restarts  int
	reconfigs int
}

func (m *fakeMailManager) MailClientSettings(context.Context, auth.SessionUser, int64) (types.MailClientProfile, error) {
	return types.MailClientProfile{Hostname: "mail.node.test", IMAPTLS: true, SMTPTLS: true, SMTPSTARTTLS: true, CheckedAt: time.Now()}, nil
}

func (m *fakeMailManager) MailSettings(context.Context, auth.SessionUser) (types.MailSettingsView, error) {
	return m.settings, nil
}

func (m *fakeMailManager) UpdateMailSettings(_ context.Context, _ auth.SessionUser, update types.MailSettingsUpdate) (types.MailSettingsView, error) {
	m.update = update
	m.settings = types.MailSettingsView{
		MailHostname: update.MailHostname, SmarthostHost: update.SmarthostHost,
		SmarthostPort: update.SmarthostPort, SmarthostUsername: update.SmarthostUsername,
		SmarthostConfigured: update.SmarthostHost != "", OutboundRateLimit: update.OutboundRateLimit,
		QueueAlertThreshold: update.QueueAlertThreshold,
	}
	return m.settings, nil
}

func (m *fakeMailManager) ReconfigureMail(context.Context, auth.SessionUser) error {
	m.reconfigs++
	return nil
}

func (m *fakeMailManager) MailServerStatus(context.Context, auth.SessionUser) (types.MailServerStatus, error) {
	return m.status, nil
}

func (m *fakeMailManager) RestartMail(context.Context, auth.SessionUser) error {
	m.restarts++
	return nil
}

func mailWorkspaceData(enabled bool) dashboard.Data {
	policy := types.HostingPolicy{
		Resources:   types.HostingResourcePolicy{MaxMailboxes: 5},
		Permissions: types.HostingPermissionPolicy{Mail: enabled},
		Mail:        types.HostingMailPolicy{Enabled: enabled, Webmail: enabled, DKIM: true, DMARCPolicy: "quarantine"},
	}
	maxMailboxes := 5
	if !enabled {
		maxMailboxes = 0
		policy.Resources.MaxMailboxes = 0
	}
	return dashboard.Data{
		Sites:         []dashboard.Site{{ID: 31, Domain: "mail-owned.test", Status: "active", SubscriptionID: 20, CustomerID: 88}},
		Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, CustomerName: "Mail Owner", SubscriptionName: "Mail Hosting", PlanID: 10, PlanName: "Business", Status: "active", MaxMailboxes: maxMailboxes}},
		SubscriptionServices: dashboard.SubscriptionServicesData{
			Accounts:     []types.SubscriptionSystemAccount{{SubscriptionID: 20, EffectivePolicy: policy}},
			MailDomains:  []dashboard.MailDomain{{ID: 41, SubscriptionID: 20, SiteID: 31, Domain: "mail-owned.test", Enabled: true, DKIM: true, DMARCPolicy: "quarantine", Status: "in_sync"}},
			Mailboxes:    []dashboard.Mailbox{{ID: 51, SubscriptionID: 20, MailDomainID: 41, Address: "hello@mail-owned.test", QuotaMB: 1024, Enabled: true}},
			MailAliases:  []dashboard.MailAlias{{ID: 61, SubscriptionID: 20, MailDomainID: 41, Address: "sales@mail-owned.test", Destinations: "hello@mail-owned.test"}},
			WebmailHosts: []dashboard.WebmailHost{{ID: 71, SubscriptionID: 20, SiteID: 31, Domain: "mail-owned.test", Hostname: "webmail.mail-owned.test", Status: "active"}},
		},
	}
}

func TestClientMailWorkspaceAndEmailAlias(t *testing.T) {
	reader := &fakeDashboardReader{data: mailWorkspaceData(true)}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: reader, Phase6Manager: &fakePhase6Manager{}})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/mail?subscription_id=20", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /mail status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Mail Hosting", "mail-owned.test", "hello@mail-owned.test", "sales@mail-owned.test", "Add mail domain", `name="site_id"`, `data-np-generate-password`, "Reconfigure webmail"} {
		if !strings.Contains(body, want) {
			t.Fatalf("mail workspace missing %q", want)
		}
	}
	if strings.Contains(body, "password_hash") || strings.Contains(body, "hunter2") {
		t.Fatal("mail workspace exposed a password or hash")
	}

	req = httptest.NewRequest(http.MethodGet, "https://panel.test/email?subscription_id=20", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/mail?subscription_id=20" {
		t.Fatalf("GET /email status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestProviderMailRoutesAndNavigationUseDomains(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller} {
		t.Run(string(role), func(t *testing.T) {
			data := mailWorkspaceData(true)
			data.SubscriptionServices.MailDomains[0].SiteID = 0 // Phase 18 compatibility fixture.
			reader := &fakeDashboardReader{data: data}
			handler, _ := newTestHandlerWithOptions(t, role, ServerOptions{DashboardReader: reader, Phase6Manager: &fakePhase6Manager{}})
			email, password := "admin@nakpanel.test", "NakpanelAdmin!2026"
			if role == auth.RoleReseller {
				email, password = "reseller@nakpanel.test", "NakpanelReseller!2026"
			}
			cookie := login(t, handler, email, password)

			for _, target := range []string{"https://panel.test/mail?domain_id=41", "https://panel.test/email?domain_id=41"} {
				req := httptest.NewRequest(http.MethodGet, target, nil)
				addAuthenticatedCookie(req, cookie)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sites/31?tab=mail" {
					t.Fatalf("GET %s status=%d location=%q", target, rec.Code, rec.Header().Get("Location"))
				}
			}

			req := httptest.NewRequest(http.MethodGet, "https://panel.test/mail", nil)
			addAuthenticatedCookie(req, cookie)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sites" {
				t.Fatalf("GET /mail status=%d location=%q", rec.Code, rec.Header().Get("Location"))
			}

			req = httptest.NewRequest(http.MethodGet, "https://panel.test/sites/31?tab=mail", nil)
			addAuthenticatedCookie(req, cookie)
			rec = httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET domain Mail status=%d body=%s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, want := range []string{`id="domain-mail-title"`, "hello@mail-owned.test", "Aliases (1)", `name="return_to" value="site-mail"`, `name="site_id" value="31"`, "Reconfigure webmail"} {
				if !strings.Contains(body, want) {
					t.Fatalf("domain Mail workspace missing %q", want)
				}
			}
			sidebarEnd := strings.Index(body, "</aside>")
			if sidebarEnd < 0 {
				t.Fatal("provider page has no sidebar")
			}
			if strings.Contains(body[:sidebarEnd], `href="/mail"`) || !strings.Contains(body[:sidebarEnd], `href="/sites"`) {
				t.Fatalf("provider sidebar did not use Domains-only mail navigation: %s", body[:sidebarEnd])
			}
		})
	}
}

func TestClientMailUnavailableState(t *testing.T) {
	reader := &fakeDashboardReader{data: mailWorkspaceData(false)}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: reader})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/mail", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Mail unavailable") || !strings.Contains(body, "Contact your hosting provider") {
		t.Fatalf("client disabled mail workspace status=%d body=%s", rec.Code, body)
	}
	if strings.Contains(body, "Edit the service plan") || strings.Contains(body, "Add mail domain") {
		t.Fatal("client disabled state exposed provider controls")
	}

	req = httptest.NewRequest(http.MethodGet, "https://panel.test/sites/31?tab=mail", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	body = rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `id="domain-mail-title"`) || !strings.Contains(body, "Contact your hosting provider") {
		t.Fatalf("client disabled domain Mail status=%d body=%s", rec.Code, body)
	}
	if strings.Contains(body, "Edit the service plan") || strings.Contains(body, "Enable mail") {
		t.Fatal("client disabled domain Mail exposed provider controls")
	}
}

func TestAdminMailSettingsStatusAndSecretHandling(t *testing.T) {
	mail := &fakeMailManager{
		settings: types.MailSettingsView{MailHostname: "mail.node.test", SmarthostHost: "smtp.relay.test", SmarthostPort: 587, SmarthostUsername: "relay-user", SmarthostConfigured: true, OutboundRateLimit: "200/1h", QueueAlertThreshold: 50},
		status:   types.MailServerStatus{State: "active", Version: "Stalwart Mail 0.12", Listeners: []int{25, 587, 993}, TotalQueued: 3, CheckedAt: time.Now()},
	}
	workspace := &fakeWorkspaceService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: &fakeDashboardReader{data: dashboard.Data{}}, MailManager: mail, Workspace: workspace})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Mail Server") || !strings.Contains(rec.Body.String(), "smtp.relay.test") {
		t.Fatalf("mail settings page status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "relay-secret") || strings.Contains(rec.Body.String(), `name="smarthost_password" value=`) {
		t.Fatal("mail settings rendered a relay password")
	}

	req = httptest.NewRequest(http.MethodGet, "https://panel.test/mail/status", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"total_queued":3`) {
		t.Fatalf("mail status response=%d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("mail status cache-control = %q", rec.Header().Get("Cache-Control"))
	}

	form := url.Values{"mail_hostname": {"mail.changed.test"}, "smarthost_host": {"smtp.changed.test"}, "smarthost_port": {"465"}, "smarthost_username": {"changed"}, "smarthost_password": {"relay-secret"}, "outbound_rate_limit": {"100/1h"}, "queue_alert_threshold": {"25"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/settings/mail", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || mail.update.SmarthostPassword != "relay-secret" {
		t.Fatalf("mail settings update status=%d update=%+v", rec.Code, mail.update)
	}
	if strings.Contains(rec.Body.String(), "relay-secret") {
		t.Fatal("mail settings response exposed relay password")
	}
	for _, event := range workspace.audits {
		if strings.Contains(string(event.Metadata), "relay-secret") {
			t.Fatal("mail settings audit exposed relay password")
		}
	}
}

func TestMailServerControlsRequireAdmin(t *testing.T) {
	mail := &fakeMailManager{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{MailManager: mail})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	for _, target := range []string{"https://panel.test/mail/status", "https://panel.test/settings/mail", "https://panel.test/settings/mail/reconfigure", "https://panel.test/settings/mail/restart"} {
		method := http.MethodPost
		if strings.HasSuffix(target, "/status") {
			method = http.MethodGet
		}
		req := httptest.NewRequest(method, target, strings.NewReader("mail_hostname=mail.test"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s status=%d, want 403", method, target, rec.Code)
		}
	}
}

func TestMailDomainRequestUsesHostedSiteAndCrossTenantWebmailIsHidden(t *testing.T) {
	services := &fakeMailDomainServices{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DomainManager: services, DashboardReader: &fakeDashboardReader{data: mailWorkspaceData(true)}})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	form := url.Values{"site_id": {"31"}, "domain": {"attacker-controlled.test"}, "dmarc_policy": {"reject"}, "dkim": {"true"}, "return_to": {"site-mail"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/subscriptions/20/mail-domains", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sites/31?tab=mail&notice=service-saved" || services.subscriptionID != 20 || services.input.SiteID != 31 || services.input.Domain != "" {
		t.Fatalf("mail domain status=%d subscription=%d input=%+v", rec.Code, services.subscriptionID, services.input)
	}

	phase6 := &fakePhase6Manager{err: provision.ErrForbidden}
	handler, _ = newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{Phase6Manager: phase6})
	cookie = login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/webmail", strings.NewReader("domain=other-customer.test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant webmail status=%d, want 404", rec.Code)
	}
}

func TestDomainMailReturnContextIsValidated(t *testing.T) {
	phase6 := &fakePhase6Manager{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{
		Phase6Manager:   phase6,
		DashboardReader: &fakeDashboardReader{data: mailWorkspaceData(true)},
		Workspace:       &fakeWorkspaceService{},
	})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	for _, test := range []struct {
		name   string
		siteID string
		want   string
	}{
		{name: "owned site", siteID: "31", want: "/sites/31?tab=mail&notice=webmail-queued"},
		{name: "unowned site", siteID: "99", want: "/subscriptions/20?tab=mail&notice=webmail-queued"},
	} {
		t.Run(test.name, func(t *testing.T) {
			form := url.Values{"return_to": {"site-mail"}, "site_id": {test.siteID}, "subscription_id": {"20"}, "domain": {"mail-owned.test"}}
			req := httptest.NewRequest(http.MethodPost, "https://panel.test/webmail", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			addAuthenticatedCookie(req, cookie)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != test.want {
				t.Fatalf("domain return status=%d location=%q, want %q", rec.Code, rec.Header().Get("Location"), test.want)
			}
		})
	}
}

func TestSupportCustomerFilterIncludesOnlyOwnedMailResources(t *testing.T) {
	data := dashboard.Data{
		Sites:         []dashboard.Site{{ID: 1, CustomerID: 88, SubscriptionID: 20, Domain: "owned.test"}, {ID: 2, CustomerID: 99, SubscriptionID: 30, Domain: "other.test"}},
		Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88}, {ID: 30, CustomerID: 99}},
		SubscriptionServices: dashboard.SubscriptionServicesData{
			MailDomains:  []dashboard.MailDomain{{ID: 1, SubscriptionID: 20, SiteID: 1}, {ID: 2, SubscriptionID: 30, SiteID: 2}},
			Mailboxes:    []dashboard.Mailbox{{ID: 1, SubscriptionID: 20}, {ID: 2, SubscriptionID: 30}},
			MailAliases:  []dashboard.MailAlias{{ID: 1, SubscriptionID: 20}, {ID: 2, SubscriptionID: 30}},
			WebmailHosts: []dashboard.WebmailHost{{ID: 1, SubscriptionID: 20, SiteID: 1}, {ID: 2, SubscriptionID: 30, SiteID: 2}},
		},
	}
	filtered := filterDashboardForCustomer(data, 88)
	if len(filtered.SubscriptionServices.MailDomains) != 1 || filtered.SubscriptionServices.MailDomains[0].SubscriptionID != 20 ||
		len(filtered.SubscriptionServices.Mailboxes) != 1 || filtered.SubscriptionServices.Mailboxes[0].SubscriptionID != 20 ||
		len(filtered.SubscriptionServices.MailAliases) != 1 || filtered.SubscriptionServices.MailAliases[0].SubscriptionID != 20 ||
		len(filtered.SubscriptionServices.WebmailHosts) != 1 || filtered.SubscriptionServices.WebmailHosts[0].SiteID != 1 {
		t.Fatalf("support mail data was not scoped: %+v", filtered.SubscriptionServices)
	}
}

func TestDomainMailFigmaMailboxActions(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: &fakeDashboardReader{data: mailWorkspaceData(true)}, Phase6Manager: &fakePhase6Manager{}})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/31?tab=mail", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	for _, want := range []string{"Create email address", "Open webmail", "Connect a mail app", "https://webmail.mail-owned.test", "mailbox_id=51", "data-np-mail-search", "/assets/mail.css", "/assets/mail.js"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("domain Mail missing %q", want)
		}
	}
}

func TestMailClientConnectionContentAndOwnership(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller, auth.RoleClient} {
		t.Run(string(role), func(t *testing.T) {
			handler, _ := newTestHandlerWithOptions(t, role, ServerOptions{DashboardReader: &fakeDashboardReader{data: mailWorkspaceData(true)}, MailManager: &fakeMailManager{}})
			cookie := login(t, handler, string(role)+"@nakpanel.test", "Nakpanel"+strings.Title(string(role))+"!2026")
			for _, partial := range []bool{false, true} {
				req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/31?tab=mail&mail_view=connection&mailbox_id=51", nil)
				addAuthenticatedCookie(req, cookie)
				if partial {
					req.Header.Set("X-Nakpanel-Mail", "connection")
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				body := rec.Body.String()
				if rec.Code != 200 || !strings.Contains(body, "mail.node.test") || !strings.Contains(body, "hello@mail-owned.test") || !strings.Contains(body, "POP3 is not enabled") || !strings.Contains(body, "Copy all settings") || rec.Header().Get("Cache-Control") != "private, no-store" {
					t.Fatalf("connection status=%d body=%s", rec.Code, body)
				}
				if partial && strings.Contains(body, "<!doctype") {
					t.Fatal("fragment returned entire workspace")
				}
			}
			for _, id := range []string{"0", "52", "-1", "garbage"} {
				req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/31?tab=mail&mail_view=connection&mailbox_id="+id, nil)
				addAuthenticatedCookie(req, cookie)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != 404 {
					t.Fatalf("unowned mailbox %q status=%d", id, rec.Code)
				}
			}
		})
	}
}

func TestMailWorkspaceLegacyDomainAndFormFallbacks(t *testing.T) {
	data := mailWorkspaceData(true)
	data.SubscriptionServices.MailDomains[0].SiteID = 0
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: &fakeDashboardReader{data: data}, MailManager: &fakeMailManager{}})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	for _, entry := range []struct{ view, want string }{{"connection&mailbox_id=51", "mail.node.test"}, {"create-address", `name="password"`}, {"edit-address&resource_id=51", `value="hello"`}, {"create-alias", `name="destinations"`}, {"edit-alias&resource_id=61", `value="sales"`}, {"webmail", `action="/webmail"`}} {
		req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/31?tab=mail&mail_view="+entry.view, nil)
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), entry.want) {
			t.Errorf("fallback %s: status=%d missing %q", entry.view, rec.Code, entry.want)
		}
	}
}

func TestMailConnectionSupportScopeAndDisabledStates(t *testing.T) {
	data := mailWorkspaceData(true)
	data.Customers = []types.Customer{{ID: 88, DisplayName: "Mail customer", Status: "active"}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: &fakeDashboardReader{data: data}, MailManager: &fakeMailManager{}, Workspace: &fakeWorkspaceService{}})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	for _, entry := range []struct {
		path string
		code int
		want string
	}{{"/support/customers/88/sites/31?tab=mail", 200, "/support/customers/88/sites/31?tab=mail&amp;mail_view=connection"}, {"/support/customers/88/sites/31?tab=mail&mail_view=connection&mailbox_id=51", 200, "mail.node.test"}, {"/support/customers/99/sites/31?tab=mail&mail_view=connection&mailbox_id=51", 404, ""}, {"/sites/31?tab=mail&mail_view=edit-address&resource_id=999", 404, ""}, {"/sites/31?tab=mail&mail_view=edit-alias&resource_id=999", 404, ""}} {
		req := httptest.NewRequest(http.MethodGet, "https://panel.test"+entry.path, nil)
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != entry.code || !strings.Contains(rec.Body.String(), entry.want) {
			t.Errorf("%s status=%d missing %q", entry.path, rec.Code, entry.want)
		}
	}
	data.SubscriptionServices.Mailboxes[0].Enabled = false
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/31?tab=mail&mail_view=connection&mailbox_id=51", nil)
	req.Header.Set("X-Nakpanel-Mail", "connection")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "mailbox is suspended") || strings.Contains(rec.Body.String(), "mail.node.test") || strings.Contains(rec.Body.String(), "Copy all settings") {
		t.Fatalf("suspended connection response=%d %s", rec.Code, rec.Body.String())
	}
}

func TestMailEnableDomainFallback(t *testing.T) {
	data := mailWorkspaceData(true)
	data.SubscriptionServices.MailDomains = nil
	data.SubscriptionServices.Mailboxes = nil
	data.SubscriptionServices.MailAliases = nil
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: &fakeDashboardReader{data: data}})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/31?tab=mail&mail_view=enable-domain", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `class="np-mail-form-page np-mail-settings-page"`) || !strings.Contains(rec.Body.String(), `name="site_id" value="31"`) {
		t.Fatal("missing visible enable-mail fallback")
	}
}

func TestMailFormsUncheckedTogglesAreNotReenabled(t *testing.T) {
	services := &fakeMailDomainServices{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DomainManager: services, DashboardReader: &fakeDashboardReader{data: mailWorkspaceData(true)}})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	for _, kind := range []string{"mail-domains", "mailboxes"} {
		req := httptest.NewRequest(http.MethodPost, "https://panel.test/subscriptions/20/"+kind, strings.NewReader("site_id=31&resource_id=41&mail_domain_id=41&mail_form=true"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 303 {
			t.Fatalf("%s status=%d", kind, rec.Code)
		}
	}
	if services.input.Enabled || services.input.DKIM || services.mailbox.Enabled {
		t.Fatalf("unchecked form controls were enabled: domain=%+v mailbox=%+v", services.input, services.mailbox)
	}
}
