package panelhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/certificates"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeUserStore struct {
	users map[string]auth.User
}

func (s fakeUserStore) FindUserByEmail(ctx context.Context, email string) (auth.User, error) {
	user, ok := s.users[email]
	if !ok {
		return auth.User{}, auth.ErrUserNotFound
	}
	return user, nil
}

type fakeSessionStore struct {
	tokenHash string
	user      auth.SessionUser
	expiresAt time.Time
	deleted   bool
}

func (s *fakeSessionStore) CreateSession(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time) error {
	s.tokenHash = tokenHash
	s.expiresAt = expiresAt
	s.deleted = false
	return nil
}

func (s *fakeSessionStore) GetSession(ctx context.Context, tokenHash string, now time.Time) (auth.SessionUser, error) {
	if s.deleted || tokenHash != s.tokenHash || !now.Before(s.expiresAt) {
		return auth.SessionUser{}, auth.ErrSessionNotFound
	}
	return s.user, nil
}

func (s *fakeSessionStore) DeleteSession(ctx context.Context, tokenHash string) error {
	if tokenHash == s.tokenHash {
		s.deleted = true
	}
	return nil
}

type fakeSiteCreator struct {
	owner           auth.SessionUser
	resourceOwnerID int64
	requests        []types.CreateSiteReq
	err             error
}

func (c *fakeSiteCreator) CreateSiteFor(ctx context.Context, owner auth.SessionUser, resourceOwnerID int64, req types.CreateSiteReq) (int64, error) {
	c.owner = owner
	c.resourceOwnerID = resourceOwnerID
	c.requests = append(c.requests, req)
	return 7, c.err
}

type fakeDatabaseCreator struct {
	owner           auth.SessionUser
	resourceOwnerID int64
	requests        []types.CreateDatabaseReq
	err             error
}

func (c *fakeDatabaseCreator) CreateDatabaseFor(ctx context.Context, owner auth.SessionUser, resourceOwnerID int64, req types.CreateDatabaseReq) (int64, error) {
	c.owner = owner
	c.resourceOwnerID = resourceOwnerID
	c.requests = append(c.requests, req)
	return 11, c.err
}

type fakeCertificateIssuer struct {
	owner  auth.SessionUser
	domain string
	issuer types.CertIssuer
	err    error
}

type fakeCustomCertificateInstaller struct {
	owner  auth.SessionUser
	siteID int64
	bundle certificates.Bundle
	err    error
}

func (i *fakeCustomCertificateInstaller) InstallCustomCertificate(_ context.Context, owner auth.SessionUser, siteID int64, bundle certificates.Bundle) (int64, error) {
	i.owner, i.siteID, i.bundle = owner, siteID, bundle
	return 91, i.err
}

type fakeDomainManager struct {
	siteID    int64
	autoRenew bool
	called    bool
}

func (m *fakeDomainManager) UpdateSiteSettings(context.Context, auth.SessionUser, types.UpdateSiteSettingsReq) error {
	return nil
}
func (m *fakeDomainManager) SetTLSAutoRenew(_ context.Context, _ auth.SessionUser, siteID int64, enabled bool) error {
	m.siteID, m.autoRenew, m.called = siteID, enabled, true
	return nil
}
func (m *fakeDomainManager) UpsertDNSRecord(context.Context, auth.SessionUser, int64, types.DNSRecord) error {
	return nil
}
func (m *fakeDomainManager) DeleteDNSRecord(context.Context, auth.SessionUser, int64, int64) error {
	return nil
}
func (m *fakeDomainManager) ChangeSubscriptionPlans(context.Context, auth.SessionUser, []int64, int64) error {
	return nil
}
func (m *fakeDomainManager) ChangeSubscriptionSubscriber(context.Context, auth.SessionUser, []int64, int64) error {
	return nil
}

func (c *fakeCertificateIssuer) IssueCertificate(ctx context.Context, owner auth.SessionUser, domain string, issuer types.CertIssuer) (int64, error) {
	c.owner = owner
	c.domain = domain
	c.issuer = issuer
	return 7, c.err
}

type fakeDashboardReader struct {
	user   auth.SessionUser
	data   dashboard.Data
	err    error
	called bool
}

func (r *fakeDashboardReader) GetDashboard(ctx context.Context, user auth.SessionUser) (dashboard.Data, error) {
	r.user = user
	r.called = true
	return r.data, r.err
}

type fakeJobRetrier struct {
	jobID  int64
	err    error
	called bool
}

func (r *fakeJobRetrier) RetryProvisioningJob(ctx context.Context, jobID int64) error {
	r.jobID = jobID
	r.called = true
	return r.err
}

type fakeQuotaManager struct {
	owner                auth.SessionUser
	limits               controlquota.Limits
	plan                 controlquota.Plan
	planID               int64
	active               bool
	customerUserID       int64
	customerReq          types.CreateCustomerReq
	customerStatus       string
	customerID           int64
	bulkCustomerIDs      []int64
	bulkSubscriptionIDs  []int64
	bulkResellerIDs      []int64
	bulkPlanIDs          []int64
	bulkAddonIDs         []int64
	bulkResellerPlanIDs  []int64
	subscriptionReq      types.CreateSubscriptionReq
	settings             controlquota.Settings
	err                  error
	called               bool
	planCalled           bool
	statusCalled         bool
	customerCalled       bool
	customerLoginCalled  bool
	customerStatusCalled bool
	subCalled            bool
	settingsCalled       bool
}

func (m *fakeQuotaManager) UpsertAccountQuota(ctx context.Context, owner auth.SessionUser, limits controlquota.Limits) error {
	m.owner = owner
	m.limits = limits
	m.called = true
	return m.err
}

func (m *fakeQuotaManager) UpsertPlan(ctx context.Context, owner auth.SessionUser, plan controlquota.Plan) (controlquota.Plan, error) {
	m.owner = owner
	m.plan = plan
	m.planCalled = true
	return plan, m.err
}

func (m *fakeQuotaManager) SetPlanActive(ctx context.Context, owner auth.SessionUser, planID int64, active bool) error {
	m.owner = owner
	m.planID = planID
	m.active = active
	m.statusCalled = true
	return m.err
}

func (m *fakeQuotaManager) SetPlanStatuses(ctx context.Context, owner auth.SessionUser, planIDs []int64, active bool) error {
	m.owner = owner
	m.bulkPlanIDs = append([]int64(nil), planIDs...)
	m.active = active
	m.statusCalled = true
	if len(planIDs) > 0 {
		m.planID = planIDs[len(planIDs)-1]
	}
	return m.err
}

func (m *fakeQuotaManager) AssignSubscription(ctx context.Context, owner auth.SessionUser, customerUserID int64, planID int64) (controlquota.SubscriptionAssignment, error) {
	m.owner = owner
	m.customerUserID = customerUserID
	m.planID = planID
	m.subCalled = true
	return controlquota.SubscriptionAssignment{SubscriptionID: 77, CustomerUserID: customerUserID, PlanID: planID}, m.err
}

func (m *fakeQuotaManager) CreateCustomer(ctx context.Context, owner auth.SessionUser, req types.CreateCustomerReq) (types.Customer, error) {
	m.owner = owner
	m.customerReq = req
	m.customerCalled = true
	if m.customerID == 0 {
		m.customerID = 88
	}
	return types.Customer{ID: m.customerID, Email: req.Email, DisplayName: req.DisplayName, Status: "active"}, m.err
}

func (m *fakeQuotaManager) EnableCustomerLogin(ctx context.Context, owner auth.SessionUser, customerID int64, email string, password string) (types.Customer, error) {
	m.owner = owner
	m.customerID = customerID
	m.customerReq.Email = email
	m.customerReq.Password = password
	m.customerLoginCalled = true
	return types.Customer{ID: customerID, Email: email, Status: "active"}, m.err
}

func (m *fakeQuotaManager) SetCustomerStatus(ctx context.Context, owner auth.SessionUser, customerID int64, status string) error {
	m.owner = owner
	m.customerID = customerID
	m.customerStatus = status
	m.customerStatusCalled = true
	return m.err
}

func (m *fakeQuotaManager) SetCustomerStatuses(ctx context.Context, owner auth.SessionUser, customerIDs []int64, status string) error {
	m.owner = owner
	m.bulkCustomerIDs = append([]int64(nil), customerIDs...)
	m.customerStatus = status
	m.customerStatusCalled = true
	if len(customerIDs) > 0 {
		m.customerID = customerIDs[len(customerIDs)-1]
	}
	return m.err
}

func (m *fakeQuotaManager) SetSubscriptionStatus(ctx context.Context, owner auth.SessionUser, subscriptionID int64, status string) error {
	m.owner = owner
	m.customerID = subscriptionID
	m.customerStatus = status
	m.customerStatusCalled = true
	return m.err
}

func (m *fakeQuotaManager) SetSubscriptionStatuses(ctx context.Context, owner auth.SessionUser, subscriptionIDs []int64, status string) error {
	m.owner = owner
	m.bulkSubscriptionIDs = append([]int64(nil), subscriptionIDs...)
	m.customerStatus = status
	m.customerStatusCalled = true
	if len(subscriptionIDs) > 0 {
		m.customerID = subscriptionIDs[len(subscriptionIDs)-1]
	}
	return m.err
}

func (m *fakeQuotaManager) CreateSubscription(ctx context.Context, owner auth.SessionUser, req types.CreateSubscriptionReq) (types.SubscriptionSummary, error) {
	m.owner = owner
	m.subscriptionReq = req
	m.subCalled = true
	return types.SubscriptionSummary{ID: 77, CustomerID: req.CustomerID, PlanID: req.PlanID, SubscriptionName: req.SubscriptionName, Status: "active"}, m.err
}

func (m *fakeQuotaManager) UpdateSettings(ctx context.Context, owner auth.SessionUser, settings controlquota.Settings) error {
	m.owner = owner
	m.settings = settings
	m.settingsCalled = true
	return m.err
}

func (m *fakeQuotaManager) CreateReseller(context.Context, auth.SessionUser, types.CreateCustomerReq, int64) (types.Reseller, error) {
	return types.Reseller{ID: 91}, m.err
}
func (m *fakeQuotaManager) SetResellerStatus(context.Context, auth.SessionUser, int64, string) error {
	return m.err
}
func (m *fakeQuotaManager) SetResellerStatuses(ctx context.Context, owner auth.SessionUser, ids []int64, status string) error {
	m.bulkResellerIDs = append([]int64(nil), ids...)
	return m.err
}
func (m *fakeQuotaManager) UpsertResellerPlan(_ context.Context, _ auth.SessionUser, p types.ResellerPlan) (types.ResellerPlan, error) {
	if p.ID == 0 {
		p.ID = 92
	}
	return p, m.err
}
func (m *fakeQuotaManager) SetResellerPlanStatuses(_ context.Context, _ auth.SessionUser, ids []int64, _ bool) error {
	m.bulkResellerPlanIDs = append([]int64(nil), ids...)
	return m.err
}
func (m *fakeQuotaManager) TransferCustomer(context.Context, auth.SessionUser, int64, int64) error {
	return m.err
}
func (m *fakeQuotaManager) UpsertAddonPlan(_ context.Context, _ auth.SessionUser, a types.AddonPlan) (types.AddonPlan, error) {
	if a.ID == 0 {
		a.ID = 93
	}
	return a, m.err
}
func (m *fakeQuotaManager) SetAddonPlanStatuses(_ context.Context, _ auth.SessionUser, ids []int64, _ bool) error {
	m.bulkAddonIDs = append([]int64(nil), ids...)
	return m.err
}
func (m *fakeQuotaManager) SetSubscriptionAddons(context.Context, auth.SessionUser, int64, []int64) error {
	return m.err
}
func (m *fakeQuotaManager) SyncSubscription(context.Context, auth.SessionUser, int64) error {
	return m.err
}
func (m *fakeQuotaManager) SetSubscriptionMode(context.Context, auth.SessionUser, int64, string, types.SubscriptionEntitlements) error {
	return m.err
}

type fakePhase6Manager struct {
	backupOwner           auth.SessionUser
	backupResourceOwnerID int64
	backupReq             types.CreateBackupReq
	webmailOwner          auth.SessionUser
	webmailDomain         string
	dnsOwner              auth.SessionUser
	dnsDomain             string
	dnsAddress            string
	reconcileOwner        auth.SessionUser
	adminerOwner          auth.SessionUser
	restoreOwner          auth.SessionUser
	restoreBackup         int64
}

type fakeWorkspaceService struct {
	results []types.SearchResult
	actor   auth.SessionUser
	query   string
	audits  []types.AuditEvent
}

func (s *fakeWorkspaceService) Search(_ context.Context, actor auth.SessionUser, query string, _ int) ([]types.SearchResult, error) {
	s.actor = actor
	s.query = query
	return s.results, nil
}
func (s *fakeWorkspaceService) RecordAudit(_ context.Context, event types.AuditEvent) error {
	s.audits = append(s.audits, event)
	return nil
}
func (s *fakeWorkspaceService) CustomerIDForSubscription(context.Context, int64) (int64, error) {
	return 88, nil
}
func (s *fakeWorkspaceService) CustomerIDForDomain(context.Context, string) (int64, error) {
	return 88, nil
}
func (s *fakeWorkspaceService) CustomerIDForBackup(context.Context, int64) (int64, error) {
	return 88, nil
}

func (m *fakePhase6Manager) CreateBackupFor(ctx context.Context, owner auth.SessionUser, resourceOwnerID int64, req types.CreateBackupReq) (int64, error) {
	m.backupOwner = owner
	m.backupResourceOwnerID = resourceOwnerID
	m.backupReq = req
	return 101, nil
}

func (m *fakePhase6Manager) ConfigureWebmail(ctx context.Context, owner auth.SessionUser, domain string) (int64, error) {
	m.webmailOwner = owner
	m.webmailDomain = domain
	return 102, nil
}

func (m *fakePhase6Manager) ConfigureDNS(ctx context.Context, owner auth.SessionUser, domain string, address string) (int64, error) {
	m.dnsOwner = owner
	m.dnsDomain = domain
	m.dnsAddress = address
	return 103, nil
}

func (m *fakePhase6Manager) ReconcileSystem(ctx context.Context, owner auth.SessionUser) (int64, error) {
	m.reconcileOwner = owner
	return 104, nil
}

func (m *fakePhase6Manager) CreateAdminerToken(ctx context.Context, owner auth.SessionUser) (types.AdminerSSO, error) {
	m.adminerOwner = owner
	return types.AdminerSSO{Token: "adminer-token", ExpiresAtUnix: 1770000000}, nil
}

func (m *fakePhase6Manager) RestoreBackup(ctx context.Context, owner auth.SessionUser, backupID int64) (int64, error) {
	m.restoreOwner = owner
	m.restoreBackup = backupID
	return 105, nil
}

func TestLoginSuccessSetsSecureCookieAndShowsAdminDashboard(t *testing.T) {
	handler, sessions := newTestHandler(t, auth.RoleAdmin)

	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	if cookie.Name != SessionCookieName {
		t.Fatalf("cookie name = %q, want %q", cookie.Name, SessionCookieName)
	}
	if !cookie.Secure {
		t.Fatal("session cookie is not Secure")
	}
	if !cookie.HttpOnly {
		t.Fatal("session cookie is not HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v, want Lax", cookie.SameSite)
	}
	if sessions.tokenHash == cookie.Value {
		t.Fatal("raw cookie value was stored instead of a token hash")
	}

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Admin dashboard") {
		t.Fatalf("dashboard body %q does not contain Admin dashboard", rec.Body.String())
	}
}

func TestLoginFormLinksEmbeddedStylesheet(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `href="/assets/app.css"`) {
		t.Fatalf("login page does not link embedded stylesheet:\n%s", body)
	}
	if !strings.Contains(body, `src="/assets/app.js"`) {
		t.Fatalf("login page does not link embedded script:\n%s", body)
	}
}

func TestEmbeddedStylesheetIsServedByPanel(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/assets/app.css", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /assets/app.css status = %d, want 200", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/css") {
		t.Fatalf("Content-Type = %q, want text/css", contentType)
	}
	if body := rec.Body.String(); !strings.Contains(body, "--np-bg") || !strings.Contains(body, ".np-app") {
		t.Fatalf("embedded stylesheet missing expected UI tokens/classes:\n%s", body)
	}
	if body := rec.Body.String(); !strings.Contains(body, ".np-routed-layout") || !strings.Contains(body, ".np-mobile-scrim") || !strings.Contains(body, ".np-object-list") {
		t.Fatalf("embedded stylesheet missing routed responsive workspace rules:\n%s", body)
	}
	if body := rec.Body.String(); !strings.Contains(body, ".np-capacity-card") || !strings.Contains(body, ".np-subscription-table") || !strings.Contains(body, ".np-search") {
		t.Fatalf("embedded stylesheet missing reference subscription shell rules:\n%s", body)
	}
	if body := rec.Body.String(); !strings.Contains(body, "overflow-y:auto") || !strings.Contains(body, "overscroll-behavior:contain") {
		t.Fatalf("embedded stylesheet missing scrollable sidebar rules:\n%s", body)
	}
}

func TestEmbeddedScriptIsServedByPanel(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/assets/app.js", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /assets/app.js status = %d, want 200", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "javascript") {
		t.Fatalf("Content-Type = %q, want javascript", contentType)
	}
	body := rec.Body.String()
	for _, want := range []string{"nakpanel", "data-np-view", "data-np-dialog-open", "X-Nakpanel-SPA", "X-Nakpanel-CSRF", "data-np-search-input"} {
		if !strings.Contains(body, want) {
			t.Fatalf("embedded script missing %q:\n%s", want, body)
		}
	}
}

func TestBundledLucideSpriteIsServedByPanel(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/assets/icons.svg", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /assets/icons.svg status = %d, want 200", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "image/svg+xml") {
		t.Fatalf("Content-Type = %q, want image/svg+xml", contentType)
	}
	for _, marker := range []string{"Lucide static", `symbol id="search"`, `symbol id="shield"`, `symbol id="pause"`} {
		if !strings.Contains(rec.Body.String(), marker) {
			t.Fatalf("icon sprite missing %q", marker)
		}
	}
}

func TestEmbeddedAssetsDoNotExposeDirectoryListing(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/assets/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /assets/ status = %d, want 404; body:\n%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "app.css") || strings.Contains(rec.Body.String(), "app.js") {
		t.Fatalf("GET /assets/ exposed asset listing:\n%s", rec.Body.String())
	}
}

func TestEmbeddedAssetsRejectUnexpectedPathsAndMethods(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleAdmin)
	tests := []struct {
		name   string
		method string
		target string
		want   int
	}{
		{
			name:   "missing asset",
			method: http.MethodGet,
			target: "https://panel.test/assets/missing.css",
			want:   http.StatusNotFound,
		},
		{
			name:   "stylesheet as directory",
			method: http.MethodGet,
			target: "https://panel.test/assets/app.css/",
			want:   http.StatusNotFound,
		},
		{
			name:   "post stylesheet",
			method: http.MethodPost,
			target: "https://panel.test/assets/app.css",
			want:   http.StatusMethodNotAllowed,
		},
		{
			name:   "post script",
			method: http.MethodPost,
			target: "https://panel.test/assets/app.js",
			want:   http.StatusMethodNotAllowed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != test.want {
				t.Fatalf("%s %s status = %d, want %d; body:\n%s", test.method, test.target, rec.Code, test.want, rec.Body.String())
			}
			if body := rec.Body.String(); strings.Contains(body, "--np-bg") || strings.Contains(body, ".np-app") || strings.Contains(body, "data-np-view") {
				t.Fatalf("%s %s exposed asset body:\n%s", test.method, test.target, body)
			}
		})
	}
}

func TestAdminDashboardRendersOperationalInventoryAndForms(t *testing.T) {
	expiresAt := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	reader := &fakeDashboardReader{
		data: dashboard.Data{
			Sites: []dashboard.Site{{
				Username:     "npdemo",
				Domain:       "example.test",
				PHPVersion:   "8.3",
				Status:       "active",
				TLSStatus:    "active",
				TLSIssuer:    "local-self-signed",
				TLSExpiresAt: dashboard.NullableTime{Time: expiresAt, Valid: true},
			}},
			Databases: []dashboard.Database{{
				Engine:    "mariadb",
				Name:      "np_demo",
				User:      "np_demo_user",
				Status:    "failed",
				LastError: "access denied",
			}},
			Jobs: []dashboard.Job{{
				ID:          41,
				Kind:        "issue_cert",
				State:       "discarded",
				Queue:       "default",
				Attempt:     2,
				MaxAttempts: 3,
				Target:      "example.test",
				LastError:   "<acme failed>",
				CreatedAt:   time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC),
			}},
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{
		SiteCreator:       &fakeSiteCreator{},
		DatabaseCreator:   &fakeDatabaseCreator{},
		CertificateIssuer: &fakeCertificateIssuer{},
		DashboardReader:   reader,
	})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	if !reader.called || reader.user.Role != auth.RoleAdmin {
		t.Fatalf("dashboard reader called=%v user=%#v, want admin user", reader.called, reader.user)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Sites",
		"example.test",
		"npdemo",
		"local-self-signed",
		"2026-10-01",
		"Databases",
		"np_demo",
		"np_demo_user",
		"access denied",
		"Recent jobs",
		"issue_cert",
		"discarded",
		"2 / 3",
		"&lt;acme failed&gt;",
		`action="/sites"`,
		`action="/certificates"`,
		`action="/databases"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard body missing %q:\n%s", want, body)
		}
	}
}

func TestAdminDashboardRendersMobileTableLabels(t *testing.T) {
	reader := &fakeDashboardReader{
		data: dashboard.Data{
			Sites: []dashboard.Site{{
				Username:   "npdemo",
				Domain:     "example.test",
				PHPVersion: "8.3",
				Status:     "active",
			}},
			Databases: []dashboard.Database{{
				Engine: "mariadb",
				Name:   "np_demo",
				User:   "np_demo_user",
				Status: "active",
			}},
			Jobs: []dashboard.Job{{
				ID:          41,
				Kind:        "create_site",
				State:       "completed",
				Target:      "example.test",
				Attempt:     1,
				MaxAttempts: 25,
				CreatedAt:   time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC),
			}},
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`data-label="Domain"><span class="np-table-value">example.test`,
		`data-label="User"><span class="np-table-value">npdemo`,
		`data-label="PHP"><span class="np-table-value">8.3`,
		`data-label="Status" class="np-status"><span class="np-table-value">active`,
		`data-label="TLS"><span class="np-table-value">none`,
		`data-label="Name"><span class="np-table-value">np_demo`,
		`data-label="Engine"><span class="np-table-value">mariadb`,
		`data-label="Kind"><span class="np-table-value">create_site`,
		`data-label="Attempts"><span class="np-table-value">1 / 25`,
		`data-label="Created"><span class="np-table-value">2026-07-07 12:00`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard body missing responsive table label %q:\n%s", want, body)
		}
	}
}

func TestAdminDashboardRendersRetryActionForDiscardedJobs(t *testing.T) {
	reader := &fakeDashboardReader{
		data: dashboard.Data{
			Jobs: []dashboard.Job{
				{
					ID:          41,
					Kind:        "create_site",
					State:       "discarded",
					Target:      "example.test",
					Attempt:     25,
					MaxAttempts: 25,
					CreatedAt:   time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC),
				},
				{
					ID:          42,
					Kind:        "create_database",
					State:       "completed",
					Target:      "np_demo",
					Attempt:     1,
					MaxAttempts: 25,
					CreatedAt:   time.Date(2026, 7, 7, 12, 1, 0, 0, time.UTC),
				},
			},
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{
		DashboardReader: reader,
		JobRetrier:      &fakeJobRetrier{},
	})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`action="/jobs/retry"`,
		`name="job_id" value="41"`,
		`Retry job`,
		`data-label="Action"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard body missing retry action %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `name="job_id" value="42"`) {
		t.Fatalf("dashboard rendered retry action for completed job:\n%s", body)
	}
}

func TestAdminCanRetryDiscardedJob(t *testing.T) {
	retrier := &fakeJobRetrier{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{JobRetrier: retrier})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	form := url.Values{"job_id": {"41"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/jobs/retry", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /jobs/retry status = %d, want 303; body:\n%s", rec.Code, rec.Body.String())
	}
	if location := rec.Header().Get("Location"); location != "/?notice=job-retried" {
		t.Fatalf("Location = %q, want /?notice=job-retried", location)
	}
	if !retrier.called || retrier.jobID != 41 {
		t.Fatalf("retrier called=%v jobID=%d, want called with 41", retrier.called, retrier.jobID)
	}
}

func TestRetryJobShowsSuccessNotice(t *testing.T) {
	reader := &fakeDashboardReader{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1&notice=job-retried", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /?notice=job-retried status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Retry queued. Refresh in a moment to see the updated status.") {
		t.Fatalf("dashboard body missing retry notice:\n%s", rec.Body.String())
	}
}

func TestClientDashboardIgnoresRetryNotice(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleClient)
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1&notice=job-retried", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /?notice=job-retried status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "Retry queued") {
		t.Fatalf("client dashboard rendered admin retry notice:\n%s", rec.Body.String())
	}
}

func TestClientCannotRetryJob(t *testing.T) {
	retrier := &fakeJobRetrier{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{JobRetrier: retrier})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/jobs/retry", strings.NewReader("job_id=41"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /jobs/retry status = %d, want 403", rec.Code)
	}
	if retrier.called {
		t.Fatal("client retry invoked retrier")
	}
}

func TestUnauthenticatedRetryJobRedirectsToLogin(t *testing.T) {
	retrier := &fakeJobRetrier{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{JobRetrier: retrier})

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/jobs/retry", strings.NewReader("job_id=41"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /jobs/retry status = %d, want 303", rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "/login" {
		t.Fatalf("Location = %q, want /login", location)
	}
	if retrier.called {
		t.Fatal("unauthenticated retry invoked retrier")
	}
}

func TestRetryJobRejectsInvalidJobID(t *testing.T) {
	retrier := &fakeJobRetrier{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{JobRetrier: retrier})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/jobs/retry", strings.NewReader("job_id=not-a-number"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /jobs/retry status = %d, want 400", rec.Code)
	}
	if retrier.called {
		t.Fatal("invalid job id invoked retrier")
	}
}

func TestAdminCanUsePhase6Actions(t *testing.T) {
	manager := &fakePhase6Manager{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{Phase6Manager: manager})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	tests := []struct {
		name   string
		target string
		form   url.Values
		check  func(t *testing.T)
	}{
		{
			name:   "backup",
			target: "https://panel.test/backups",
			form:   url.Values{"domain": {"example.test"}, "owner_user_id": {"2"}},
			check: func(t *testing.T) {
				if manager.backupOwner.Role != auth.RoleAdmin || manager.backupResourceOwnerID != 2 || manager.backupReq.Domain != "example.test" {
					t.Fatalf("backup request = owner:%#v resourceOwner:%d req:%#v", manager.backupOwner, manager.backupResourceOwnerID, manager.backupReq)
				}
			},
		},
		{
			name:   "webmail",
			target: "https://panel.test/webmail",
			form:   url.Values{"domain": {"example.test"}},
			check: func(t *testing.T) {
				if manager.webmailOwner.Role != auth.RoleAdmin || manager.webmailDomain != "example.test" {
					t.Fatalf("webmail request = owner:%#v domain:%q", manager.webmailOwner, manager.webmailDomain)
				}
			},
		},
		{
			name:   "dns",
			target: "https://panel.test/dns",
			form:   url.Values{"domain": {"example.test"}, "address": {"192.0.2.10"}},
			check: func(t *testing.T) {
				if manager.dnsOwner.Role != auth.RoleAdmin || manager.dnsDomain != "example.test" || manager.dnsAddress != "192.0.2.10" {
					t.Fatalf("dns request = owner:%#v domain:%q address:%q", manager.dnsOwner, manager.dnsDomain, manager.dnsAddress)
				}
			},
		},
		{
			name:   "reconcile",
			target: "https://panel.test/reconcile",
			form:   url.Values{},
			check: func(t *testing.T) {
				if manager.reconcileOwner.Role != auth.RoleAdmin {
					t.Fatalf("reconcile owner = %#v, want admin", manager.reconcileOwner)
				}
			},
		},
		{
			name:   "restore",
			target: "https://panel.test/restores",
			form:   url.Values{"backup_id": {"7"}},
			check: func(t *testing.T) {
				if manager.restoreOwner.Role != auth.RoleAdmin || manager.restoreBackup != 7 {
					t.Fatalf("restore owner=%#v backup=%d, want admin and backup 7", manager.restoreOwner, manager.restoreBackup)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, test.target, strings.NewReader(test.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			addAuthenticatedCookie(req, cookie)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("POST %s status = %d, want 303; body:\n%s", test.target, rec.Code, rec.Body.String())
			}
			if location := rec.Header().Get("Location"); !strings.HasPrefix(location, "/?notice=") {
				t.Fatalf("Location = %q, want dashboard notice redirect", location)
			}
			test.check(t)
		})
	}
}

func TestAdminerRouteRequiresAdminAndIssuesToken(t *testing.T) {
	manager := &fakePhase6Manager{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{Phase6Manager: manager})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/db", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /db status = %d, want 200; body:\n%s", rec.Code, rec.Body.String())
	}
	if manager.adminerOwner.Role != auth.RoleAdmin {
		t.Fatalf("adminer owner = %#v, want admin", manager.adminerOwner)
	}
	if !strings.Contains(rec.Body.String(), "adminer-token") || !strings.Contains(rec.Body.String(), "Adminer SSO") {
		t.Fatalf("adminer page missing token/details:\n%s", rec.Body.String())
	}
}

func TestAdminDashboardRendersPhase6Operations(t *testing.T) {
	createdAt := time.Date(2026, 7, 7, 13, 0, 0, 0, time.UTC)
	reader := &fakeDashboardReader{
		data: dashboard.Data{
			Phase6: dashboard.Phase6Data{
				Backups: []dashboard.Backup{{
					ID:          1,
					TargetName:  "example.test",
					Status:      "active",
					ArchivePath: "/var/lib/nakpanel/backups/example.tar.gz",
					SizeBytes:   42,
					CreatedAt:   createdAt,
				}},
				Restores: []dashboard.RestoreRun{{
					BackupID:   1,
					TargetName: "example.test",
					Status:     "blocked",
					LastError:  "operator approval required",
					CreatedAt:  createdAt,
				}},
				WebmailHosts: []dashboard.WebmailHost{{
					Hostname:   "webmail.example.test",
					Status:     "active",
					ConfigPath: "/etc/nginx/sites-available/webmail.example.test.conf",
					CreatedAt:  createdAt,
				}},
				DNSZones: []dashboard.DNSZone{{
					Domain:    "example.test",
					Address:   "192.0.2.10",
					Serial:    2026070701,
					Status:    "active",
					ZonePath:  "/etc/bind/nakpanel/zones/db.example.test",
					CreatedAt: createdAt,
				}},
				Reconciliations: []dashboard.ReconciliationRun{{
					ID:         7,
					Status:     "active",
					SitesTotal: 1,
					SitesOK:    1,
					CreatedAt:  createdAt,
				}},
			},
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{
		DashboardReader: reader,
		Phase6Manager:   &fakePhase6Manager{},
	})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Operations",
		`action="/backups"`,
		`action="/webmail"`,
		`action="/dns"`,
		`action="/reconcile"`,
		`action="/restores"`,
		`href="/db"`,
		"example.test",
		"webmail.example.test",
		"/etc/bind/nakpanel/zones/db.example.test",
		"operator approval required",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard body missing %q:\n%s", want, body)
		}
	}
}

func TestClientCannotUsePhase6Actions(t *testing.T) {
	manager := &fakePhase6Manager{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{Phase6Manager: manager})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	for _, target := range []string{
		"https://panel.test/backups",
		"https://panel.test/webmail",
		"https://panel.test/dns",
		"https://panel.test/reconcile",
		"https://panel.test/restores",
	} {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader("domain=example.test&address=192.0.2.10"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("POST %s status = %d, want 403", target, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/db", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /db status = %d, want 403", rec.Code)
	}
	if manager.backupReq.Domain != "" || manager.webmailDomain != "" || manager.dnsDomain != "" || manager.reconcileOwner.Role != "" || manager.adminerOwner.Role != "" || manager.restoreOwner.Role != "" {
		t.Fatalf("client invoked phase6 manager: %#v", manager)
	}
}

func TestCrossSiteAdminPostIsRejected(t *testing.T) {
	manager := &fakePhase6Manager{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{Phase6Manager: manager})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/backups", strings.NewReader("domain=example.test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://attacker.test")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST status = %d, want 403", rec.Code)
	}
	if manager.backupReq.Domain != "" {
		t.Fatalf("cross-site POST invoked backup manager: %#v", manager)
	}
}

func TestAdminDashboardHidesUnavailableActionForms(t *testing.T) {
	reader := &fakeDashboardReader{
		data: dashboard.Data{
			Sites:     []dashboard.Site{{Domain: "example.test", Status: "active"}},
			Databases: []dashboard.Database{{Name: "np_demo", Status: "active"}},
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"example.test", "np_demo"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard body missing inventory %q:\n%s", want, body)
		}
	}
	for _, unwanted := range []string{`action="/sites"`, `action="/certificates"`, `action="/databases"`} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("dashboard body rendered unavailable form %q:\n%s", unwanted, body)
		}
	}
}

func TestAdminDashboardRendersQuotaManagement(t *testing.T) {
	reader := &fakeDashboardReader{
		data: dashboard.Data{
			Quotas: []controlquota.Summary{{
				UserID:         2,
				Email:          "client@nakpanel.test",
				Role:           "client",
				HasQuota:       true,
				PlanID:         10,
				PlanName:       "Starter",
				SubscriptionID: 20,
				Limits:         controlquota.Limits{UserID: 2, MaxSites: 2, MaxDatabases: 1, MaxBackups: 3, BackupStorageMB: 20, SiteDiskQuotaMB: 512, PHPFPMMaxChildren: 3, PHPMemoryMB: 128},
				Usage:          controlquota.Usage{UserID: 2, Sites: 1, Databases: 1, Backups: 2, BackupStorageBytes: 4096},
			}},
			Plans: []controlquota.Plan{{
				ID:                  10,
				Name:                "Starter",
				DiskMB:              5120,
				MaxSites:            1,
				MaxDatabases:        2,
				MaxBackups:          7,
				PHPFPMMaxChildren:   3,
				PHPMemoryMB:         128,
				AllowDNS:            true,
				BackupRetentionDays: 7,
				IsActive:            true,
			}},
			Customers: []types.Customer{{
				ID:          88,
				LoginUserID: 2,
				Email:       "client@nakpanel.test",
				DisplayName: "Client Contact",
				Status:      "active",
			}},
			Subscriptions: []types.SubscriptionSummary{{
				ID:               20,
				CustomerID:       88,
				CustomerUserID:   2,
				CustomerEmail:    "client@nakpanel.test",
				CustomerName:     "Client Contact",
				PlanID:           10,
				PlanName:         "Starter",
				SubscriptionName: "client.example.test",
				Status:           "active",
				MaxSites:         2,
			}},
			Settings:        controlquota.Settings{OversellPolicy: controlquota.OversellPolicyWarn, ServerDiskCapacityMB: 10000},
			CommittedDiskMB: 5120,
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{
		DashboardReader: reader,
		QuotaManager:    &fakeQuotaManager{},
	})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Plans & subscriptions",
		"Add Subscription",
		"Change Plan",
		"Service Plans",
		`data-np-subscription-filter`,
		`data-np-change-plan`,
		`data-np-subscription-check`,
		`data-customer-user-id="2"`,
		`data-subscriber-email="client@nakpanel.test"`,
		`data-plan-name="Starter"`,
		`>Subscription<`,
		`>Subscriber<`,
		`>Resources<`,
		"Starter",
		"Committed disk",
		"5120 MB",
		`action="/plans"`,
		`action="/plans/status"`,
		`action="/subscriptions"`,
		`action="/settings/oversell"`,
		"client@nakpanel.test",
		`name="plan_id"`,
		`name="site_disk_quota_mb"`,
		"1 / 2",
		"2 / 3",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `action="/quotas"`) || strings.Contains(body, "Account quotas") {
		t.Fatalf("admin dashboard exposed legacy quota form:\n%s", body)
	}
}

func TestAdminDashboardRendersPrototypeShellAndCreateGateData(t *testing.T) {
	reader := &fakeDashboardReader{
		data: dashboard.Data{
			Sites: []dashboard.Site{{
				Username:   "npdemo",
				Domain:     "example.test",
				PHPVersion: "8.3",
				Status:     "active",
			}},
			Jobs: []dashboard.Job{{
				ID:          41,
				Kind:        "create_site",
				State:       "running",
				Target:      "example.test",
				Attempt:     1,
				MaxAttempts: 3,
				CreatedAt:   time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC),
			}},
			Quotas: []controlquota.Summary{{
				UserID:         2,
				Email:          "client@nakpanel.test",
				Role:           "client",
				HasQuota:       true,
				PlanName:       "Starter",
				SubscriptionID: 20,
				Limits:         controlquota.Limits{UserID: 2, MaxSites: 2, StorageMB: 5120, SiteDiskQuotaMB: 5120, PHPFPMMaxChildren: 3, PHPMemoryMB: 128},
				Usage:          controlquota.Usage{UserID: 2, Sites: 2},
			}},
			Plans: []controlquota.Plan{{
				ID:                  10,
				Name:                "Starter",
				Description:         "Single site",
				DiskMB:              5120,
				MaxSites:            2,
				MaxDatabases:        2,
				MaxBackups:          7,
				PHPFPMMaxChildren:   3,
				PHPMemoryMB:         128,
				SiteDiskQuotaMB:     5120,
				AllowDNS:            true,
				BackupRetentionDays: 7,
				IsActive:            true,
			}},
			Customers: []types.Customer{{
				ID:          88,
				LoginUserID: 2,
				Email:       "client@nakpanel.test",
				DisplayName: "Client Contact",
				Status:      "active",
			}},
			Subscriptions: []types.SubscriptionSummary{{
				ID:               20,
				CustomerID:       88,
				CustomerUserID:   2,
				CustomerEmail:    "client@nakpanel.test",
				CustomerName:     "Client Contact",
				PlanID:           10,
				PlanName:         "Starter",
				SubscriptionName: "client.example.test",
				Status:           "active",
				MaxSites:         2,
				SitesUsed:        2,
			}},
			Settings:        controlquota.Settings{OversellPolicy: controlquota.OversellPolicyWarn, ServerDiskCapacityMB: 10000},
			CommittedDiskMB: 5120,
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{
		SiteCreator:     &fakeSiteCreator{},
		DashboardReader: reader,
		QuotaManager:    &fakeQuotaManager{},
	})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`class="np-layout"`,
		`ns1.nakroteck.com`,
		`data-np-view="dashboard"`,
		`data-np-view="sites"`,
		`data-np-view="subscriptions"`,
		`class="np-nav-item is-active" data-np-view="subscriptions"`,
		`data-np-section-title>Subscriptions`,
		`placeholder="Search sites, databases, records..."`,
		`id="create-site-modal"`,
		`agent connected`,
		`RA</button>`,
		`Add Subscription`,
		`Change Plan`,
		`Service Plans`,
		`data-np-subscription-filter`,
		`data-np-subscription-row`,
		`data-np-subscription-check`,
		`data-customer-user-id="2"`,
		`data-customer-id="88"`,
		`data-subscriber-email="client@nakpanel.test"`,
		`Server capacity`,
		`Committed to plans (at max)`,
		`settings.oversell_policy`,
		`name="oversell_policy" value="warn"`,
		`>Subscription<`,
		`>Subscriber<`,
		`>Resources<`,
		`Manage`,
		`New site`,
		`data-max-sites="2"`,
		`data-sites-used="2"`,
		`data-plan-name="Starter"`,
		`data-subscription-id="20"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard shell missing %q:\n%s", want, body)
		}
	}
}

func TestAdminDashboardRendersPleskStyleSettingsHub(t *testing.T) {
	reader := &fakeDashboardReader{
		data: dashboard.Data{
			Plans: []controlquota.Plan{{
				ID:                  10,
				Name:                "Business",
				DiskMB:              20480,
				MaxSites:            10,
				MaxDatabases:        10,
				MaxBackups:          14,
				BackupStorageMB:     40960,
				PHPAllowlist:        "8.3,8.2",
				PHPFPMMaxChildren:   8,
				PHPMemoryMB:         256,
				AllowSSH:            true,
				AllowDNS:            true,
				BackupRetentionDays: 14,
				IsActive:            true,
			}},
			Settings:        controlquota.Settings{OversellPolicy: controlquota.OversellPolicyCap, ServerDiskCapacityMB: 512000},
			CommittedDiskMB: 245760,
			Phase6: dashboard.Phase6Data{
				Backups: []dashboard.Backup{{TargetName: "example.test", Status: "active", SizeBytes: 42}},
			},
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{
		DashboardReader: reader,
		Phase6Manager:   &fakePhase6Manager{},
		QuotaManager:    &fakeQuotaManager{},
	})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`data-np-view="settings"`,
		`data-np-panel="settings"`,
		"Tools &amp; Settings",
		"General Server",
		"Global PHP",
		"Database Server",
		"Backup Settings",
		"Firewall",
		"SSH Terminal",
		"Privileged agent op pending",
		"Timezone/NTP summary",
		"Default PHP version",
		"MariaDB",
		`href="/db"`,
		`action="/settings/oversell"`,
		"Business",
		"8.3,8.2",
		"14 days",
		"nftables preview",
		"Root terminal disabled",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("settings hub missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `data-np-view="settings" disabled`) {
		t.Fatalf("settings nav is still disabled:\n%s", body)
	}
}

func TestClientDashboardDoesNotRenderSettingsHub(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{
		DashboardReader: &fakeDashboardReader{},
		QuotaManager:    &fakeQuotaManager{},
	})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, unwanted := range []string{
		`data-np-view="settings"`,
		`data-np-panel="settings"`,
		"Tools &amp; Settings",
		"Global PHP",
		"SSH Terminal",
	} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("client dashboard rendered settings hub fragment %q:\n%s", unwanted, body)
		}
	}
}

func TestNonAdminDashboardRendersOwnQuotaReadOnly(t *testing.T) {
	reader := &fakeDashboardReader{
		data: dashboard.Data{
			Quotas: []controlquota.Summary{{
				UserID:   1,
				Email:    "client@nakpanel.test",
				Role:     "client",
				HasQuota: true,
				Limits:   controlquota.Limits{UserID: 1, MaxSites: 2},
				Usage:    controlquota.Usage{UserID: 1, Sites: 1},
			}},
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: reader, QuotaManager: &fakeQuotaManager{}})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Resource usage") || !strings.Contains(body, "1 / 2") {
		t.Fatalf("client dashboard missing own quota usage:\n%s", body)
	}
	if strings.Contains(body, `action="/quotas"`) {
		t.Fatalf("client dashboard exposed quota form:\n%s", body)
	}
}

func TestAdminCanUpsertQuota(t *testing.T) {
	manager := &fakeQuotaManager{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{QuotaManager: manager})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	form := url.Values{
		"user_id":            {"2"},
		"max_sites":          {"3"},
		"max_databases":      {"4"},
		"storage_mb":         {"2048"},
		"max_backups":        {"5"},
		"backup_storage_mb":  {"4096"},
		"site_disk_quota_mb": {"512"},
		"php_max_children":   {"6"},
		"php_memory_mb":      {"256"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/quotas", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /quotas status = %d, want 303; body:\n%s", rec.Code, rec.Body.String())
	}
	want := controlquota.Limits{UserID: 2, MaxSites: 3, MaxDatabases: 4, StorageMB: 2048, MaxBackups: 5, BackupStorageMB: 4096, SiteDiskQuotaMB: 512, PHPFPMMaxChildren: 6, PHPMemoryMB: 256}
	if !manager.called || manager.owner.Role != auth.RoleAdmin || manager.limits != want {
		t.Fatalf("quota manager = called:%v owner:%#v limits:%#v, want %#v", manager.called, manager.owner, manager.limits, want)
	}
}

func TestClientCannotUpsertQuota(t *testing.T) {
	manager := &fakeQuotaManager{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{QuotaManager: manager})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/quotas", strings.NewReader("user_id=1&max_sites=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /quotas status = %d, want 403", rec.Code)
	}
	if manager.called {
		t.Fatal("client quota upsert invoked manager")
	}
}

func TestAdminCanUpsertPlan(t *testing.T) {
	manager := &fakeQuotaManager{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{QuotaManager: manager})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	form := url.Values{
		"plan_id":               {"9"},
		"name":                  {"Launch"},
		"description":           {"Launch plan"},
		"price_cents":           {"1200"},
		"disk_mb":               {"-1"},
		"max_sites":             {"3"},
		"max_databases":         {"4"},
		"bandwidth_mb":          {"-1"},
		"max_mailboxes":         {"0"},
		"allow_ssh":             {"true"},
		"allow_dns":             {"true"},
		"backup_retention_days": {"30"},
		"php_allowlist":         {"8.3,8.2"},
		"php_max_children":      {"6"},
		"php_memory_mb":         {"256"},
		"site_disk_quota_mb":    {"1024"},
		"max_backups":           {"7"},
		"backup_storage_mb":     {"4096"},
		"is_active":             {"true"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/plans", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /plans status = %d, want 303; body:\n%s", rec.Code, rec.Body.String())
	}
	if !manager.planCalled || manager.plan.ID != 9 || manager.plan.Name != "Launch" || !manager.plan.PriceCents.Valid || manager.plan.PriceCents.Int64 != 1200 {
		t.Fatalf("plan manager = called:%v plan:%#v", manager.planCalled, manager.plan)
	}
	if manager.plan.DiskMB != -1 || manager.plan.MaxSites != 3 || !manager.plan.AllowSSH || !manager.plan.AllowDNS || !manager.plan.IsActive {
		t.Fatalf("plan limits/options = %#v", manager.plan)
	}
}

func TestAdminCanAssignSubscriptionAndUpdateOversellSettings(t *testing.T) {
	manager := &fakeQuotaManager{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{QuotaManager: manager})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	subForm := url.Values{"customer_user_id": {"2"}, "plan_id": {"10"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/subscriptions", strings.NewReader(subForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /subscriptions status = %d, want 303; body:\n%s", rec.Code, rec.Body.String())
	}
	if !manager.subCalled || manager.customerUserID != 2 || manager.planID != 10 {
		t.Fatalf("subscription call = called:%v customer:%d plan:%d", manager.subCalled, manager.customerUserID, manager.planID)
	}

	settingsForm := url.Values{"oversell_policy": {"cap"}, "server_disk_capacity_mb": {"50000"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/settings/oversell", strings.NewReader(settingsForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /settings/oversell status = %d, want 303; body:\n%s", rec.Code, rec.Body.String())
	}
	if !manager.settingsCalled || manager.settings.OversellPolicy != controlquota.OversellPolicyCap || manager.settings.ServerDiskCapacityMB != 50000 {
		t.Fatalf("settings call = called:%v settings:%#v", manager.settingsCalled, manager.settings)
	}
}

func TestAdminCanCreateContactCustomerAndSubscriptionTogether(t *testing.T) {
	manager := &fakeQuotaManager{customerID: 99}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{QuotaManager: manager})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	form := url.Values{
		"customer_mode":     {"new"},
		"customer_email":    {"owner@example.test"},
		"display_name":      {"Example Owner"},
		"company":           {"Example Co"},
		"enable_login":      {"false"},
		"subscription_name": {"example.test"},
		"plan_id":           {"10"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/subscriptions", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /subscriptions status = %d, want 303; body:\n%s", rec.Code, rec.Body.String())
	}
	if !manager.customerCalled {
		t.Fatal("subscription flow did not create customer")
	}
	if manager.customerReq.Email != "owner@example.test" || manager.customerReq.DisplayName != "Example Owner" || manager.customerReq.Company != "Example Co" || manager.customerReq.EnableLogin {
		t.Fatalf("customer request = %#v", manager.customerReq)
	}
	if !manager.subCalled || manager.subscriptionReq.CustomerID != 99 || manager.subscriptionReq.PlanID != 10 || manager.subscriptionReq.SubscriptionName != "example.test" {
		t.Fatalf("subscription request = called:%v req:%#v", manager.subCalled, manager.subscriptionReq)
	}
}

func TestClientCannotManagePlansSubscriptionsOrSettings(t *testing.T) {
	manager := &fakeQuotaManager{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{QuotaManager: manager})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	for _, target := range []string{
		"https://panel.test/plans",
		"https://panel.test/plans/status",
		"https://panel.test/subscriptions",
		"https://panel.test/settings/oversell",
	} {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader("plan_id=1&customer_user_id=2&name=Starter&oversell_policy=warn&server_disk_capacity_mb=1"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("POST %s status = %d, want 403", target, rec.Code)
		}
	}
	if manager.planCalled || manager.statusCalled || manager.subCalled || manager.settingsCalled {
		t.Fatalf("client invoked plan manager: %#v", manager)
	}
}

func TestOverQuotaCreateShowsClearBadRequest(t *testing.T) {
	creator := &fakeSiteCreator{err: controlquota.ErrExceeded}
	handler, _ := newTestHandlerWithSiteCreator(t, auth.RoleAdmin, creator)
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites", strings.NewReader("username=npdemo&domain=example.test&php_version=8.3"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /sites status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "quota exceeded") {
		t.Fatalf("over-quota response missing clear message:\n%s", rec.Body.String())
	}
}

func TestAdminDashboardRendersAllSiteErrorsSafely(t *testing.T) {
	reader := &fakeDashboardReader{
		data: dashboard.Data{
			Sites: []dashboard.Site{{
				Username:     "npdemo",
				Domain:       "example.test",
				PHPVersion:   "8.3",
				Status:       "failed",
				LastError:    "site create failed",
				TLSStatus:    "failed",
				TLSLastError: "<script>alert(1)</script>",
			}},
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "site create failed") {
		t.Fatalf("dashboard body missing site error:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("dashboard body missing escaped TLS error:\n%s", body)
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("dashboard body rendered unescaped TLS error:\n%s", body)
	}
}

func TestAdminDashboardRendersJobLoadErrorWithInventory(t *testing.T) {
	reader := &fakeDashboardReader{
		data: dashboard.Data{
			Sites:        []dashboard.Site{{Domain: "example.test", Status: "active"}},
			Databases:    []dashboard.Database{{Name: "np_demo", Status: "active"}},
			JobLoadError: "recent jobs unavailable",
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"example.test", "np_demo", "Recent jobs", "recent jobs unavailable"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard body missing %q:\n%s", want, body)
		}
	}
}

func TestClientDashboardDoesNotLoadAdminInventory(t *testing.T) {
	reader := &fakeDashboardReader{
		data: dashboard.Data{
			Sites: []dashboard.Site{{Domain: "admin-only.test", Status: "active"}},
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: reader})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "admin-only.test") {
		t.Fatalf("client dashboard leaked admin inventory:\n%s", rec.Body.String())
	}
}

func TestNonAdminDashboardHidesCreateSiteLauncherWhenConfigured(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{
		SiteCreator:     &fakeSiteCreator{},
		DashboardReader: &fakeDashboardReader{},
	})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, blocked := range []string{`data-np-open-create`, `id="create-site-modal"`, `action="/sites"`} {
		if strings.Contains(body, blocked) {
			t.Fatalf("client dashboard exposed create-site UI %q:\n%s", blocked, body)
		}
	}
}

func TestClientUsesSameURLAndSeesClientDashboard(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleClient)
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Client dashboard") {
		t.Fatalf("dashboard body %q does not contain Client dashboard", rec.Body.String())
	}
	for _, want := range []string{"Account overview", "Hosting account"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("client dashboard body missing %q:\n%s", want, rec.Body.String())
		}
	}
}

func TestResellerUsesSameURLAndSeesResellerDashboard(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleReseller)
	cookie := login(t, handler, "reseller@nakpanel.test", "NakpanelReseller!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	for _, want := range []string{"Reseller dashboard", "Account overview", "Customer portfolio"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("reseller dashboard body missing %q:\n%s", want, rec.Body.String())
		}
	}
	for _, blocked := range []string{`action="/sites"`, `action="/databases"`, `action="/certificates"`} {
		if strings.Contains(rec.Body.String(), blocked) {
			t.Fatalf("reseller dashboard exposed admin action %s:\n%s", blocked, rec.Body.String())
		}
	}
}

func TestLoginFailureDoesNotSetSessionCookie(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleAdmin)
	form := url.Values{
		"email":    {"admin@nakpanel.test"},
		"password": {"wrong"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /login status = %d, want 401", rec.Code)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == SessionCookieName {
			t.Fatal("login failure set a session cookie")
		}
	}
}

func TestUnauthenticatedDashboardRedirectsToLogin(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("GET / status = %d, want 303", rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "/login" {
		t.Fatalf("Location = %q, want /login", location)
	}
}

func TestLogoutDeletesSessionAndClearsCookie(t *testing.T) {
	handler, sessions := newTestHandler(t, auth.RoleAdmin)
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/logout", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /logout status = %d, want 303", rec.Code)
	}
	if !sessions.deleted {
		t.Fatal("logout did not delete the server-side session")
	}

	var cleared bool
	for _, responseCookie := range rec.Result().Cookies() {
		if responseCookie.Name == SessionCookieName && responseCookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout did not clear the session cookie")
	}

	req = httptest.NewRequest(http.MethodGet, "https://panel.test/?legacy=1", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("GET / after logout status = %d, want 303", rec.Code)
	}
}

func TestHealthzReturnsOK(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want 200", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Fatalf("GET /healthz body = %q, want ok", rec.Body.String())
	}
}

func TestAdminCanCreateSite(t *testing.T) {
	creator := &fakeSiteCreator{}
	handler, _ := newTestHandlerWithSiteCreator(t, auth.RoleAdmin, creator)
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	form := url.Values{
		"owner_user_id": {"2"},
		"username":      {"npdemo"},
		"domain":        {"example.test"},
		"php_version":   {"8.3"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /sites status = %d, want 303", rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "/" {
		t.Fatalf("Location = %q, want /", location)
	}
	if creator.owner.Role != auth.RoleAdmin || creator.owner.Email != "admin@nakpanel.test" {
		t.Fatalf("owner = %#v, want admin session user", creator.owner)
	}
	if creator.resourceOwnerID != 2 {
		t.Fatalf("resource owner id = %d, want selected customer 2", creator.resourceOwnerID)
	}
	want := types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3"}
	if len(creator.requests) != 1 || creator.requests[0] != want {
		t.Fatalf("site requests = %#v, want %#v", creator.requests, []types.CreateSiteReq{want})
	}
}

func TestAdminCanCreateSiteWithSPAJSON(t *testing.T) {
	creator := &fakeSiteCreator{}
	handler, _ := newTestHandlerWithSiteCreator(t, auth.RoleAdmin, creator)
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	form := url.Values{
		"owner_user_id": {"2"},
		"username":      {"npdemo"},
		"domain":        {"example.test"},
		"php_version":   {"8.3"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Nakpanel-SPA", "true")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /sites SPA status = %d, want 202; body:\n%s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", contentType)
	}
	var body struct {
		OK       bool   `json:"ok"`
		SiteID   int64  `json:"site_id"`
		Redirect string `json:"redirect"`
		Notice   string `json:"notice"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.OK || body.SiteID != 7 || body.Redirect != "/" || body.Notice == "" {
		t.Fatalf("SPA response = %#v, want ok site id redirect and notice", body)
	}
}

func TestOverQuotaCreateWithSPAJSONReturnsError(t *testing.T) {
	creator := &fakeSiteCreator{err: controlquota.ErrExceeded}
	handler, _ := newTestHandlerWithSiteCreator(t, auth.RoleAdmin, creator)
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites", strings.NewReader("username=npdemo&domain=example.test&php_version=8.3"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Nakpanel-SPA", "true")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /sites SPA status = %d, want 400", rec.Code)
	}
	var body struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.OK || !strings.Contains(body.Error, "quota exceeded") {
		t.Fatalf("SPA error response = %#v, want quota exceeded error", body)
	}
}

func TestClientCannotCreateSite(t *testing.T) {
	creator := &fakeSiteCreator{}
	handler, _ := newTestHandlerWithSiteCreator(t, auth.RoleClient, creator)
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites", strings.NewReader("username=npdemo&domain=example.test&php_version=8.3"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /sites status = %d, want 403", rec.Code)
	}
	if len(creator.requests) != 0 {
		t.Fatalf("client create invoked site creator: %#v", creator.requests)
	}
}

func TestUnauthenticatedCreateSiteRedirectsToLogin(t *testing.T) {
	creator := &fakeSiteCreator{}
	handler, _ := newTestHandlerWithSiteCreator(t, auth.RoleAdmin, creator)

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites", strings.NewReader("username=npdemo&domain=example.test&php_version=8.3"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /sites status = %d, want 303", rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "/login" {
		t.Fatalf("Location = %q, want /login", location)
	}
	if len(creator.requests) != 0 {
		t.Fatalf("unauthenticated create invoked site creator: %#v", creator.requests)
	}
}

func TestAdminCanCreateDatabase(t *testing.T) {
	creator := &fakeDatabaseCreator{}
	handler, _ := newTestHandlerWithCreators(t, auth.RoleAdmin, nil, creator, nil)
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	form := url.Values{
		"owner_user_id": {"2"},
		"engine":        {"mariadb"},
		"db_name":       {"np_demo"},
		"db_user":       {"np_demo_user"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/databases", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /databases status = %d, want 303", rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "/" {
		t.Fatalf("Location = %q, want /", location)
	}
	if creator.owner.Role != auth.RoleAdmin || creator.owner.Email != "admin@nakpanel.test" {
		t.Fatalf("owner = %#v, want admin session user", creator.owner)
	}
	if creator.resourceOwnerID != 2 {
		t.Fatalf("resource owner id = %d, want selected customer 2", creator.resourceOwnerID)
	}
	want := types.CreateDatabaseReq{Engine: types.EngineMariaDB, DBName: "np_demo", DBUser: "np_demo_user"}
	if len(creator.requests) != 1 || creator.requests[0] != want {
		t.Fatalf("database requests = %#v, want %#v", creator.requests, []types.CreateDatabaseReq{want})
	}
}

func TestCreateDatabaseDefaultsToMariaDB(t *testing.T) {
	creator := &fakeDatabaseCreator{}
	handler, _ := newTestHandlerWithCreators(t, auth.RoleAdmin, nil, creator, nil)
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/databases", strings.NewReader("db_name=np_demo&db_user=np_demo_user"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /databases status = %d, want 303", rec.Code)
	}
	want := types.CreateDatabaseReq{Engine: types.EngineMariaDB, DBName: "np_demo", DBUser: "np_demo_user"}
	if len(creator.requests) != 1 || creator.requests[0] != want {
		t.Fatalf("database requests = %#v, want %#v", creator.requests, []types.CreateDatabaseReq{want})
	}
}

func TestClientCannotCreateDatabase(t *testing.T) {
	creator := &fakeDatabaseCreator{}
	handler, _ := newTestHandlerWithCreators(t, auth.RoleClient, nil, creator, nil)
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/databases", strings.NewReader("engine=mariadb&db_name=np_demo&db_user=np_demo_user"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /databases status = %d, want 403", rec.Code)
	}
	if len(creator.requests) != 0 {
		t.Fatalf("client create invoked database creator: %#v", creator.requests)
	}
}

func TestAdminCanIssueCertificate(t *testing.T) {
	issuer := &fakeCertificateIssuer{}
	handler, _ := newTestHandlerWithCreators(t, auth.RoleAdmin, nil, nil, issuer)
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	form := url.Values{
		"domain": {"example.test"},
		"issuer": {"local-self-signed"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/certificates", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /certificates status = %d, want 303", rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "/" {
		t.Fatalf("Location = %q, want /", location)
	}
	if issuer.owner.Role != auth.RoleAdmin || issuer.owner.Email != "admin@nakpanel.test" {
		t.Fatalf("owner = %#v, want admin session user", issuer.owner)
	}
	if issuer.domain != "example.test" || issuer.issuer != types.CertIssuerLocalSelfSigned {
		t.Fatalf("certificate request domain=%q issuer=%q, want example.test local-self-signed", issuer.domain, issuer.issuer)
	}
}

func TestClientCannotIssueCertificate(t *testing.T) {
	issuer := &fakeCertificateIssuer{}
	handler, _ := newTestHandlerWithCreators(t, auth.RoleClient, nil, nil, issuer)
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/certificates", strings.NewReader("domain=example.test&issuer=local-self-signed"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /certificates status = %d, want 403", rec.Code)
	}
	if issuer.domain != "" {
		t.Fatalf("client issue invoked certificate issuer: %#v", issuer)
	}
}

func TestAuthenticatedUserCanQueueCustomCertificateWithoutEchoingKey(t *testing.T) {
	installer := &fakeCustomCertificateInstaller{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{CustomCertificateInstaller: installer})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := customCertificateRequest(t, "https://panel.test/sites/7/certificates/custom", cookie, []byte("leaf-pem"), []byte("private-key-secret"), []byte("chain-pem"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if installer.siteID != 7 || installer.owner.Role != auth.RoleClient || string(installer.bundle.PrivateKeyPEM) != "private-key-secret" {
		t.Fatalf("installer call = site %d owner %#v bundle %#v", installer.siteID, installer.owner, installer.bundle)
	}
	if strings.Contains(rec.Body.String(), "private-key-secret") || strings.Contains(rec.Header().Get("Location"), "private-key-secret") {
		t.Fatal("private key was exposed in HTTP response")
	}
}

func TestCrossTenantCustomCertificateReturnsNotFound(t *testing.T) {
	installer := &fakeCustomCertificateInstaller{err: provision.ErrForbidden}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{CustomCertificateInstaller: installer})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := customCertificateRequest(t, "https://panel.test/sites/99/certificates/custom", cookie, []byte("leaf"), []byte("key"), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func customCertificateRequest(t *testing.T, target string, cookie *http.Cookie, certificate, key, chain []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for name, data := range map[string][]byte{"certificate": certificate, "private_key": key, "chain": chain} {
		if len(data) == 0 {
			continue
		}
		part, err := writer.CreateFormFile(name, name+".pem")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = part.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, target, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	addAuthenticatedCookie(req, cookie)
	req.Header.Set("X-Nakpanel-CSRF", csrfToken(req))
	return req
}

func newTestHandler(t *testing.T, role auth.Role) (http.Handler, *fakeSessionStore) {
	return newTestHandlerWithSiteCreator(t, role, nil)
}

func newTestHandlerWithSiteCreator(t *testing.T, role auth.Role, creator *fakeSiteCreator) (http.Handler, *fakeSessionStore) {
	return newTestHandlerWithCreators(t, role, creator, nil, nil)
}

func newTestHandlerWithCreators(t *testing.T, role auth.Role, siteCreator *fakeSiteCreator, databaseCreator *fakeDatabaseCreator, certificateIssuer *fakeCertificateIssuer) (http.Handler, *fakeSessionStore) {
	return newTestHandlerWithOptions(t, role, ServerOptions{SiteCreator: siteCreator, DatabaseCreator: databaseCreator, CertificateIssuer: certificateIssuer})
}

func newTestHandlerWithOptions(t *testing.T, role auth.Role, options ServerOptions) (http.Handler, *fakeSessionStore) {
	t.Helper()
	password := "NakpanelAdmin!2026"
	email := "admin@nakpanel.test"
	switch role {
	case auth.RoleClient:
		password = "NakpanelClient!2026"
		email = "client@nakpanel.test"
	case auth.RoleReseller:
		password = "NakpanelReseller!2026"
		email = "reseller@nakpanel.test"
	}

	hash, err := auth.HashPassword(password, auth.TestPasswordParams)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	sessionStore := &fakeSessionStore{
		user: auth.SessionUser{
			ID:    1,
			Email: email,
			Role:  role,
		},
	}
	sessionManager := auth.NewSessionManager(sessionStore, auth.SessionOptions{
		TTL:        time.Hour,
		TokenBytes: 32,
		Now:        func() time.Time { return time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC) },
	})
	server := NewServer(fakeUserStore{
		users: map[string]auth.User{
			email: {
				ID:           1,
				Email:        email,
				PasswordHash: hash,
				Role:         role,
			},
		},
	}, sessionManager, options)
	return server.Handler(), sessionStore
}

func TestRootRedirectsToRoutedDashboard(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("GET / = %d Location %q, want 303 /dashboard", rec.Code, rec.Header().Get("Location"))
	}
}

func TestHandlerSetsSecurityHeaders(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Security-Policy") == "" || rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers missing: %#v", rec.Header())
	}
}

func TestHandlerRejectsOversizedPostBody(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleAdmin)
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/login", strings.NewReader(strings.Repeat("a", maxFormBodyBytes+1)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized POST status = %d, want 413", rec.Code)
	}
}

func TestRoutedAdminWorkspacePagesAndDetailNavigation(t *testing.T) {
	reader := &fakeDashboardReader{data: dashboard.Data{
		Sites:         []dashboard.Site{{ID: 7, Domain: "owned.test", Username: "owned", DocumentRoot: "/home/owned/domains/owned.test/public_html", PHPVersion: "8.3", Status: "active", CustomerID: 88, SubscriptionID: 20}},
		Databases:     []dashboard.Database{{ID: 8, Name: "owned_db", User: "owned_user", Engine: "mariadb", Status: "active", CustomerID: 88, SubscriptionID: 20}},
		Customers:     []types.Customer{{ID: 88, Email: "owner@test", DisplayName: "Owner", Status: "active"}},
		Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, CustomerName: "Owner", SubscriptionName: "Owned hosting", PlanID: 10, PlanName: "Business", Status: "active", MaxSites: 5}},
		Plans:         []controlquota.Plan{{ID: 10, Name: "Business", IsActive: true, DiskMB: 1024, MaxSites: 5, MaxDatabases: 5, MaxBackups: 5}},
		Resellers:     []types.Reseller{{ID: 91, Email: "provider@test", DisplayName: "Provider", Status: "active", PlanName: "Agency"}},
		ResellerPlans: []types.ResellerPlan{{ID: 92, Name: "Agency", IsActive: true, MaxCustomers: 10}},
	}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{
		DashboardReader: reader, SiteCreator: &fakeSiteCreator{}, DatabaseCreator: &fakeDatabaseCreator{}, CertificateIssuer: &fakeCertificateIssuer{}, Phase6Manager: &fakePhase6Manager{}, QuotaManager: &fakeQuotaManager{},
	})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	cases := map[string]string{
		"/dashboard": "Recent websites", "/sites": "Websites &amp; Domains", "/sites/7": "Hosting overview", "/sites/7?tab=hosting": "Hosting settings", "/databases": "owned_db", "/backups": "Create backup", "/dns": "Configure DNS", "/certificates": "Issue certificate", "/activity": "Audit events", "/customers": "Add customer", "/customers/88": "Open support view", "/subscriptions": "Add subscription", "/subscriptions/20": "Subscription settings", "/subscriptions/new": "First website", "/service-plans": "Create plan", "/service-plans/new": "Create Plan", "/service-plans/10": "Save and synchronize", "/service-plans/resellers/new": "Create Plan", "/service-plans/resellers/92": "Update Plan", "/tools-settings": "Tools &amp; Settings", "/resellers": "Add reseller", "/resellers/91": "Provider account", "/reseller-plans": "Add Reseller Plan",
	}
	for path, marker := range cases {
		req := httptest.NewRequest(http.MethodGet, "https://panel.test"+path, nil)
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), marker) {
			t.Fatalf("GET %s = %d, marker %q missing\n%s", path, rec.Code, marker, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `name="nakpanel-csrf"`) || !strings.Contains(rec.Body.String(), `src="/assets/app.js"`) {
			t.Fatalf("GET %s missing routed assets or CSRF metadata", path)
		}
		if path == "/subscriptions" {
			for _, want := range []string{"Change Plan", "Change Subscriber", "Service Plans", "Subscription", "Subscriber", "Resources", "data-np-subscription-row", "data-np-subscription-check", "np-subscription-check", "data-customer-user-id", "data-plan-name", "data-subscriber-email"} {
				if !strings.Contains(rec.Body.String(), want) {
					t.Fatalf("GET /subscriptions missing %q", want)
				}
			}
		}
		if path == "/subscriptions/20" {
			for _, want := range []string{"Websites &amp; Domains", "owned.test", "?tab=hosting", "?tab=php", "?tab=dns", "?tab=ssl", "?tab=databases", "?tab=backups"} {
				if !strings.Contains(rec.Body.String(), want) {
					t.Fatalf("GET /subscriptions/20 missing %q", want)
				}
			}
		}
		if path == "/sites/7" {
			for _, want := range []string{"Overview", "Hosting", "PHP", "DNS", "SSL/TLS", "Databases", "Backups"} {
				if !strings.Contains(rec.Body.String(), want) {
					t.Fatalf("GET /sites/7 missing domain tab %q", want)
				}
			}
		}
		if path == "/sites/7?tab=hosting" {
			for _, want := range []string{`class="np-readonly-field"`, "/home/owned/domains/owned.test/public_html"} {
				if !strings.Contains(rec.Body.String(), want) {
					t.Fatalf("GET /sites/7?tab=hosting missing %q", want)
				}
			}
		}
		postActions := map[string]string{
			"/databases":         "/databases",
			"/backups":           "/backups",
			"/dns":               "/dns",
			"/service-plans/new": "/plans",
			"/tools-settings":    "/settings/oversell",
		}
		if action, ok := postActions[path]; ok && !renderedFormContainsCSRF(rec.Body.String(), action) {
			t.Fatalf("GET %s form action %s missing server-rendered CSRF token", path, action)
		}
	}
}

func TestTLSAutoRenewRendersAndUpdates(t *testing.T) {
	reader := &fakeDashboardReader{data: dashboard.Data{Sites: []dashboard.Site{{ID: 7, Domain: "owned.test", Status: "active", TLSStatus: "active", TLSAutoRenew: true, CustomerID: 88, SubscriptionID: 20}}, Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, Status: "active", AllowTLS: true}}}}
	domains := &fakeDomainManager{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader, CertificateIssuer: &fakeCertificateIssuer{}, DomainManager: domains})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7?tab=ssl", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `action="/sites/7/tls-auto-renew"`) || !strings.Contains(rec.Body.String(), `name="tls_auto_renew" value="true" checked`) {
		t.Fatalf("TLS auto-renew form missing or unchecked: status=%d\n%s", rec.Code, rec.Body.String())
	}
	form := url.Values{"tls_auto_renew": {"false"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/sites/7/tls-auto-renew", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || !domains.called || domains.siteID != 7 || domains.autoRenew {
		t.Fatalf("POST auto-renew status=%d manager=%#v", rec.Code, domains)
	}
}

func TestClientDomainTabsHonorSubscriptionPermissions(t *testing.T) {
	reader := &fakeDashboardReader{data: dashboard.Data{
		Sites:         []dashboard.Site{{ID: 7, Domain: "owned.test", Username: "owned", PHPVersion: "8.3", DesiredPHPVersion: "8.3", Status: "active", CustomerID: 88, SubscriptionID: 20}},
		Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, SubscriptionName: "Restricted hosting", PlanName: "Restricted", Status: "active", PHPAllowlist: "8.3"}},
	}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{
		DashboardReader: reader, CertificateIssuer: &fakeCertificateIssuer{}, Phase6Manager: &fakePhase6Manager{},
	})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	cases := []struct {
		path, gate, action string
	}{
		{"/sites/7?tab=php", "PHP settings are disabled", `/sites/7/php`},
		{"/sites/7?tab=dns", "DNS management is disabled", `/sites/7/dns-records`},
		{"/sites/7?tab=ssl", "SSL/TLS management is disabled", `/certificates`},
		{"/sites/7?tab=backups", "Backup and restore are disabled", `/backups`},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "https://panel.test"+tc.path, nil)
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tc.gate) {
			t.Fatalf("GET %s = %d, missing gate %q\n%s", tc.path, rec.Code, tc.gate, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), `action="`+tc.action+`"`) {
			t.Fatalf("GET %s exposed disabled action %s", tc.path, tc.action)
		}
	}
}

func TestClientSubscriptionToolbarHidesProviderActions(t *testing.T) {
	reader := &fakeDashboardReader{data: dashboard.Data{Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, CustomerName: "Owner", CustomerEmail: "owner@test", SubscriptionName: "Owned hosting", PlanName: "Business", Status: "active"}}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: reader})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/subscriptions", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /subscriptions = %d", rec.Code)
	}
	for _, hidden := range []string{"Change Plan", "Change Subscriber", "Service Plans", "data-np-subscription-check"} {
		if strings.Contains(rec.Body.String(), hidden) {
			t.Fatalf("client subscription page exposed provider control %q", hidden)
		}
	}
	if !strings.Contains(rec.Body.String(), "Search subscriptions") || !strings.Contains(rec.Body.String(), "Owned hosting") {
		t.Fatal("client subscription page lost read-only workspace content")
	}
}

func renderedFormContainsCSRF(body, action string) bool {
	start := strings.Index(body, `action="`+action+`"`)
	if start < 0 {
		return false
	}
	end := strings.Index(body[start:], "</form>")
	if end < 0 {
		return false
	}
	return strings.Contains(body[start:start+end], `name="csrf_token"`)
}

func addAuthenticatedCookie(req *http.Request, cookie *http.Cookie) {
	req.AddCookie(cookie)
	if req.Method == http.MethodPost && req.URL.Path != "/login" {
		req.Header.Set("X-Nakpanel-CSRF", csrfToken(req))
	}
}

func TestClientWorkspaceHidesAdminModulesAndUnknownSite(t *testing.T) {
	reader := &fakeDashboardReader{data: dashboard.Data{Sites: []dashboard.Site{{ID: 7, Domain: "owned.test", Status: "active", CustomerID: 88}}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DashboardReader: reader, SiteCreator: &fakeSiteCreator{}})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/dashboard", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /dashboard = %d", rec.Code)
	}
	for _, blocked := range []string{"Customers", "Service Plans", "Tools &amp; Settings"} {
		if strings.Contains(rec.Body.String(), blocked) {
			t.Fatalf("client dashboard exposed %q", blocked)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "https://panel.test/sites/999", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET cross-customer site = %d, want 404", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "https://panel.test/customers", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /customers as client = %d, want 403", rec.Code)
	}
}

func TestBrowserPostRequiresSessionBoundCSRFToken(t *testing.T) {
	handler, sessions := newTestHandler(t, auth.RoleAdmin)
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/logout", nil)
	req.Header.Set("Origin", "https://panel.test")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || sessions.deleted {
		t.Fatalf("POST without CSRF = %d deleted=%v, want 403 false", rec.Code, sessions.deleted)
	}

	req = httptest.NewRequest(http.MethodPost, "https://panel.test/logout", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || sessions.deleted {
		t.Fatalf("headerless POST without CSRF = %d deleted=%v, want 403 false", rec.Code, sessions.deleted)
	}

	tokenRequest := httptest.NewRequest(http.MethodGet, "https://panel.test/dashboard", nil)
	addAuthenticatedCookie(tokenRequest, cookie)
	form := url.Values{"csrf_token": {csrfToken(tokenRequest)}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Origin", "https://panel.test")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || !sessions.deleted {
		t.Fatalf("POST with CSRF = %d deleted=%v, want 303 true", rec.Code, sessions.deleted)
	}
}

func TestProviderBulkLifecycleRoutesUseSelectedObjects(t *testing.T) {
	quotaManager := &fakeQuotaManager{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleReseller, ServerOptions{QuotaManager: quotaManager})
	cookie := login(t, handler, "reseller@nakpanel.test", "NakpanelReseller!2026")
	tokenRequest := httptest.NewRequest(http.MethodGet, "https://panel.test/customers", nil)
	addAuthenticatedCookie(tokenRequest, cookie)

	form := url.Values{
		"csrf_token":  {csrfToken(tokenRequest)},
		"customer_id": {"77", "78"},
		"status":      {"suspended"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/customers/bulk-status", strings.NewReader(form.Encode()))
	req.Header.Set("Origin", "https://panel.test")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || !quotaManager.customerStatusCalled || !slices.Equal(quotaManager.bulkCustomerIDs, []int64{77, 78}) || quotaManager.customerStatus != "suspended" {
		t.Fatalf("bulk customers = %d manager=%#v", rec.Code, quotaManager)
	}

	form = url.Values{
		"csrf_token":      {csrfToken(tokenRequest)},
		"subscription_id": {"31"},
		"status":          {"active"},
	}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/subscriptions/bulk-status", strings.NewReader(form.Encode()))
	req.Header.Set("Origin", "https://panel.test")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || !slices.Equal(quotaManager.bulkSubscriptionIDs, []int64{31}) || quotaManager.customerStatus != "active" {
		t.Fatalf("bulk subscriptions = %d manager=%#v", rec.Code, quotaManager)
	}

	form = url.Values{"csrf_token": {csrfToken(tokenRequest)}, "plan_id": {"41", "42"}, "is_active": {"false"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/plans/bulk-status", strings.NewReader(form.Encode()))
	req.Header.Set("Origin", "https://panel.test")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || !slices.Equal(quotaManager.bulkPlanIDs, []int64{41, 42}) || quotaManager.active {
		t.Fatalf("bulk plans = %d manager=%#v", rec.Code, quotaManager)
	}

	form = url.Values{"csrf_token": {csrfToken(tokenRequest)}, "addon_id": {"51"}, "is_active": {"true"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/addons/bulk-status", strings.NewReader(form.Encode()))
	req.Header.Set("Origin", "https://panel.test")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || !slices.Equal(quotaManager.bulkAddonIDs, []int64{51}) {
		t.Fatalf("bulk add-ons = %d manager=%#v", rec.Code, quotaManager)
	}

	form = url.Values{"csrf_token": {csrfToken(tokenRequest)}, "reseller_plan_id": {"61"}, "is_active": {"true"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/reseller-plans/bulk-status", strings.NewReader(form.Encode()))
	req.Header.Set("Origin", "https://panel.test")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || len(quotaManager.bulkResellerPlanIDs) != 0 {
		t.Fatalf("reseller bulk reseller plans = %d manager=%#v", rec.Code, quotaManager)
	}
}

func TestResellerCanProvisionOnlyWithSelectedSubscription(t *testing.T) {
	creator := &fakeSiteCreator{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleReseller, ServerOptions{SiteCreator: creator})
	cookie := login(t, handler, "reseller@nakpanel.test", "NakpanelReseller!2026")

	form := url.Values{"subscription_id": {"21"}, "username": {"reseller-site"}, "domain": {"reseller.test"}, "php_version": {"8.3"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || len(creator.requests) != 1 || creator.requests[0].SubscriptionID != 21 {
		t.Fatalf("reseller site create = %d creator=%#v", rec.Code, creator)
	}

	creator.requests = nil
	form.Del("subscription_id")
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/sites", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || len(creator.requests) != 0 {
		t.Fatalf("reseller site create without subscription = %d requests=%d", rec.Code, len(creator.requests))
	}
}

func TestScopedSearchReturnsJSON(t *testing.T) {
	workspace := &fakeWorkspaceService{results: []types.SearchResult{{Kind: "site", ID: 7, Label: "owned.test", URL: "/sites/7"}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{Workspace: workspace})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/search?q=owned", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"url":"/sites/7"`) {
		t.Fatalf("GET /search = %d %s", rec.Code, rec.Body.String())
	}
	if workspace.actor.Role != auth.RoleClient || workspace.query != "owned" {
		t.Fatalf("search scope actor=%#v query=%q", workspace.actor, workspace.query)
	}
}

func TestOnboardingRetainsSubscriptionWhenInitialSiteFails(t *testing.T) {
	quotas := &fakeQuotaManager{}
	sites := &fakeSiteCreator{err: errors.New("agent unavailable")}
	workspace := &fakeWorkspaceService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{QuotaManager: quotas, SiteCreator: sites, Workspace: workspace})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	form := url.Values{"customer_mode": {"existing"}, "customer_id": {"88"}, "plan_id": {"10"}, "subscription_name": {"Owned hosting"}, "create_site": {"true"}, "domain": {"owned.test"}, "username": {"owned"}, "php_version": {"8.3"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/subscriptions/onboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/subscriptions/77?notice=subscription-site-warning" {
		t.Fatalf("onboard = %d Location %q; body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if !quotas.subCalled || len(sites.requests) != 1 {
		t.Fatalf("subscription called=%v site calls=%d", quotas.subCalled, len(sites.requests))
	}
	if len(workspace.audits) != 1 || workspace.audits[0].Action != "subscription.created" {
		t.Fatalf("audits = %#v", workspace.audits)
	}
}

func TestSupportViewFiltersCustomerInventory(t *testing.T) {
	reader := &fakeDashboardReader{data: dashboard.Data{
		Customers:     []types.Customer{{ID: 88, DisplayName: "Owned", Email: "owned@test", Status: "active"}, {ID: 99, DisplayName: "Other", Email: "other@test", Status: "active"}},
		Sites:         []dashboard.Site{{ID: 7, Domain: "owned.test", CustomerID: 88, Status: "active"}, {ID: 9, Domain: "other.test", CustomerID: 99, Status: "active"}},
		Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, SubscriptionName: "Owned sub", Status: "active"}, {ID: 30, CustomerID: 99, SubscriptionName: "Other sub", Status: "active"}},
	}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader, SiteCreator: &fakeSiteCreator{}})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/support/customers/88/sites", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Support view") || !strings.Contains(rec.Body.String(), "owned.test") || strings.Contains(rec.Body.String(), "other.test") {
		t.Fatalf("support inventory = %d\n%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `/support/customers/88/sites/7`) {
		t.Fatalf("support site link is not scoped:\n%s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "https://panel.test/support/customers/88/sites/9", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-customer support detail = %d, want 404", rec.Code)
	}
}

func login(t *testing.T, handler http.Handler, email string, password string) *http.Cookie {
	t.Helper()

	form := url.Values{
		"email":    {email},
		"password": {password},
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		body, _ := io.ReadAll(rec.Result().Body)
		t.Fatalf("POST /login status = %d, want 303; body=%q", rec.Code, string(body))
	}
	if location := rec.Header().Get("Location"); location != "/dashboard" {
		t.Fatalf("Location = %q, want /dashboard", location)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == SessionCookieName {
			return cookie
		}
	}
	t.Fatal("login did not set session cookie")
	return nil
}
