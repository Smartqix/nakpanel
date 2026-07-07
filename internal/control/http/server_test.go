package panelhttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
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
	owner          auth.SessionUser
	limits         controlquota.Limits
	plan           controlquota.Plan
	planID         int64
	active         bool
	customerUserID int64
	settings       controlquota.Settings
	err            error
	called         bool
	planCalled     bool
	statusCalled   bool
	subCalled      bool
	settingsCalled bool
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

func (m *fakeQuotaManager) AssignSubscription(ctx context.Context, owner auth.SessionUser, customerUserID int64, planID int64) (controlquota.SubscriptionAssignment, error) {
	m.owner = owner
	m.customerUserID = customerUserID
	m.planID = planID
	m.subCalled = true
	return controlquota.SubscriptionAssignment{SubscriptionID: 77, CustomerUserID: customerUserID, PlanID: planID}, m.err
}

func (m *fakeQuotaManager) UpdateSettings(ctx context.Context, owner auth.SessionUser, settings controlquota.Settings) error {
	m.owner = owner
	m.settings = settings
	m.settingsCalled = true
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

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
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
	if body := rec.Body.String(); !strings.Contains(body, "content:attr(data-label)") || !strings.Contains(body, ".np-table thead") || !strings.Contains(body, ".np-table-value") {
		t.Fatalf("embedded stylesheet missing responsive table-card rules:\n%s", body)
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
	if strings.Contains(rec.Body.String(), "app.css") {
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != test.want {
				t.Fatalf("%s %s status = %d, want %d; body:\n%s", test.method, test.target, rec.Code, test.want, rec.Body.String())
			}
			if body := rec.Body.String(); strings.Contains(body, "--np-bg") || strings.Contains(body, ".np-app") {
				t.Fatalf("%s %s exposed stylesheet body:\n%s", test.method, test.target, body)
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

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
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

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
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

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?notice=job-retried", nil)
	req.AddCookie(cookie)
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

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/?notice=job-retried", nil)
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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
			req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
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
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("POST %s status = %d, want 403", target, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/db", nil)
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
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
			Settings:        controlquota.Settings{OversellPolicy: controlquota.OversellPolicyWarn, ServerDiskCapacityMB: 10000},
			CommittedDiskMB: 5120,
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{
		DashboardReader: reader,
		QuotaManager:    &fakeQuotaManager{},
	})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Plans & subscriptions",
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

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /settings/oversell status = %d, want 303; body:\n%s", rec.Code, rec.Body.String())
	}
	if !manager.settingsCalled || manager.settings.OversellPolicy != controlquota.OversellPolicyCap || manager.settings.ServerDiskCapacityMB != 50000 {
		t.Fatalf("settings call = called:%v settings:%#v", manager.settingsCalled, manager.settings)
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
		req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
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

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
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

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "admin-only.test") {
		t.Fatalf("client dashboard leaked admin inventory:\n%s", rec.Body.String())
	}
}

func TestClientUsesSameURLAndSeesClientDashboard(t *testing.T) {
	handler, _ := newTestHandler(t, auth.RoleClient)
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
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

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
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
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
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
	req.AddCookie(cookie)
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

	req = httptest.NewRequest(http.MethodGet, "https://panel.test/", nil)
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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

func TestClientCannotCreateSite(t *testing.T) {
	creator := &fakeSiteCreator{}
	handler, _ := newTestHandlerWithSiteCreator(t, auth.RoleClient, creator)
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")

	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites", strings.NewReader("username=npdemo&domain=example.test&php_version=8.3"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
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
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /certificates status = %d, want 403", rec.Code)
	}
	if issuer.domain != "" {
		t.Fatalf("client issue invoked certificate issuer: %#v", issuer)
	}
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
	if location := rec.Header().Get("Location"); location != "/" {
		t.Fatalf("Location = %q, want /", location)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == SessionCookieName {
			return cookie
		}
	}
	t.Fatal("login did not set session cookie")
	return nil
}
