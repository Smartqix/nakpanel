package panelhttp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/a-h/templ"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/web"
	"github.com/nakroteck/nakpanel/internal/types"
)

const SessionCookieName = "nakpanel_session"

type UserStore interface {
	FindUserByEmail(ctx context.Context, email string) (auth.User, error)
}

type SiteCreator interface {
	CreateSiteFor(ctx context.Context, owner auth.SessionUser, resourceOwnerID int64, req types.CreateSiteReq) (int64, error)
}

type DatabaseCreator interface {
	CreateDatabaseFor(ctx context.Context, owner auth.SessionUser, resourceOwnerID int64, req types.CreateDatabaseReq) (int64, error)
}

type CertificateIssuer interface {
	IssueCertificate(ctx context.Context, owner auth.SessionUser, domain string, issuer types.CertIssuer) (int64, error)
}

type DashboardReader interface {
	GetDashboard(ctx context.Context, owner auth.SessionUser) (dashboard.Data, error)
}

type JobRetrier interface {
	RetryProvisioningJob(ctx context.Context, jobID int64) error
}

type Phase6Manager interface {
	CreateBackupFor(ctx context.Context, owner auth.SessionUser, resourceOwnerID int64, req types.CreateBackupReq) (int64, error)
	RestoreBackup(ctx context.Context, owner auth.SessionUser, backupID int64) (int64, error)
	ConfigureWebmail(ctx context.Context, owner auth.SessionUser, domain string) (int64, error)
	ConfigureDNS(ctx context.Context, owner auth.SessionUser, domain string, address string) (int64, error)
	ReconcileSystem(ctx context.Context, owner auth.SessionUser) (int64, error)
	CreateAdminerToken(ctx context.Context, owner auth.SessionUser) (types.AdminerSSO, error)
}

type QuotaManager interface {
	UpsertAccountQuota(ctx context.Context, owner auth.SessionUser, limits controlquota.Limits) error
	UpsertPlan(ctx context.Context, owner auth.SessionUser, plan controlquota.Plan) (controlquota.Plan, error)
	SetPlanActive(ctx context.Context, owner auth.SessionUser, planID int64, active bool) error
	AssignSubscription(ctx context.Context, owner auth.SessionUser, customerUserID int64, planID int64) (controlquota.SubscriptionAssignment, error)
	CreateCustomer(ctx context.Context, owner auth.SessionUser, req types.CreateCustomerReq) (types.Customer, error)
	EnableCustomerLogin(ctx context.Context, owner auth.SessionUser, customerID int64, email string, password string) (types.Customer, error)
	SetCustomerStatus(ctx context.Context, owner auth.SessionUser, customerID int64, status string) error
	CreateSubscription(ctx context.Context, owner auth.SessionUser, req types.CreateSubscriptionReq) (types.SubscriptionSummary, error)
	UpdateSettings(ctx context.Context, owner auth.SessionUser, settings controlquota.Settings) error
}

type ServerOptions struct {
	SiteCreator       SiteCreator
	DatabaseCreator   DatabaseCreator
	CertificateIssuer CertificateIssuer
	DashboardReader   DashboardReader
	JobRetrier        JobRetrier
	Phase6Manager     Phase6Manager
	QuotaManager      QuotaManager
}

type Server struct {
	users        UserStore
	sessions     *auth.SessionManager
	sites        SiteCreator
	databases    DatabaseCreator
	certificates CertificateIssuer
	dashboard    DashboardReader
	jobs         JobRetrier
	phase6       Phase6Manager
	quotas       QuotaManager
}

func NewServer(users UserStore, sessions *auth.SessionManager, options ...ServerOptions) *Server {
	var opts ServerOptions
	if len(options) > 0 {
		opts = options[0]
	}
	return &Server{
		users:        users,
		sessions:     sessions,
		sites:        opts.SiteCreator,
		databases:    opts.DatabaseCreator,
		certificates: opts.CertificateIssuer,
		dashboard:    opts.DashboardReader,
		jobs:         opts.JobRetrier,
		phase6:       opts.Phase6Manager,
		quotas:       opts.QuotaManager,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", web.StaticHandler()))
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("POST /sites", s.handleCreateSite)
	mux.HandleFunc("POST /databases", s.handleCreateDatabase)
	mux.HandleFunc("POST /certificates", s.handleIssueCertificate)
	mux.HandleFunc("POST /jobs/retry", s.handleRetryJob)
	mux.HandleFunc("POST /backups", s.handleCreateBackup)
	mux.HandleFunc("POST /restores", s.handleRestoreBackup)
	mux.HandleFunc("POST /webmail", s.handleConfigureWebmail)
	mux.HandleFunc("POST /dns", s.handleConfigureDNS)
	mux.HandleFunc("POST /reconcile", s.handleReconcileSystem)
	mux.HandleFunc("POST /quotas", s.handleUpsertQuota)
	mux.HandleFunc("POST /customers", s.handleCreateCustomer)
	mux.HandleFunc("POST /customers/login", s.handleEnableCustomerLogin)
	mux.HandleFunc("POST /customers/status", s.handleSetCustomerStatus)
	mux.HandleFunc("POST /plans", s.handleUpsertPlan)
	mux.HandleFunc("POST /plans/status", s.handleSetPlanStatus)
	mux.HandleFunc("POST /subscriptions", s.handleAssignSubscription)
	mux.HandleFunc("POST /settings/oversell", s.handleUpdateOversellSettings)
	mux.HandleFunc("GET /db", s.handleAdminer)
	mux.HandleFunc("GET /", s.handleDashboard)
	return sameOriginPostGuard(mux)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, web.LoginPage())
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid login form", http.StatusBadRequest)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.Form.Get("email")))
	password := r.Form.Get("password")
	user, err := s.users.FindUserByEmail(r.Context(), email)
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	if !user.Role.Valid() {
		http.Error(w, "Invalid account role", http.StatusInternalServerError)
		return
	}

	ok, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil || !ok {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	token, expiresAt, err := s.sessions.Create(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "Could not create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	title := dashboardTitle(user.Role)
	if title == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	data := dashboard.Data{}
	if s.dashboard != nil {
		var err error
		data, err = s.dashboard.GetDashboard(r.Context(), user)
		if err != nil {
			http.Error(w, "Could not load dashboard", http.StatusInternalServerError)
			return
		}
	}
	if user.Role == auth.RoleAdmin {
		data.Notice = dashboardNotice(r.URL.Query().Get("notice"))
	}

	renderPage(w, r, web.DashboardPage(title, user, data, web.DashboardActions{
		CanCreateSite:       s.sites != nil,
		CanCreateDatabase:   s.databases != nil,
		CanIssueCertificate: s.certificates != nil,
		CanRetryJob:         s.jobs != nil,
		CanUsePhase6:        s.phase6 != nil,
		CanManageQuotas:     s.quotas != nil,
	}))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		_ = s.sessions.Delete(r.Context(), cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role != auth.RoleAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if s.sites == nil {
		if wantsSPAJSON(r) {
			writeSPAError(w, http.StatusServiceUnavailable, "Site provisioning is not configured")
			return
		}
		http.Error(w, "Site provisioning is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		if wantsSPAJSON(r) {
			writeSPAError(w, http.StatusBadRequest, "Invalid site form")
			return
		}
		http.Error(w, "Invalid site form", http.StatusBadRequest)
		return
	}

	req := types.CreateSiteReq{
		SubscriptionID: parseFormInt64Default(r, "subscription_id", 0),
		Username:       strings.ToLower(strings.TrimSpace(r.Form.Get("username"))),
		Domain:         strings.ToLower(strings.TrimSpace(r.Form.Get("domain"))),
		PHPVersion:     strings.TrimSpace(r.Form.Get("php_version")),
	}
	resourceOwnerID, err := parseOptionalOwnerID(r, user.ID)
	if err != nil {
		if wantsSPAJSON(r) {
			writeSPAError(w, http.StatusBadRequest, "Invalid site form: "+err.Error())
			return
		}
		http.Error(w, "Invalid site form: "+err.Error(), http.StatusBadRequest)
		return
	}
	siteID, err := s.sites.CreateSiteFor(r.Context(), user, resourceOwnerID, req)
	if err != nil {
		if wantsSPAJSON(r) {
			writeSPAError(w, http.StatusBadRequest, "Could not create site: "+err.Error())
			return
		}
		http.Error(w, "Could not create site: "+err.Error(), http.StatusBadRequest)
		return
	}
	if wantsSPAJSON(r) {
		writeSPAJSON(w, http.StatusAccepted, map[string]any{
			"ok":       true,
			"site_id":  siteID,
			"redirect": "/",
			"notice":   "Site provisioning queued.",
		})
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role != auth.RoleAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if s.databases == nil {
		http.Error(w, "Database provisioning is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid database form", http.StatusBadRequest)
		return
	}

	engine := strings.TrimSpace(r.Form.Get("engine"))
	if engine == "" {
		engine = string(types.EngineMariaDB)
	}
	req := types.CreateDatabaseReq{
		SubscriptionID: parseFormInt64Default(r, "subscription_id", 0),
		Engine:         types.DBEngine(engine),
		DBName:         strings.ToLower(strings.TrimSpace(r.Form.Get("db_name"))),
		DBUser:         strings.ToLower(strings.TrimSpace(r.Form.Get("db_user"))),
	}
	resourceOwnerID, err := parseOptionalOwnerID(r, user.ID)
	if err != nil {
		http.Error(w, "Invalid database form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := s.databases.CreateDatabaseFor(r.Context(), user, resourceOwnerID, req); err != nil {
		http.Error(w, "Could not create database: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleIssueCertificate(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role != auth.RoleAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if s.certificates == nil {
		http.Error(w, "Certificate provisioning is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid certificate form", http.StatusBadRequest)
		return
	}

	issuer := types.CertIssuer(strings.TrimSpace(r.Form.Get("issuer")))
	if issuer == "" {
		issuer = types.CertIssuerLocalSelfSigned
	}
	if _, err := s.certificates.IssueCertificate(r.Context(), user, strings.TrimSpace(r.Form.Get("domain")), issuer); err != nil {
		http.Error(w, "Could not issue certificate: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleRetryJob(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role != auth.RoleAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if s.jobs == nil {
		http.Error(w, "Job recovery is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid job retry form", http.StatusBadRequest)
		return
	}

	jobID, err := strconv.ParseInt(strings.TrimSpace(r.Form.Get("job_id")), 10, 64)
	if err != nil || jobID <= 0 {
		http.Error(w, "Invalid job id", http.StatusBadRequest)
		return
	}
	if err := s.jobs.RetryProvisioningJob(r.Context(), jobID); err != nil {
		http.Error(w, "Could not retry job: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?notice=job-retried", http.StatusSeeOther)
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.phase6 == nil {
		http.Error(w, "Phase 6 operations are not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid backup form", http.StatusBadRequest)
		return
	}
	req := types.CreateBackupReq{
		SubscriptionID: parseFormInt64Default(r, "subscription_id", 0),
		Domain:         strings.TrimSpace(r.Form.Get("domain")),
	}
	resourceOwnerID, err := parseOptionalOwnerID(r, user.ID)
	if err != nil {
		http.Error(w, "Invalid backup form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := s.phase6.CreateBackupFor(r.Context(), user, resourceOwnerID, req); err != nil {
		http.Error(w, "Could not create backup: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?notice=backup-queued", http.StatusSeeOther)
}

func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.phase6 == nil {
		http.Error(w, "Phase 6 operations are not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid restore form", http.StatusBadRequest)
		return
	}
	backupID, err := strconv.ParseInt(strings.TrimSpace(r.Form.Get("backup_id")), 10, 64)
	if err != nil || backupID <= 0 {
		http.Error(w, "Invalid backup id", http.StatusBadRequest)
		return
	}
	if _, err := s.phase6.RestoreBackup(r.Context(), user, backupID); err != nil {
		http.Error(w, "Could not restore backup: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?notice=restore-queued", http.StatusSeeOther)
}

func (s *Server) handleConfigureWebmail(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.phase6 == nil {
		http.Error(w, "Phase 6 operations are not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid webmail form", http.StatusBadRequest)
		return
	}
	if _, err := s.phase6.ConfigureWebmail(r.Context(), user, strings.TrimSpace(r.Form.Get("domain"))); err != nil {
		http.Error(w, "Could not configure webmail: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?notice=webmail-queued", http.StatusSeeOther)
}

func (s *Server) handleConfigureDNS(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.phase6 == nil {
		http.Error(w, "Phase 6 operations are not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid dns form", http.StatusBadRequest)
		return
	}
	if _, err := s.phase6.ConfigureDNS(r.Context(), user, strings.TrimSpace(r.Form.Get("domain")), strings.TrimSpace(r.Form.Get("address"))); err != nil {
		http.Error(w, "Could not configure dns: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?notice=dns-queued", http.StatusSeeOther)
}

func (s *Server) handleReconcileSystem(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.phase6 == nil {
		http.Error(w, "Phase 6 operations are not configured", http.StatusServiceUnavailable)
		return
	}
	if _, err := s.phase6.ReconcileSystem(r.Context(), user); err != nil {
		http.Error(w, "Could not reconcile system: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?notice=reconcile-queued", http.StatusSeeOther)
}

func (s *Server) handleAdminer(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.phase6 == nil {
		http.Error(w, "Phase 6 operations are not configured", http.StatusServiceUnavailable)
		return
	}
	token, err := s.phase6.CreateAdminerToken(r.Context(), user)
	if err != nil {
		http.Error(w, "Could not create Adminer token: "+err.Error(), http.StatusBadRequest)
		return
	}
	renderPage(w, r, web.AdminerPage(token))
}

func (s *Server) handleUpsertQuota(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.quotas == nil {
		http.Error(w, "Quota management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid quota form", http.StatusBadRequest)
		return
	}
	limits, err := parseQuotaLimits(r)
	if err != nil {
		http.Error(w, "Invalid quota form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.quotas.UpsertAccountQuota(r.Context(), user, limits); err != nil {
		http.Error(w, "Could not save quota: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?notice=quota-saved", http.StatusSeeOther)
}

func (s *Server) handleUpsertPlan(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.quotas == nil {
		http.Error(w, "Plan management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid plan form", http.StatusBadRequest)
		return
	}
	plan, err := parsePlan(r)
	if err != nil {
		http.Error(w, "Invalid plan form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := s.quotas.UpsertPlan(r.Context(), user, plan); err != nil {
		http.Error(w, "Could not save plan: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?notice=plan-saved", http.StatusSeeOther)
}

func (s *Server) handleSetPlanStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.quotas == nil {
		http.Error(w, "Plan management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid plan status form", http.StatusBadRequest)
		return
	}
	planID, err := parseFormInt64(r, "plan_id")
	if err != nil {
		http.Error(w, "Invalid plan status form: "+err.Error(), http.StatusBadRequest)
		return
	}
	active := strings.TrimSpace(r.Form.Get("is_active")) == "true"
	if err := s.quotas.SetPlanActive(r.Context(), user, planID, active); err != nil {
		http.Error(w, "Could not update plan status: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?notice=plan-status-saved", http.StatusSeeOther)
}

func (s *Server) handleAssignSubscription(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.quotas == nil {
		http.Error(w, "Subscription management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid subscription form", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(r.Form.Get("customer_id")) != "" || strings.TrimSpace(r.Form.Get("customer_mode")) == "new" || strings.TrimSpace(r.Form.Get("subscription_name")) != "" {
		req, err := s.parseCreateSubscriptionRequest(r, user)
		if err != nil {
			http.Error(w, "Invalid subscription form: "+err.Error(), http.StatusBadRequest)
			return
		}
		subscription, err := s.quotas.CreateSubscription(r.Context(), user, req)
		if err != nil {
			http.Error(w, "Could not save subscription: "+err.Error(), http.StatusBadRequest)
			return
		}
		if subscription.Warning != "" {
			http.Redirect(w, r, "/?notice=subscription-warning", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/?notice=subscription-saved", http.StatusSeeOther)
		return
	}
	customerUserID, err := parseFormInt64(r, "customer_user_id")
	if err != nil {
		http.Error(w, "Invalid subscription form: "+err.Error(), http.StatusBadRequest)
		return
	}
	planID, err := parseFormInt64(r, "plan_id")
	if err != nil {
		http.Error(w, "Invalid subscription form: "+err.Error(), http.StatusBadRequest)
		return
	}
	assignment, err := s.quotas.AssignSubscription(r.Context(), user, customerUserID, planID)
	if err != nil {
		http.Error(w, "Could not assign subscription: "+err.Error(), http.StatusBadRequest)
		return
	}
	if assignment.Warning != "" {
		http.Redirect(w, r, "/?notice=subscription-warning", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?notice=subscription-saved", http.StatusSeeOther)
}

func (s *Server) handleCreateCustomer(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.quotas == nil {
		http.Error(w, "Customer management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid customer form", http.StatusBadRequest)
		return
	}
	req := parseCustomerRequest(r)
	if _, err := s.quotas.CreateCustomer(r.Context(), user, req); err != nil {
		http.Error(w, "Could not create customer: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?notice=customer-saved", http.StatusSeeOther)
}

func (s *Server) handleEnableCustomerLogin(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.quotas == nil {
		http.Error(w, "Customer management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid customer login form", http.StatusBadRequest)
		return
	}
	customerID, err := parseFormInt64(r, "customer_id")
	if err != nil {
		http.Error(w, "Invalid customer login form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := s.quotas.EnableCustomerLogin(r.Context(), user, customerID, strings.TrimSpace(r.Form.Get("email")), r.Form.Get("password")); err != nil {
		http.Error(w, "Could not enable customer login: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?notice=customer-login-saved", http.StatusSeeOther)
}

func (s *Server) handleSetCustomerStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.quotas == nil {
		http.Error(w, "Customer management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid customer status form", http.StatusBadRequest)
		return
	}
	customerID, err := parseFormInt64(r, "customer_id")
	if err != nil {
		http.Error(w, "Invalid customer status form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.quotas.SetCustomerStatus(r.Context(), user, customerID, strings.TrimSpace(r.Form.Get("status"))); err != nil {
		http.Error(w, "Could not update customer status: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?notice=customer-status-saved", http.StatusSeeOther)
}

func (s *Server) handleUpdateOversellSettings(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.quotas == nil {
		http.Error(w, "Settings management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid oversell settings form", http.StatusBadRequest)
		return
	}
	capacity, err := parseFormInt(r, "server_disk_capacity_mb")
	if err != nil {
		http.Error(w, "Invalid oversell settings form: "+err.Error(), http.StatusBadRequest)
		return
	}
	settings := controlquota.Settings{
		OversellPolicy:       strings.TrimSpace(r.Form.Get("oversell_policy")),
		ServerDiskCapacityMB: capacity,
	}
	if err := s.quotas.UpdateSettings(r.Context(), user, settings); err != nil {
		http.Error(w, "Could not update oversell settings: "+err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?notice=settings-saved", http.StatusSeeOther)
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (auth.SessionUser, bool) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return auth.SessionUser{}, false
	}
	if user.Role != auth.RoleAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return auth.SessionUser{}, false
	}
	return user, true
}

func (s *Server) currentUser(w http.ResponseWriter, r *http.Request) (auth.SessionUser, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return auth.SessionUser{}, false
	}

	user, err := s.sessions.Authenticate(r.Context(), cookie.Value)
	if err != nil {
		clearSessionCookie(w)
		return auth.SessionUser{}, false
	}

	return user, true
}

func sameOriginPostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && !isSameOriginPost(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSameOriginPost(r *http.Request) bool {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		return sameOriginHeader(origin, r)
	}
	if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" {
		return sameOriginHeader(referer, r)
	}
	return true
}

func sameOriginHeader(value string, r *http.Request) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	if !strings.EqualFold(parsed.Host, r.Host) {
		return false
	}
	if r.TLS != nil && parsed.Scheme != "https" {
		return false
	}
	if r.TLS == nil && parsed.Scheme != "http" {
		return false
	}
	return true
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func dashboardNotice(code string) string {
	switch code {
	case "job-retried":
		return "Retry queued. Refresh in a moment to see the updated status."
	case "backup-queued":
		return "Backup queued. Refresh in a moment to see the updated status."
	case "restore-queued":
		return "Restore queued. Refresh in a moment to see the updated status."
	case "webmail-queued":
		return "Webmail configuration queued."
	case "dns-queued":
		return "DNS zone configuration queued."
	case "reconcile-queued":
		return "Reconciliation queued. Generated configs will be refreshed from intent."
	case "quota-saved":
		return "Account quota saved."
	case "plan-saved":
		return "Plan saved."
	case "plan-status-saved":
		return "Plan status updated."
	case "subscription-saved":
		return "Subscription assigned."
	case "subscription-warning":
		return "Subscription assigned with an oversell warning."
	case "customer-saved":
		return "Customer saved."
	case "customer-login-saved":
		return "Customer login saved."
	case "customer-status-saved":
		return "Customer status updated."
	case "settings-saved":
		return "Oversell settings saved."
	default:
		return ""
	}
}

func dashboardTitle(role auth.Role) string {
	switch role {
	case auth.RoleAdmin:
		return "Admin dashboard"
	case auth.RoleReseller:
		return "Reseller dashboard"
	case auth.RoleClient:
		return "Client dashboard"
	default:
		return ""
	}
}

func renderPage(w http.ResponseWriter, r *http.Request, component templ.Component) {
	var body bytes.Buffer
	if err := component.Render(r.Context(), &body); err != nil {
		http.Error(w, "Could not render page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = body.WriteTo(w)
}

func wantsSPAJSON(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Nakpanel-SPA")), "true")
}

func writeSPAError(w http.ResponseWriter, status int, message string) {
	writeSPAJSON(w, status, map[string]any{
		"ok":    false,
		"error": message,
	})
}

func writeSPAJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func parseQuotaLimits(r *http.Request) (controlquota.Limits, error) {
	userID, err := parseFormInt64(r, "user_id")
	if err != nil {
		return controlquota.Limits{}, err
	}
	limits := controlquota.Limits{UserID: userID}
	fields := []struct {
		name   string
		target *int
	}{
		{name: "max_sites", target: &limits.MaxSites},
		{name: "max_databases", target: &limits.MaxDatabases},
		{name: "storage_mb", target: &limits.StorageMB},
		{name: "max_backups", target: &limits.MaxBackups},
		{name: "backup_storage_mb", target: &limits.BackupStorageMB},
		{name: "site_disk_quota_mb", target: &limits.SiteDiskQuotaMB},
		{name: "php_max_children", target: &limits.PHPFPMMaxChildren},
		{name: "php_memory_mb", target: &limits.PHPMemoryMB},
	}
	for _, field := range fields {
		value, err := parseFormInt(r, field.name)
		if err != nil {
			return controlquota.Limits{}, err
		}
		*field.target = value
	}
	return limits, nil
}

func parsePlan(r *http.Request) (controlquota.Plan, error) {
	planID, err := parseOptionalFormInt64(r, "plan_id")
	if err != nil {
		return controlquota.Plan{}, err
	}
	priceCents, err := parseOptionalSQLInt64(r, "price_cents")
	if err != nil {
		return controlquota.Plan{}, err
	}
	plan := controlquota.Plan{
		ID:           planID,
		Name:         strings.TrimSpace(r.Form.Get("name")),
		Description:  strings.TrimSpace(r.Form.Get("description")),
		PriceCents:   priceCents,
		AllowSSH:     parseFormBool(r, "allow_ssh"),
		AllowDNS:     parseFormBool(r, "allow_dns"),
		PHPAllowlist: strings.TrimSpace(r.Form.Get("php_allowlist")),
		IsActive:     parseFormBool(r, "is_active"),
	}
	fields := []struct {
		name   string
		target *int
	}{
		{name: "disk_mb", target: &plan.DiskMB},
		{name: "max_sites", target: &plan.MaxSites},
		{name: "max_databases", target: &plan.MaxDatabases},
		{name: "bandwidth_mb", target: &plan.BandwidthMB},
		{name: "max_mailboxes", target: &plan.MaxMailboxes},
		{name: "backup_retention_days", target: &plan.BackupRetentionDays},
		{name: "php_max_children", target: &plan.PHPFPMMaxChildren},
		{name: "php_memory_mb", target: &plan.PHPMemoryMB},
		{name: "site_disk_quota_mb", target: &plan.SiteDiskQuotaMB},
		{name: "max_backups", target: &plan.MaxBackups},
		{name: "backup_storage_mb", target: &plan.BackupStorageMB},
	}
	for _, field := range fields {
		value, err := parseFormIntAllowUnlimited(r, field.name)
		if err != nil {
			return controlquota.Plan{}, err
		}
		*field.target = value
	}
	return plan, nil
}

func (s *Server) parseCreateSubscriptionRequest(r *http.Request, owner auth.SessionUser) (types.CreateSubscriptionReq, error) {
	var customerID int64
	var err error
	if strings.TrimSpace(r.Form.Get("customer_mode")) == "new" {
		customer, err := s.quotas.CreateCustomer(r.Context(), owner, parseCustomerRequest(r))
		if err != nil {
			return types.CreateSubscriptionReq{}, err
		}
		customerID = customer.ID
	} else {
		customerID, err = parseFormInt64(r, "customer_id")
		if err != nil {
			return types.CreateSubscriptionReq{}, err
		}
	}
	planID, err := parseFormInt64(r, "plan_id")
	if err != nil {
		return types.CreateSubscriptionReq{}, err
	}
	subscriptionID, err := parseOptionalFormInt64(r, "subscription_id")
	if err != nil {
		return types.CreateSubscriptionReq{}, err
	}
	status := strings.TrimSpace(r.Form.Get("status"))
	if status == "" {
		status = "active"
	}
	return types.CreateSubscriptionReq{
		ID:               subscriptionID,
		CustomerID:       customerID,
		PlanID:           planID,
		SubscriptionName: strings.TrimSpace(r.Form.Get("subscription_name")),
		Status:           status,
	}, nil
}

func parseCustomerRequest(r *http.Request) types.CreateCustomerReq {
	return types.CreateCustomerReq{
		Email:       strings.TrimSpace(firstNonEmpty(r.Form.Get("customer_email"), r.Form.Get("email"))),
		DisplayName: strings.TrimSpace(firstNonEmpty(r.Form.Get("customer_name"), r.Form.Get("display_name"))),
		Company:     strings.TrimSpace(r.Form.Get("company")),
		Notes:       strings.TrimSpace(r.Form.Get("notes")),
		EnableLogin: parseFormBool(r, "enable_login"),
		Password:    r.Form.Get("password"),
	}
}

func parseOptionalOwnerID(r *http.Request, fallback int64) (int64, error) {
	value := strings.TrimSpace(r.Form.Get("owner_user_id"))
	if value == "" {
		value = strings.TrimSpace(r.Form.Get("customer_user_id"))
	}
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, errors.New("owner_user_id is required")
	}
	return parsed, nil
}

func parseFormInt64Default(r *http.Request, name string, fallback int64) int64 {
	raw := strings.TrimSpace(r.Form.Get(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func parseFormInt64(r *http.Request, name string) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(r.Form.Get(name)), 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func parseOptionalFormInt64(r *http.Request, name string) (int64, error) {
	raw := strings.TrimSpace(r.Form.Get(name))
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", name)
	}
	return value, nil
}

func parseFormInt(r *http.Request, name string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(r.Form.Get(name)))
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", name)
	}
	return value, nil
}

func parseFormIntAllowUnlimited(r *http.Request, name string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(r.Form.Get(name)))
	if err != nil || value < -1 {
		return 0, fmt.Errorf("%s must be -1 or a non-negative integer", name)
	}
	return value, nil
}

func parseOptionalSQLInt64(r *http.Request, name string) (sql.NullInt64, error) {
	raw := strings.TrimSpace(r.Form.Get(name))
	if raw == "" {
		return sql.NullInt64{}, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return sql.NullInt64{}, fmt.Errorf("%s must be a non-negative integer", name)
	}
	return sql.NullInt64{Int64: value, Valid: true}, nil
}

func parseFormBool(r *http.Request, name string) bool {
	value := strings.ToLower(strings.TrimSpace(r.Form.Get(name)))
	return value == "true" || value == "on" || value == "1" || value == "yes"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
