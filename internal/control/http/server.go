package panelhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/a-h/templ"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlfiles "github.com/nakroteck/nakpanel/internal/control/filemanager"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/web"
	"github.com/nakroteck/nakpanel/internal/types"
)

const (
	SessionCookieName = "nakpanel_session"
	maxFormBodyBytes  = 1 << 20
)

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
	SetPlanStatuses(ctx context.Context, owner auth.SessionUser, planIDs []int64, active bool) error
	AssignSubscription(ctx context.Context, owner auth.SessionUser, customerUserID int64, planID int64) (controlquota.SubscriptionAssignment, error)
	CreateCustomer(ctx context.Context, owner auth.SessionUser, req types.CreateCustomerReq) (types.Customer, error)
	EnableCustomerLogin(ctx context.Context, owner auth.SessionUser, customerID int64, email string, password string) (types.Customer, error)
	SetCustomerStatus(ctx context.Context, owner auth.SessionUser, customerID int64, status string) error
	SetCustomerStatuses(ctx context.Context, owner auth.SessionUser, customerIDs []int64, status string) error
	SetSubscriptionStatus(ctx context.Context, owner auth.SessionUser, subscriptionID int64, status string) error
	SetSubscriptionStatuses(ctx context.Context, owner auth.SessionUser, subscriptionIDs []int64, status string) error
	CreateSubscription(ctx context.Context, owner auth.SessionUser, req types.CreateSubscriptionReq) (types.SubscriptionSummary, error)
	UpdateSettings(ctx context.Context, owner auth.SessionUser, settings controlquota.Settings) error
	CreateReseller(ctx context.Context, owner auth.SessionUser, req types.CreateCustomerReq, planID int64) (types.Reseller, error)
	SetResellerStatus(ctx context.Context, owner auth.SessionUser, resellerID int64, status string) error
	SetResellerStatuses(ctx context.Context, owner auth.SessionUser, resellerIDs []int64, status string) error
	UpsertResellerPlan(ctx context.Context, owner auth.SessionUser, plan types.ResellerPlan) (types.ResellerPlan, error)
	SetResellerPlanStatuses(ctx context.Context, owner auth.SessionUser, planIDs []int64, active bool) error
	TransferCustomer(ctx context.Context, owner auth.SessionUser, customerID, resellerID int64) error
	UpsertAddonPlan(ctx context.Context, owner auth.SessionUser, addon types.AddonPlan) (types.AddonPlan, error)
	SetAddonPlanStatuses(ctx context.Context, owner auth.SessionUser, addonIDs []int64, active bool) error
	SetSubscriptionAddons(ctx context.Context, owner auth.SessionUser, subscriptionID int64, addonIDs []int64) error
	SyncSubscription(ctx context.Context, owner auth.SessionUser, subscriptionID int64) error
	SetSubscriptionMode(ctx context.Context, owner auth.SessionUser, subscriptionID int64, mode string, custom types.SubscriptionEntitlements) error
}

type DomainManager interface {
	UpdateSiteSettings(ctx context.Context, owner auth.SessionUser, req types.UpdateSiteSettingsReq) error
	SetTLSAutoRenew(ctx context.Context, owner auth.SessionUser, siteID int64, enabled bool) error
	UpsertDNSRecord(ctx context.Context, owner auth.SessionUser, siteID int64, record types.DNSRecord) error
	DeleteDNSRecord(ctx context.Context, owner auth.SessionUser, siteID, recordID int64) error
	ChangeSubscriptionPlans(ctx context.Context, owner auth.SessionUser, subscriptionIDs []int64, planID int64) error
	ChangeSubscriptionSubscriber(ctx context.Context, owner auth.SessionUser, subscriptionIDs []int64, customerID int64) error
}

type WorkspaceService interface {
	Search(ctx context.Context, actor auth.SessionUser, query string, limit int) ([]types.SearchResult, error)
	RecordAudit(ctx context.Context, event types.AuditEvent) error
	CustomerIDForSubscription(ctx context.Context, subscriptionID int64) (int64, error)
	CustomerIDForDomain(ctx context.Context, domain string) (int64, error)
	CustomerIDForBackup(ctx context.Context, backupID int64) (int64, error)
}

type FileManagerService interface {
	UploadMaxBytes() int64
	Site(context.Context, auth.SessionUser, int64) (controlfiles.Site, error)
	List(context.Context, auth.SessionUser, int64, types.FileListReq) (controlfiles.Site, types.FileListResult, error)
	Search(context.Context, auth.SessionUser, int64, types.FileSearchReq) (controlfiles.Site, types.FileSearchResult, error)
	Read(context.Context, auth.SessionUser, int64, string) (controlfiles.Site, types.FileReadResult, error)
	Write(context.Context, auth.SessionUser, int64, types.FileWriteReq) (types.FileMutationResult, error)
	Create(context.Context, auth.SessionUser, int64, types.FileCreateReq) (types.FileMutationResult, error)
	Copy(context.Context, auth.SessionUser, int64, types.FileBatchReq) (types.FileMutationResult, error)
	Move(context.Context, auth.SessionUser, int64, types.FileBatchReq) (types.FileMutationResult, error)
	Delete(context.Context, auth.SessionUser, int64, types.FileBatchReq) (types.FileMutationResult, error)
	Archive(context.Context, auth.SessionUser, int64, types.FileArchiveReq) (types.FileMutationResult, error)
	Extract(context.Context, auth.SessionUser, int64, types.FileExtractReq) (types.FileMutationResult, error)
	Chmod(context.Context, auth.SessionUser, int64, types.FileModeReq) (types.FileMutationResult, error)
	StageUpload(context.Context, io.Reader) (string, int64, error)
	Import(context.Context, auth.SessionUser, int64, string, string, bool, int64) (types.FileMutationResult, error)
	Download(context.Context, auth.SessionUser, int64, string) (controlfiles.Site, types.FileTransferResult, string, error)
	CleanupTransfer(string)
}

type ServerOptions struct {
	SiteCreator       SiteCreator
	DatabaseCreator   DatabaseCreator
	CertificateIssuer CertificateIssuer
	DashboardReader   DashboardReader
	JobRetrier        JobRetrier
	Phase6Manager     Phase6Manager
	QuotaManager      QuotaManager
	Workspace         WorkspaceService
	DomainManager     DomainManager
	FileManager       FileManagerService
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
	workspace    WorkspaceService
	domains      DomainManager
	files        FileManagerService
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
		workspace:    opts.Workspace,
		domains:      opts.DomainManager,
		files:        opts.FileManager,
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
	mux.HandleFunc("POST /customers/bulk-status", s.handleBulkCustomerStatus)
	mux.HandleFunc("POST /plans", s.handleUpsertPlan)
	mux.HandleFunc("POST /plans/preview", s.handlePreviewPlan)
	mux.HandleFunc("POST /plans/status", s.handleSetPlanStatus)
	mux.HandleFunc("POST /plans/bulk-status", s.handleBulkPlanStatus)
	mux.HandleFunc("POST /addons/bulk-status", s.handleBulkAddonPlanStatus)
	mux.HandleFunc("POST /reseller-plans/bulk-status", s.handleBulkResellerPlanStatus)
	mux.HandleFunc("POST /subscriptions", s.handleAssignSubscription)
	mux.HandleFunc("POST /settings/oversell", s.handleUpdateOversellSettings)
	mux.HandleFunc("POST /subscriptions/onboard", s.handleOnboardSubscription)
	mux.HandleFunc("POST /subscriptions/{id}/status", s.handleSubscriptionStatus)
	mux.HandleFunc("POST /subscriptions/bulk-status", s.handleBulkSubscriptionStatus)
	mux.HandleFunc("POST /subscriptions/bulk-plan", s.handleBulkSubscriptionPlan)
	mux.HandleFunc("POST /subscriptions/bulk-subscriber", s.handleBulkSubscriptionSubscriber)
	mux.HandleFunc("POST /sites/{id}/hosting", s.handleSiteHosting)
	mux.HandleFunc("POST /sites/{id}/php", s.handleSitePHP)
	mux.HandleFunc("POST /sites/{id}/tls-auto-renew", s.handleTLSAutoRenew)
	mux.HandleFunc("POST /sites/{id}/dns-records", s.handleUpsertDNSRecord)
	mux.HandleFunc("POST /sites/{id}/dns-records/{recordID}/delete", s.handleDeleteDNSRecord)
	s.registerFileManagerRoutes(mux)
	mux.HandleFunc("POST /plans/{id}/clone", s.handleClonePlan)
	mux.HandleFunc("POST /support/customers/{id}/enter", s.handleEnterSupport)
	mux.HandleFunc("POST /support/customers/{id}/exit", s.handleExitSupport)
	mux.HandleFunc("POST /resellers", s.handleCreateReseller)
	mux.HandleFunc("POST /resellers/status", s.handleSetResellerStatus)
	mux.HandleFunc("POST /resellers/bulk-status", s.handleBulkResellerStatus)
	mux.HandleFunc("POST /reseller-plans", s.handleUpsertResellerPlan)
	mux.HandleFunc("POST /customers/provider", s.handleTransferCustomer)
	mux.HandleFunc("POST /addons", s.handleUpsertAddonPlan)
	mux.HandleFunc("POST /subscriptions/{id}/addons", s.handleSetSubscriptionAddons)
	mux.HandleFunc("POST /subscriptions/{id}/sync", s.handleSyncSubscription)
	mux.HandleFunc("POST /subscriptions/{id}/mode", s.handleSetSubscriptionMode)
	mux.HandleFunc("GET /db", s.handleAdminer)
	mux.HandleFunc("GET /search", s.handleSearch)
	mux.HandleFunc("GET /dashboard", s.handleWorkspace("dashboard"))
	mux.HandleFunc("GET /sites", s.handleWorkspace("sites"))
	mux.HandleFunc("GET /sites/{id}", s.handleWorkspace("site-detail"))
	mux.HandleFunc("GET /databases", s.handleWorkspace("databases"))
	mux.HandleFunc("GET /backups", s.handleWorkspace("backups"))
	mux.HandleFunc("GET /dns", s.handleWorkspace("dns"))
	mux.HandleFunc("GET /certificates", s.handleWorkspace("certificates"))
	mux.HandleFunc("GET /activity", s.handleWorkspace("activity"))
	mux.HandleFunc("GET /customers", s.handleWorkspace("customers"))
	mux.HandleFunc("GET /customers/{id}", s.handleWorkspace("customer-detail"))
	mux.HandleFunc("GET /subscriptions", s.handleWorkspace("subscriptions"))
	mux.HandleFunc("GET /subscriptions/new", s.handleWorkspace("subscription-new"))
	mux.HandleFunc("GET /subscriptions/{id}", s.handleWorkspace("subscription-detail"))
	mux.HandleFunc("GET /service-plans", s.handleWorkspace("service-plans"))
	mux.HandleFunc("GET /service-plans/new", s.handleWorkspace("plan-new"))
	mux.HandleFunc("GET /service-plans/addons/new", s.handleWorkspace("addon-new"))
	mux.HandleFunc("GET /service-plans/addons/{id}", s.handleWorkspace("addon-detail"))
	mux.HandleFunc("GET /service-plans/resellers/new", s.handleWorkspace("reseller-plan-new"))
	mux.HandleFunc("GET /service-plans/resellers/{id}", s.handleWorkspace("reseller-plan-detail"))
	mux.HandleFunc("GET /service-plans/{id}", s.handleWorkspace("plan-detail"))
	mux.HandleFunc("GET /tools-settings", s.handleWorkspace("tools-settings"))
	mux.HandleFunc("GET /resellers", s.handleWorkspace("resellers"))
	mux.HandleFunc("GET /resellers/{id}", s.handleWorkspace("reseller-detail"))
	mux.HandleFunc("GET /reseller-plans", s.handleWorkspace("reseller-plans"))
	mux.HandleFunc("GET /my-resources", s.handleWorkspace("my-resources"))
	mux.HandleFunc("GET /support/customers/{customerID}/sites/{id}", s.handleSupportWorkspace)
	mux.HandleFunc("GET /support/customers/{customerID}/subscriptions/{id}", s.handleSupportWorkspace)
	mux.HandleFunc("GET /support/customers/{customerID}/{page}", s.handleSupportWorkspace)
	mux.HandleFunc("GET /", s.handleRoot)
	return securityHeaders(sameOriginPostGuard(limitPostBody(csrfGuard(mux), s.files)))
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	// Keep the pre-Phase 11 dashboard reachable for deployment-chain compatibility.
	if r.URL.Query().Get("legacy") == "1" {
		s.handleDashboard(w, r)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
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
	target := "/dashboard"
	if r.Form.Get("legacy") == "1" {
		target = "/?legacy=1"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
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

func (s *Server) dashboardActions(user auth.SessionUser) web.DashboardActions {
	selfService := user.Role == auth.RoleAdmin || user.Role == auth.RoleClient || user.Role == auth.RoleReseller
	return web.DashboardActions{
		CanCreateSite:       selfService && s.sites != nil,
		CanCreateDatabase:   selfService && s.databases != nil,
		CanIssueCertificate: selfService && s.certificates != nil,
		CanRetryJob:         user.Role == auth.RoleAdmin && s.jobs != nil,
		CanUsePhase6:        selfService && s.phase6 != nil,
		CanManageQuotas:     (user.Role == auth.RoleAdmin || user.Role == auth.RoleReseller) && s.quotas != nil,
		CanUseFileManager:   selfService && s.files != nil,
	}
}

func (s *Server) handleWorkspace(route string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.currentUser(w, r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !workspaceRouteAllowed(user.Role, route) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		data, err := s.loadDashboard(r.Context(), user)
		if err != nil {
			http.Error(w, "Could not load workspace", http.StatusInternalServerError)
			return
		}
		data.Notice = dashboardNotice(r.URL.Query().Get("notice"))
		view := web.WorkspaceView{Route: route, Title: dashboardTitle(user.Role), CSRFToken: csrfToken(r)}
		if raw := r.PathValue("id"); raw != "" {
			view.DetailID, err = strconv.ParseInt(raw, 10, 64)
			if err != nil || view.DetailID <= 0 {
				http.NotFound(w, r)
				return
			}
		}
		view.SelectedSubscription = parseQueryInt64(r, "subscription_id")
		view.PlanType = strings.TrimSpace(r.URL.Query().Get("type"))
		if user.Role != auth.RoleAdmin && view.PlanType == "reseller" {
			view.PlanType = "hosting"
		}
		view.PlanTab = strings.TrimSpace(r.URL.Query().Get("tab"))
		view.SearchQuery = strings.TrimSpace(r.URL.Query().Get("q"))
		view.StatusFilter = strings.TrimSpace(r.URL.Query().Get("status"))
		view.ProviderFilter = strings.TrimSpace(r.URL.Query().Get("provider"))
		view.CloneFrom = parseQueryInt64(r, "clone_from")
		view.Tab = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tab")))
		if view.Tab == "" {
			view.Tab = "overview"
		}
		if !map[string]bool{"overview": true, "hosting": true, "php": true, "dns": true, "ssl": true, "databases": true, "backups": true}[view.Tab] {
			view.Tab = "overview"
		}
		if route == "subscription-new" {
			view.DetailID = parseQueryInt64(r, "customer_id")
		}
		if !workspaceDetailVisible(route, view.DetailID, data) {
			http.NotFound(w, r)
			return
		}
		renderPage(w, r, web.RoutedDashboardPage(routeTitle(route), user, data, s.dashboardActions(user), view))
	}
}

func (s *Server) handleSupportWorkspace(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	customerID, err := strconv.ParseInt(r.PathValue("customerID"), 10, 64)
	if err != nil || customerID <= 0 {
		http.NotFound(w, r)
		return
	}
	page := strings.TrimSpace(r.PathValue("page"))
	if page == "" {
		page = "dashboard"
	}
	detailID := int64(0)
	if raw := strings.TrimSpace(r.PathValue("id")); raw != "" {
		detailID, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || detailID <= 0 {
			http.NotFound(w, r)
			return
		}
		switch page {
		case "sites":
			page = "site-detail"
		case "subscriptions":
			page = "subscription-detail"
		default:
			http.NotFound(w, r)
			return
		}
	}
	if !workspaceRouteAllowed(auth.RoleClient, page) {
		http.NotFound(w, r)
		return
	}
	data, err := s.loadDashboard(r.Context(), user)
	if err != nil {
		http.Error(w, "Could not load support workspace", http.StatusInternalServerError)
		return
	}
	name := ""
	for _, customer := range data.Customers {
		if customer.ID == customerID {
			name = customer.DisplayName
			if name == "" {
				name = customer.Email
			}
			break
		}
	}
	if name == "" {
		http.NotFound(w, r)
		return
	}
	data = filterDashboardForCustomer(data, customerID)
	if !workspaceDetailVisible(page, detailID, data) {
		http.NotFound(w, r)
		return
	}
	tab := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tab")))
	if !map[string]bool{"overview": true, "hosting": true, "php": true, "dns": true, "ssl": true, "databases": true, "backups": true}[tab] {
		tab = "overview"
	}
	view := web.WorkspaceView{Route: page, Title: "Support view", DetailID: detailID, Tab: tab, CSRFToken: csrfToken(r), SupportCustomerID: customerID, SupportCustomerName: name}
	renderPage(w, r, web.RoutedDashboardPage("Support · "+name, user, data, s.dashboardActions(auth.SessionUser{Role: auth.RoleClient}), view))
}

func workspaceDetailVisible(route string, id int64, data dashboard.Data) bool {
	switch route {
	case "site-detail", "site-files", "site-file-edit":
		for _, item := range data.Sites {
			if item.ID == id {
				return true
			}
		}
		return false
	case "customer-detail":
		for _, item := range data.Customers {
			if item.ID == id {
				return true
			}
		}
		return false
	case "subscription-detail":
		for _, item := range data.Subscriptions {
			if item.ID == id {
				return true
			}
		}
		return false
	case "plan-detail":
		for _, item := range data.Plans {
			if item.ID == id {
				return true
			}
		}
		return false
	case "addon-detail":
		for _, item := range data.AddonPlans {
			if item.ID == id {
				return true
			}
		}
		return false
	case "reseller-detail":
		for _, item := range data.Resellers {
			if item.ID == id {
				return true
			}
		}
		return false
	case "reseller-plan-detail":
		for _, item := range data.ResellerPlans {
			if item.ID == id {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func filterDashboardForCustomer(data dashboard.Data, customerID int64) dashboard.Data {
	sites := make([]dashboard.Site, 0)
	domains := make(map[string]bool)
	for _, item := range data.Sites {
		if item.CustomerID == customerID {
			sites = append(sites, item)
			domains[item.Domain] = true
		}
	}
	databases := make([]dashboard.Database, 0)
	for _, item := range data.Databases {
		if item.CustomerID == customerID {
			databases = append(databases, item)
		}
	}
	subscriptions := make([]types.SubscriptionSummary, 0)
	for _, item := range data.Subscriptions {
		if item.CustomerID == customerID {
			subscriptions = append(subscriptions, item)
		}
	}
	backups := make([]dashboard.Backup, 0)
	backupIDs := make(map[int64]bool)
	for _, item := range data.Phase6.Backups {
		if domains[item.TargetName] {
			backups = append(backups, item)
			backupIDs[item.ID] = true
		}
	}
	restores := make([]dashboard.RestoreRun, 0)
	for _, item := range data.Phase6.Restores {
		if backupIDs[item.BackupID] {
			restores = append(restores, item)
		}
	}
	zones := make([]dashboard.DNSZone, 0)
	for _, item := range data.Phase6.DNSZones {
		if domains[item.Domain] {
			zones = append(zones, item)
		}
	}
	audit := make([]types.AuditEvent, 0)
	for _, item := range data.AuditEvents {
		if item.CustomerID == customerID {
			audit = append(audit, item)
		}
	}
	data.Sites = sites
	data.Databases = databases
	data.Subscriptions = subscriptions
	data.Jobs = nil
	data.AuditEvents = audit
	data.Phase6 = dashboard.Phase6Data{Backups: backups, Restores: restores, DNSZones: zones}
	return data
}

func (s *Server) loadDashboard(ctx context.Context, user auth.SessionUser) (dashboard.Data, error) {
	if s.dashboard == nil {
		return dashboard.Data{}, nil
	}
	return s.dashboard.GetDashboard(ctx, user)
}

func workspaceRouteAllowed(role auth.Role, route string) bool {
	clientRoutes := map[string]bool{"dashboard": true, "sites": true, "site-detail": true, "site-files": true, "site-file-edit": true, "subscriptions": true, "databases": true, "backups": true, "dns": true, "certificates": true, "activity": true, "subscription-detail": true}
	if role == auth.RoleAdmin {
		return true
	}
	if role == auth.RoleClient {
		return clientRoutes[route]
	}
	if role == auth.RoleReseller {
		return map[string]bool{"dashboard": true, "sites": true, "site-detail": true, "site-files": true, "site-file-edit": true, "databases": true, "backups": true, "dns": true, "certificates": true, "activity": true, "customers": true, "customer-detail": true, "subscriptions": true, "subscription-detail": true, "subscription-new": true, "service-plans": true, "plan-detail": true, "plan-new": true, "addon-detail": true, "addon-new": true, "my-resources": true}[route]
	}
	return false
}

func routeTitle(route string) string {
	return map[string]string{"dashboard": "Home", "sites": "Domains", "site-detail": "Domain", "site-files": "File Manager", "site-file-edit": "Edit File", "databases": "Databases", "backups": "Backups", "dns": "DNS", "certificates": "SSL/TLS Certificates", "activity": "Activity", "customers": "Customers", "customer-detail": "Customer", "subscriptions": "Subscriptions", "subscription-detail": "Subscription", "subscription-new": "Add Subscription", "service-plans": "Service Plans", "plan-detail": "Service Plan", "plan-new": "Add a Plan", "addon-detail": "Add-on Plan", "addon-new": "Add an Add-on", "reseller-plan-new": "Add Reseller Plan", "reseller-plan-detail": "Reseller Plan", "tools-settings": "Tools & Settings", "resellers": "Resellers", "reseller-detail": "Reseller", "reseller-plans": "Reseller Plans", "my-resources": "My Resources"}[route]
}

func parseQueryInt64(r *http.Request, name string) int64 {
	value, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get(name)), 10, 64)
	if value < 0 {
		return 0
	}
	return value
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if s.workspace == nil {
		writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "results": []types.SearchResult{}})
		return
	}
	results, err := s.workspace.Search(r.Context(), user, r.URL.Query().Get("q"), 8)
	if err != nil {
		writeSPAError(w, http.StatusInternalServerError, "Search unavailable")
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "results": results})
}

func (s *Server) handleOnboardSubscription(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	if s.quotas == nil {
		http.Error(w, "Subscription management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid onboarding form", http.StatusBadRequest)
		return
	}
	req := types.OnboardSubscriptionReq{CustomerMode: strings.TrimSpace(r.Form.Get("customer_mode")), Customer: parseCustomerRequest(r), PlanID: parseFormInt64Default(r, "plan_id", 0), SubscriptionName: strings.TrimSpace(r.Form.Get("subscription_name")), CreateSite: parseFormBool(r, "create_site"), Site: types.CreateSiteReq{Username: strings.ToLower(strings.TrimSpace(r.Form.Get("username"))), Domain: strings.ToLower(strings.TrimSpace(r.Form.Get("domain"))), PHPVersion: strings.TrimSpace(r.Form.Get("php_version"))}}
	if req.CustomerMode == "new" {
		customer, err := s.quotas.CreateCustomer(r.Context(), user, req.Customer)
		if err != nil {
			writeQuotaError(w, r, "Could not create customer", err)
			return
		}
		req.CustomerID = customer.ID
	} else {
		req.CustomerID = parseFormInt64Default(r, "customer_id", 0)
	}
	if req.CustomerID <= 0 || req.PlanID <= 0 {
		http.Error(w, "Customer and plan are required", http.StatusBadRequest)
		return
	}
	sub, err := s.quotas.CreateSubscription(r.Context(), user, types.CreateSubscriptionReq{CustomerID: req.CustomerID, PlanID: req.PlanID, SubscriptionName: req.SubscriptionName, Status: "active"})
	if err != nil {
		writeQuotaError(w, r, "Could not create subscription", err)
		return
	}
	s.recordAudit(r.Context(), user, req.CustomerID, sub.ID, "subscription.created", "subscription", sub.ID, nil)
	notice := "subscription-saved"
	if req.CreateSite {
		if s.sites == nil {
			notice = "subscription-site-warning"
		} else {
			req.Site.SubscriptionID = sub.ID
			siteID, siteErr := s.sites.CreateSiteFor(r.Context(), user, user.ID, req.Site)
			if siteErr != nil {
				notice = "subscription-site-warning"
			} else {
				s.recordAudit(r.Context(), user, req.CustomerID, sub.ID, "site.queued", "site", siteID, nil)
			}
		}
	}
	http.Redirect(w, r, "/subscriptions/"+strconv.FormatInt(sub.ID, 10)+"?notice="+notice, http.StatusSeeOther)
}

func (s *Server) handleSubscriptionStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	if s.quotas == nil {
		http.Error(w, "Subscription management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid subscription status form", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	req := types.CreateSubscriptionReq{ID: id, CustomerID: parseFormInt64Default(r, "customer_id", 0), PlanID: parseFormInt64Default(r, "plan_id", 0), SubscriptionName: strings.TrimSpace(r.Form.Get("subscription_name")), Status: strings.TrimSpace(r.Form.Get("status")), SyncMode: strings.TrimSpace(r.Form.Get("sync_mode"))}
	if _, err = s.quotas.CreateSubscription(r.Context(), user, req); err != nil {
		writeQuotaError(w, r, "Could not update subscription", err)
		return
	}
	s.recordAudit(r.Context(), user, req.CustomerID, id, "subscription.status_changed", "subscription", id, map[string]any{"status": req.Status})
	http.Redirect(w, r, "/subscriptions/"+strconv.FormatInt(id, 10)+"?notice=subscription-saved", http.StatusSeeOther)
}

func (s *Server) handleClonePlan(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	if s.quotas == nil {
		http.Error(w, "Plan management is not configured", http.StatusServiceUnavailable)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid plan clone form", http.StatusBadRequest)
		return
	}
	data, err := s.loadDashboard(r.Context(), user)
	if err != nil {
		http.Error(w, "Could not load plan", http.StatusInternalServerError)
		return
	}
	var source controlquota.Plan
	found := false
	for _, plan := range data.Plans {
		if plan.ID == id {
			source = plan
			found = true
			break
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	originalName := source.Name
	source.ID = 0
	source.Name = strings.TrimSpace(r.Form.Get("clone_name"))
	if source.Name == "" {
		source.Name = originalName + " Copy"
	}
	source.IsActive = false
	cloned, err := s.quotas.UpsertPlan(r.Context(), user, source)
	if err != nil {
		writeQuotaError(w, r, "Could not clone plan", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "plan.cloned", "plan", cloned.ID, map[string]any{"source_plan_id": id})
	http.Redirect(w, r, "/service-plans/"+strconv.FormatInt(cloned.ID, 10)+"?notice=plan-saved", http.StatusSeeOther)
}

func (s *Server) handleEnterSupport(w http.ResponseWriter, r *http.Request) {
	s.handleSupportTransition(w, r, "support.entered", true)
}
func (s *Server) handleExitSupport(w http.ResponseWriter, r *http.Request) {
	s.handleSupportTransition(w, r, "support.exited", false)
}
func (s *Server) handleSupportTransition(w http.ResponseWriter, r *http.Request, action string, enter bool) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	s.recordAudit(r.Context(), user, id, 0, action, "customer", id, nil)
	target := "/customers/" + strconv.FormatInt(id, 10)
	if enter {
		target = "/support/customers/" + strconv.FormatInt(id, 10) + "/dashboard"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) recordAudit(ctx context.Context, actor auth.SessionUser, customerID, subscriptionID int64, action, target string, targetID int64, metadata map[string]any) {
	if s.workspace == nil {
		return
	}
	raw, _ := json.Marshal(metadata)
	_ = s.workspace.RecordAudit(ctx, types.AuditEvent{ActorUserID: actor.ID, CustomerID: customerID, SubscriptionID: subscriptionID, Action: action, TargetType: target, TargetID: targetID, Metadata: raw})
}

func writeQuotaError(w http.ResponseWriter, r *http.Request, prefix string, err error) {
	if errors.Is(err, provision.ErrForbidden) {
		http.NotFound(w, r)
		return
	}
	http.Error(w, prefix+": "+err.Error(), http.StatusBadRequest)
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
	if user.Role != auth.RoleAdmin && user.Role != auth.RoleClient && user.Role != auth.RoleReseller {
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
	if (user.Role == auth.RoleClient || user.Role == auth.RoleReseller) && req.SubscriptionID <= 0 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
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
		if errors.Is(err, provision.ErrForbidden) {
			http.NotFound(w, r)
			return
		}
		if wantsSPAJSON(r) {
			writeSPAError(w, http.StatusBadRequest, "Could not create site: "+err.Error())
			return
		}
		http.Error(w, "Could not create site: "+err.Error(), http.StatusBadRequest)
		return
	}
	customerID := int64(0)
	if s.workspace != nil {
		customerID, _ = s.workspace.CustomerIDForSubscription(r.Context(), req.SubscriptionID)
	}
	s.recordAudit(r.Context(), user, customerID, req.SubscriptionID, "site.queued", "site", siteID, map[string]any{"domain": req.Domain})
	if wantsSPAJSON(r) {
		writeSPAJSON(w, http.StatusAccepted, map[string]any{
			"ok":       true,
			"site_id":  siteID,
			"redirect": "/",
			"notice":   "Site provisioning queued.",
		})
		return
	}
	redirectAfterPost(w, r, "/", "/sites?notice=site-queued")
}

func (s *Server) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role != auth.RoleAdmin && user.Role != auth.RoleClient && user.Role != auth.RoleReseller {
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
		SiteID:         parseFormInt64Default(r, "site_id", 0),
		Engine:         types.DBEngine(engine),
		DBName:         strings.ToLower(strings.TrimSpace(r.Form.Get("db_name"))),
		DBUser:         strings.ToLower(strings.TrimSpace(r.Form.Get("db_user"))),
	}
	if (user.Role == auth.RoleClient || user.Role == auth.RoleReseller) && req.SubscriptionID <= 0 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	resourceOwnerID, err := parseOptionalOwnerID(r, user.ID)
	if err != nil {
		http.Error(w, "Invalid database form: "+err.Error(), http.StatusBadRequest)
		return
	}
	databaseID, err := s.databases.CreateDatabaseFor(r.Context(), user, resourceOwnerID, req)
	if err != nil {
		if errors.Is(err, provision.ErrForbidden) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Could not create database: "+err.Error(), http.StatusBadRequest)
		return
	}
	customerID := int64(0)
	if s.workspace != nil {
		customerID, _ = s.workspace.CustomerIDForSubscription(r.Context(), req.SubscriptionID)
	}
	s.recordAudit(r.Context(), user, customerID, req.SubscriptionID, "database.queued", "database", databaseID, map[string]any{"name": req.DBName})
	if req.SiteID > 0 {
		http.Redirect(w, r, "/sites/"+strconv.FormatInt(req.SiteID, 10)+"?tab=databases&notice=database-queued", http.StatusSeeOther)
		return
	}
	redirectAfterPost(w, r, "/", "/databases?notice=database-queued")
}

func (s *Server) handleIssueCertificate(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role != auth.RoleAdmin && user.Role != auth.RoleClient && user.Role != auth.RoleReseller {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if s.certificates == nil {
		http.Error(w, "Certificate provisioning is not configured", http.StatusServiceUnavailable)
		return
	}
	if user.Role != auth.RoleAdmin && s.workspace == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
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
	domain := strings.TrimSpace(r.Form.Get("domain"))
	certificateID, err := s.certificates.IssueCertificate(r.Context(), user, domain, issuer)
	if err != nil {
		if errors.Is(err, provision.ErrForbidden) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Could not issue certificate: "+err.Error(), http.StatusBadRequest)
		return
	}
	customerID := int64(0)
	if s.workspace != nil {
		customerID, _ = s.workspace.CustomerIDForDomain(r.Context(), domain)
	}
	s.recordAudit(r.Context(), user, customerID, 0, "certificate.queued", "site", certificateID, map[string]any{"domain": domain, "issuer": issuer})
	if siteID := parseFormInt64Default(r, "site_id", 0); siteID > 0 {
		http.Redirect(w, r, "/sites/"+strconv.FormatInt(siteID, 10)+"?tab=ssl&notice=certificate-queued", http.StatusSeeOther)
		return
	}
	redirectAfterPost(w, r, "/", "/certificates?notice=certificate-queued")
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
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role != auth.RoleAdmin && user.Role != auth.RoleClient && user.Role != auth.RoleReseller {
		http.Error(w, "Forbidden", http.StatusForbidden)
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
	if (user.Role == auth.RoleClient || user.Role == auth.RoleReseller) && req.SubscriptionID <= 0 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	resourceOwnerID, err := parseOptionalOwnerID(r, user.ID)
	if err != nil {
		http.Error(w, "Invalid backup form: "+err.Error(), http.StatusBadRequest)
		return
	}
	backupID, err := s.phase6.CreateBackupFor(r.Context(), user, resourceOwnerID, req)
	if err != nil {
		if errors.Is(err, provision.ErrForbidden) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Could not create backup: "+err.Error(), http.StatusBadRequest)
		return
	}
	customerID := int64(0)
	if s.workspace != nil {
		customerID, _ = s.workspace.CustomerIDForSubscription(r.Context(), req.SubscriptionID)
	}
	s.recordAudit(r.Context(), user, customerID, req.SubscriptionID, "backup.queued", "backup", backupID, map[string]any{"domain": req.Domain})
	if siteID := parseFormInt64Default(r, "site_id", 0); siteID > 0 {
		http.Redirect(w, r, "/sites/"+strconv.FormatInt(siteID, 10)+"?tab=backups&notice=backup-queued", http.StatusSeeOther)
		return
	}
	redirectAfterPost(w, r, "/?notice=backup-queued", "/backups?notice=backup-queued")
}

func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role != auth.RoleAdmin && user.Role != auth.RoleClient && user.Role != auth.RoleReseller {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if s.phase6 == nil {
		http.Error(w, "Phase 6 operations are not configured", http.StatusServiceUnavailable)
		return
	}
	if user.Role != auth.RoleAdmin && s.workspace == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
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
	restoreID, err := s.phase6.RestoreBackup(r.Context(), user, backupID)
	if err != nil {
		if errors.Is(err, provision.ErrForbidden) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Could not restore backup: "+err.Error(), http.StatusBadRequest)
		return
	}
	customerID := int64(0)
	if s.workspace != nil {
		customerID, _ = s.workspace.CustomerIDForBackup(r.Context(), backupID)
	}
	s.recordAudit(r.Context(), user, customerID, 0, "restore.queued", "restore", restoreID, map[string]any{"backup_id": backupID})
	if siteID := parseFormInt64Default(r, "site_id", 0); siteID > 0 {
		http.Redirect(w, r, "/sites/"+strconv.FormatInt(siteID, 10)+"?tab=backups&notice=restore-queued", http.StatusSeeOther)
		return
	}
	redirectAfterPost(w, r, "/?notice=restore-queued", "/backups?notice=restore-queued")
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
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role != auth.RoleAdmin && user.Role != auth.RoleClient && user.Role != auth.RoleReseller {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if s.phase6 == nil {
		http.Error(w, "Phase 6 operations are not configured", http.StatusServiceUnavailable)
		return
	}
	if user.Role != auth.RoleAdmin && s.workspace == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid dns form", http.StatusBadRequest)
		return
	}
	domain := strings.TrimSpace(r.Form.Get("domain"))
	address := strings.TrimSpace(r.Form.Get("address"))
	zoneID, err := s.phase6.ConfigureDNS(r.Context(), user, domain, address)
	if err != nil {
		if errors.Is(err, provision.ErrForbidden) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Could not configure dns: "+err.Error(), http.StatusBadRequest)
		return
	}
	customerID := int64(0)
	if s.workspace != nil {
		customerID, _ = s.workspace.CustomerIDForDomain(r.Context(), domain)
	}
	s.recordAudit(r.Context(), user, customerID, 0, "dns.queued", "dns_zone", zoneID, map[string]any{"domain": domain, "address": address})
	if siteID := parseFormInt64Default(r, "site_id", 0); siteID > 0 {
		http.Redirect(w, r, "/sites/"+strconv.FormatInt(siteID, 10)+"?tab=dns&notice=dns-queued", http.StatusSeeOther)
		return
	}
	redirectAfterPost(w, r, "/?notice=dns-queued", "/dns?notice=dns-queued")
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
	user, ok := s.requireProvider(w, r)
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
	saved, err := s.quotas.UpsertPlan(r.Context(), user, plan)
	if err != nil {
		writeQuotaError(w, r, "Could not save plan", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "plan.saved", "plan", saved.ID, nil)
	redirectAfterPost(w, r, "/?notice=plan-saved", "/service-plans/"+strconv.FormatInt(saved.ID, 10)+"?notice=plan-saved")
}

type planPreviewer interface {
	PreviewPlan(ctx context.Context, owner auth.SessionUser, plan controlquota.Plan) (types.PlanPreview, error)
}

func (s *Server) handlePreviewPlan(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	previewer, ok := s.quotas.(planPreviewer)
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Plan preview is not configured")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeSPAError(w, http.StatusBadRequest, "Invalid plan form")
		return
	}
	plan, err := parsePlan(r)
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, err.Error())
		return
	}
	preview, err := previewer.PreviewPlan(r.Context(), user, plan)
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "preview": preview})
}

func (s *Server) handleSetPlanStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
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
		writeQuotaError(w, r, "Could not update plan status", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "plan.status_changed", "plan", planID, map[string]any{"active": active})
	redirectAfterPost(w, r, "/?notice=plan-status-saved", "/service-plans/"+strconv.FormatInt(planID, 10)+"?notice=plan-status-saved")
}

func (s *Server) handleBulkPlanStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
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
	active := parseFormBool(r, "is_active")
	ids, err := parseFormInt64List(r, "plan_id")
	if err != nil || len(ids) == 0 {
		http.Error(w, "Select at least one plan", http.StatusBadRequest)
		return
	}
	if err := s.quotas.SetPlanStatuses(r.Context(), user, ids, active); err != nil {
		writeQuotaError(w, r, "Could not update plans", err)
		return
	}
	for _, id := range ids {
		s.recordAudit(r.Context(), user, 0, 0, "plan.status_changed", "plan", id, map[string]any{"active": active, "bulk": true})
	}
	http.Redirect(w, r, "/service-plans?type=hosting&notice=plan-status-saved", http.StatusSeeOther)
}

func (s *Server) handleBulkAddonPlanStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid add-on status form", http.StatusBadRequest)
		return
	}
	ids, err := parseFormInt64List(r, "addon_id")
	if err != nil || len(ids) == 0 {
		http.Error(w, "Select at least one add-on", http.StatusBadRequest)
		return
	}
	active := parseFormBool(r, "is_active")
	if err := s.quotas.SetAddonPlanStatuses(r.Context(), user, ids, active); err != nil {
		writeQuotaError(w, r, "Could not update add-ons", err)
		return
	}
	for _, id := range ids {
		s.recordAudit(r.Context(), user, 0, 0, "addon.status_changed", "addon", id, map[string]any{"active": active, "bulk": true})
	}
	http.Redirect(w, r, "/service-plans?type=addon&notice=plan-status-saved", http.StatusSeeOther)
}

func (s *Server) handleBulkResellerPlanStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid reseller plan status form", http.StatusBadRequest)
		return
	}
	ids, err := parseFormInt64List(r, "reseller_plan_id")
	if err != nil || len(ids) == 0 {
		http.Error(w, "Select at least one reseller plan", http.StatusBadRequest)
		return
	}
	active := parseFormBool(r, "is_active")
	if err := s.quotas.SetResellerPlanStatuses(r.Context(), user, ids, active); err != nil {
		writeQuotaError(w, r, "Could not update reseller plans", err)
		return
	}
	for _, id := range ids {
		s.recordAudit(r.Context(), user, 0, 0, "reseller_plan.status_changed", "reseller_plan", id, map[string]any{"active": active, "bulk": true})
	}
	http.Redirect(w, r, "/service-plans?type=reseller&notice=plan-status-saved", http.StatusSeeOther)
}

func (s *Server) handleAssignSubscription(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
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
			writeQuotaError(w, r, "Could not save subscription", err)
			return
		}
		s.recordAudit(r.Context(), user, subscription.CustomerID, subscription.ID, "subscription.saved", "subscription", subscription.ID, nil)
		if subscription.Warning != "" {
			redirectAfterPost(w, r, "/?notice=subscription-warning", "/subscriptions/"+strconv.FormatInt(subscription.ID, 10)+"?notice=subscription-warning")
			return
		}
		redirectAfterPost(w, r, "/?notice=subscription-saved", "/subscriptions/"+strconv.FormatInt(subscription.ID, 10)+"?notice=subscription-saved")
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
	user, ok := s.requireProvider(w, r)
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
	customer, err := s.quotas.CreateCustomer(r.Context(), user, req)
	if err != nil {
		writeQuotaError(w, r, "Could not create customer", err)
		return
	}
	s.recordAudit(r.Context(), user, customer.ID, 0, "customer.created", "customer", customer.ID, nil)
	redirectAfterPost(w, r, "/?notice=customer-saved", "/customers/"+strconv.FormatInt(customer.ID, 10)+"?notice=customer-saved")
}

func (s *Server) handleEnableCustomerLogin(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
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
		writeQuotaError(w, r, "Could not enable customer login", err)
		return
	}
	s.recordAudit(r.Context(), user, customerID, 0, "customer.login_enabled", "customer", customerID, nil)
	redirectAfterPost(w, r, "/?notice=customer-login-saved", "/customers/"+strconv.FormatInt(customerID, 10)+"?notice=customer-login-saved")
}

func (s *Server) handleSetCustomerStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
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
	status := strings.TrimSpace(r.Form.Get("status"))
	if err := s.quotas.SetCustomerStatus(r.Context(), user, customerID, status); err != nil {
		writeQuotaError(w, r, "Could not update customer status", err)
		return
	}
	s.recordAudit(r.Context(), user, customerID, 0, "customer.status_changed", "customer", customerID, map[string]any{"status": status})
	redirectAfterPost(w, r, "/?notice=customer-status-saved", "/customers/"+strconv.FormatInt(customerID, 10)+"?notice=customer-status-saved")
}

func parseFormIDs(r *http.Request, name string) ([]int64, error) {
	values := r.Form[name]
	if len(values) == 0 {
		return nil, fmt.Errorf("select at least one item")
	}
	ids := make([]int64, 0, len(values))
	seen := make(map[int64]struct{}, len(values))
	for _, value := range values {
		id, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("invalid %s", name)
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, nil
}

func (s *Server) handleBulkCustomerStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid bulk customer action", http.StatusBadRequest)
		return
	}
	ids, err := parseFormIDs(r, "customer_id")
	if err != nil {
		http.Error(w, "Invalid bulk customer action: "+err.Error(), http.StatusBadRequest)
		return
	}
	status := strings.TrimSpace(r.Form.Get("status"))
	if err := s.quotas.SetCustomerStatuses(r.Context(), user, ids, status); err != nil {
		writeQuotaError(w, r, "Could not update customers", err)
		return
	}
	for _, id := range ids {
		s.recordAudit(r.Context(), user, id, 0, "customer.status_changed", "customer", id, map[string]any{"status": status, "bulk": true})
	}
	http.Redirect(w, r, "/customers?notice=customer-status-saved", http.StatusSeeOther)
}

func (s *Server) handleBulkSubscriptionStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid bulk subscription action", http.StatusBadRequest)
		return
	}
	ids, err := parseFormIDs(r, "subscription_id")
	if err != nil {
		http.Error(w, "Invalid bulk subscription action: "+err.Error(), http.StatusBadRequest)
		return
	}
	status := strings.TrimSpace(r.Form.Get("status"))
	if err := s.quotas.SetSubscriptionStatuses(r.Context(), user, ids, status); err != nil {
		writeQuotaError(w, r, "Could not update subscriptions", err)
		return
	}
	for _, id := range ids {
		s.recordAudit(r.Context(), user, 0, id, "subscription.status_changed", "subscription", id, map[string]any{"status": status, "bulk": true})
	}
	http.Redirect(w, r, "/subscriptions?notice=subscription-saved", http.StatusSeeOther)
}

func (s *Server) handleBulkSubscriptionPlan(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	if s.domains == nil {
		http.Error(w, "Subscription changes are not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid subscription plan form", http.StatusBadRequest)
		return
	}
	ids, err := parseFormIDs(r, "subscription_id")
	if err != nil {
		http.Error(w, "Invalid subscription plan form: "+err.Error(), http.StatusBadRequest)
		return
	}
	planID, err := parseFormInt64(r, "plan_id")
	if err != nil {
		http.Error(w, "Invalid subscription plan form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err = s.domains.ChangeSubscriptionPlans(r.Context(), user, ids, planID); err != nil {
		writeQuotaError(w, r, "Could not change subscription plan", err)
		return
	}
	for _, id := range ids {
		s.recordAudit(r.Context(), user, 0, id, "subscription.plan_changed", "subscription", id, map[string]any{"plan_id": planID, "bulk": true})
	}
	http.Redirect(w, r, "/subscriptions?notice=subscription-saved", http.StatusSeeOther)
}

func (s *Server) handleBulkSubscriptionSubscriber(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	if s.domains == nil {
		http.Error(w, "Subscription changes are not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid subscriber form", http.StatusBadRequest)
		return
	}
	ids, err := parseFormIDs(r, "subscription_id")
	if err != nil {
		http.Error(w, "Invalid subscriber form: "+err.Error(), http.StatusBadRequest)
		return
	}
	customerID, err := parseFormInt64(r, "customer_id")
	if err != nil {
		http.Error(w, "Invalid subscriber form: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err = s.domains.ChangeSubscriptionSubscriber(r.Context(), user, ids, customerID); err != nil {
		writeQuotaError(w, r, "Could not change subscriber", err)
		return
	}
	for _, id := range ids {
		s.recordAudit(r.Context(), user, customerID, id, "subscription.subscriber_changed", "subscription", id, map[string]any{"customer_id": customerID, "bulk": true})
	}
	http.Redirect(w, r, "/subscriptions?notice=subscription-saved", http.StatusSeeOther)
}

func (s *Server) handleSiteHosting(w http.ResponseWriter, r *http.Request) {
	s.handleSiteSettings(w, r, "hosting")
}
func (s *Server) handleSitePHP(w http.ResponseWriter, r *http.Request) {
	s.handleSiteSettings(w, r, "php")
}

func (s *Server) handleTLSAutoRenew(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if s.domains == nil {
		http.Error(w, "Domain settings are not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid TLS settings", http.StatusBadRequest)
		return
	}
	siteID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || siteID <= 0 {
		http.NotFound(w, r)
		return
	}
	enabled := parseFormBool(r, "tls_auto_renew")
	if err = s.domains.SetTLSAutoRenew(r.Context(), user, siteID, enabled); err != nil {
		writeQuotaError(w, r, "Could not update automatic renewal", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "certificate.auto_renew_changed", "site", siteID, map[string]any{"enabled": enabled})
	http.Redirect(w, r, "/sites/"+strconv.FormatInt(siteID, 10)+"?tab=ssl&notice=site-settings-saved", http.StatusSeeOther)
}

func (s *Server) handleSiteSettings(w http.ResponseWriter, r *http.Request, tab string) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if s.domains == nil {
		http.Error(w, "Domain settings are not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid domain settings", http.StatusBadRequest)
		return
	}
	siteID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || siteID <= 0 {
		http.NotFound(w, r)
		return
	}
	req := types.UpdateSiteSettingsReq{SiteID: siteID, Section: tab, DesiredStatus: strings.TrimSpace(r.Form.Get("desired_status")), DesiredPHPVersion: strings.TrimSpace(r.Form.Get("desired_php_version")), DesiredHTTPSRedirect: parseFormBool(r, "desired_https_redirect")}
	if err = s.domains.UpdateSiteSettings(r.Context(), user, req); err != nil {
		writeQuotaError(w, r, "Could not update domain settings", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "site.settings_changed", "site", siteID, map[string]any{"tab": tab, "status": req.DesiredStatus, "php_version": req.DesiredPHPVersion, "https_redirect": req.DesiredHTTPSRedirect})
	http.Redirect(w, r, "/sites/"+strconv.FormatInt(siteID, 10)+"?tab="+tab+"&notice=site-settings-saved", http.StatusSeeOther)
}

func (s *Server) handleUpsertDNSRecord(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if s.domains == nil {
		http.Error(w, "DNS record management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid DNS record form", http.StatusBadRequest)
		return
	}
	siteID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || siteID <= 0 {
		http.NotFound(w, r)
		return
	}
	record := types.DNSRecord{ID: parseFormInt64Default(r, "record_id", 0), Host: strings.TrimSpace(r.Form.Get("host")), Type: strings.TrimSpace(r.Form.Get("record_type")), Value: strings.TrimSpace(r.Form.Get("value")), Priority: parseFormIntDefault(r, "priority", 0), TTL: parseFormIntDefault(r, "ttl", 3600)}
	if err = s.domains.UpsertDNSRecord(r.Context(), user, siteID, record); err != nil {
		writeQuotaError(w, r, "Could not save DNS record", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.record_saved", "site", siteID, map[string]any{"type": record.Type, "host": record.Host})
	http.Redirect(w, r, "/sites/"+strconv.FormatInt(siteID, 10)+"?tab=dns&notice=dns-record-saved", http.StatusSeeOther)
}

func (s *Server) handleDeleteDNSRecord(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if s.domains == nil {
		http.Error(w, "DNS record management is not configured", http.StatusServiceUnavailable)
		return
	}
	siteID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || siteID <= 0 {
		http.NotFound(w, r)
		return
	}
	recordID, err := strconv.ParseInt(r.PathValue("recordID"), 10, 64)
	if err != nil || recordID <= 0 {
		http.NotFound(w, r)
		return
	}
	if err = s.domains.DeleteDNSRecord(r.Context(), user, siteID, recordID); err != nil {
		writeQuotaError(w, r, "Could not delete DNS record", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.record_deleted", "site", siteID, map[string]any{"record_id": recordID})
	http.Redirect(w, r, "/sites/"+strconv.FormatInt(siteID, 10)+"?tab=dns&notice=dns-record-deleted", http.StatusSeeOther)
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
	s.recordAudit(r.Context(), user, 0, 0, "settings.oversell_changed", "settings", 1, map[string]any{"policy": settings.OversellPolicy, "capacity_mb": settings.ServerDiskCapacityMB})
	redirectAfterPost(w, r, "/?notice=settings-saved", "/tools-settings?notice=settings-saved")
}

func (s *Server) handleCreateReseller(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.quotas == nil {
		http.Error(w, "Provider management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid reseller form", http.StatusBadRequest)
		return
	}
	planID, err := parseFormInt64(r, "reseller_plan_id")
	if err != nil {
		http.Error(w, "Invalid reseller form: "+err.Error(), http.StatusBadRequest)
		return
	}
	req := parseCustomerRequest(r)
	req.Password = r.Form.Get("password")
	reseller, err := s.quotas.CreateReseller(r.Context(), user, req, planID)
	if err != nil {
		http.Error(w, "Could not create reseller: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "reseller.created", "reseller", reseller.ID, nil)
	redirectAfterPost(w, r, "/?notice=reseller-saved", "/resellers/"+strconv.FormatInt(reseller.ID, 10)+"?notice=reseller-saved")
}

func (s *Server) handleSetResellerStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid reseller status form", 400)
		return
	}
	id, err := parseFormInt64(r, "reseller_id")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	status := strings.TrimSpace(r.Form.Get("status"))
	if err = s.quotas.SetResellerStatus(r.Context(), user, id, status); err != nil {
		http.Error(w, "Could not update reseller: "+err.Error(), 400)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "reseller.status_changed", "reseller", id, map[string]any{"status": status})
	http.Redirect(w, r, "/resellers/"+strconv.FormatInt(id, 10)+"?notice=reseller-status-saved", 303)
}

func (s *Server) handleBulkResellerStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid bulk reseller action", http.StatusBadRequest)
		return
	}
	ids, err := parseFormIDs(r, "reseller_id")
	if err != nil {
		http.Error(w, "Invalid bulk reseller action: "+err.Error(), http.StatusBadRequest)
		return
	}
	status := strings.TrimSpace(r.Form.Get("status"))
	if err := s.quotas.SetResellerStatuses(r.Context(), user, ids, status); err != nil {
		http.Error(w, "Could not update resellers: "+err.Error(), http.StatusBadRequest)
		return
	}
	for _, id := range ids {
		s.recordAudit(r.Context(), user, 0, 0, "reseller.status_changed", "reseller", id, map[string]any{"status": status, "bulk": true})
	}
	http.Redirect(w, r, "/resellers?notice=reseller-status-saved", http.StatusSeeOther)
}

func (s *Server) handleUpsertResellerPlan(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid reseller plan form", 400)
		return
	}
	p := types.ResellerPlan{ID: parseFormInt64Default(r, "reseller_plan_id", 0), Name: strings.TrimSpace(r.Form.Get("name")), Description: strings.TrimSpace(r.Form.Get("description")), AllowCustomPlans: parseFormBool(r, "allow_custom_plans"), AllowSSH: parseFormBool(r, "allow_ssh"), AllowDNS: parseFormBool(r, "allow_dns"), AllowTLS: formBoolDefault(r, "allow_tls", true), AllowBackups: formBoolDefault(r, "allow_backups", true), AllowPHPSettings: parseFormBool(r, "allow_php_settings"), IsActive: parseFormBool(r, "is_active")}
	var err error
	fields := []struct {
		name   string
		target *int
	}{{"max_customers", &p.MaxCustomers}, {"max_subscriptions", &p.MaxSubscriptions}, {"disk_mb", &p.DiskMB}, {"max_sites", &p.MaxSites}, {"max_subdomains", &p.MaxSubdomains}, {"max_domain_aliases", &p.MaxDomainAliases}, {"max_databases", &p.MaxDatabases}, {"bandwidth_mb", &p.BandwidthMB}, {"max_mailboxes", &p.MaxMailboxes}, {"max_ftp_accounts", &p.MaxFTPAccounts}, {"max_backups", &p.MaxBackups}, {"backup_storage_mb", &p.BackupStorageMB}}
	for _, f := range fields {
		*f.target, err = parsePlanLimit(r, f.name)
		if err != nil {
			http.Error(w, "Invalid reseller plan: "+err.Error(), 400)
			return
		}
	}
	saved, err := s.quotas.UpsertResellerPlan(r.Context(), user, p)
	if err != nil {
		http.Error(w, "Could not save reseller plan: "+err.Error(), 400)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "reseller_plan.saved", "reseller_plan", saved.ID, nil)
	http.Redirect(w, r, "/service-plans/resellers/"+strconv.FormatInt(saved.ID, 10)+"?notice=reseller-plan-saved", 303)
}

func (s *Server) handleTransferCustomer(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid provider transfer", 400)
		return
	}
	customerID, err := parseFormInt64(r, "customer_id")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	resellerID := parseFormInt64Default(r, "reseller_id", 0)
	if err = s.quotas.TransferCustomer(r.Context(), user, customerID, resellerID); err != nil {
		http.Error(w, "Could not transfer customer: "+err.Error(), 400)
		return
	}
	s.recordAudit(r.Context(), user, customerID, 0, "customer.provider_changed", "customer", customerID, map[string]any{"reseller_id": resellerID})
	http.Redirect(w, r, "/customers/"+strconv.FormatInt(customerID, 10)+"?notice=provider-saved", 303)
}

func (s *Server) handleUpsertAddonPlan(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid add-on form", 400)
		return
	}
	plan, err := parsePlan(r)
	if err != nil {
		http.Error(w, "Invalid add-on form: "+err.Error(), 400)
		return
	}
	addon := types.AddonPlan{ID: parseFormInt64Default(r, "addon_id", 0), Name: plan.Name, Description: plan.Description, IsActive: plan.IsActive, Entitlements: parsedAddonEntitlements(plan)}
	saved, err := s.quotas.UpsertAddonPlan(r.Context(), user, addon)
	if err != nil {
		writeQuotaError(w, r, "Could not save add-on", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "addon.saved", "addon", saved.ID, nil)
	http.Redirect(w, r, "/service-plans/addons/"+strconv.FormatInt(saved.ID, 10)+"?notice=addon-saved", 303)
}

func pathInt64(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("valid id is required")
	}
	return id, nil
}
func (s *Server) handleSetSubscriptionAddons(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	id, err := pathInt64(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err = r.ParseForm(); err != nil {
		http.Error(w, "Invalid add-on assignment", 400)
		return
	}
	var ids []int64
	for _, raw := range r.Form["addon_id"] {
		v, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || v <= 0 {
			http.Error(w, "Invalid add-on id", 400)
			return
		}
		ids = append(ids, v)
	}
	if err = s.quotas.SetSubscriptionAddons(r.Context(), user, id, ids); err != nil {
		writeQuotaError(w, r, "Could not update add-ons", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, id, "subscription.addons_changed", "subscription", id, nil)
	http.Redirect(w, r, "/subscriptions/"+strconv.FormatInt(id, 10)+"?notice=addons-saved", 303)
}
func (s *Server) handleSyncSubscription(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	id, err := pathInt64(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err = s.quotas.SyncSubscription(r.Context(), user, id); err != nil {
		writeQuotaError(w, r, "Could not synchronize subscription", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, id, "subscription.synced", "subscription", id, nil)
	http.Redirect(w, r, "/subscriptions/"+strconv.FormatInt(id, 10)+"?notice=subscription-synced", 303)
}
func (s *Server) handleSetSubscriptionMode(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireProvider(w, r)
	if !ok {
		return
	}
	id, err := pathInt64(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err = r.ParseForm(); err != nil {
		http.Error(w, "Invalid subscription mode", 400)
		return
	}
	mode := strings.TrimSpace(r.Form.Get("sync_mode"))
	custom := types.SubscriptionEntitlements{}
	if mode == "custom" {
		plan, parseErr := parsePlan(r)
		if parseErr != nil {
			http.Error(w, "Invalid custom entitlement: "+parseErr.Error(), http.StatusBadRequest)
			return
		}
		custom = parsedCustomEntitlements(r, plan)
		custom.PlanName = "Custom"
	}
	if err = s.quotas.SetSubscriptionMode(r.Context(), user, id, mode, custom); err != nil {
		writeQuotaError(w, r, "Could not update subscription mode", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, id, "subscription.mode_changed", "subscription", id, map[string]any{"mode": mode})
	http.Redirect(w, r, "/subscriptions/"+strconv.FormatInt(id, 10)+"?notice=subscription-mode-saved", 303)
}

func parsedPlanEntitlements(plan controlquota.Plan) types.SubscriptionEntitlements {
	return types.SubscriptionEntitlements{
		PlanName: plan.Name, DiskMB: plan.DiskMB, MaxSites: plan.MaxSites,
		MaxDatabases: plan.MaxDatabases, BandwidthMB: plan.BandwidthMB,
		MaxMailboxes: plan.MaxMailboxes, AllowSSH: plan.AllowSSH, AllowDNS: plan.AllowDNS,
		BackupRetentionDays: plan.BackupRetentionDays, PHPAllowlist: plan.PHPAllowlist,
		PHPFPMMaxChildren: plan.PHPFPMMaxChildren, PHPMemoryMB: plan.PHPMemoryMB,
		SiteDiskQuotaMB: plan.SiteDiskQuotaMB, MaxBackups: plan.MaxBackups,
		BackupStorageMB: plan.BackupStorageMB, MaxSubdomains: plan.MaxSubdomains,
		MaxDomainAliases: plan.MaxDomainAliases, MaxFTPAccounts: plan.MaxFTPAccounts,
		ValidityDays: plan.ValidityDays, HostingEnabled: plan.HostingEnabled,
		DefaultPHPVersion: plan.DefaultPHPVersion, AllowTLS: plan.AllowTLS,
		AllowBackups: plan.AllowBackups, AllowPHPSettings: plan.AllowPHPSettings,
		OverusePolicy: plan.OverusePolicy, DiskWarningPercent: plan.DiskWarningPercent,
		TrafficWarningPercent: plan.TrafficWarningPercent, ServicePresets: plan.Presets,
	}
}

func parsedAddonEntitlements(plan controlquota.Plan) types.SubscriptionEntitlements {
	entitlements := parsedPlanEntitlements(plan)
	entitlements.HostingEnabled = false
	entitlements.DefaultPHPVersion = ""
	entitlements.ValidityDays = 0
	entitlements.ServicePresets.Hosting.DefaultPHPVersion = ""
	return entitlements
}

func parsedCustomEntitlements(r *http.Request, plan controlquota.Plan) types.SubscriptionEntitlements {
	entitlements := parsedPlanEntitlements(plan)
	if _, submitted := r.Form["default_php_version"]; submitted || !entitlements.HostingEnabled || entitlements.DefaultPHPVersion != "" {
		return entitlements
	}
	versions := normalizeFormList(strings.Split(entitlements.PHPAllowlist, ","))
	if len(versions) > 0 {
		entitlements.DefaultPHPVersion = versions[0]
		entitlements.ServicePresets.Hosting.DefaultPHPVersion = versions[0]
	}
	return entitlements
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

func (s *Server) requireProvider(w http.ResponseWriter, r *http.Request) (auth.SessionUser, bool) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return auth.SessionUser{}, false
	}
	if user.Role != auth.RoleAdmin && user.Role != auth.RoleReseller {
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

func limitPostBody(next http.Handler, files FileManagerService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			limit := int64(maxFormBodyBytes)
			if files != nil && strings.HasSuffix(r.URL.Path, "/files/upload") {
				limit = files.UploadMaxBytes() + fileUploadOverhead
			}
			if r.ContentLength > limit {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := r.Cookie(SessionCookieName); err != nil {
			next.ServeHTTP(w, r)
			return
		}
		expected := csrfToken(r)
		if expected == "" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		provided := strings.TrimSpace(r.Header.Get("X-Nakpanel-CSRF"))
		if provided == "" {
			_ = r.ParseForm()
			provided = strings.TrimSpace(r.Form.Get("csrf_token"))
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) != 1 {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func csrfToken(r *http.Request) string {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("nakpanel-csrf-v1:" + cookie.Value))
	return fmt.Sprintf("%x", sum[:])
}

func redirectAfterPost(w http.ResponseWriter, r *http.Request, legacyTarget, routedTarget string) {
	target := legacyTarget
	if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" {
		if parsed, err := url.Parse(referer); err == nil && parsed.Path != "/" {
			target = routedTarget
		}
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
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
	case "subscription-site-warning":
		return "Customer and subscription were created, but the first website was not queued. Retry from this subscription."
	case "subscription-plan-saved":
		return "Subscription plan updated."
	case "subscription-subscriber-saved":
		return "Subscription subscriber updated."
	case "site-settings-saved":
		return "Domain settings queued for application."
	case "dns-record-saved":
		return "DNS record saved and zone update queued."
	case "dns-record-deleted":
		return "DNS record deleted and zone update queued."
	case "customer-saved":
		return "Customer saved."
	case "customer-login-saved":
		return "Customer login saved."
	case "customer-status-saved":
		return "Customer status updated."
	case "settings-saved":
		return "Oversell settings saved."
	case "file-uploaded":
		return "Upload complete."
	case "file-created":
		return "File or folder created."
	case "file-saved":
		return "File saved."
	case "file-renamed":
		return "Item renamed."
	case "file-copied":
		return "Selected items copied."
	case "file-moved":
		return "Selected items moved."
	case "file-deleted":
		return "Selected items deleted."
	case "file-archived":
		return "ZIP archive created."
	case "file-extracted":
		return "Archive extracted."
	case "file-permissions":
		return "Permissions updated."
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
		ID:                    planID,
		Name:                  strings.TrimSpace(r.Form.Get("name")),
		Description:           strings.TrimSpace(r.Form.Get("description")),
		PriceCents:            priceCents,
		AllowSSH:              parseFormBool(r, "allow_ssh"),
		AllowDNS:              parseFormBool(r, "allow_dns"),
		PHPAllowlist:          strings.TrimSpace(r.Form.Get("php_allowlist")),
		IsActive:              parseFormBool(r, "is_active"),
		OverusePolicy:         types.PlanOverusePolicy(strings.TrimSpace(r.Form.Get("overuse_policy"))),
		DiskWarningPercent:    parseFormIntDefault(r, "disk_warning_percent", 80),
		TrafficWarningPercent: parseFormIntDefault(r, "traffic_warning_percent", 80),
		HostingEnabled:        formBoolDefault(r, "hosting_enabled", true),
		DefaultPHPVersion:     strings.TrimSpace(r.Form.Get("default_php_version")),
		AllowTLS:              formBoolDefault(r, "allow_tls", true),
		AllowBackups:          formBoolDefault(r, "allow_backups", true),
		AllowPHPSettings:      parseFormBool(r, "allow_php_settings"),
	}
	if versions := r.Form["php_versions"]; len(versions) > 0 {
		plan.PHPAllowlist = strings.Join(normalizeFormList(versions), ",")
	}
	fields := []struct {
		name     string
		target   *int
		fallback int
	}{
		{name: "disk_mb", target: &plan.DiskMB},
		{name: "max_sites", target: &plan.MaxSites},
		{name: "max_databases", target: &plan.MaxDatabases},
		{name: "bandwidth_mb", target: &plan.BandwidthMB, fallback: -1},
		{name: "max_mailboxes", target: &plan.MaxMailboxes},
		{name: "backup_retention_days", target: &plan.BackupRetentionDays},
		{name: "php_max_children", target: &plan.PHPFPMMaxChildren},
		{name: "php_memory_mb", target: &plan.PHPMemoryMB},
		{name: "site_disk_quota_mb", target: &plan.SiteDiskQuotaMB},
		{name: "max_backups", target: &plan.MaxBackups},
		{name: "backup_storage_mb", target: &plan.BackupStorageMB},
		{name: "max_subdomains", target: &plan.MaxSubdomains},
		{name: "max_domain_aliases", target: &plan.MaxDomainAliases},
		{name: "max_ftp_accounts", target: &plan.MaxFTPAccounts},
		{name: "validity_days", target: &plan.ValidityDays, fallback: -1},
	}
	for _, field := range fields {
		value, err := parsePlanLimitDefault(r, field.name, field.fallback)
		if err != nil {
			return controlquota.Plan{}, err
		}
		*field.target = value
	}
	plan.Presets = types.PlanServicePresets{SchemaVersion: 1,
		Hosting:      types.HostingPreset{WebServer: formStringDefault(r, "hosting_web_server", "nginx"), PreferredDomain: formStringDefault(r, "preferred_domain", "none"), DefaultPHPVersion: plan.DefaultPHPVersion, AllowedPHPVersions: normalizeFormList(strings.Split(plan.PHPAllowlist, ","))},
		PHP:          types.PHPPreset{MaxExecutionSeconds: parseFormIntDefault(r, "php_max_execution_seconds", 30), MaxInputSeconds: parseFormIntDefault(r, "php_max_input_seconds", 60), PostMaxMB: parseFormIntDefault(r, "php_post_max_mb", 128), UploadMaxMB: parseFormIntDefault(r, "php_upload_max_mb", 128), FPMMaxRequests: parseFormIntDefault(r, "php_fpm_max_requests", 500), DisplayErrors: parseFormBool(r, "php_display_errors"), LogErrors: formBoolDefault(r, "php_log_errors", true), AllowURLFOpen: parseFormBool(r, "php_allow_url_fopen")},
		Mail:         types.MailPreset{WebmailEnabled: parseFormBool(r, "mail_webmail_enabled"), SpamFilter: parseFormBool(r, "mail_spam_filter"), DKIM: parseFormBool(r, "mail_dkim"), DMARCPolicy: formStringDefault(r, "mail_dmarc_policy", "none")},
		DNS:          types.DNSPreset{Mode: formStringDefault(r, "dns_mode", "primary"), DefaultTTL: parseFormIntDefault(r, "dns_default_ttl", 3600)},
		Performance:  types.PerformancePreset{MaxConnections: parseFormIntDefault(r, "performance_max_connections", 0), StaticFileCache: parseFormBool(r, "performance_static_cache")},
		Logs:         types.LogsPreset{RotationEnabled: formBoolDefault(r, "logs_rotation_enabled", true), RetentionDays: parseFormIntDefault(r, "logs_retention_days", 14), StatisticsEnabled: parseFormBool(r, "logs_statistics_enabled")},
		Applications: types.ApplicationsPreset{CatalogEnabled: parseFormBool(r, "applications_catalog_enabled"), Allowed: normalizeFormList(r.Form["applications_allowed"])},
	}
	return plan, nil
}

func parsePlanLimitDefault(r *http.Request, name string, fallback int) (int, error) {
	if strings.TrimSpace(r.Form.Get(name)) == "" && !parseFormBool(r, name+"_unlimited") {
		return fallback, nil
	}
	return parsePlanLimit(r, name)
}

func parsePlanLimit(r *http.Request, name string) (int, error) {
	if parseFormBool(r, name+"_unlimited") {
		return -1, nil
	}
	if strings.TrimSpace(r.Form.Get(name)) == "" {
		return 0, nil
	}
	value, err := parseFormIntAllowUnlimited(r, name)
	if err != nil {
		return 0, err
	}
	if value == -1 {
		return -1, nil
	}
	factor := 1
	switch strings.ToUpper(strings.TrimSpace(r.Form.Get(name + "_unit"))) {
	case "", "MB", "COUNT", "DAYS":
	case "GB":
		factor = 1024
	case "TB":
		factor = 1024 * 1024
	default:
		return 0, fmt.Errorf("unsupported unit for %s", name)
	}
	maxInt := int(^uint(0) >> 1)
	if value > maxInt/factor {
		return 0, fmt.Errorf("%s is too large", name)
	}
	return value * factor, nil
}

func formBoolDefault(r *http.Request, name string, fallback bool) bool {
	if _, ok := r.Form[name]; !ok {
		return fallback
	}
	return parseFormBool(r, name)
}

func formStringDefault(r *http.Request, name, fallback string) string {
	value := strings.TrimSpace(r.Form.Get(name))
	if value == "" {
		return fallback
	}
	return value
}

func normalizeFormList(values []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
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
		SyncMode:         strings.TrimSpace(r.Form.Get("sync_mode")),
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

func parseFormIntDefault(r *http.Request, name string, fallback int) int {
	raw := strings.TrimSpace(r.Form.Get(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < -1 {
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

func parseFormInt64List(r *http.Request, name string) ([]int64, error) {
	values := r.Form[name]
	result := make([]int64, 0, len(values))
	seen := make(map[int64]struct{}, len(values))
	for _, raw := range values {
		value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || value <= 0 {
			return nil, fmt.Errorf("%s must contain positive integers", name)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
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
	for _, raw := range r.Form[name] {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "true" || value == "on" || value == "1" || value == "yes" {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
