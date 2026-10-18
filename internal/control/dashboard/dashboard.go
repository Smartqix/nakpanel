package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/servertiming"
	"github.com/nakroteck/nakpanel/internal/control/store"
	"github.com/nakroteck/nakpanel/internal/types"
)

type Querier interface {
	ListSites(ctx context.Context) ([]store.Site, error)
	ListDatabases(ctx context.Context) ([]store.Database, error)
}

type JobReader interface {
	ListRecentJobs(ctx context.Context, limit int) ([]Job, error)
}

type Phase6Reader interface {
	GetPhase6(ctx context.Context) (Phase6Data, error)
}

type QuotaReader interface {
	ListAccountQuotas(ctx context.Context) ([]controlquota.Summary, error)
	GetAccountQuotaSummary(ctx context.Context, userID int64) (controlquota.Summary, error)
	ListPlans(ctx context.Context) ([]controlquota.Plan, error)
	ListCustomers(ctx context.Context) ([]types.Customer, error)
	ListSubscriptionSummaries(ctx context.Context) ([]types.SubscriptionSummary, error)
	ListSubscriptionSummariesForUser(ctx context.Context, userID int64) ([]types.SubscriptionSummary, error)
	GetSettings(ctx context.Context) (controlquota.Settings, error)
	CommittedAllocationMB(ctx context.Context) (int, error)
}

type ProviderReader interface {
	ListCustomersForUser(ctx context.Context, userID int64) ([]types.Customer, error)
	ListPlansForUser(ctx context.Context, userID int64) ([]controlquota.Plan, error)
	ListResellers(ctx context.Context) ([]types.Reseller, error)
	ListResellerPlans(ctx context.Context) ([]types.ResellerPlan, error)
	ListResellerPlansForUser(ctx context.Context, userID int64) ([]types.ResellerPlan, error)
	ListResellersForUser(ctx context.Context, userID int64) ([]types.Reseller, error)
	ListAddonPlans(ctx context.Context) ([]types.AddonPlan, error)
	ListAddonPlansForUser(ctx context.Context, userID int64) ([]types.AddonPlan, error)
}

type PlanRevisionReader interface {
	ListPlanRevisions(ctx context.Context, limit int) ([]types.PlanRevision, error)
	ListPlanRevisionsForUser(ctx context.Context, userID int64, limit int) ([]types.PlanRevision, error)
}

type ScopedReader interface {
	ListSitesForUser(ctx context.Context, userID int64) ([]Site, error)
	ListDatabasesForUser(ctx context.Context, userID int64) ([]Database, error)
	GetPhase6ForUser(ctx context.Context, userID int64) (Phase6Data, error)
}

type AuditReader interface {
	ListAudit(ctx context.Context, actor auth.SessionUser, limit int) ([]types.AuditEvent, error)
}

type UsageReader interface {
	ListSubscriptionUsage(ctx context.Context, actor auth.SessionUser) ([]types.SubscriptionUsage, error)
	ListUsageAlerts(ctx context.Context, actor auth.SessionUser, limit int) ([]types.UsageAlert, error)
}

type CapabilityReader interface {
	RuntimeCapabilities(ctx context.Context) (types.RuntimeCapabilities, error)
}

type SubscriptionServiceReader interface {
	ListSubscriptionServices(context.Context, auth.SessionUser) (SubscriptionServicesData, error)
}

type Store struct {
	queries      Querier
	jobs         JobReader
	phase6       Phase6Reader
	quotas       QuotaReader
	scoped       ScopedReader
	audit        AuditReader
	capabilities CapabilityReader
}

// NoticeKind classifies a post-redirect message so the panel can render a
// failed outcome as a failure. Before this existed every notice — including
// "the website was not queued" — rendered in success green.
type NoticeKind string

const (
	NoticeSuccess NoticeKind = "success"
	NoticeWarning NoticeKind = "warning"
	NoticeError   NoticeKind = "error"
	NoticeInfo    NoticeKind = "info"
)

type Data struct {
	Sites                []Site
	Databases            []Database
	ActiveJobs           int
	Jobs                 []Job
	JobLoadError         string
	Phase6               Phase6Data
	Phase6Error          string
	Quotas               []controlquota.Summary
	QuotaLoadError       string
	Plans                []controlquota.Plan
	PlanRevisions        []types.PlanRevision
	Customers            []types.Customer
	Subscriptions        []types.SubscriptionSummary
	Settings             controlquota.Settings
	CommittedDiskMB      int
	PlanLoadError        string
	Notice               string
	NoticeKind           NoticeKind
	AuditEvents          []types.AuditEvent
	Resellers            []types.Reseller
	ResellerPlans        []types.ResellerPlan
	AddonPlans           []types.AddonPlan
	SubscriptionUsage    []types.SubscriptionUsage
	UsageAlerts          []types.UsageAlert
	Capabilities         types.RuntimeCapabilities
	CapabilityLoadError  string
	SubscriptionServices SubscriptionServicesData
	ServiceLoadError     string
}

type SubscriptionServicesData struct {
	Accounts               []types.SubscriptionSystemAccount
	SFTP                   []SFTPIdentity
	Tasks                  []ScheduledTask
	MailDomains            []MailDomain
	Mailboxes              []Mailbox
	MailAliases            []MailAlias
	WebmailHosts           []WebmailHost
	Applications           []Application
	ApplicationGenerations []types.ApplicationGeneration
	ApplicationPresets     []types.ApplicationPreset
	ProtectedDirectories   []types.ProtectedDirectory
	SitePolicies           []SitePolicy
	FTP                    []types.FTPAccount
	Git                    []types.GitRepository
	GitDeployments         []types.GitDeployment
	Valkey                 []types.ValkeyInstance
	Staging                []types.StagingOperation
	TaskRuns               []types.ScheduledTaskRun
	SiteUsage              []SiteUsage
}

type SitePolicy struct {
	SiteID          int64
	SubscriptionID  int64
	InheritedPolicy types.HostingPolicy
	SiteOverride    json.RawMessage
	EffectivePolicy types.HostingPolicy
}

type SFTPIdentity struct {
	ID             int64
	SubscriptionID int64
	Name           string
	RelativeRoot   string
	Enabled        bool
}

type ScheduledTask struct {
	ID               int64
	SubscriptionID   int64
	SiteID           int64
	Name             string
	Schedule         string
	Command          string
	WorkingDirectory string
	TimeoutSeconds   int
	Enabled          bool
	Status           string
	LastError        string
	Kind             string
	URL              string
	Script           string
	Timezone         string
}

type SiteUsage struct {
	SiteID            int64
	PeriodStart       time.Time
	DocumentRootBytes int64
	TrafficBytes      int64
	RequestCount      int64
	ErrorCount        int64
	PHPState          string
	CollectedAt       NullableTime
	LastError         string
}

type MailDomain struct {
	ID             int64
	SubscriptionID int64
	SiteID         int64
	Domain         string
	Enabled        bool
	DKIM           bool
	DMARCPolicy    string
	Status         string
	LastError      string
}

type Mailbox struct {
	ID             int64
	SubscriptionID int64
	MailDomainID   int64
	Address        string
	QuotaMB        int
	Enabled        bool
}

type MailAlias struct {
	ID             int64
	SubscriptionID int64
	MailDomainID   int64
	Address        string
	Destinations   string
}

type Application struct {
	ID              int64
	SubscriptionID  int64
	SiteID          int64
	Name            string
	Runtime         string
	ImageRef        string
	DesiredState    string
	AppliedState    string
	Status          string
	LastError       string
	RouteMode       string
	RoutePrefix     string
	ContainerPort   int
	EndpointPort    int
	HealthKind      string
	HealthPath      string
	ActiveRevision  int64
	ObservedState   string
	ObservedMessage string
	ObservedAt      NullableTime
}

type Site struct {
	RemovalState         string
	ID                   int64
	Username             string
	DocumentRoot         string
	Domain               string
	PHPVersion           string
	Status               string
	LastError            string
	TLSStatus            string
	TLSIssuer            string
	TLSExpiresAt         NullableTime
	TLSLastError         string
	TLSAutoRenew         bool
	TLSCertPath          string
	TLSKeyPath           string
	SubscriptionID       int64
	CustomerID           int64
	DesiredStatus        string
	DesiredPHPVersion    string
	HTTPSRedirect        bool
	DesiredHTTPSRedirect bool
	SettingsStatus       string
	SettingsError        string
	ParentSiteID         int64
	DNSZoneMode          string
}

type Database struct {
	ID             int64
	Engine         string
	Name           string
	User           string
	Status         string
	LastError      string
	SubscriptionID int64
	CustomerID     int64
	SiteID         int64
}

type Job struct {
	ID          int64
	Kind        string
	State       string
	Queue       string
	Attempt     int
	MaxAttempts int
	Target      string
	LastError   string
	CreatedAt   time.Time
	ScheduledAt time.Time
	AttemptedAt NullableTime
	FinalizedAt NullableTime
}

type Phase6Data struct {
	Backups         []Backup
	Restores        []RestoreRun
	WebmailHosts    []WebmailHost
	DNSZones        []DNSZone
	DNSRecords      []types.DNSRecord
	Reconciliations []ReconciliationRun
}

type Backup struct {
	ID             int64
	TargetName     string
	Status         string
	ArchivePath    string
	SizeBytes      int64
	LastError      string
	CreatedAt      time.Time
	SiteID         int64
	SubscriptionID int64
}

type RestoreRun struct {
	ID         int64
	BackupID   int64
	TargetName string
	Status     string
	RestoredAt NullableTime
	LastError  string
	CreatedAt  time.Time
}

type WebmailHost struct {
	ID             int64
	SubscriptionID int64
	SiteID         int64
	Domain         string
	Hostname       string
	Status         string
	ConfigPath     string
	LastError      string
	CreatedAt      time.Time
}

type DNSZone struct {
	ID                int64
	Domain            string
	Address           string
	IPv6Address       string
	Serial            int64
	Status            string
	ZonePath          string
	LastError         string
	CreatedAt         time.Time
	SiteID            int64
	ParentZoneID      int64
	Mode              string
	UpstreamPrimaries string
	TransferCIDRs     string
	TemplateRevision  int64
	TemplateStatus    string
	DesiredRevision   int64
	AppliedRevision   int64
	SOA               types.DNSSOASettings
}

type ReconciliationRun struct {
	ID         int64
	Status     string
	SitesTotal int
	SitesOK    int
	LastError  string
	CreatedAt  time.Time
}

type NullableTime struct {
	Time  time.Time
	Valid bool
}

const DefaultRecentJobLimit = 15

type StoreOption func(*Store)

func WithJobReader(jobs JobReader) StoreOption {
	return func(s *Store) {
		s.jobs = jobs
	}
}

func WithPhase6Reader(phase6 Phase6Reader) StoreOption {
	return func(s *Store) {
		s.phase6 = phase6
	}
}

func WithQuotaReader(quotas QuotaReader) StoreOption {
	return func(s *Store) {
		s.quotas = quotas
	}
}

func WithScopedReader(reader ScopedReader) StoreOption {
	return func(s *Store) { s.scoped = reader }
}

func WithAuditReader(reader AuditReader) StoreOption {
	return func(s *Store) { s.audit = reader }
}

func WithCapabilityReader(reader CapabilityReader) StoreOption {
	return func(s *Store) { s.capabilities = reader }
}

func NewStore(queries Querier, options ...StoreOption) *Store {
	s := &Store{queries: queries}
	for _, option := range options {
		option(s)
	}
	return s
}

// WithServiceScope narrows service reads while leaving shared shell data intact.
// A site scope is resolved from the role-scoped sites already read by the loader.
func WithServiceScope(ctx context.Context, subscriptionID, siteID int64) context.Context {
	return context.WithValue(ctx, serviceScopeKey{}, serviceScope{subscriptionID, siteID})
}

type serviceScopeKey struct{}
type serviceScope struct{ subscriptionID, siteID int64 }
type scopedSubscriptionServiceReader interface {
	ListSubscriptionServicesFor(context.Context, auth.SessionUser, int64) (SubscriptionServicesData, error)
}

func timedRead(ctx context.Context, name string, read func()) {
	started := time.Now()
	defer func() {
		if name != "" {
			servertiming.Record(ctx, name, time.Since(started))
		}
	}()
	read()
}

func (s *Store) GetDashboard(ctx context.Context, user auth.SessionUser) (Data, error) {
	return s.getDashboard(ctx, user, 4)
}

func (s *Store) getDashboard(ctx context.Context, user auth.SessionUser, concurrency int) (Data, error) {
	if user.Role == auth.RoleAdmin && s.queries == nil {
		return Data{}, errors.New("dashboard queries are not configured")
	}
	var data Data
	var group errgroup.Group
	group.SetLimit(concurrency)
	run := func(name string, read func()) { group.Go(func() error { timedRead(ctx, name, read); return nil }) }
	scope, scoped := ctx.Value(serviceScopeKey{}).(serviceScope)
	loadServices := func() {
		services, ok := s.scoped.(SubscriptionServiceReader)
		if !ok {
			return
		}
		var err error
		if narrowed, ok := services.(scopedSubscriptionServiceReader); ok && scoped {
			id := scope.subscriptionID
			if scope.siteID > 0 {
				id = 0
				for _, site := range data.Sites {
					if site.ID == scope.siteID {
						id = site.SubscriptionID
						break
					}
				}
			}
			// Zero also narrows (to no subscription), never falls back to all services.
			data.SubscriptionServices, err = narrowed.ListSubscriptionServicesFor(ctx, user, id)
		} else {
			data.SubscriptionServices, err = services.ListSubscriptionServices(ctx, user)
		}
		if err != nil {
			log.Printf("dashboard: %v", err)
			data.ServiceLoadError = "hosting service policy unavailable"
		}
	}
	// Site service reads depend on the mapped sites. Other service reads are independent.
	if !scoped || scope.siteID == 0 {
		run("services", loadServices)
	}
	if s.capabilities != nil {
		run("caps", func() {
			var err error
			data.Capabilities, err = s.capabilities.RuntimeCapabilities(ctx)
			if err != nil {
				data.CapabilityLoadError = "runtime capabilities unavailable"
			}
		})
	}
	if user.Role != auth.RoleAdmin {
		if s.scoped != nil {
			run("sites", func() { data.Sites, _ = s.scoped.ListSitesForUser(ctx, user.ID) })
			run("databases", func() { data.Databases, _ = s.scoped.ListDatabasesForUser(ctx, user.ID) })
			run("phase6", func() { data.Phase6, _ = s.scoped.GetPhase6ForUser(ctx, user.ID) })
		}
		if s.quotas != nil {
			run("quotas", func() {
				summary, err := s.quotas.GetAccountQuotaSummary(ctx, user.ID)
				if err != nil {
					data.QuotaLoadError = "account quotas unavailable"
				} else {
					data.Quotas = []controlquota.Summary{summary}
				}
			})
			run("subscriptions", func() {
				subscriptions, err := s.quotas.ListSubscriptionSummariesForUser(ctx, user.ID)
				if err == nil {
					data.Subscriptions = subscriptions
				}
			})
			if user.Role == auth.RoleReseller {
				if provider, ok := s.quotas.(ProviderReader); ok {
					run("customers", func() { data.Customers, _ = provider.ListCustomersForUser(ctx, user.ID) })
					run("plans", func() { data.Plans, _ = provider.ListPlansForUser(ctx, user.ID) })
					run("resellerplans", func() { data.ResellerPlans, _ = provider.ListResellerPlansForUser(ctx, user.ID) })
					run("resellers", func() { data.Resellers, _ = provider.ListResellersForUser(ctx, user.ID) })
					run("addons", func() { data.AddonPlans, _ = provider.ListAddonPlansForUser(ctx, user.ID) })
				}
			}
		}
		if usage, ok := s.quotas.(UsageReader); ok {
			run("usage", func() { data.SubscriptionUsage, _ = usage.ListSubscriptionUsage(ctx, user) })
			run("alerts", func() { data.UsageAlerts, _ = usage.ListUsageAlerts(ctx, user, 25) })
		}
		_ = group.Wait()
		if scoped && scope.siteID > 0 {
			timedRead(ctx, "services", loadServices)
		}
		return data, nil
	}
	var sites []store.Site
	var databases []store.Database
	var siteErr, databaseErr, jobCountErr error
	run("sites", func() { sites, siteErr = s.queries.ListSites(ctx) })
	run("databases", func() { databases, databaseErr = s.queries.ListDatabases(ctx) })
	if counter, ok := s.jobs.(activeJobReader); ok {
		run("jobcount", func() { data.ActiveJobs, jobCountErr = counter.CountActiveJobs(ctx) })
	}
	if s.jobs != nil {
		run("jobs", func() {
			var err error
			data.Jobs, err = s.jobs.ListRecentJobs(ctx, DefaultRecentJobLimit)
			if err != nil {
				data.Jobs = nil
				data.JobLoadError = "recent jobs unavailable"
			}
		})
	}
	if s.phase6 != nil {
		run("phase6", func() {
			var err error
			data.Phase6, err = s.phase6.GetPhase6(ctx)
			if err != nil {
				data.Phase6 = Phase6Data{}
				data.Phase6Error = "phase6 operations unavailable"
			}
		})
	}
	var customerErr, subscriptionErr error
	if s.quotas != nil {
		run("quotas", func() {
			var err error
			data.Quotas, err = s.quotas.ListAccountQuotas(ctx)
			if err != nil {
				data.Quotas = nil
				data.QuotaLoadError = "account quotas unavailable"
			}
		})
		// Preserve short-circuiting and error precedence of this chain.
		run("", func() {
			var err error
			timedRead(ctx, "plans", func() { data.Plans, err = s.quotas.ListPlans(ctx) })
			if err != nil {
				data.Plans = nil
				data.PlanLoadError = "plans unavailable"
				return
			}
			timedRead(ctx, "settings", func() { data.Settings, err = s.quotas.GetSettings(ctx) })
			if err != nil {
				data.PlanLoadError = "plan settings unavailable"
				return
			}
			timedRead(ctx, "committed", func() { data.CommittedDiskMB, err = s.quotas.CommittedAllocationMB(ctx) })
			if err != nil {
				data.PlanLoadError = "committed allocation unavailable"
			}
		})
		run("customers", func() {
			data.Customers, customerErr = s.quotas.ListCustomers(ctx)
			if customerErr != nil {
				data.Customers = nil
			}
		})
		run("subscriptions", func() {
			data.Subscriptions, subscriptionErr = s.quotas.ListSubscriptionSummaries(ctx)
			if subscriptionErr != nil {
				data.Subscriptions = nil
			}
		})
	}
	if usage, ok := s.quotas.(UsageReader); ok {
		run("usage", func() { data.SubscriptionUsage, _ = usage.ListSubscriptionUsage(ctx, user) })
		run("alerts", func() { data.UsageAlerts, _ = usage.ListUsageAlerts(ctx, user, 25) })
	}
	if s.audit != nil {
		run("audit", func() { data.AuditEvents, _ = s.audit.ListAudit(ctx, user, 50) })
	}
	if provider, ok := s.quotas.(ProviderReader); ok {
		run("resellers", func() { data.Resellers, _ = provider.ListResellers(ctx) })
		run("resellerplans", func() { data.ResellerPlans, _ = provider.ListResellerPlans(ctx) })
		run("addons", func() { data.AddonPlans, _ = provider.ListAddonPlans(ctx) })
	}
	if revisions, ok := s.quotas.(PlanRevisionReader); ok {
		run("revisions", func() { data.PlanRevisions, _ = revisions.ListPlanRevisions(ctx, 200) })
	}
	_ = group.Wait()
	if _, ok := s.jobs.(activeJobReader); !ok || jobCountErr != nil {
		data.ActiveJobs = ActiveJobs(data.Jobs)
	}
	// Return the original first fatal error, regardless of completion order.
	if siteErr != nil {
		return Data{}, siteErr
	}
	if databaseErr != nil {
		return Data{}, databaseErr
	}
	if data.PlanLoadError == "" {
		if customerErr != nil {
			data.PlanLoadError = "customers unavailable"
		} else if subscriptionErr != nil {
			data.PlanLoadError = "subscriptions unavailable"
		}
	}
	data.Sites = make([]Site, 0, len(sites))
	data.Databases = make([]Database, 0, len(databases))

	for _, site := range sites {
		data.Sites = append(data.Sites, Site{
			RemovalState:         site.RemovalState,
			ID:                   site.ID,
			Username:             site.Username,
			DocumentRoot:         site.DocumentRoot,
			Domain:               site.Domain,
			PHPVersion:           site.PhpVersion,
			Status:               site.Status,
			LastError:            site.LastError,
			TLSStatus:            site.TlsStatus,
			TLSIssuer:            site.TlsIssuer,
			TLSExpiresAt:         NullableTime{Time: site.TlsExpiresAt.Time, Valid: site.TlsExpiresAt.Valid},
			TLSLastError:         site.TlsLastError,
			TLSAutoRenew:         site.TlsAutoRenew,
			TLSCertPath:          site.TlsCertPath,
			TLSKeyPath:           site.TlsKeyPath,
			SubscriptionID:       site.SubscriptionID,
			CustomerID:           site.CustomerID,
			DesiredStatus:        site.DesiredStatus,
			DesiredPHPVersion:    site.DesiredPhpVersion,
			HTTPSRedirect:        site.HttpsRedirect,
			DesiredHTTPSRedirect: site.DesiredHttpsRedirect,
			SettingsStatus:       site.SettingsStatus,
			SettingsError:        site.SettingsError,
			ParentSiteID:         site.ParentSiteID.Int64,
			DNSZoneMode:          site.DnsZoneMode,
		})
	}
	for _, database := range databases {
		data.Databases = append(data.Databases, Database{
			ID:             database.ID,
			Engine:         database.Engine,
			Name:           database.DbName,
			User:           database.DbUser,
			Status:         database.Status,
			LastError:      database.LastError,
			SubscriptionID: database.SubscriptionID,
			CustomerID:     database.CustomerID,
			SiteID:         database.SiteID.Int64,
		})
	}
	if scoped && scope.siteID > 0 {
		timedRead(ctx, "services", loadServices)
	}
	return data, nil
}
