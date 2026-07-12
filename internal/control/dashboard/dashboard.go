package dashboard

import (
	"context"
	"errors"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
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

type Store struct {
	queries      Querier
	jobs         JobReader
	phase6       Phase6Reader
	quotas       QuotaReader
	scoped       ScopedReader
	audit        AuditReader
	capabilities CapabilityReader
}

type Data struct {
	Sites             []Site
	Databases         []Database
	Jobs              []Job
	JobLoadError      string
	Phase6            Phase6Data
	Phase6Error       string
	Quotas            []controlquota.Summary
	QuotaLoadError    string
	Plans             []controlquota.Plan
	Customers         []types.Customer
	Subscriptions     []types.SubscriptionSummary
	Settings          controlquota.Settings
	CommittedDiskMB   int
	PlanLoadError     string
	Notice            string
	AuditEvents       []types.AuditEvent
	Resellers         []types.Reseller
	ResellerPlans     []types.ResellerPlan
	AddonPlans        []types.AddonPlan
	SubscriptionUsage []types.SubscriptionUsage
	UsageAlerts       []types.UsageAlert
	Capabilities      types.RuntimeCapabilities
}

type Site struct {
	ID                   int64
	Username             string
	Domain               string
	PHPVersion           string
	Status               string
	LastError            string
	TLSStatus            string
	TLSIssuer            string
	TLSExpiresAt         NullableTime
	TLSLastError         string
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
	ID         int64
	Hostname   string
	Status     string
	ConfigPath string
	LastError  string
	CreatedAt  time.Time
}

type DNSZone struct {
	ID        int64
	Domain    string
	Address   string
	Serial    int64
	Status    string
	ZonePath  string
	LastError string
	CreatedAt time.Time
	SiteID    int64
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

func (s *Store) GetDashboard(ctx context.Context, user auth.SessionUser) (Data, error) {
	if user.Role != auth.RoleAdmin {
		data := Data{}
		if s.scoped != nil {
			data.Sites, _ = s.scoped.ListSitesForUser(ctx, user.ID)
			data.Databases, _ = s.scoped.ListDatabasesForUser(ctx, user.ID)
			data.Phase6, _ = s.scoped.GetPhase6ForUser(ctx, user.ID)
		}
		if s.quotas != nil {
			summary, err := s.quotas.GetAccountQuotaSummary(ctx, user.ID)
			if err != nil {
				data.QuotaLoadError = "account quotas unavailable"
			} else {
				data.Quotas = []controlquota.Summary{summary}
			}
			subscriptions, err := s.quotas.ListSubscriptionSummariesForUser(ctx, user.ID)
			if err == nil {
				data.Subscriptions = subscriptions
			}
			if user.Role == auth.RoleReseller {
				if provider, ok := s.quotas.(ProviderReader); ok {
					data.Customers, _ = provider.ListCustomersForUser(ctx, user.ID)
					data.Plans, _ = provider.ListPlansForUser(ctx, user.ID)
					data.ResellerPlans, _ = provider.ListResellerPlansForUser(ctx, user.ID)
					data.Resellers, _ = provider.ListResellersForUser(ctx, user.ID)
					data.AddonPlans, _ = provider.ListAddonPlansForUser(ctx, user.ID)
				}
			}
			if usage, ok := s.quotas.(UsageReader); ok {
				data.SubscriptionUsage, _ = usage.ListSubscriptionUsage(ctx, user)
				data.UsageAlerts, _ = usage.ListUsageAlerts(ctx, user, 25)
			}
		}
		if s.capabilities != nil {
			data.Capabilities, _ = s.capabilities.RuntimeCapabilities(ctx)
		}
		return data, nil
	}
	if s.queries == nil {
		return Data{}, errors.New("dashboard queries are not configured")
	}

	sites, err := s.queries.ListSites(ctx)
	if err != nil {
		return Data{}, err
	}
	databases, err := s.queries.ListDatabases(ctx)
	if err != nil {
		return Data{}, err
	}
	jobs := []Job(nil)
	jobLoadError := ""
	if s.jobs != nil {
		jobs, err = s.jobs.ListRecentJobs(ctx, DefaultRecentJobLimit)
		if err != nil {
			jobs = nil
			jobLoadError = "recent jobs unavailable"
		}
	}
	phase6 := Phase6Data{}
	phase6Error := ""
	if s.phase6 != nil {
		phase6, err = s.phase6.GetPhase6(ctx)
		if err != nil {
			phase6 = Phase6Data{}
			phase6Error = "phase6 operations unavailable"
		}
	}
	quotas := []controlquota.Summary(nil)
	quotaLoadError := ""
	if s.quotas != nil {
		quotas, err = s.quotas.ListAccountQuotas(ctx)
		if err != nil {
			quotas = nil
			quotaLoadError = "account quotas unavailable"
		}
	}
	usageItems := []types.SubscriptionUsage(nil)
	usageAlerts := []types.UsageAlert(nil)
	if usage, ok := s.quotas.(UsageReader); ok {
		usageItems, _ = usage.ListSubscriptionUsage(ctx, user)
		usageAlerts, _ = usage.ListUsageAlerts(ctx, user, 25)
	}
	capabilities := types.RuntimeCapabilities{}
	if s.capabilities != nil {
		capabilities, _ = s.capabilities.RuntimeCapabilities(ctx)
	}
	plans := []controlquota.Plan(nil)
	settings := controlquota.Settings{}
	committedDiskMB := 0
	planLoadError := ""
	if s.quotas != nil {
		plans, err = s.quotas.ListPlans(ctx)
		if err != nil {
			plans = nil
			planLoadError = "plans unavailable"
		} else if settings, err = s.quotas.GetSettings(ctx); err != nil {
			planLoadError = "plan settings unavailable"
		} else if committedDiskMB, err = s.quotas.CommittedAllocationMB(ctx); err != nil {
			planLoadError = "committed allocation unavailable"
		}
	}
	customers := []types.Customer(nil)
	subscriptions := []types.SubscriptionSummary(nil)
	if s.quotas != nil {
		customers, err = s.quotas.ListCustomers(ctx)
		if err != nil {
			customers = nil
			if planLoadError == "" {
				planLoadError = "customers unavailable"
			}
		}
		subscriptions, err = s.quotas.ListSubscriptionSummaries(ctx)
		if err != nil {
			subscriptions = nil
			if planLoadError == "" {
				planLoadError = "subscriptions unavailable"
			}
		}
	}
	auditEvents := []types.AuditEvent(nil)
	if s.audit != nil {
		auditEvents, _ = s.audit.ListAudit(ctx, user, 50)
	}
	resellers := []types.Reseller(nil)
	resellerPlans := []types.ResellerPlan(nil)
	addonPlans := []types.AddonPlan(nil)
	if provider, ok := s.quotas.(ProviderReader); ok {
		resellers, _ = provider.ListResellers(ctx)
		resellerPlans, _ = provider.ListResellerPlans(ctx)
		addonPlans, _ = provider.ListAddonPlans(ctx)
	}

	data := Data{
		Sites:             make([]Site, 0, len(sites)),
		Databases:         make([]Database, 0, len(databases)),
		Jobs:              jobs,
		JobLoadError:      jobLoadError,
		Phase6:            phase6,
		Phase6Error:       phase6Error,
		Quotas:            quotas,
		QuotaLoadError:    quotaLoadError,
		Plans:             plans,
		Customers:         customers,
		Subscriptions:     subscriptions,
		Settings:          settings,
		CommittedDiskMB:   committedDiskMB,
		PlanLoadError:     planLoadError,
		AuditEvents:       auditEvents,
		Resellers:         resellers,
		ResellerPlans:     resellerPlans,
		AddonPlans:        addonPlans,
		SubscriptionUsage: usageItems,
		UsageAlerts:       usageAlerts,
		Capabilities:      capabilities,
	}
	for _, site := range sites {
		data.Sites = append(data.Sites, Site{
			ID:                   site.ID,
			Username:             site.Username,
			Domain:               site.Domain,
			PHPVersion:           site.PhpVersion,
			Status:               site.Status,
			LastError:            site.LastError,
			TLSStatus:            site.TlsStatus,
			TLSIssuer:            site.TlsIssuer,
			TLSExpiresAt:         NullableTime{Time: site.TlsExpiresAt.Time, Valid: site.TlsExpiresAt.Valid},
			TLSLastError:         site.TlsLastError,
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
	return data, nil
}
