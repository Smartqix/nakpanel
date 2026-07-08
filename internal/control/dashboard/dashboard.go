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

type Store struct {
	queries Querier
	jobs    JobReader
	phase6  Phase6Reader
	quotas  QuotaReader
}

type Data struct {
	Sites           []Site
	Databases       []Database
	Jobs            []Job
	JobLoadError    string
	Phase6          Phase6Data
	Phase6Error     string
	Quotas          []controlquota.Summary
	QuotaLoadError  string
	Plans           []controlquota.Plan
	Customers       []types.Customer
	Subscriptions   []types.SubscriptionSummary
	Settings        controlquota.Settings
	CommittedDiskMB int
	PlanLoadError   string
	Notice          string
}

type Site struct {
	ID           int64
	Username     string
	Domain       string
	PHPVersion   string
	Status       string
	LastError    string
	TLSStatus    string
	TLSIssuer    string
	TLSExpiresAt NullableTime
	TLSLastError string
}

type Database struct {
	ID        int64
	Engine    string
	Name      string
	User      string
	Status    string
	LastError string
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
	Reconciliations []ReconciliationRun
}

type Backup struct {
	ID          int64
	TargetName  string
	Status      string
	ArchivePath string
	SizeBytes   int64
	LastError   string
	CreatedAt   time.Time
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

	data := Data{
		Sites:           make([]Site, 0, len(sites)),
		Databases:       make([]Database, 0, len(databases)),
		Jobs:            jobs,
		JobLoadError:    jobLoadError,
		Phase6:          phase6,
		Phase6Error:     phase6Error,
		Quotas:          quotas,
		QuotaLoadError:  quotaLoadError,
		Plans:           plans,
		Customers:       customers,
		Subscriptions:   subscriptions,
		Settings:        settings,
		CommittedDiskMB: committedDiskMB,
		PlanLoadError:   planLoadError,
	}
	for _, site := range sites {
		data.Sites = append(data.Sites, Site{
			ID:           site.ID,
			Username:     site.Username,
			Domain:       site.Domain,
			PHPVersion:   site.PhpVersion,
			Status:       site.Status,
			LastError:    site.LastError,
			TLSStatus:    site.TlsStatus,
			TLSIssuer:    site.TlsIssuer,
			TLSExpiresAt: NullableTime{Time: site.TlsExpiresAt.Time, Valid: site.TlsExpiresAt.Valid},
			TLSLastError: site.TlsLastError,
		})
	}
	for _, database := range databases {
		data.Databases = append(data.Databases, Database{
			ID:        database.ID,
			Engine:    database.Engine,
			Name:      database.DbName,
			User:      database.DbUser,
			Status:    database.Status,
			LastError: database.LastError,
		})
	}
	return data, nil
}
