package dashboard

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/store"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeQuerier struct {
	sites     []store.Site
	databases []store.Database
}

func (q *fakeQuerier) ListSites(ctx context.Context) ([]store.Site, error) {
	return q.sites, nil
}

func (q *fakeQuerier) ListDatabases(ctx context.Context) ([]store.Database, error) {
	return q.databases, nil
}

type fakeJobReader struct {
	jobs   []Job
	err    error
	limit  int
	called bool
}

func (r *fakeJobReader) ListRecentJobs(ctx context.Context, limit int) ([]Job, error) {
	r.called = true
	r.limit = limit
	return r.jobs, r.err
}

type fakePhase6Reader struct {
	data   Phase6Data
	err    error
	called bool
}

func (r *fakePhase6Reader) GetPhase6(ctx context.Context) (Phase6Data, error) {
	r.called = true
	return r.data, r.err
}

type fakeQuotaReader struct {
	summaries       []controlquota.Summary
	summary         controlquota.Summary
	plans           []controlquota.Plan
	customers       []types.Customer
	subscriptions   []types.SubscriptionSummary
	settings        controlquota.Settings
	committed       int
	err             error
	listCalled      bool
	getCalled       bool
	plansCalled     bool
	settingsCalled  bool
	committedCalled bool
	userID          int64
}

func (r *fakeQuotaReader) ListAccountQuotas(ctx context.Context) ([]controlquota.Summary, error) {
	r.listCalled = true
	return r.summaries, r.err
}

func (r *fakeQuotaReader) GetAccountQuotaSummary(ctx context.Context, userID int64) (controlquota.Summary, error) {
	r.getCalled = true
	r.userID = userID
	return r.summary, r.err
}

func (r *fakeQuotaReader) ListPlans(ctx context.Context) ([]controlquota.Plan, error) {
	r.plansCalled = true
	return r.plans, r.err
}

func (r *fakeQuotaReader) ListCustomers(ctx context.Context) ([]types.Customer, error) {
	return r.customers, r.err
}

func (r *fakeQuotaReader) ListSubscriptionSummaries(ctx context.Context) ([]types.SubscriptionSummary, error) {
	return r.subscriptions, r.err
}

func (r *fakeQuotaReader) ListSubscriptionSummariesForUser(ctx context.Context, userID int64) ([]types.SubscriptionSummary, error) {
	r.userID = userID
	return r.subscriptions, r.err
}

func (r *fakeQuotaReader) GetSettings(ctx context.Context) (controlquota.Settings, error) {
	r.settingsCalled = true
	return r.settings, r.err
}

func (r *fakeQuotaReader) CommittedAllocationMB(ctx context.Context) (int, error) {
	r.committedCalled = true
	return r.committed, r.err
}

func TestStoreMapsSitesAndDatabases(t *testing.T) {
	expiresAt := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	querier := &fakeQuerier{
		sites: []store.Site{{
			ID:           7,
			Username:     "npdemo",
			Domain:       "example.test",
			PhpVersion:   "8.3",
			Status:       "active",
			LastError:    "",
			TlsStatus:    "active",
			TlsIssuer:    "local-self-signed",
			TlsExpiresAt: sql.NullTime{Time: expiresAt, Valid: true},
			TlsLastError: "",
		}},
		databases: []store.Database{{
			ID:        11,
			Engine:    "mariadb",
			DbName:    "np_demo",
			DbUser:    "np_demo_user",
			Status:    "failed",
			LastError: "access denied",
		}},
	}
	data, err := NewStore(querier).GetDashboard(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin})
	if err != nil {
		t.Fatalf("GetDashboard returned error: %v", err)
	}

	if len(data.Sites) != 1 {
		t.Fatalf("sites length = %d, want 1", len(data.Sites))
	}
	site := data.Sites[0]
	if site.Domain != "example.test" || site.Username != "npdemo" || site.PHPVersion != "8.3" {
		t.Fatalf("site = %#v, want mapped site identity", site)
	}
	if site.Status != "active" || site.TLSStatus != "active" || site.TLSIssuer != "local-self-signed" {
		t.Fatalf("site status = %#v, want active site and TLS", site)
	}
	if !site.TLSExpiresAt.Valid || !site.TLSExpiresAt.Time.Equal(expiresAt) {
		t.Fatalf("site TLS expiry = %#v, want %v", site.TLSExpiresAt, expiresAt)
	}

	if len(data.Databases) != 1 {
		t.Fatalf("databases length = %d, want 1", len(data.Databases))
	}
	database := data.Databases[0]
	if database.Name != "np_demo" || database.User != "np_demo_user" || database.Engine != "mariadb" {
		t.Fatalf("database = %#v, want mapped database identity", database)
	}
	if database.Status != "failed" || database.LastError != "access denied" {
		t.Fatalf("database status = %#v, want failed database with error", database)
	}
}

func TestStoreIncludesQuotaSummariesForAdmins(t *testing.T) {
	reader := &fakeQuotaReader{
		summaries: []controlquota.Summary{{
			UserID:   2,
			Email:    "client@nakpanel.test",
			Role:     "client",
			HasQuota: true,
			Limits:   controlquota.Limits{UserID: 2, MaxSites: 2, MaxDatabases: 1, MaxBackups: 3, SiteDiskQuotaMB: 512, PHPFPMMaxChildren: 3, PHPMemoryMB: 128},
			Usage:    controlquota.Usage{UserID: 2, Sites: 1, Databases: 1, Backups: 2, BackupStorageBytes: 2048},
		}},
		plans:     []controlquota.Plan{{ID: 10, Name: "Starter", IsActive: true}},
		settings:  controlquota.Settings{OversellPolicy: controlquota.OversellPolicyWarn, ServerDiskCapacityMB: 100},
		committed: 50,
	}

	data, err := NewStore(&fakeQuerier{}, WithQuotaReader(reader)).GetDashboard(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin})
	if err != nil {
		t.Fatalf("GetDashboard returned error: %v", err)
	}
	if !reader.listCalled || reader.getCalled || !reader.plansCalled || !reader.settingsCalled || !reader.committedCalled {
		t.Fatalf("quota reader calls list=%v get=%v plans=%v settings=%v committed=%v, want admin planning data", reader.listCalled, reader.getCalled, reader.plansCalled, reader.settingsCalled, reader.committedCalled)
	}
	if len(data.Quotas) != 1 || data.Quotas[0].Email != "client@nakpanel.test" || data.Quotas[0].Usage.Sites != 1 {
		t.Fatalf("quota summaries = %#v", data.Quotas)
	}
	if len(data.Plans) != 1 || data.Plans[0].Name != "Starter" || data.Settings.OversellPolicy != controlquota.OversellPolicyWarn || data.CommittedDiskMB != 50 {
		t.Fatalf("plan dashboard data = plans:%#v settings:%#v committed:%d", data.Plans, data.Settings, data.CommittedDiskMB)
	}
}

func TestStoreIncludesOwnQuotaForNonAdmins(t *testing.T) {
	reader := &fakeQuotaReader{
		summary: controlquota.Summary{
			UserID: 2,
			Email:  "client@nakpanel.test",
			Role:   "client",
			Usage:  controlquota.Usage{UserID: 2, Sites: 1},
		},
	}

	data, err := NewStore(&fakeQuerier{}, WithQuotaReader(reader)).GetDashboard(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient})
	if err != nil {
		t.Fatalf("GetDashboard returned error: %v", err)
	}
	if !reader.getCalled || reader.userID != 2 || reader.listCalled || reader.plansCalled {
		t.Fatalf("quota reader calls list=%v get=%v plans=%v user=%d, want own quota only", reader.listCalled, reader.getCalled, reader.plansCalled, reader.userID)
	}
	if len(data.Quotas) != 1 || data.Quotas[0].UserID != 2 || data.Quotas[0].Usage.Sites != 1 {
		t.Fatalf("own quota = %#v", data.Quotas)
	}
}

func TestStoreIncludesPhase6OperationsForAdmins(t *testing.T) {
	createdAt := time.Date(2026, 7, 7, 13, 0, 0, 0, time.UTC)
	reader := &fakePhase6Reader{
		data: Phase6Data{
			Backups: []Backup{{
				ID:          51,
				TargetName:  "example.test",
				Status:      "active",
				ArchivePath: "/var/lib/nakpanel/backups/example.tar.gz",
				SizeBytes:   512,
				CreatedAt:   createdAt,
			}},
			Restores: []RestoreRun{{
				ID:         52,
				BackupID:   51,
				TargetName: "example.test",
				Status:     "blocked",
				LastError:  "operator approval required",
				CreatedAt:  createdAt,
			}},
			WebmailHosts: []WebmailHost{{
				ID:         53,
				Hostname:   "webmail.example.test",
				Status:     "active",
				ConfigPath: "/etc/nginx/sites-available/webmail.example.test.conf",
				CreatedAt:  createdAt,
			}},
			DNSZones: []DNSZone{{
				ID:        54,
				Domain:    "example.test",
				Address:   "192.0.2.10",
				Serial:    2026070701,
				Status:    "active",
				ZonePath:  "/etc/bind/nakpanel/zones/db.example.test",
				CreatedAt: createdAt,
			}},
			Reconciliations: []ReconciliationRun{{
				ID:         55,
				Status:     "active",
				SitesTotal: 1,
				SitesOK:    1,
				CreatedAt:  createdAt,
			}},
		},
	}

	data, err := NewStore(&fakeQuerier{}, WithPhase6Reader(reader)).GetDashboard(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin})
	if err != nil {
		t.Fatalf("GetDashboard returned error: %v", err)
	}
	if !reader.called {
		t.Fatal("phase6 reader was not called for admin dashboard")
	}
	if len(data.Phase6.Backups) != 1 || len(data.Phase6.Restores) != 1 || len(data.Phase6.WebmailHosts) != 1 || len(data.Phase6.DNSZones) != 1 || len(data.Phase6.Reconciliations) != 1 {
		t.Fatalf("phase6 data not mapped: %#v", data.Phase6)
	}
	if data.Phase6.Restores[0].LastError != "operator approval required" {
		t.Fatalf("restore record = %#v, want mapped last error", data.Phase6.Restores[0])
	}
}

func TestStoreSkipsPhase6ForNonAdmins(t *testing.T) {
	reader := &fakePhase6Reader{data: Phase6Data{Backups: []Backup{{ID: 51}}}}

	data, err := NewStore(&fakeQuerier{}, WithPhase6Reader(reader)).GetDashboard(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient})
	if err != nil {
		t.Fatalf("GetDashboard returned error: %v", err)
	}
	if reader.called {
		t.Fatal("non-admin dashboard loaded phase6 data")
	}
	if len(data.Phase6.Backups) != 0 {
		t.Fatalf("phase6 backups length = %d, want 0", len(data.Phase6.Backups))
	}
}

func TestStoreKeepsInventoryWhenPhase6Fails(t *testing.T) {
	reader := &fakePhase6Reader{err: errors.New("phase6 unavailable")}
	querier := &fakeQuerier{sites: []store.Site{{Domain: "example.test", Status: "active"}}}

	data, err := NewStore(querier, WithPhase6Reader(reader)).GetDashboard(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin})
	if err != nil {
		t.Fatalf("GetDashboard returned error: %v", err)
	}
	if !reader.called {
		t.Fatal("phase6 reader was not called")
	}
	if len(data.Sites) != 1 {
		t.Fatalf("sites length = %d, want inventory preserved", len(data.Sites))
	}
	if data.Phase6Error != "phase6 operations unavailable" {
		t.Fatalf("Phase6Error = %q, want phase6 operations unavailable", data.Phase6Error)
	}
}

func TestStoreIncludesRecentJobsForAdmins(t *testing.T) {
	createdAt := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	reader := &fakeJobReader{
		jobs: []Job{{
			ID:          41,
			Kind:        "issue_cert",
			State:       "discarded",
			Queue:       "default",
			Attempt:     3,
			MaxAttempts: 3,
			Target:      "example.test",
			LastError:   "acme failed",
			CreatedAt:   createdAt,
		}},
	}

	data, err := NewStore(&fakeQuerier{}, WithJobReader(reader)).GetDashboard(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin})
	if err != nil {
		t.Fatalf("GetDashboard returned error: %v", err)
	}
	if !reader.called || reader.limit != DefaultRecentJobLimit {
		t.Fatalf("job reader called=%v limit=%d, want limit %d", reader.called, reader.limit, DefaultRecentJobLimit)
	}
	if len(data.Jobs) != 1 {
		t.Fatalf("jobs length = %d, want 1", len(data.Jobs))
	}
	job := data.Jobs[0]
	if job.Kind != "issue_cert" || job.State != "discarded" || job.Target != "example.test" {
		t.Fatalf("job = %#v, want mapped issue_cert job", job)
	}
	if job.Attempt != 3 || job.MaxAttempts != 3 || job.LastError != "acme failed" || !job.CreatedAt.Equal(createdAt) {
		t.Fatalf("job details = %#v, want attempts/error/created_at", job)
	}
}

func TestStoreSkipsRecentJobsForNonAdmins(t *testing.T) {
	reader := &fakeJobReader{jobs: []Job{{ID: 41, Kind: "issue_cert"}}}

	data, err := NewStore(&fakeQuerier{}, WithJobReader(reader)).GetDashboard(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient})
	if err != nil {
		t.Fatalf("GetDashboard returned error: %v", err)
	}
	if reader.called {
		t.Fatal("non-admin dashboard loaded recent jobs")
	}
	if len(data.Jobs) != 0 {
		t.Fatalf("jobs length = %d, want 0", len(data.Jobs))
	}
}

func TestStoreKeepsInventoryWhenRecentJobsFail(t *testing.T) {
	reader := &fakeJobReader{err: errors.New("river unavailable")}
	querier := &fakeQuerier{
		sites:     []store.Site{{Domain: "example.test", Status: "active"}},
		databases: []store.Database{{DbName: "np_demo", Status: "active"}},
	}

	data, err := NewStore(querier, WithJobReader(reader)).GetDashboard(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin})
	if err != nil {
		t.Fatalf("GetDashboard returned error: %v", err)
	}
	if !reader.called {
		t.Fatal("job reader was not called")
	}
	if len(data.Sites) != 1 || len(data.Databases) != 1 {
		t.Fatalf("inventory lengths = sites:%d databases:%d, want 1 each", len(data.Sites), len(data.Databases))
	}
	if data.JobLoadError != "recent jobs unavailable" {
		t.Fatalf("JobLoadError = %q, want recent jobs unavailable", data.JobLoadError)
	}
	if len(data.Jobs) != 0 {
		t.Fatalf("jobs length = %d, want 0 on job reader error", len(data.Jobs))
	}
}
