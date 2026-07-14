package provision

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeQuotaStore struct {
	limits          controlquota.Limits
	hasLimits       bool
	usage           controlquota.Usage
	upserted        controlquota.Limits
	upsertCalled    bool
	getLimitCalls   int
	lastLimitUserID int64
	lastLimitSubID  int64
	lastUsageSubID  int64
}

func (s *fakeQuotaStore) GetLimits(ctx context.Context, userID int64) (controlquota.Limits, bool, error) {
	s.getLimitCalls++
	s.lastLimitUserID = userID
	if !s.hasLimits {
		return controlquota.Limits{}, false, nil
	}
	s.limits.UserID = userID
	return s.limits, true, nil
}

func (s *fakeQuotaStore) GetUsage(ctx context.Context, userID int64) (controlquota.Usage, error) {
	s.usage.UserID = userID
	return s.usage, nil
}

func (s *fakeQuotaStore) GetLimitsForSubscription(ctx context.Context, subscriptionID int64) (controlquota.Limits, bool, error) {
	s.getLimitCalls++
	s.lastLimitSubID = subscriptionID
	if !s.hasLimits {
		return controlquota.Limits{}, false, nil
	}
	s.limits.SubscriptionID = subscriptionID
	return s.limits, true, nil
}

func (s *fakeQuotaStore) GetUsageForSubscription(ctx context.Context, subscriptionID int64) (controlquota.Usage, error) {
	s.lastUsageSubID = subscriptionID
	s.usage.SubscriptionID = subscriptionID
	return s.usage, nil
}

func (s *fakeQuotaStore) UpsertLimits(ctx context.Context, limits controlquota.Limits) error {
	s.upserted = limits
	s.upsertCalled = true
	return nil
}

func (s *fakeQuotaStore) ListAccountQuotas(ctx context.Context) ([]controlquota.Summary, error) {
	return nil, nil
}

func (s *fakeQuotaStore) GetAccountQuotaSummary(ctx context.Context, userID int64) (controlquota.Summary, error) {
	return controlquota.Summary{UserID: userID}, nil
}

func TestManagerRejectsSiteCreationWithoutActiveSubscription(t *testing.T) {
	repo := &fakeSiteRepository{}
	quotas := &fakeQuotaStore{}
	manager := NewManager(repo, WithQuotaStore(quotas))

	_, err := manager.CreateSite(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, types.CreateSiteReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
	})
	if !errors.Is(err, controlquota.ErrNoActiveSubscription) {
		t.Fatalf("CreateSite error = %v, want no active subscription", err)
	}
	if repo.req != (types.CreateSiteReq{}) {
		t.Fatalf("repository was called despite missing subscription: %#v", repo.req)
	}
}

func TestManagerCreatesSiteForSelectedSubscribedCustomer(t *testing.T) {
	repo := &fakeSiteRepository{}
	quotas := &fakeQuotaStore{
		hasLimits: true,
		limits: controlquota.Limits{
			MaxSites:          -1,
			SiteDiskQuotaMB:   512,
			PHPFPMMaxChildren: 3,
			PHPMemoryMB:       128,
		},
	}
	manager := NewManager(repo, WithQuotaStore(quotas))

	_, err := manager.CreateSiteFor(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, 42, types.CreateSiteReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
	})
	if err != nil {
		t.Fatalf("CreateSiteFor returned error: %v", err)
	}
	if quotas.lastLimitUserID != 42 {
		t.Fatalf("quota user = %d, want selected customer 42", quotas.lastLimitUserID)
	}
	if repo.ownerID != 42 {
		t.Fatalf("repository owner = %d, want selected customer 42", repo.ownerID)
	}
}

func TestManagerCreatesSiteForSelectedSubscription(t *testing.T) {
	repo := &fakeSiteRepository{}
	quotas := &fakeQuotaStore{
		hasLimits: true,
		limits: controlquota.Limits{
			CustomerID:        7,
			MaxSites:          -1,
			SiteDiskQuotaMB:   512,
			PHPFPMMaxChildren: 3,
			PHPMemoryMB:       128,
		},
	}
	manager := NewManager(repo, WithQuotaStore(quotas))

	_, err := manager.CreateSiteForSubscription(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, 44, types.CreateSiteReq{
		Username:       "npdemo",
		Domain:         "example.test",
		PHPVersion:     "8.3",
		SubscriptionID: 44,
	})
	if err != nil {
		t.Fatalf("CreateSiteForSubscription returned error: %v", err)
	}
	if quotas.lastLimitSubID != 44 || quotas.lastUsageSubID != 44 {
		t.Fatalf("quota subscription calls limit=%d usage=%d, want 44", quotas.lastLimitSubID, quotas.lastUsageSubID)
	}
	if repo.req.SubscriptionID != 44 {
		t.Fatalf("repository subscription = %d, want 44", repo.req.SubscriptionID)
	}
	if repo.ownerID != 1 {
		t.Fatalf("legacy ownerID = %d, want actor 1", repo.ownerID)
	}
}

func TestManagerRejectsSiteCreationAtQuotaAndDoesNotCallRepository(t *testing.T) {
	repo := &fakeSiteRepository{}
	quotas := &fakeQuotaStore{
		hasLimits: true,
		limits:    controlquota.Limits{MaxSites: 1, SiteDiskQuotaMB: 512, PHPFPMMaxChildren: 3, PHPMemoryMB: 128},
		usage:     controlquota.Usage{Sites: 1},
	}
	manager := NewManager(repo, WithQuotaStore(quotas))

	_, err := manager.CreateSite(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, types.CreateSiteReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
	})
	if !errors.Is(err, controlquota.ErrExceeded) {
		t.Fatalf("CreateSite error = %v, want quota exceeded", err)
	}
	if repo.req != (types.CreateSiteReq{}) {
		t.Fatalf("repository was called despite quota failure: %#v", repo.req)
	}
}

func TestManagerDerivesSiteResourceLimitsFromQuota(t *testing.T) {
	repo := &fakeSiteRepository{}
	quotas := &fakeQuotaStore{
		hasLimits: true,
		limits:    controlquota.Limits{MaxSites: 2, SiteDiskQuotaMB: 768, PHPFPMMaxChildren: 4, PHPMemoryMB: 192},
		usage:     controlquota.Usage{Sites: 1},
	}
	manager := NewManager(repo, WithQuotaStore(quotas))

	_, err := manager.CreateSite(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, types.CreateSiteReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
	})
	if err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}
	want := types.SiteResourceLimits{DiskQuotaMB: 768, PHPFPMMaxChildren: 4, PHPMemoryMB: 192}
	if repo.req.Limits != want {
		t.Fatalf("derived limits = %#v, want %#v", repo.req.Limits, want)
	}
}

func TestManagerRejectsDatabaseCreationAtQuota(t *testing.T) {
	repo := &fakeDatabaseRepository{}
	quotas := &fakeQuotaStore{
		hasLimits: true,
		limits:    controlquota.Limits{MaxDatabases: 1},
		usage:     controlquota.Usage{Databases: 1},
	}
	manager := NewManager(nil, WithDatabaseRepository(repo), WithQuotaStore(quotas), WithPasswordGenerator(func() (string, error) {
		return "generated-password", nil
	}))

	_, err := manager.CreateDatabase(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, types.CreateDatabaseReq{
		Engine: types.EngineMariaDB,
		DBName: "np_demo",
		DBUser: "np_demo_user",
	})
	if !errors.Is(err, controlquota.ErrExceeded) {
		t.Fatalf("CreateDatabase error = %v, want quota exceeded", err)
	}
	if repo.req != (types.CreateDatabaseReq{}) {
		t.Fatalf("repository was called despite quota failure: %#v", repo.req)
	}
}

func TestManagerRejectsBackupCreationAtCountAndStorageQuota(t *testing.T) {
	tests := []struct {
		name   string
		limits controlquota.Limits
		usage  controlquota.Usage
	}{
		{
			name:   "backup count",
			limits: controlquota.Limits{MaxBackups: 1, BackupStorageMB: 100},
			usage:  controlquota.Usage{Backups: 1},
		},
		{
			name:   "backup storage",
			limits: controlquota.Limits{MaxBackups: 10, BackupStorageMB: 1},
			usage:  controlquota.Usage{BackupStorageBytes: 1024 * 1024},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakePhase6Repository{}
			quotas := &fakeQuotaStore{hasLimits: true, limits: tt.limits, usage: tt.usage}
			manager := NewManager(nil, WithPhase6Repository(repo), WithQuotaStore(quotas))

			_, err := manager.CreateBackup(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, types.CreateBackupReq{Domain: "example.test"})
			if !errors.Is(err, controlquota.ErrExceeded) {
				t.Fatalf("CreateBackup error = %v, want quota exceeded", err)
			}
			if repo.backupReq.Domain != "" {
				t.Fatalf("repository was called despite quota failure: %#v", repo.backupReq)
			}
		})
	}
}

func TestManagerUpsertsQuotaForAdminsOnly(t *testing.T) {
	quotas := &fakeQuotaStore{}
	manager := NewManager(nil, WithQuotaStore(quotas))
	limits := controlquota.Limits{UserID: 2, MaxSites: 3, MaxDatabases: 4, MaxBackups: 5, SiteDiskQuotaMB: 512, PHPFPMMaxChildren: 3, PHPMemoryMB: 128}

	if err := manager.UpsertAccountQuota(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleClient}, limits); !errors.Is(err, ErrForbidden) {
		t.Fatalf("client UpsertAccountQuota error = %v, want forbidden", err)
	}
	if quotas.upsertCalled {
		t.Fatal("client quota upsert reached store")
	}
	if err := manager.UpsertAccountQuota(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, limits); err != nil {
		t.Fatalf("admin UpsertAccountQuota returned error: %v", err)
	}
	if quotas.upserted != limits {
		t.Fatalf("upserted limits = %#v, want %#v", quotas.upserted, limits)
	}
}
