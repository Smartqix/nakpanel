package quota

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeStore struct {
	limits    Limits
	hasLimits bool
	usage     Usage
}

func (s fakeStore) GetLimits(ctx context.Context, userID int64) (Limits, bool, error) {
	s.limits.UserID = userID
	return s.limits, s.hasLimits, nil
}

func (s fakeStore) GetUsage(ctx context.Context, userID int64) (Usage, error) {
	s.usage.UserID = userID
	return s.usage, nil
}

func (s fakeStore) GetLimitsForSubscription(ctx context.Context, subscriptionID int64) (Limits, bool, error) {
	s.limits.SubscriptionID = subscriptionID
	return s.limits, s.hasLimits, nil
}

func (s fakeStore) GetUsageForSubscription(ctx context.Context, subscriptionID int64) (Usage, error) {
	s.usage.SubscriptionID = subscriptionID
	return s.usage, nil
}

func (s fakeStore) UpsertLimits(ctx context.Context, limits Limits) error {
	return nil
}

func (s fakeStore) ListAccountQuotas(ctx context.Context) ([]Summary, error) {
	return nil, nil
}

func (s fakeStore) GetAccountQuotaSummary(ctx context.Context, userID int64) (Summary, error) {
	return Summary{}, nil
}

func TestMissingActiveSubscriptionDeniesProvisioning(t *testing.T) {
	store := fakeStore{}

	if _, err := SiteLimits(context.Background(), store, 2); !errors.Is(err, ErrNoActiveSubscription) {
		t.Fatalf("SiteLimits error = %v, want ErrNoActiveSubscription", err)
	}
	if err := CheckDatabase(context.Background(), store, 2); !errors.Is(err, ErrNoActiveSubscription) {
		t.Fatalf("CheckDatabase error = %v, want ErrNoActiveSubscription", err)
	}
	if err := CheckBackup(context.Background(), store, 2); !errors.Is(err, ErrNoActiveSubscription) {
		t.Fatalf("CheckBackup error = %v, want ErrNoActiveSubscription", err)
	}
}

func TestUnlimitedNegativeLimitsAllowProvisioningWithAgentDefaults(t *testing.T) {
	store := fakeStore{
		hasLimits: true,
		limits: Limits{
			MaxSites:          -1,
			MaxDatabases:      -1,
			MaxBackups:        -1,
			BackupStorageMB:   -1,
			SiteDiskQuotaMB:   -1,
			PHPFPMMaxChildren: -1,
			PHPMemoryMB:       -1,
		},
		usage: Usage{Sites: 100, Databases: 100, Backups: 100, BackupStorageBytes: 1024 * 1024 * 1024},
	}

	limits, err := SiteLimits(context.Background(), store, 2)
	if err != nil {
		t.Fatalf("SiteLimits returned error: %v", err)
	}
	if limits != (types.SiteResourceLimits{}) {
		t.Fatalf("unlimited site limits = %#v, want agent defaults", limits)
	}
	if err := CheckDatabase(context.Background(), store, 2); err != nil {
		t.Fatalf("CheckDatabase returned error: %v", err)
	}
	if err := CheckBackup(context.Background(), store, 2); err != nil {
		t.Fatalf("CheckBackup returned error: %v", err)
	}
}

func TestExplicitZeroSiteResourceLimitsDenyProvisioning(t *testing.T) {
	tests := []struct {
		name   string
		limits Limits
	}{
		{
			name:   "disk",
			limits: Limits{MaxSites: -1, SiteDiskQuotaMB: 0, PHPFPMMaxChildren: 3, PHPMemoryMB: 128},
		},
		{
			name:   "children",
			limits: Limits{MaxSites: -1, SiteDiskQuotaMB: 512, PHPFPMMaxChildren: 0, PHPMemoryMB: 128},
		},
		{
			name:   "memory",
			limits: Limits{MaxSites: -1, SiteDiskQuotaMB: 512, PHPFPMMaxChildren: 3, PHPMemoryMB: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := fakeStore{hasLimits: true, limits: tt.limits}
			if _, err := SiteLimits(context.Background(), store, 2); !errors.Is(err, ErrExceeded) {
				t.Fatalf("SiteLimits error = %v, want ErrExceeded", err)
			}
		})
	}
}

func TestZeroDatabaseAndBackupLimitsDenyProvisioning(t *testing.T) {
	store := fakeStore{
		hasLimits: true,
		limits:    Limits{MaxDatabases: 0, MaxBackups: 0, BackupStorageMB: -1},
	}

	if err := CheckDatabase(context.Background(), store, 2); !errors.Is(err, ErrExceeded) {
		t.Fatalf("CheckDatabase error = %v, want ErrExceeded", err)
	}
	if err := CheckBackup(context.Background(), store, 2); !errors.Is(err, ErrExceeded) {
		t.Fatalf("CheckBackup error = %v, want ErrExceeded", err)
	}
}
