package quota

import (
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestComposeEntitlementsAppliesAddonRules(t *testing.T) {
	base := types.SubscriptionEntitlements{
		PlanName: "Business", DiskMB: 1000, MaxSites: 2, MaxDatabases: 3,
		BandwidthMB: 5000, MaxMailboxes: 2, BackupRetentionDays: 7,
		PHPAllowlist: "8.3, 8.2", PHPFPMMaxChildren: 4, PHPMemoryMB: 128,
		SiteDiskQuotaMB: 500, MaxBackups: 2, BackupStorageMB: 250,
		ServicePresets: types.PlanServicePresets{SchemaVersion: 1,
			PHP:          types.PHPPreset{MaxExecutionSeconds: 30},
			Applications: types.ApplicationsPreset{Allowed: []string{"wordpress"}}},
	}
	addons := []types.AddonPlan{{
		Name: "Growth", IsActive: true, Revision: 3,
		Entitlements: types.SubscriptionEntitlements{
			DiskMB: 500, MaxSites: 3, MaxDatabases: 1, BandwidthMB: 1000,
			MaxMailboxes: 4, BackupRetentionDays: 30, PHPAllowlist: "8.1,8.3",
			PHPFPMMaxChildren: 12, PHPMemoryMB: 256, SiteDiskQuotaMB: 900,
			MaxBackups: 1, BackupStorageMB: 750, AllowDNS: true,
			ServicePresets: types.PlanServicePresets{SchemaVersion: 1,
				PHP:          types.PHPPreset{MaxExecutionSeconds: 60, AllowURLFOpen: true},
				Applications: types.ApplicationsPreset{Allowed: []string{"drupal", "wordpress"}}},
		},
	}}

	got, err := ComposeEntitlements(base, addons)
	if err != nil {
		t.Fatalf("ComposeEntitlements: %v", err)
	}
	if got.DiskMB != 1500 || got.MaxSites != 5 || got.MaxDatabases != 4 || got.BackupStorageMB != 1000 {
		t.Fatalf("aggregate limits = %#v", got)
	}
	if got.PHPFPMMaxChildren != 12 || got.PHPMemoryMB != 256 || got.SiteDiskQuotaMB != 900 {
		t.Fatalf("highest-value limits = %#v", got)
	}
	if !got.AllowDNS || got.AllowSSH {
		t.Fatalf("permission composition = dns:%v ssh:%v", got.AllowDNS, got.AllowSSH)
	}
	if got.PHPAllowlist != "8.1,8.2,8.3" {
		t.Fatalf("PHPAllowlist = %q", got.PHPAllowlist)
	}
	if got.ServicePresets.PHP.MaxExecutionSeconds != 60 || !got.ServicePresets.PHP.AllowURLFOpen {
		t.Fatalf("PHP preset increments = %#v", got.ServicePresets.PHP)
	}
	if strings.Join(got.ServicePresets.Applications.Allowed, ",") != "drupal,wordpress" {
		t.Fatalf("application preset increments = %#v", got.ServicePresets.Applications)
	}
}

func TestComposeEntitlementsUnlimitedAndFailureSemantics(t *testing.T) {
	base := types.SubscriptionEntitlements{PlanName: "Starter", DiskMB: 100, MaxSites: 1}
	unlimited := types.AddonPlan{Name: "Unlimited disk", IsActive: true, Entitlements: types.SubscriptionEntitlements{DiskMB: -1}}
	got, err := ComposeEntitlements(base, []types.AddonPlan{unlimited})
	if err != nil || got.DiskMB != -1 {
		t.Fatalf("ComposeEntitlements unlimited = %#v, %v", got, err)
	}

	inactive := unlimited
	inactive.IsActive = false
	if got, err := ComposeEntitlements(base, []types.AddonPlan{inactive}); err != nil || got.DiskMB != -1 {
		t.Fatalf("existing inactive add-on = %#v, %v", got, err)
	}
	if err := ValidateEntitlements(types.SubscriptionEntitlements{DiskMB: -2}); err == nil {
		t.Fatal("ValidateEntitlements accepted a value below -1")
	}
	if _, err := ComposeEntitlements(
		types.SubscriptionEntitlements{PlanName: "Large", DiskMB: maxPlanLimit},
		[]types.AddonPlan{{Name: "One more", Entitlements: types.SubscriptionEntitlements{DiskMB: 1}}},
	); err == nil {
		t.Fatal("ComposeEntitlements accepted an overflowing combined limit")
	}
}

func TestEntitlementSnapshotPreservesTypedPlanPolicy(t *testing.T) {
	plan := normalizePlanDefaults(Plan{
		Name: "Advanced", DiskMB: 1024, MaxSites: 2, MaxDatabases: 1, BandwidthMB: -1,
		PHPAllowlist: "8.3", DefaultPHPVersion: "8.3", HostingEnabled: true,
		HostingPolicy: types.HostingPolicy{
			SchemaVersion: 1,
			Resources:     types.HostingResourcePolicy{DiskMB: 1024, TrafficMB: -1, MaxSites: 2, MaxDatabases: 1, CPUPercent: 125},
			Permissions:   types.HostingPermissionPolicy{Hosting: true, Applications: true},
			PHP:           types.HostingPHPPolicy{DefaultVersion: "8.3", AllowedVersions: []string{"8.3"}},
			DNS:           types.HostingDNSPolicy{Mode: "authoritative", DefaultTTL: 3600},
			Access:        types.HostingAccessPolicy{ShellMode: "disabled"},
			Mail:          types.HostingMailPolicy{DMARCPolicy: "none"},
		},
	})
	snapshot := entitlementsFromPlan(plan)
	if snapshot.HostingPolicy.Resources.CPUPercent != 125 || !snapshot.HostingPolicy.Permissions.Applications {
		t.Fatalf("typed plan policy was not preserved: %#v", snapshot.HostingPolicy)
	}
	composed, err := ComposeEntitlements(snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if composed.HostingPolicy.Resources.CPUPercent != 125 || !composed.HostingPolicy.Permissions.Applications {
		t.Fatalf("typed policy was lost during composition: %#v", composed.HostingPolicy)
	}
}
