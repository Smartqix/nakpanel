package quota

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
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

func TestComposeEntitlementsCombinesTypedAddonPolicy(t *testing.T) {
	base := types.SubscriptionEntitlements{
		PlanName: "Base",
		HostingPolicy: types.HostingPolicy{
			SchemaVersion: 2,
			Resources: types.HostingResourcePolicy{
				MaxDatabaseUsers: 2, MaxMailAliases: 3, MaxSFTPIdentities: 1,
				MaxApplications: 1, ValkeyMemoryMB: 64,
			},
			Permissions:  types.HostingPermissionPolicy{Applications: true},
			Web:          types.HostingWebPolicy{AllowedCIDRs: []string{"10.0.0.0/24"}},
			Mail:         types.HostingMailPolicy{DMARCPolicy: "none"},
			DNS:          types.HostingDNSPolicy{DefaultTTL: 900},
			Backups:      types.HostingBackupPolicy{RetentionDays: 7},
			Applications: types.HostingApplicationPolicy{AllowedRuntimes: []string{"php"}, AllowedRegistries: []string{"docker.io"}},
			Valkey:       types.HostingValkeyPolicy{MemoryMB: 64, MaxClients: 16, EvictionPolicy: "allkeys-lru"},
		},
	}
	addon := types.AddonPlan{IsActive: true, Entitlements: types.SubscriptionEntitlements{
		AllowDNS: true, AllowBackups: true, BackupRetentionDays: 30,
		ServicePresets: types.PlanServicePresets{
			SchemaVersion: 1,
			Mail:          types.MailPreset{DMARCPolicy: "reject"},
			DNS:           types.DNSPreset{Mode: "primary", DefaultTTL: 3600},
		},
		HostingPolicy: types.HostingPolicy{
			SchemaVersion: 2,
			Resources: types.HostingResourcePolicy{
				MaxDatabaseUsers: 4, MaxMailAliases: 2, MaxSFTPIdentities: 3,
				MaxApplications: 2, ValkeyMemoryMB: 64,
			},
			Permissions:  types.HostingPermissionPolicy{SFTP: true, FTPS: true, ApplicationEgress: true, Valkey: true},
			Web:          types.HostingWebPolicy{HTTPSRedirect: true, AllowedCIDRs: []string{"192.0.2.0/24"}},
			Mail:         types.HostingMailPolicy{DMARCPolicy: "reject"},
			DNS:          types.HostingDNSPolicy{DefaultTTL: 3600, DNSSEC: true},
			Backups:      types.HostingBackupPolicy{Enabled: true, RetentionDays: 30},
			Applications: types.HostingApplicationPolicy{AllowedRuntimes: []string{"node"}, AllowedRegistries: []string{"ghcr.io"}, EgressEnabled: true},
			Valkey:       types.HostingValkeyPolicy{Enabled: true, MemoryMB: 128, MaxClients: 32, IdleTimeoutSeconds: 600, EvictionPolicy: "allkeys-lru"},
		},
	}}
	got, err := ComposeEntitlements(base, []types.AddonPlan{addon})
	if err != nil {
		t.Fatal(err)
	}
	if got.HostingPolicy.Resources.MaxDatabaseUsers != 6 || got.HostingPolicy.Resources.MaxMailAliases != 5 ||
		got.HostingPolicy.Resources.MaxSFTPIdentities != 4 || got.HostingPolicy.Resources.MaxApplications != 3 ||
		got.HostingPolicy.Resources.ValkeyMemoryMB != 128 {
		t.Fatalf("typed additive resources = %#v", got.HostingPolicy.Resources)
	}
	if !got.HostingPolicy.Permissions.SFTP || !got.HostingPolicy.Permissions.FTPS ||
		!got.HostingPolicy.Permissions.ApplicationEgress || !got.HostingPolicy.Applications.EgressEnabled ||
		!got.HostingPolicy.Permissions.Valkey || got.HostingPolicy.Valkey.IdleTimeoutSeconds != 600 {
		t.Fatalf("typed permissions/settings were not composed: %#v", got.HostingPolicy)
	}
	if strings.Join(got.HostingPolicy.Applications.AllowedRuntimes, ",") != "node,php" ||
		strings.Join(got.HostingPolicy.Applications.AllowedRegistries, ",") != "docker.io,ghcr.io" {
		t.Fatalf("typed allowlists were not unioned: %#v", got.HostingPolicy.Applications)
	}
	if !got.HostingPolicy.Web.HTTPSRedirect ||
		strings.Join(got.HostingPolicy.Web.AllowedCIDRs, ",") != "10.0.0.0/24,192.0.2.0/24" ||
		got.HostingPolicy.Mail.DMARCPolicy != "reject" || got.HostingPolicy.DNS.DefaultTTL != 3600 ||
		!got.HostingPolicy.DNS.DNSSEC || !got.HostingPolicy.Backups.Enabled ||
		got.HostingPolicy.Backups.RetentionDays != 30 {
		t.Fatalf("typed service settings were not composed: %#v", got.HostingPolicy)
	}
}

func TestComposeEntitlementsCombinesPHPHostingAddonWithoutImplicitGrant(t *testing.T) {
	base := types.SubscriptionEntitlements{
		HostingPolicy: types.HostingPolicy{SchemaVersion: 2},
	}
	withoutAddon, err := ComposeEntitlements(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if withoutAddon.HostingPolicy.Permissions.Composer ||
		withoutAddon.HostingPolicy.Permissions.ComposerCodeExecution ||
		withoutAddon.HostingPolicy.Permissions.ManagedPHPDeployments ||
		withoutAddon.HostingPolicy.Permissions.PHPWorkers {
		t.Fatalf("legacy subscription gained PHP hosting permissions: %#v", withoutAddon.HostingPolicy)
	}

	addon := types.AddonPlan{Name: "Managed PHP", Entitlements: types.SubscriptionEntitlements{
		HostingPolicy: types.HostingPolicy{
			SchemaVersion: 3,
			Resources:     types.HostingResourcePolicy{MaxPHPWorkers: 2, MaxPHPReleases: 5},
			Permissions: types.HostingPermissionPolicy{
				Composer: true, ComposerCodeExecution: true,
				ManagedPHPDeployments: true, PHPWorkers: true,
			},
		},
	}}
	got, err := ComposeEntitlements(base, []types.AddonPlan{addon})
	if err != nil {
		t.Fatal(err)
	}
	if got.HostingPolicy.Resources.MaxPHPWorkers != 2 || got.HostingPolicy.Resources.MaxPHPReleases != 5 ||
		!got.HostingPolicy.Permissions.Composer || !got.HostingPolicy.Permissions.ComposerCodeExecution ||
		!got.HostingPolicy.Permissions.ManagedPHPDeployments || !got.HostingPolicy.Permissions.PHPWorkers {
		t.Fatalf("PHP hosting add-on was not composed: %#v", got.HostingPolicy)
	}
}

func TestSetSubscriptionModeCustomQueuesHostConvergence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs(int64(91)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT provisioning_state`).WithArgs(int64(91)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT COALESCE\(c\.reseller_id,0\),s\.status`).
		WithArgs(int64(91)).
		WillReturnRows(sqlmock.NewRows([]string{"reseller_id", "status"}).AddRow(int64(0), "active"))
	mock.ExpectExec(`DELETE FROM subscription_addons`).WithArgs(int64(91)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO subscription_entitlements`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE subscriptions SET plan_id=NULL`).
		WithArgs(int64(91)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT oversell_policy, server_disk_capacity_mb, valkey_capacity_mb`).
		WillReturnRows(sqlmock.NewRows([]string{"oversell_policy", "server_disk_capacity_mb", "valkey_capacity_mb", "created_at", "updated_at"}).
			AddRow(OversellPolicyWarn, 1024, 256, now, now))
	mock.ExpectQuery(`UPDATE subscription_system_accounts\s+SET desired_revision=desired_revision\+1`).
		WithArgs(int64(91)).
		WillReturnRows(sqlmock.NewRows([]string{"desired_revision"}).AddRow(int64(8)))
	mock.ExpectCommit()

	if err := NewSQLStore(db).SetSubscriptionMode(context.Background(), 91, "custom", types.SubscriptionEntitlements{
		PlanName: "Custom",
	}); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
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
			SchemaVersion: 2,
			Resources:     types.HostingResourcePolicy{DiskMB: 1024, TrafficMB: -1, MaxSites: 2, MaxDatabases: 1, CPUPercent: 125, MaxFTPAccounts: 4, ValkeyMemoryMB: 128},
			Permissions:   types.HostingPermissionPolicy{Hosting: true, Applications: true, FTPS: true, Git: true, Valkey: true},
			Web:           types.HostingWebPolicy{RequestBodyLimitMB: 64, FastCGIMicrocache: true},
			PHP:           types.HostingPHPPolicy{DefaultVersion: "8.3", AllowedVersions: []string{"8.3"}, FPMMode: "ondemand", OPcacheEnabled: true},
			DNS:           types.HostingDNSPolicy{Mode: "authoritative", DefaultTTL: 3600},
			Access:        types.HostingAccessPolicy{ShellMode: "disabled", FTPSEnabled: true},
			Mail:          types.HostingMailPolicy{DMARCPolicy: "none"},
			Valkey:        types.HostingValkeyPolicy{Enabled: true, MemoryMB: 128, MaxClients: 64, CPUPercent: 25, ProcessLimit: 64},
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
	if composed.HostingPolicy.Resources.CPUPercent != 125 || composed.HostingPolicy.Resources.ValkeyMemoryMB != 128 ||
		!composed.HostingPolicy.Permissions.Applications || !composed.HostingPolicy.Permissions.Git ||
		!composed.HostingPolicy.Web.FastCGIMicrocache || !composed.HostingPolicy.Valkey.Enabled {
		t.Fatalf("typed policy was lost during composition: %#v", composed.HostingPolicy)
	}
}
