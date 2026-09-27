package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestListPlanRevisionsForUserIsProviderScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE $2 OR p.reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$1)`)).
		WithArgs(int64(77), false, 25).
		WillReturnRows(sqlmock.NewRows([]string{"id", "plan_id", "revision", "lifecycle_status", "definition", "definition_hash", "actor_user_id", "actor_label", "change_reason", "created_at"}).
			AddRow(int64(9), int64(4), 3, "active", []byte(`{"name":"Business"}`), strings.Repeat("a", 64), int64(77), "reseller@test", "Raised site limit", now))

	revisions, err := NewSQLStore(db).ListPlanRevisionsForUser(context.Background(), 77, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(revisions) != 1 || revisions[0].PlanID != 4 || revisions[0].ActorLabel != "reseller@test" {
		t.Fatalf("revisions = %+v", revisions)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalPlanDefinitionHashIgnoresRevisionAuditMetadata(t *testing.T) {
	plan := Plan{
		ID: 4, Name: "Production", Description: "Stable contract", Revision: 7,
		LifecycleStatus: types.PlanLifecycleActive, ResellerID: 9, RevisionActorUserID: 11,
		RevisionActorLabel: "admin@example.test", ChangeReason: "first reason",
		DiskMB: 2048, MaxSites: 3, SiteDiskQuotaMB: 512, PHPFPMMaxChildren: 4,
		PHPMemoryMB: 256, BackupRetentionDays: 14, HostingEnabled: true,
		DefaultPHPVersion: "8.4", PHPAllowlist: "8.4,8.5",
		HostingPolicy: types.HostingPolicy{SchemaVersion: 3,
			Resources:   types.HostingResourcePolicy{DiskMB: 2048, MaxSites: 3},
			Permissions: types.HostingPermissionPolicy{Hosting: true},
			PHP:         types.HostingPHPPolicy{DefaultVersion: "8.4", AllowedVersions: []string{"8.4", "8.5"}},
		},
	}
	definition1, hash1, err := CanonicalPlanDefinition(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.RevisionActorUserID = 22
	plan.RevisionActorLabel = "another@example.test"
	plan.ChangeReason = "different reason"
	definition2, hash2, err := CanonicalPlanDefinition(plan)
	if err != nil {
		t.Fatal(err)
	}
	if string(definition1) != string(definition2) || hash1 != hash2 {
		t.Fatalf("audit metadata changed definition/hash:\n%s\n%s\n%s\n%s", definition1, definition2, hash1, hash2)
	}
	if len(hash1) != 64 {
		t.Fatalf("definition hash length = %d, want 64", len(hash1))
	}
	var definition types.PlanDefinition
	if err := json.Unmarshal(definition1, &definition); err != nil {
		t.Fatal(err)
	}
	if definition.ResellerID != 9 || definition.Resources.SiteDiskQuotaMB != 512 ||
		definition.Resources.PHPFPMMaxChildren != 4 || definition.Resources.PHPMemoryMB != 256 ||
		definition.Resources.BackupRetentionDays != 14 || definition.Resources.PHPAllowlist != "8.4,8.5" {
		t.Fatalf("canonical definition omitted compatibility contract fields: %+v", definition)
	}
}

func TestEvaluateSubscriptionComplianceIsNonDestructiveAndHonorsUnlimited(t *testing.T) {
	entitlements := types.SubscriptionEntitlements{
		DiskMB: 100, BandwidthMB: -1, MaxSites: 2, MaxDatabases: 1,
		MaxBackups: 1, BackupStorageMB: 20, MaxMailboxes: 0,
	}
	status, violations := EvaluateSubscriptionCompliance(entitlements, SubscriptionComplianceUsage{
		Sites: 3, Databases: 1, Backups: 2, Mailboxes: 1,
		DiskBytes: 101 * 1024 * 1024, TrafficBytes: 1 << 50,
		BackupBytes: 21 * 1024 * 1024, MeasurementComplete: true,
	})
	if status != types.SubscriptionComplianceOverLimit {
		t.Fatalf("status = %q, want over_limit", status)
	}
	joined := strings.Join(violations, " | ")
	for _, want := range []string{"sites 3/2", "backups 2/1", "mailboxes 1/0", "disk 101/100 MB", "backup storage 21/20 MB"} {
		if !strings.Contains(joined, want) {
			t.Errorf("violations %q missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "traffic") {
		t.Fatalf("unlimited traffic produced violation: %q", joined)
	}
}

func TestEvaluateSubscriptionComplianceRequiresCompleteMeasuredUsage(t *testing.T) {
	status, violations := EvaluateSubscriptionCompliance(types.SubscriptionEntitlements{
		DiskMB: 100, BandwidthMB: 100, MaxSites: -1, MaxDatabases: -1,
		MaxBackups: -1, BackupStorageMB: -1, MaxMailboxes: -1,
	}, SubscriptionComplianceUsage{
		DiskBytes: 1000 * 1024 * 1024, TrafficBytes: 1000 * 1024 * 1024,
		MeasurementComplete: false,
	})
	if status != types.SubscriptionComplianceUnknown || len(violations) != 0 {
		t.Fatalf("incomplete usage = %q %v, want unknown with no measured violations", status, violations)
	}
}

func TestEvaluateSubscriptionComplianceCountsAuthoritativeBackupBytesWithoutAgentMeasurement(t *testing.T) {
	status, violations := EvaluateSubscriptionCompliance(types.SubscriptionEntitlements{
		DiskMB: 100, BandwidthMB: 100, MaxSites: -1, MaxDatabases: -1,
		MaxBackups: -1, BackupStorageMB: 20, MaxMailboxes: -1,
	}, SubscriptionComplianceUsage{
		BackupBytes: 21 * 1024 * 1024, MeasurementComplete: false,
	})
	if status != types.SubscriptionComplianceOverLimit || len(violations) != 1 || violations[0] != "backup storage 21/20 MB" {
		t.Fatalf("incomplete agent measurement with authoritative backup usage = %q %v", status, violations)
	}
}

func TestBytesToCeilingMBDoesNotOverflowAtMaxInt64(t *testing.T) {
	const maxInt64 = int64(1<<63 - 1)
	const mb = int64(1024 * 1024)
	want := int64(1 + (maxInt64-1)/mb)
	if got := bytesToCeilingMB(maxInt64); got != want {
		t.Fatalf("bytesToCeilingMB(maxInt64) = %d, want %d", got, want)
	}
}

func TestDiffPlanDefinitionsReturnsStructuredEnforcementChanges(t *testing.T) {
	current := Plan{
		ID: 8, Name: "Business", Description: "Current offer", PriceCents: sql.NullInt64{Int64: 1000, Valid: true}, LifecycleStatus: types.PlanLifecycleActive,
		HostingPolicy: types.HostingPolicy{SchemaVersion: 3,
			Resources:   types.HostingResourcePolicy{MaxSites: 5, DiskMB: 2048},
			Permissions: types.HostingPermissionPolicy{Hosting: true, Mail: false},
			PHP:         types.HostingPHPPolicy{DefaultVersion: "8.4", AllowedVersions: []string{"8.4"}},
		},
	}
	candidate := current
	candidate.Name = "Business Plus"
	candidate.Description = "Updated offer"
	candidate.PriceCents = sql.NullInt64{Int64: 1500, Valid: true}
	candidate.LifecycleStatus = types.PlanLifecycleRetired
	candidate.HostingPolicy.Resources.MaxSites = 3
	candidate.HostingPolicy.Permissions.Mail = true
	candidate.HostingPolicy.PHP.DefaultVersion = "8.5"

	changes, err := DiffPlanDefinitions(current, candidate)
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string]types.PlanFieldChange, len(changes))
	for _, change := range changes {
		byPath[change.Path] = change
	}
	for path, want := range map[string]types.PlanEnforcementKind{
		"name":                types.PlanEnforcementCreationDefault,
		"description":         types.PlanEnforcementCreationDefault,
		"price_cents":         types.PlanEnforcementCreationDefault,
		"lifecycle_status":    types.PlanEnforcementServicePermission,
		"resources.max_sites": types.PlanEnforcementHardLimit,
		"permissions.mail":    types.PlanEnforcementServicePermission,
		"php.default_version": types.PlanEnforcementCreationDefault,
	} {
		change, ok := byPath[path]
		if !ok {
			t.Errorf("missing change %q in %+v", path, changes)
			continue
		}
		if change.Enforcement != want || change.OldValue == change.NewValue {
			t.Errorf("change %q = %+v, want enforcement %q and distinct values", path, change, want)
		}
	}
	if len(changes) != 7 {
		t.Fatalf("changes = %+v, want exactly seven", changes)
	}
}

func TestDiffPlanDefinitionsIncludesTopLevelContractControls(t *testing.T) {
	current := Plan{
		Name: "Business", LifecycleStatus: types.PlanLifecycleActive,
		MaxSubdomains: 2, MaxDomainAliases: 3, ValidityDays: 30, SiteDiskQuotaMB: 512,
		OverusePolicy: types.PlanOveruseBlock, DiskWarningPercent: 80, TrafficWarningPercent: 80,
		HostingPolicy: types.HostingPolicy{SchemaVersion: 3},
	}
	candidate := current
	candidate.MaxSubdomains = 4
	candidate.MaxDomainAliases = 5
	candidate.ValidityDays = 365
	candidate.SiteDiskQuotaMB = 1024
	candidate.OverusePolicy = types.PlanOveruseNotify
	candidate.DiskWarningPercent = 70
	candidate.TrafficWarningPercent = 75

	changes, err := DiffPlanDefinitions(current, candidate)
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string]types.PlanFieldChange, len(changes))
	for _, change := range changes {
		byPath[change.Path] = change
	}
	for path, enforcement := range map[string]types.PlanEnforcementKind{
		"resources.max_subdomains":          types.PlanEnforcementHardLimit,
		"resources.max_domain_aliases":      types.PlanEnforcementHardLimit,
		"resources.validity_days":           types.PlanEnforcementCreationDefault,
		"resources.site_disk_quota_mb":      types.PlanEnforcementHardLimit,
		"resources.overuse_policy":          types.PlanEnforcementMeasuredLimit,
		"resources.disk_warning_percent":    types.PlanEnforcementMeasuredLimit,
		"resources.traffic_warning_percent": types.PlanEnforcementMeasuredLimit,
	} {
		change, ok := byPath[path]
		if !ok || change.Enforcement != enforcement {
			t.Errorf("change %q = %+v, want enforcement %q", path, change, enforcement)
		}
	}
}

func TestExistingPlanPreviewKeepsStoredProviderOwnership(t *testing.T) {
	candidate := Plan{ID: 7, ResellerID: 0, Name: "Updated"}
	stored := Plan{ID: 7, ResellerID: 22, Name: "Current"}
	got := preserveStoredPlanProvider(candidate, stored)
	if got.ResellerID != stored.ResellerID {
		t.Fatalf("preview provider = %d, want stored provider %d", got.ResellerID, stored.ResellerID)
	}
}

func TestRefreshSubscriptionComplianceUsesFreshMeasuredUsage(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT disk_mb,bandwidth_mb,max_sites,max_databases,max_backups,backup_storage_mb,max_mailboxes`).
		WithArgs(int64(42)).
		WillReturnRows(sqlmock.NewRows([]string{"disk_mb", "bandwidth_mb", "max_sites", "max_databases", "max_backups", "backup_storage_mb", "max_mailboxes"}).
			AddRow(1, -1, 2, 2, 2, -1, 0))
	mock.ExpectQuery(`COALESCE\(\(SELECT COUNT\(\*\) FROM sites`).
		WithArgs(int64(42)).
		WillReturnRows(sqlmock.NewRows([]string{"sites", "databases", "backups", "mailboxes", "disk_bytes", "traffic_bytes", "backup_bytes", "is_complete"}).
			AddRow(1, 0, 0, 0, int64(2*1024*1024), int64(0), int64(0), true))
	mock.ExpectExec(`UPDATE subscriptions SET compliance_status`).
		WithArgs(int64(42), types.SubscriptionComplianceOverLimit, "disk 2/1 MB").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := refreshSubscriptionComplianceTx(context.Background(), tx, 42); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSettingsRejectsNegativeValkeyCapacity(t *testing.T) {
	err := ValidateSettings(Settings{
		OversellPolicy:       OversellPolicyWarn,
		ServerDiskCapacityMB: 1024,
		ValkeyCapacityMB:     -1,
	})
	if err == nil || !strings.Contains(err.Error(), "Valkey capacity") {
		t.Fatalf("ValidateSettings error = %v, want Valkey capacity error", err)
	}
}

func TestUpdateSettingsRejectsValkeyCapacityBelowEnabledAllocations(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO settings`).
		WithArgs(OversellPolicyWarn, 1024, 64).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT oversell_policy, server_disk_capacity_mb, valkey_capacity_mb`).
		WillReturnRows(sqlmock.NewRows([]string{
			"oversell_policy", "server_disk_capacity_mb", "valkey_capacity_mb", "created_at", "updated_at",
		}).AddRow(OversellPolicyWarn, 1024, 64, now, now))
	mock.ExpectQuery(`SELECT COALESCE\(SUM\(memory_mb\), 0\)`).
		WillReturnRows(sqlmock.NewRows([]string{"committed_mb"}).AddRow(96))
	mock.ExpectRollback()

	err = NewSQLStore(db).UpdateSettings(context.Background(), Settings{
		OversellPolicy:       OversellPolicyWarn,
		ServerDiskCapacityMB: 1024,
		ValkeyCapacityMB:     64,
	})
	if !errors.Is(err, ErrExceeded) {
		t.Fatalf("UpdateSettings error = %v, want ErrExceeded", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPleskOveruseModesControlCountLimits(t *testing.T) {
	tests := []struct {
		policy  types.PlanOverusePolicy
		blocked bool
	}{
		{types.PlanOveruseBlock, true},
		{types.PlanOveruseNormal, false},
		{types.PlanOveruseNotify, false},
		{types.PlanOveruseNotSuspend, true},
		{types.PlanOveruseNotSuspendNotify, true},
	}
	for _, test := range tests {
		if got := countLimitReached(2, 2, test.policy); got != test.blocked {
			t.Errorf("countLimitReached policy=%s = %v, want %v", test.policy, got, test.blocked)
		}
	}
}

func TestUsageLevelHandlesUnlimitedZeroAndWarning(t *testing.T) {
	if over, warning := usageLevel(1<<30, -1, 80); over || warning {
		t.Fatal("unlimited usage produced an alert")
	}
	if over, warning := usageLevel(1, 0, 80); !over || !warning {
		t.Fatal("zero limit did not reject non-zero usage")
	}
	if over, warning := usageLevel(80*1024*1024, 100, 80); over || !warning {
		t.Fatalf("80 percent usage = over:%v warning:%v", over, warning)
	}
}

func TestServicePlanMigrationContainsDurableUsageAndProviderScopedNames(t *testing.T) {
	raw, err := os.ReadFile("../../../migrations/20260711000015_service_plan_designer.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"plans_provider_name_admin_idx", "subscription_usage_current", "site_traffic_cursors", "notification_deliveries", "overuse_policy", "max_subdomains", "allow_php_settings"} {
		if !strings.Contains(text, want) {
			t.Fatalf("migration missing %q", want)
		}
	}
}

func TestServicePlanIntegrityMigrationScopesEveryPlanType(t *testing.T) {
	raw, err := os.ReadFile("../../../migrations/20260711000016_service_plan_name_integrity.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"addon_plans_provider_name_admin_idx",
		"addon_plans_provider_name_reseller_idx",
		"reseller_plans_name_ci_idx",
		"row_number() OVER",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("integrity migration missing %q", want)
		}
	}
}
