package phpapp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestPhase30MigrationPersistsReleaseRetention(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	payload, err := os.ReadFile(filepath.Join(root, "migrations", "20260829000044_phase30_production_php.sql"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(payload)
	if !strings.Contains(source, "release_retention INTEGER NOT NULL") {
		t.Fatal("Phase 30 migration does not persist the application release-retention setting")
	}
}

func TestApplicationQueriesUseSubscriptionCustomerOwnership(t *testing.T) {
	if !strings.Contains(applicationSelect, "subscription.customer_id") {
		t.Fatal("PHP application query does not derive customer ownership from its subscription")
	}
	if strings.Contains(applicationSelect, "site.customer_id") {
		t.Fatal("PHP application query trusts the denormalized site customer owner")
	}
}

func TestPHPSecretNamesAreBoundedAndOpaque(t *testing.T) {
	name := "A" + strings.Repeat("B", 127)
	got := phpSecretName(name)
	if len(got) > 128 {
		t.Fatalf("secret name length = %d, exceeds service_secrets constraint", len(got))
	}
	if strings.Contains(strings.ToLower(got), strings.ToLower(name)) {
		t.Fatalf("secret name exposes the environment key: %q", got)
	}
	if got != phpSecretName(name) || got == phpSecretName(name+"C") {
		t.Fatal("secret name is not deterministic and collision-resistant for distinct keys")
	}
}

func TestSweepQueriesAreLockableAndProviderAware(t *testing.T) {
	if strings.Contains(sweepWorkerCandidatesSQL, "SELECT DISTINCT") {
		t.Fatal("worker sweep combines DISTINCT with FOR UPDATE and is not valid PostgreSQL")
	}
	if !strings.Contains(sweepApplicationCandidatesSQL, "reseller_subscriptions") {
		t.Fatal("application sweep does not account for effective reseller suspension")
	}
	for _, want := range []string{"hosting_mode='managed'", "last_reconciled_at", "interval '5 minutes'", "COALESCE(application.last_reconciled_at"} {
		if !strings.Contains(sweepApplicationCandidatesSQL, want) {
			t.Fatalf("application sweep does not periodically inspect healthy managed applications: missing %q", want)
		}
	}
	for _, want := range []string{"river_job", "job.args->>'application_id'", "job.args->>'desired_revision'"} {
		if !strings.Contains(sweepApplicationCandidatesSQL, want) {
			t.Fatalf("application sweep can starve later pages behind already queued work: missing %q", want)
		}
	}
}

func TestRollbackTargetsOnlyMaterializedReleaseRows(t *testing.T) {
	if strings.Contains(rollbackTargetSelect, "rolled_back") {
		t.Fatal("rollback intent rows were accepted as physical release targets")
	}
	for _, status := range []string{"healthy", "retired"} {
		if !strings.Contains(rollbackTargetSelect, status) {
			t.Fatalf("rollback target query omits retained %s releases", status)
		}
	}
}

func TestPersistedRollbackConfigurationRechecksManagedPolicy(t *testing.T) {
	record := applicationRecord{spec: types.PHPApplicationSpec{
		HostingMode: types.PHPHostingModeManaged, PHPVersion: "8.4", RepositoryID: 11,
		RepositoryRef: "main", FrameworkProfile: types.PHPFrameworkPlain, HealthPath: "/",
		ReleaseRetention: 3, DesiredState: "active",
		Policy: types.HostingPolicy{
			Permissions: types.HostingPermissionPolicy{Hosting: true, Git: true, ManagedPHPDeployments: false},
			Resources:   types.HostingResourcePolicy{MaxPHPReleases: 3},
			PHP:         types.HostingPHPPolicy{AllowedVersions: []string{"8.4"}},
		},
	}}
	err := validatePersistedManagedApplication(record, types.PHPRuntimeCapability{Version: "8.4", Ready: true})
	if err == nil || !strings.Contains(err.Error(), "managed PHP deployments") {
		t.Fatalf("rollback policy recheck error = %v", err)
	}
}

func TestRollbackTargetMustDifferFromCurrentActiveRelease(t *testing.T) {
	record := applicationRecord{activeDeploymentID: 17, spec: types.PHPApplicationSpec{ApplicationID: 9}}
	target := types.PHPDeployment{ID: 17, ApplicationID: 9, Status: "healthy", ResolvedRevision: strings.Repeat("a", 40)}
	if err := validateRollbackTarget(record, target); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("active rollback target error = %v", err)
	}
	target.ID, target.Status = 16, "retired"
	if err := validateRollbackTarget(record, target); err != nil {
		t.Fatalf("retained rollback target rejected: %v", err)
	}
}
