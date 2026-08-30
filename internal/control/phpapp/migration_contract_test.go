package phpapp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
