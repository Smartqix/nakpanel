package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase12VerifierCoversProviderScopeSyncAndLifecycle(t *testing.T) {
	const path = "phase12-verify.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable", path)
	}
	for _, want := range []string{
		"phase11-verify.sh", "Phase12 Agency", "phase12-reseller@nakpanel.test",
		"reseller capacity exceeded", "sync_status", "locked snapshot changed",
		"phase12-suspend", "suspended website", "wait_for_http_status",
		"cross-provider customer lookup", "hosting.state_converged",
		"updated add-on snapshot", "foreign-addon-rejected", "provider add-on assignment retained",
		"custom-over-allocation", "reseller plan rollback", "admin plan edit preserves provider",
		"rapid lifecycle convergence",
		"subscription reactivation", "foreign-subscription-update",
		"foreign-site-conflict", "foreign-database-conflict", "tenant integrity guards",
		"service-plan-new.html", "data-np-plan-editor", "service plan schema is incomplete",
		"provider-scoped plan name indexes are incomplete",
		"/addons/bulk-status", "/reseller-plans/bulk-status",
		"phase12-overuse-plan", "usage collection completed", "overuse subscription suspension",
		"overuse notifications are incomplete", "overuse manual reactivation",
		"Phase 12 service provider verification passed",
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("%s is missing %q", path, want)
		}
	}
}
