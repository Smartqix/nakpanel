package quota

import (
	"os"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

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
