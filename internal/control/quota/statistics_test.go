package quota

import (
	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/types"
	"testing"
)

func TestStatisticsLegacyCompositionNormalizesEachSnapshot(t *testing.T) {
	legacyEnabled := types.SubscriptionEntitlements{HostingPolicy: types.HostingPolicy{SchemaVersion: 4}, ServicePresets: types.PlanServicePresets{Logs: types.LogsPreset{StatisticsEnabled: true}}}
	currentDisabled := types.SubscriptionEntitlements{HostingPolicy: types.HostingPolicy{SchemaVersion: 5, Logs: types.LogsPreset{StatisticsEngine: "disabled"}}}
	staleEnabled := currentDisabled
	staleEnabled.ServicePresets.Logs.StatisticsEnabled = true
	untypedEnabled := legacyEnabled
	untypedEnabled.HostingPolicy.SchemaVersion = 0
	for _, tc := range []struct {
		name        string
		base, addon types.SubscriptionEntitlements
		want        string
	}{
		{"legacy base with typed addon", legacyEnabled, currentDisabled, "goaccess"},
		{"legacy addon with current base", currentDisabled, legacyEnabled, "goaccess"},
		{"untyped addon with current base", currentDisabled, untypedEnabled, "goaccess"},
		{"explicit disabled base beats stale preset", staleEnabled, currentDisabled, "disabled"},
		{"explicit disabled addon beats stale preset", currentDisabled, staleEnabled, "disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ComposeEntitlements(tc.base, []types.AddonPlan{{Name: "Add-on", Entitlements: tc.addon}})
			if err != nil {
				t.Fatal(err)
			}
			if got.HostingPolicy.Logs.StatisticsEngine != tc.want || got.ServicePresets.Logs.StatisticsEngine != tc.want || got.HostingPolicy.Logs.StatisticsEnabled != (tc.want == "goaccess") {
				t.Fatalf("inconsistent composed statistics: policy=%#v presets=%#v", got.HostingPolicy.Logs, got.ServicePresets.Logs)
			}
			if got.HostingPolicy.Permissions.WebStatistics {
				t.Fatal("composition granted override permission")
			}
		})
	}
}

func TestStatisticsLegacyChildCannotBypassResellerCeiling(t *testing.T) {
	child := Plan{HostingPolicy: types.HostingPolicy{SchemaVersion: 4}, Presets: types.PlanServicePresets{Logs: types.LogsPreset{StatisticsEnabled: true}}}
	ceiling := types.HostingPolicy{SchemaVersion: 5, Logs: types.LogsPreset{StatisticsEngine: "disabled"}}
	if err := controlpolicy.ValidateWithin(EffectivePlanHostingPolicy(child), ceiling); err == nil {
		t.Fatal("legacy statistics bypassed disabled reseller ceiling")
	}
}

func TestStatisticsLegacyPlanAndEntitlements(t *testing.T) {
	legacy := types.HostingPolicy{SchemaVersion: 4}
	presets := types.PlanServicePresets{Logs: types.LogsPreset{StatisticsEnabled: true}}
	plan := Plan{HostingPolicy: legacy, Presets: presets}
	got := EffectivePlanHostingPolicy(plan)
	if got.Logs.StatisticsEngine != "goaccess" || got.Permissions.WebStatistics {
		t.Fatalf("legacy plan lost statistics: %#v", got)
	}
	got = mergeLegacyEntitlementsPolicy(types.SubscriptionEntitlements{ServicePresets: presets}, legacy)
	if got.Logs.StatisticsEngine != "goaccess" || got.Permissions.WebStatistics {
		t.Fatalf("legacy entitlements lost statistics: %#v", got)
	}
	got.Logs = types.LogsPreset{StatisticsEngine: "disabled"}
	got = mergeLegacyEntitlementsPolicy(types.SubscriptionEntitlements{ServicePresets: presets}, got)
	if got.Logs.StatisticsEngine != "disabled" {
		t.Fatal("legacy preset overrode explicit engine")
	}
}

func TestStatisticsAddonComposition(t *testing.T) {
	base := types.HostingPolicy{SchemaVersion: 5, Logs: types.LogsPreset{StatisticsEngine: "disabled"}}
	addon := types.HostingPolicy{SchemaVersion: 5, Logs: types.LogsPreset{StatisticsEngine: "goaccess"}, Permissions: types.HostingPermissionPolicy{WebStatistics: true}}
	got, err := composeHostingPolicyAddon(base, addon)
	if err != nil || got.Logs.StatisticsEngine != "goaccess" || !got.Logs.StatisticsEnabled || !got.Permissions.WebStatistics {
		t.Fatalf("addon composition failed: %#v %v", got, err)
	}
	got, err = composeHostingPolicyAddon(got, base)
	if err != nil || got.Logs.StatisticsEngine != "goaccess" {
		t.Fatal("disabled addon removed statistics")
	}
}

func TestStatisticsCustomEditPreservesAuthoritativePermissions(t *testing.T) {
	current := types.SubscriptionEntitlements{HostingPolicy: types.HostingPolicy{SchemaVersion: 5,
		Logs:        types.LogsPreset{StatisticsEngine: "goaccess", StatisticsEnabled: true},
		Permissions: types.HostingPermissionPolicy{WebStatistics: true, Composer: true, WordPressToolkit: true},
	}}
	custom := types.SubscriptionEntitlements{DiskMB: 42, PreserveHostingPolicy: true}
	got := preserveCustomHostingPolicy(custom, current)
	if got.HostingPolicy.Resources.DiskMB != 42 || got.HostingPolicy.Logs.StatisticsEngine != "goaccess" || !got.HostingPolicy.Permissions.WebStatistics || !got.HostingPolicy.Permissions.Composer || !got.HostingPolicy.Permissions.WordPressToolkit {
		t.Fatalf("unrelated custom edit dropped policy: %#v", got.HostingPolicy)
	}
	custom.StatisticsEdited = true
	custom.ServicePresets.Logs.StatisticsEnabled = false
	got = preserveCustomHostingPolicy(custom, current)
	if got.HostingPolicy.Logs.StatisticsEngine != "disabled" || !got.HostingPolicy.Permissions.WebStatistics {
		t.Fatal("explicit legacy edit ignored or permission dropped")
	}
}
