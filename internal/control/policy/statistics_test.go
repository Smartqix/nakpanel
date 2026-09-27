package policy

import (
	"github.com/nakroteck/nakpanel/internal/types"
	"testing"
)

func TestStatisticsLegacyUpgradeAndExplicitEngine(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		p := Upgrade(types.HostingPolicy{SchemaVersion: 4, Logs: types.LogsPreset{StatisticsEnabled: enabled}})
		if p.SchemaVersion != 5 || p.Logs.StatisticsEnabled != enabled || p.Permissions.WebStatistics {
			t.Fatalf("legacy upgrade changed entitlement: %#v", p)
		}
	}
	logs := NormalizeLogs(types.LogsPreset{StatisticsEngine: "disabled", StatisticsEnabled: true})
	if logs.StatisticsEnabled {
		t.Fatal("explicit disabled engine lost precedence")
	}
	if err := Validate(types.HostingPolicy{SchemaVersion: 5, Logs: types.LogsPreset{StatisticsEngine: "awstats"}}); err == nil {
		t.Fatal("unsupported engine accepted")
	}
}

func TestStatisticsOverrideAndCeiling(t *testing.T) {
	p := Upgrade(types.HostingPolicy{SchemaVersion: 4, Logs: types.LogsPreset{StatisticsEnabled: true}})
	if err := ValidateSitePatchPermissions(p, []byte(`{"logs":{"statistics_engine":"disabled"}}`)); err == nil {
		t.Fatal("override without permission accepted")
	}
	p.Permissions.WebStatistics = true
	got, err := Resolve(p, nil, []byte(`{"logs":{"statistics_enabled":false}}`))
	if err != nil || got.Logs.StatisticsEngine != "disabled" || got.Logs.StatisticsEnabled {
		t.Fatalf("legacy explicit edit ignored: %#v %v", got.Logs, err)
	}
	got, err = Resolve(p, nil, []byte(`{"logs":{"statistics_engine":null}}`))
	if err != nil || got.Logs.StatisticsEngine != "goaccess" {
		t.Fatalf("inheritance failed: %#v %v", got.Logs, err)
	}
	ceiling := p
	ceiling.Permissions.WebStatistics = false
	if ValidateWithin(p, ceiling) == nil {
		t.Fatal("override permission exceeded ceiling")
	}
	ceiling = p
	ceiling.Logs = types.LogsPreset{StatisticsEngine: "disabled"}
	if ValidateWithin(p, ceiling) == nil {
		t.Fatal("engine exceeded ceiling")
	}
}

func TestStatisticsReadiness(t *testing.T) {
	p := types.HostingPolicy{SchemaVersion: 5, Logs: types.LogsPreset{StatisticsEngine: "goaccess"}}
	if issues := ValidatePlanCapabilities(p, types.RuntimeCapabilities{}); len(issues) != 1 || issues[0].Field != "logs.statistics_engine" {
		t.Fatalf("missing readiness issue: %#v", issues)
	}
	if issues := ValidatePlanCapabilities(p, types.RuntimeCapabilities{GoAccessAvailable: true}); len(issues) != 0 {
		t.Fatalf("ready engine rejected: %#v", issues)
	}
}

func TestStatisticsRevokedOverrideFallsBackToInheritance(t *testing.T) {
	for _, patch := range []string{`{"logs":{"statistics_engine":"disabled"}}`, `{"logs":{"statistics_enabled":false}}`} {
		base := types.HostingPolicy{SchemaVersion: 5, Logs: types.LogsPreset{StatisticsEngine: "goaccess"}}
		got, err := Resolve(base, nil, []byte(patch))
		if err != nil || got.Logs.StatisticsEngine != "goaccess" {
			t.Fatalf("revoked saved override broke inheritance: %#v %v", got.Logs, err)
		}
		if err := ValidateSitePatchPermissions(base, []byte(patch)); err == nil {
			t.Fatal("fresh unauthorized statistics write accepted")
		}
		if err := ValidateSitePatchPermissions(base, []byte(`{"logs":{"statistics_engine":null,"statistics_enabled":null}}`)); err != nil {
			t.Fatalf("reset to inheritance rejected: %v", err)
		}
		if err := ValidateSitePatchPermissions(base, []byte(`{"web":{"https_redirect":true}}`)); err != nil {
			t.Fatalf("unrelated update blocked: %v", err)
		}
	}
}
