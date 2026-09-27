package panelhttp

import (
	"github.com/nakroteck/nakpanel/internal/types"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestStatisticsPlanFormLegacyAndEngineEdits(t *testing.T) {
	for _, tc := range []struct {
		form    url.Values
		engine  string
		enabled bool
	}{
		{url.Values{"logs_statistics_enabled": {"true"}}, "goaccess", true},
		{url.Values{"logs_statistics_enabled": {"false"}}, "disabled", false},
		{url.Values{"logs_statistics_enabled": {"true"}, "logs_statistics_engine": {"disabled"}}, "disabled", false},
		{url.Values{"logs_statistics_engine": {"goaccess"}, "allow_web_statistics": {"true"}}, "goaccess", true},
	} {
		r := httptest.NewRequest("POST", "/plans", nil)
		r.Form = tc.form
		plan, err := parsePlan(r)
		if err != nil {
			t.Fatal(err)
		}
		if plan.HostingPolicy.Logs.StatisticsEngine != tc.engine || plan.Presets.Logs.StatisticsEnabled != tc.enabled {
			t.Fatalf("form %v: %#v", tc.form, plan.HostingPolicy.Logs)
		}
		if plan.HostingPolicy.Permissions.WebStatistics != (tc.form.Get("allow_web_statistics") == "true") {
			t.Fatal("override permission inferred from reporting")
		}
	}
	r := httptest.NewRequest("POST", "/plans", nil)
	r.Form = url.Values{"logs_statistics_enabled": {"false"}}
	logs := statisticsLogsFromForm(r, types.LogsPreset{StatisticsEngine: "goaccess", StatisticsEnabled: true})
	if logs.StatisticsEngine != "disabled" {
		t.Fatal("legacy edit ignored inherited engine")
	}
	plan, err := parsePlan(r)
	if err != nil {
		t.Fatal(err)
	}
	custom := parsedCustomEntitlements(r, plan)
	if !custom.PreserveHostingPolicy || !custom.StatisticsEdited {
		t.Fatal("legacy custom edit not marked explicit")
	}
	r.Form = url.Values{}
	custom = parsedCustomEntitlements(r, plan)
	if !custom.PreserveHostingPolicy || custom.StatisticsEdited {
		t.Fatal("unrelated custom edit marked as statistics edit")
	}
}
