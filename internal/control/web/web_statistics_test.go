package web

import (
	"bytes"
	"context"
	"github.com/nakroteck/nakpanel/internal/control/webstatistics"
	"strings"
	"testing"
)

func TestGoAccessReportIsIsolatedAndNativeSummaryRetained(t *testing.T) {
	v := webstatistics.Workspace{Enabled: true, ReportAvailable: true, Active: true, Engine: "goaccess", Status: "failed", LastError: "Generation failed"}
	var out bytes.Buffer
	if err := domainGoAccess(7, v, WorkspaceView{CSRFToken: "csrf", SupportCustomerID: 8}).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"Requests", "Estimated visitors", "Generation failed", "Open detailed GoAccess report", `sandbox="allow-scripts"`, `support_customer_id=8`} {
		if !strings.Contains(out.String(), value) {
			t.Fatalf("missing %q", value)
		}
	}
	if strings.Contains(out.String(), "allow-same-origin") || strings.Contains(out.String(), `name="engine"`) {
		t.Fatal("report origin or override permission widened")
	}
}

func TestWebStatisticsSettingsGroupsScheduleAndPrivacy(t *testing.T) {
	var out bytes.Buffer
	if err := statisticsSettings(webstatistics.Settings{Enabled: true, RetentionDays: 30, ScheduleHour: 3, AnonymizeIP: true}, WorkspaceView{CSRFToken: "csrf"}).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{`class="np-statistics-settings"`, "Generation &amp; schedule", "Visitor privacy", `name="retention_days"`, `name="schedule_hour"`, `name="anonymize_ip"`, "Save settings"} {
		if !strings.Contains(out.String(), value) {
			t.Fatalf("missing %q", value)
		}
	}
}
