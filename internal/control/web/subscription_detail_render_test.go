package web

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

// subscriptionTabs are the nine tabs the detail page carries. Seven of these
// labels are grepped verbatim by deploy/multipass/phase15-verify.sh, so the
// vocabulary is a deployment contract, not a design choice.
var subscriptionTabs = []string{"overview", "resources", "access", "cache", "mail", "tasks", "applications", "backups", "activity"}

var pinnedTabLabels = []string{
	"Websites &amp; Domains",
	"Resources",
	"Account Access",
	"Mail",
	"Scheduled Tasks",
	"Applications",
	"Activity",
}

func detailFixture() dashboard.Data {
	created := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)
	return dashboard.Data{
		Sites: []dashboard.Site{{
			ID: 7, Domain: "pinned.test", Username: "pinned", PHPVersion: "8.3",
			Status: "active", CustomerID: 88, SubscriptionID: 42,
		}},
		Subscriptions: []types.SubscriptionSummary{{
			ID: 42, CustomerID: 88, CustomerName: "Example Customer", CustomerEmail: "owner@example.test",
			PlanID: 10, PlanName: "Production", SubscriptionName: "example.test", Status: "active",
			MaxSites: 2, DomainsUsed: 1, MaxDatabases: 2, DatabasesUsed: 2,
			MaxBackups: 3, BackupsUsed: 6, MaxMailboxes: 0, DiskMB: 1024,
			SyncMode: "custom", SyncStatus: "in_sync", PlanRevision: 4,
			ComplianceStatus: types.SubscriptionComplianceCompliant, ComplianceCheckedAt: created,
			CreatedAt: created, UpdatedAt: created,
		}},
		SubscriptionServices: dashboard.SubscriptionServicesData{
			Accounts: []types.SubscriptionSystemAccount{{
				ID: 3, SubscriptionID: 42, Username: "nps42", HomePath: "/home/nps42",
				ShellMode: "jailed", DesiredState: "present", AppliedState: "present",
				ConvergenceStatus: "in_sync",
			}},
		},
		AuditEvents: []types.AuditEvent{{
			ID: 1, SubscriptionID: 42, ActorEmail: "admin@nakpanel.test",
			Action: "subscription.mode_changed", TargetType: "subscription", TargetID: 42,
			CreatedAt: created,
		}},
	}
}

func renderSubscriptionDetail(t *testing.T, role auth.Role, tab string) string {
	t.Helper()
	var body bytes.Buffer
	err := routedSubscriptionDetail(
		auth.SessionUser{Role: role},
		detailFixture(),
		DashboardActions{CanCreateSite: true},
		WorkspaceView{Route: "/subscriptions/42", DetailID: 42, Tab: tab},
	).Render(context.Background(), &body)
	if err != nil {
		t.Fatalf("render tab %q: %v", tab, err)
	}
	return body.String()
}

// Every tab must carry the whole tab vocabulary and the compliance value,
// because the verifiers fetch the default tab and grep for both.
func TestSubscriptionDetailKeepsPinnedTabVocabularyOnEveryTab(t *testing.T) {
	for _, tab := range subscriptionTabs {
		html := renderSubscriptionDetail(t, auth.RoleAdmin, tab)
		for _, label := range pinnedTabLabels {
			if !strings.Contains(html, label) {
				t.Fatalf("tab %q is missing the pinned label %q", tab, label)
			}
		}
		for _, label := range []string{"Cache", "Backups"} {
			if !strings.Contains(html, label) {
				t.Fatalf("tab %q is missing the tab label %q", tab, label)
			}
		}
		if !strings.Contains(html, "Compliance") || !strings.Contains(html, "compliant") {
			t.Fatalf("tab %q must expose the compliance state outside the tab bodies", tab)
		}
		if !strings.Contains(html, "Subscription settings") {
			t.Fatalf("tab %q must keep the literal \"Subscription settings\"", tab)
		}
	}
}

// The six per-domain deep links are pinned by server_test.go and
// deploy/multipass/phase13-verify.sh.
func TestSubscriptionDetailKeepsPerDomainDeepLinks(t *testing.T) {
	html := renderSubscriptionDetail(t, auth.RoleAdmin, "overview")
	for _, tab := range []string{"hosting", "php", "dns", "ssl", "databases", "backups"} {
		if !strings.Contains(html, "?tab="+tab) {
			t.Fatalf("overview is missing the per-domain deep link ?tab=%s", tab)
		}
	}
	if !strings.Contains(html, "pinned.test") {
		t.Fatalf("overview does not list the hosted domain")
	}
}

// The selected tab has to be announced as well as drawn: the helper used to
// emit a class the stylesheet did not define, and no aria-current at all.
func TestSubscriptionDetailMarksTheSelectedTab(t *testing.T) {
	html := renderSubscriptionDetail(t, auth.RoleAdmin, "backups")
	if !strings.Contains(html, `aria-current="page"`) {
		t.Fatalf("the selected tab must carry aria-current=\"page\"")
	}
	if !strings.Contains(html, `class="is-active"`) {
		t.Fatalf("the selected tab must carry the is-active class the stylesheet defines")
	}
	if strings.Contains(html, `class="active"`) {
		t.Fatalf("the unstyled legacy \"active\" class must not come back")
	}
}

// Status pills must name a tone class that exists. Building the class in markup
// from a fragment silently purged all five tone rules from the stylesheet.
func TestSubscriptionDetailPillsUseDefinedToneClasses(t *testing.T) {
	html := renderSubscriptionDetail(t, auth.RoleAdmin, "overview")
	if !strings.Contains(html, "np-status-pill-ok") {
		t.Fatalf("an active subscription must render the ok pill tone")
	}
	css := string(appCSS)
	for _, tone := range []string{"ok", "pend", "run", "fail", "susp"} {
		if !strings.Contains(css, ".np-status-pill-"+tone) {
			t.Fatalf("the stylesheet does not define .np-status-pill-%s", tone)
		}
	}
}

// Going over the plan is the most important fact on the page, so it is stated
// on every tab rather than left to a grey corner label.
func TestSubscriptionDetailStatesBreachesOnEveryTab(t *testing.T) {
	for _, tab := range subscriptionTabs {
		html := renderSubscriptionDetail(t, auth.RoleAdmin, tab)
		if !strings.Contains(html, "holds more than its plan allows") {
			t.Fatalf("tab %q does not state the limit breach", tab)
		}
		if !strings.Contains(html, "backups 6 against a limit of 3") {
			t.Fatalf("tab %q does not name the breached resource and its figures", tab)
		}
	}
}

// A zero allowance has no denominator, so it must not draw a full bar, and an
// unlimited allowance must not draw one either.
func TestSubscriptionLimitRowsOnlyDrawBarsWithADenominator(t *testing.T) {
	data := detailFixture()
	subscription := data.Subscriptions[0]
	subscription.MaxDomainAliases = -1
	rows := subscriptionLimitRows(subscription, data)
	for _, row := range rows {
		switch row.Label {
		case "Mailboxes":
			if row.HasBar {
				t.Fatalf("a zero mailbox allowance must not draw a bar")
			}
			if row.Note != "Not allowed by this plan" {
				t.Fatalf("mailbox note = %q", row.Note)
			}
		case "Domain aliases":
			if row.HasBar {
				t.Fatalf("an unlimited allowance must not draw a bar")
			}
		case "Backups":
			if row.Tone != limitToneOver || !strings.Contains(row.Note, "3 over") {
				t.Fatalf("backups row = %+v, want an over-limit tone naming the overage", row)
			}
		case "Databases":
			if row.Tone != limitToneFull {
				t.Fatalf("a resource at its limit must read as full, got %q", row.Tone)
			}
		}
	}
}

// The Resources tab used to render its link for clients and then nothing at
// all, because the body was role gated but the tab was not.
func TestSubscriptionResourcesTabIsNeverBlankForClients(t *testing.T) {
	html := renderSubscriptionDetail(t, auth.RoleClient, "resources")
	if !strings.Contains(html, "Your limits are set by your hosting provider") {
		t.Fatalf("a client opening Resources must be told who owns these values")
	}
	if !strings.Contains(html, "np-limit-table") {
		t.Fatalf("a client opening Resources must still see what they are using")
	}
	if strings.Contains(html, "/subscriptions/42/status") {
		t.Fatalf("a client must not be offered the provider-only status form")
	}
}

// Mail is gated on the mailbox allowance, which the tab never checked.
func TestSubscriptionMailTabGatesOnTheMailboxAllowance(t *testing.T) {
	html := renderSubscriptionDetail(t, auth.RoleAdmin, "mail")
	if !strings.Contains(html, "Mail is not included in this plan") {
		t.Fatalf("a plan allowing no mailboxes must say so on the Mail tab")
	}
	if !strings.Contains(html, "Mail off") {
		t.Fatalf("each domain must show that mail is off rather than offering it")
	}
}

// The audit trail is rendered from data that was already loaded and simply
// never shown. The window it draws from is the dashboard's recent-activity
// list, so the tab claims a share of that window rather than a full history.
func TestSubscriptionActivityTabRendersTheAuditTrail(t *testing.T) {
	html := renderSubscriptionDetail(t, auth.RoleAdmin, "activity")
	if !strings.Contains(html, "Entitlement source changed") {
		t.Fatalf("the activity tab must name the recorded action in words")
	}
	if !strings.Contains(html, "admin@nakpanel.test") {
		t.Fatalf("the activity tab must say who made the change")
	}
	if !strings.Contains(html, "Present and enabled") {
		t.Fatalf("convergence state must read as words, not as a stored token")
	}
	if strings.Contains(html, "Nothing from this subscription") {
		t.Fatalf("the empty state must not render when there are events")
	}
}

func TestRelativeLabelReadsAsProse(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	cases := map[time.Time]string{
		now.Add(-30 * time.Second):   "just now",
		now.Add(-5 * time.Minute):    "5 minutes ago",
		now.Add(-1 * time.Hour):      "an hour ago",
		now.Add(-5 * time.Hour):      "5 hours ago",
		now.Add(-30 * time.Hour):     "yesterday",
		now.Add(-3 * 24 * time.Hour): "3 days ago",
	}
	for value, want := range cases {
		if got := relativeTo(value, now); got != want {
			t.Fatalf("relativeTo(%s) = %q, want %q", value, got, want)
		}
	}
	if got := relativeTo(time.Time{}, now); got != "" {
		t.Fatalf("a zero time has no relative label, got %q", got)
	}
}

// The desired and applied states use different vocabularies, so a settled cache
// must not be reported as still applying.
func TestValkeyStateReadsConvergenceNotStateEquality(t *testing.T) {
	settled := types.ValkeyInstance{DesiredState: "enabled", AppliedState: "running", ConvergenceStatus: "in_sync"}
	if got := valkeyStateWord(settled); got != "Running" {
		t.Fatalf("a settled enabled cache = %q, want Running", got)
	}
	if got := valkeyStateTone(settled); got != "ok" {
		t.Fatalf("a settled enabled cache tone = %q, want ok", got)
	}
	pending := types.ValkeyInstance{DesiredState: "enabled", AppliedState: "", ConvergenceStatus: "pending"}
	if got := valkeyStateWord(pending); got != "Applying" {
		t.Fatalf("a pending cache = %q, want Applying", got)
	}
	stopped := types.ValkeyInstance{DesiredState: "disabled", AppliedState: "stopped", ConvergenceStatus: "in_sync"}
	if got := valkeyStateWord(stopped); got != "Stopped" {
		t.Fatalf("a settled disabled cache = %q, want Stopped", got)
	}
	failed := types.ValkeyInstance{DesiredState: "enabled", ConvergenceStatus: "in_sync", LastError: "boom"}
	if got := valkeyStateWord(failed); got != "Failed" {
		t.Fatalf("a cache with an error = %q, want Failed", got)
	}
}

// Usage counted in bytes must not be rounded away by a megabyte-based limit.
func TestByteLimitRowKeepsSmallUsageVisible(t *testing.T) {
	row := byteLimitRow("Storage", "Disk", "disk_mb", 100, 1024)
	if row.Used != "100 B" {
		t.Fatalf("100 bytes rendered as %q, want \"100 B\"", row.Used)
	}
	if row.Limit != "1 GB" || !row.HasBar {
		t.Fatalf("row = %+v, want a 1 GB limit with a bar", row)
	}
	over := byteLimitRow("Storage", "Disk", "disk_mb", 2*1024*1024*1024, 1024)
	if over.Tone != limitToneOver {
		t.Fatalf("usage past the limit must read as over, got %q", over.Tone)
	}
}
