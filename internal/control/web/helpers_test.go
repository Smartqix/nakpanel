package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestAddonsForProviderExcludesForeignAndInactivePlans(t *testing.T) {
	items := []types.AddonPlan{
		{ID: 1, ResellerID: 17, Name: "Matching", IsActive: true},
		{ID: 2, ResellerID: 18, Name: "Foreign", IsActive: true},
		{ID: 3, ResellerID: 17, Name: "Inactive", IsActive: false},
	}
	got := addonsForProvider(items, 17)
	if len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("addonsForProvider() = %#v, want only matching active add-on", got)
	}
}

func TestAddonAsPlanPreservesTypedHostingPolicyForEditing(t *testing.T) {
	addon := types.AddonPlan{
		ID: 19,
		Entitlements: types.SubscriptionEntitlements{
			HostingPolicy: types.HostingPolicy{
				SchemaVersion: 2,
				Resources:     types.HostingResourcePolicy{MaxScheduledTasks: 8, ValkeyMemoryMB: 256},
				Permissions:   types.HostingPermissionPolicy{ScheduledTasks: true, Valkey: true},
			},
		},
	}
	plan := addonAsPlan(addon)
	if plan.HostingPolicy.Resources.MaxScheduledTasks != 8 ||
		plan.HostingPolicy.Resources.ValkeyMemoryMB != 256 ||
		!plan.HostingPolicy.Permissions.ScheduledTasks ||
		!plan.HostingPolicy.Permissions.Valkey {
		t.Fatalf("addonAsPlan lost typed policy: %#v", plan.HostingPolicy)
	}
}

func TestFormatQuotaPHPHandlesUnlimitedFields(t *testing.T) {
	tests := []struct {
		name    string
		summary controlquota.Summary
		want    string
	}{
		{
			name:    "no active subscription",
			summary: controlquota.Summary{},
			want:    "no active subscription",
		},
		{
			name: "both defaults",
			summary: controlquota.Summary{
				HasQuota: true,
				Limits:   controlquota.Limits{PHPFPMMaxChildren: -1, PHPMemoryMB: -1},
			},
			want: "agent defaults",
		},
		{
			name: "default children with finite memory",
			summary: controlquota.Summary{
				HasQuota: true,
				Limits:   controlquota.Limits{PHPFPMMaxChildren: -1, PHPMemoryMB: 128},
			},
			want: "agent default / 128 MB",
		},
		{
			name: "finite children with default memory",
			summary: controlquota.Summary{
				HasQuota: true,
				Limits:   controlquota.Limits{PHPFPMMaxChildren: 3, PHPMemoryMB: -1},
			},
			want: "3 children / agent default",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := formatQuotaPHP(test.summary); got != test.want {
				t.Fatalf("formatQuotaPHP() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestFormatPlanLimitMB(t *testing.T) {
	if got := formatPlanLimitMB(-1); got != "unlimited" {
		t.Fatalf("formatPlanLimitMB(-1) = %q, want unlimited", got)
	}
	if got := formatPlanLimitMB(512); got != "512 MB" {
		t.Fatalf("formatPlanLimitMB(512) = %q, want 512 MB", got)
	}
	if got := formatPlanLimitMB(5 * 1024); got != "5 GB" {
		t.Fatalf("formatPlanLimitMB(5 GiB) = %q, want 5 GB", got)
	}
	if got := formatPlanLimitMB(1024 * 1024); got != "1 TB" {
		t.Fatalf("formatPlanLimitMB(1 TiB) = %q, want 1 TB", got)
	}
}

func TestFormatPlanPHPHandlesUnlimitedFields(t *testing.T) {
	tests := []struct {
		name string
		plan controlquota.Plan
		want string
	}{
		{
			name: "both defaults",
			plan: controlquota.Plan{PHPFPMMaxChildren: -1, PHPMemoryMB: -1},
			want: "agent defaults",
		},
		{
			name: "default children with finite memory",
			plan: controlquota.Plan{PHPFPMMaxChildren: -1, PHPMemoryMB: 256},
			want: "agent default / 256 MB",
		},
		{
			name: "finite limits",
			plan: controlquota.Plan{PHPFPMMaxChildren: 8, PHPMemoryMB: 256},
			want: "8 children / 256 MB",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := formatPlanPHP(test.plan); got != test.want {
				t.Fatalf("formatPlanPHP() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestStatusPillClassMapsOperationalStates(t *testing.T) {
	tests := map[string]string{
		"active":             "ok",
		"completed":          "ok",
		"healthy":            "ok",
		"in_sync":            "ok",
		"pending":            "pend",
		"queued":             "pend",
		"running":            "run",
		"provisioning":       "run",
		"preparing":          "run",
		"validating":         "run",
		"activating":         "run",
		"failed":             "fail",
		"discarded":          "fail",
		"over_limit":         "fail",
		"capability_blocked": "fail",
		"suspended":          "susp",
		"unknown":            "susp",
	}
	for state, want := range tests {
		if got := statusPillClass(state); got != want {
			t.Fatalf("statusPillClass(%q) = %q, want %q", state, got, want)
		}
	}
}

func TestUsageMeterHandlesUnlimitedZeroAndFullLimits(t *testing.T) {
	tests := []struct {
		name      string
		used      int
		allowed   int
		hasLimits bool
		wantPct   string
		wantClass string
	}{
		{name: "no subscription", used: 3, allowed: 0, hasLimits: false, wantPct: "0", wantClass: "none"},
		{name: "unlimited", used: 3, allowed: -1, hasLimits: true, wantPct: "4", wantClass: ""},
		{name: "zero", used: 0, allowed: 0, hasLimits: true, wantPct: "100", wantClass: "full"},
		{name: "half", used: 1, allowed: 2, hasLimits: true, wantPct: "50", wantClass: ""},
		{name: "hot", used: 4, allowed: 5, hasLimits: true, wantPct: "80", wantClass: "hot"},
		{name: "full", used: 2, allowed: 2, hasLimits: true, wantPct: "100", wantClass: "full"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := usageMeter(test.used, test.allowed, test.hasLimits)
			if got.Percent != test.wantPct || got.Class != test.wantClass {
				t.Fatalf("usageMeter() = %#v, want pct=%q class=%q", got, test.wantPct, test.wantClass)
			}
		})
	}
}

func TestCustomerGateDataReflectsQuotaSummary(t *testing.T) {
	summary := controlquota.Summary{
		UserID:         7,
		Email:          "client@nakpanel.test",
		HasQuota:       true,
		PlanName:       "Starter",
		SubscriptionID: 11,
		Limits:         controlquota.Limits{MaxSites: 2, StorageMB: 5120},
		Usage:          controlquota.Usage{Sites: 1},
	}

	data := customerGateData(summary)
	for key, want := range map[string]string{
		"user-id":         "7",
		"subscription-id": "11",
		"email":           "client@nakpanel.test",
		"plan-name":       "Starter",
		"has-quota":       "true",
		"max-sites":       "2",
		"sites-used":      "1",
		"storage-mb":      "5120",
	} {
		if got := data[key]; got != want {
			t.Fatalf("customerGateData[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestReferenceSubscriptionFormatting(t *testing.T) {
	summary := controlquota.Summary{
		Email:    "ama-catering@example.gh",
		HasQuota: true,
		PlanName: "Starter",
		Limits: controlquota.Limits{
			MaxSites:  1,
			StorageMB: 5120,
		},
		Usage: controlquota.Usage{
			Sites:              1,
			BackupStorageBytes: 805 * 1024 * 1024,
		},
	}

	if got := displayCustomerName(summary); got != "Ama Catering" {
		t.Fatalf("displayCustomerName() = %q, want Ama Catering", got)
	}
	if got := siteLimitLabel(summary); got != "full" {
		t.Fatalf("siteLimitLabel() = %q, want full", got)
	}
	if got := formatQuotaCompactCount(summary.Usage.Sites, summary.Limits.MaxSites, summary.HasQuota); got != "1/1" {
		t.Fatalf("formatQuotaCompactCount() = %q, want 1/1", got)
	}
	if got := formatQuotaCompactStorage(summary); got != "0.8 GB/5 GB" {
		t.Fatalf("formatQuotaCompactStorage() = %q, want 0.8 GB/5 GB", got)
	}
	if got := formatCapacityCommitment(245760, 245760); got != "240 GB / 240 GB (100%)" {
		t.Fatalf("formatCapacityCommitment() = %q, want 240 GB / 240 GB (100%%)", got)
	}
}

func TestFileSortPathPreservesSupportScopeAndFilters(t *testing.T) {
	view := WorkspaceView{SupportCustomerID: 88}
	data := &FileManagerView{SiteID: 7, Path: "assets", Query: "php", Sort: "size", Order: "asc"}
	got := fileSortPath(view, data, "size")
	want := "/support/customers/88/sites/7/files?order=desc&path=assets&q=php&sort=size"
	if got != want {
		t.Fatalf("fileSortPath() = %q, want %q", got, want)
	}
}

func TestDatabaseWorkspaceHelpers(t *testing.T) {
	if !databaseLimitReached(types.SubscriptionSummary{MaxDatabases: 2, DatabasesUsed: 2}) {
		t.Fatal("databaseLimitReached() = false at the subscription limit")
	}
	if databaseLimitReached(types.SubscriptionSummary{MaxDatabases: -1, DatabasesUsed: 50}) {
		t.Fatal("databaseLimitReached() = true for an unlimited subscription")
	}
	if got := databaseEngineLabel("mariadb"); got != "MariaDB" {
		t.Fatalf("databaseEngineLabel() = %q, want MariaDB", got)
	}
}

func TestPHPVersionsRequireInstalledAllowedRuntime(t *testing.T) {
	capabilities := types.RuntimeCapabilities{PHPVersions: []string{"8.4", "8.3"}}
	if got := phpVersionsFromCapabilities(capabilities, "8.3,8.2"); len(got) != 1 || got[0] != "8.3" {
		t.Fatalf("phpVersionsFromCapabilities() = %#v, want only installed and allowed 8.3", got)
	}
	if got := phpVersionsFromCapabilities(types.RuntimeCapabilities{}, "8.3,8.2"); len(got) != 0 {
		t.Fatalf("missing capabilities must fail closed, got %#v", got)
	}
	if got := phpVersions(""); len(got) != 0 {
		t.Fatalf("empty allowlist must not invent a runtime, got %#v", got)
	}
}

func TestNewPlanPrefersReadyPHP84AndKeepsPHP85Selectable(t *testing.T) {
	capabilities := types.RuntimeCapabilities{PHPVersions: []string{"8.5", "8.4", "8.3"}}
	plan := planEditorDefault(capabilities)
	if plan.LifecycleStatus != types.PlanLifecycleDraft || plan.IsActive {
		t.Fatalf("new plan lifecycle = %q active=%t, want draft and unavailable", plan.LifecycleStatus, plan.IsActive)
	}
	if plan.DefaultPHPVersion != "8.4" {
		t.Fatalf("new plan default PHP = %q, want ready PHP 8.4", plan.DefaultPHPVersion)
	}
	if plan.PHPAllowlist != "8.5,8.4,8.3" {
		t.Fatalf("new plan PHP allowlist = %q, want every ready runtime", plan.PHPAllowlist)
	}
	if got := planPHPVersions(plan, capabilities); len(got) != 3 || got[0] != "8.5" || got[1] != "8.4" || got[2] != "8.3" {
		t.Fatalf("new plan selectable PHP versions = %#v", got)
	}
}

func TestPlanEditorTabsUseProductionContractGroups(t *testing.T) {
	for _, tab := range []string{"overview", "resources", "services", "customer-permissions", "defaults", "advanced"} {
		if got := planEditorTab(WorkspaceView{PlanTab: tab}); got != tab {
			t.Fatalf("planEditorTab(%q) = %q", tab, got)
		}
	}
	if got := planEditorTab(WorkspaceView{PlanTab: "php"}); got != "overview" {
		t.Fatalf("legacy editor tab should fall back to overview, got %q", got)
	}
}

func TestPlanPreviewJavaScriptPreservesZeroValuesAndClearsStaleResults(t *testing.T) {
	javascript := string(appJS)
	for _, want := range []string{
		"function previewValue(value)",
		"previewValue(change.old_value)",
		"previewValue(change.new_value)",
		"function clearPlanPreview()",
		"clearPlanPreview();",
		"function revealInvalidPlanField(form)",
		`selectPlanTab(panel.getAttribute("data-np-plan-panel"), true)`,
		"invalid.reportValidity()",
	} {
		if !strings.Contains(javascript, want) {
			t.Fatalf("plan preview JavaScript missing %q", want)
		}
	}
}

func TestSiteRuntimeChoicesPutPreferredPHP84First(t *testing.T) {
	capabilities := types.RuntimeCapabilities{PHPVersions: []string{"8.5", "8.4", "8.3"}}
	subscriptions := []types.SubscriptionSummary{{PHPAllowlist: "8.5,8.4,8.3"}}
	got := subscriptionPHPVersions(subscriptions, capabilities)
	if len(got) != 3 || got[0] != "8.4" || got[1] != "8.5" || got[2] != "8.3" {
		t.Fatalf("site runtime choices = %#v, want preferred PHP 8.4 first", got)
	}
}

func TestApplicationDeploymentRequiresPresetOrCustomOCI(t *testing.T) {
	policy := types.HostingPolicy{
		Permissions:  types.HostingPermissionPolicy{Applications: true},
		Applications: types.HostingApplicationPolicy{AllowedCatalogSlugs: []string{"wordpress"}, AllowedRuntimes: []string{"php"}},
	}
	if applicationDeploymentAvailable(nil, policy) {
		t.Fatal("application form is available without an allowed preset or custom OCI")
	}
	presets := []types.ApplicationPreset{{Slug: "wordpress", Runtime: "php", Active: true}}
	if !applicationDeploymentAvailable(presets, policy) {
		t.Fatal("allowed active preset did not enable application deployment")
	}
	policy.Permissions.CustomOCIImages = true
	if !applicationDeploymentAvailable(nil, policy) {
		t.Fatal("custom OCI permission did not enable application deployment")
	}
}

func TestSitePolicyScopeCustomized(t *testing.T) {
	item := dashboard.SitePolicy{SiteOverride: json.RawMessage(`{"php":{"memory_limit_mb":256}}`)}
	if !sitePolicyScopeCustomized(item, "php") {
		t.Fatal("PHP override was not marked customized")
	}
	if sitePolicyScopeCustomized(item, "web") {
		t.Fatal("missing web override was marked customized")
	}
	if got := domainToolLabel("scheduled-tasks"); got != "Scheduled Tasks" {
		t.Fatalf("domainToolLabel() = %q", got)
	}
	if got := domainMoreActive("databases"); got != "is-active" {
		t.Fatalf("domainMoreActive() = %q", got)
	}
}

func TestSiteCreationRouteTitle(t *testing.T) {
	if got := routeTitle("site-new"); got != "Add Website" {
		t.Fatalf("site-new title = %q", got)
	}
}
