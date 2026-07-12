package web

import (
	"testing"

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
		"active":       "ok",
		"completed":    "ok",
		"pending":      "pend",
		"queued":       "pend",
		"running":      "run",
		"provisioning": "run",
		"failed":       "fail",
		"discarded":    "fail",
		"suspended":    "susp",
		"unknown":      "susp",
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
