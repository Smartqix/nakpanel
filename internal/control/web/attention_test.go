package web

import (
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestSiteHealthCorrelatesScatteredErrorFields(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	site := dashboard.Site{
		ID:            7,
		SettingsError: "read agent response: EOF",
		TLSExpiresAt:  dashboard.NullableTime{Time: now.Add(5 * 24 * time.Hour), Valid: true},
	}

	health := siteHealth(site, now)
	if health.Severity != SeverityCritical {
		t.Fatalf("severity = %v, want critical", health.Severity)
	}
	if !health.NeedsAttention() {
		t.Fatal("a site with an unconverged config must need attention")
	}
	if len(health.Issues) != 2 {
		t.Fatalf("issues = %d, want convergence and expiry", len(health.Issues))
	}
	// The most severe issue leads, so a list column shows the worst problem.
	if health.Issues[0].Severity != SeverityCritical || health.Summary != "Configuration has not converged" {
		t.Fatalf("summary = %q (%v), want the critical issue first", health.Summary, health.Issues[0].Severity)
	}
}

func TestSiteHealthIgnoresCertificatesOutsideTheWindow(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	site := dashboard.Site{ID: 1, TLSExpiresAt: dashboard.NullableTime{Time: now.Add(90 * 24 * time.Hour), Valid: true}}
	if health := siteHealth(site, now); health.NeedsAttention() {
		t.Fatalf("a certificate valid for 90 days must not raise attention: %+v", health)
	}
}

func TestBuildAttentionGroupsDuplicateAlerts(t *testing.T) {
	now := time.Date(2026, 9, 8, 23, 10, 0, 0, time.UTC)
	data := dashboard.Data{}
	for i := 0; i < 14; i++ {
		data.UsageAlerts = append(data.UsageAlerts, types.UsageAlert{
			Kind: "usage_collection", Severity: "warning",
			Title: "Usage collection failed", Body: "Retained last values.",
			CreatedAt: now.Add(-time.Duration(i) * time.Minute),
		})
	}
	attention := buildAttention(data, SiteHealthMap{}, now)

	if len(attention.Items) != 1 {
		t.Fatalf("items = %d, want the duplicates collapsed into one row", len(attention.Items))
	}
	if attention.Items[0].Count != 14 {
		t.Fatalf("count = %d, want 14", attention.Items[0].Count)
	}
	if attention.Items[0].Occurrences() != "14 occurrences" {
		t.Fatalf("occurrences = %q", attention.Items[0].Occurrences())
	}
}

func TestBuildAttentionPutsCriticalFirst(t *testing.T) {
	now := time.Now()
	data := dashboard.Data{UsageAlerts: []types.UsageAlert{
		{Kind: "usage", Severity: "warning", Title: "Usage collection failed", CreatedAt: now},
		{Kind: "reconcile", Severity: "critical", Title: "System reconciliation failed", CreatedAt: now},
	}}
	attention := buildAttention(data, SiteHealthMap{}, now)
	if attention.Items[0].Severity != SeverityCritical {
		t.Fatalf("first item = %v, want the critical row pinned above warnings", attention.Items[0].Severity)
	}
	if attention.Critical != 1 || attention.Warning != 1 {
		t.Fatalf("critical=%d warning=%d, want 1/1", attention.Critical, attention.Warning)
	}
	if attention.BadgeSeverity() != SeverityCritical {
		t.Fatal("badge must take the worst open severity")
	}
}

func TestBuildAttentionDoesNotCountOneIncidentTwice(t *testing.T) {
	now := time.Now()
	data := dashboard.Data{
		UsageAlerts: []types.UsageAlert{{Kind: "reconcile", Severity: "critical", Title: "System reconciliation failed", CreatedAt: now}},
		// The same incident also surfaces as a failed job.
		Jobs: []dashboard.Job{{ID: 1, Kind: "reconcile_system", State: "discarded"}},
	}
	attention := buildAttention(data, SiteHealthMap{}, now)
	if len(attention.Items) != 1 {
		t.Fatalf("items = %d, want the alert and its job counted once: %+v", len(attention.Items), attention.Items)
	}
}

func TestBuildAttentionIgnoresResolvedAndInfoAlerts(t *testing.T) {
	now := time.Now()
	data := dashboard.Data{UsageAlerts: []types.UsageAlert{
		{Kind: "a", Severity: "critical", Title: "Handled", CreatedAt: now, ResolvedAt: now},
		{Kind: "b", Severity: "info", Title: "New sign-in address", CreatedAt: now},
	}}
	if attention := buildAttention(data, SiteHealthMap{}, now); attention.Total() != 0 {
		t.Fatalf("total = %d, want resolved and informational alerts excluded", attention.Total())
	}
}

func TestCapacityPressureShowsOnlyStrainedSubscriptions(t *testing.T) {
	pressure := capacityPressure([]types.SubscriptionSummary{
		{ID: 1, SubscriptionName: "Idle", MaxSites: 5, SitesUsed: 0},
		{ID: 2, SubscriptionName: "At limit", MaxSites: 1, SitesUsed: 1},
		{ID: 3, SubscriptionName: "Unlimited", MaxSites: 0, SitesUsed: 900},
	})
	if len(pressure.Items) != 1 {
		t.Fatalf("items = %+v, want only the subscription at its limit", pressure.Items)
	}
	if pressure.Items[0].SubscriptionID != 2 || pressure.Items[0].Severity != SeverityCritical {
		t.Fatalf("item = %+v, want subscription 2 as critical", pressure.Items[0])
	}
	if pressure.Remaining != 2 {
		t.Fatalf("remaining = %d, want the other two summarised", pressure.Remaining)
	}
}

func TestNavBadgeCountsAttentionNotInventory(t *testing.T) {
	now := time.Now()
	sites := []dashboard.Site{
		{ID: 1},
		{ID: 2, SettingsError: "boom"},
		{ID: 3, TLSExpiresAt: dashboard.NullableTime{Time: now.Add(2 * 24 * time.Hour), Valid: true}},
	}
	// Three sites, two of them with a problem: the badge must read 2, not 3.
	if got := sitesNeedingAttention(sites); got != 2 {
		t.Fatalf("sitesNeedingAttention = %d, want 2", got)
	}
}
