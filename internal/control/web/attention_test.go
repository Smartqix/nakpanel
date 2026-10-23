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

func TestCapacityPressureShowsOnlyStrainedSubscriptions(t *testing.T) {
	pressure := capacityPressure([]types.SubscriptionSummary{
		{ID: 1, SubscriptionName: "Idle", MaxSites: 5, SitesUsed: 0, DomainsUsed: 0},
		{ID: 2, SubscriptionName: "At limit", MaxSites: 1, SitesUsed: 1, DomainsUsed: 1},
		{ID: 3, SubscriptionName: "Unlimited", MaxSites: 0, SitesUsed: 900, DomainsUsed: 900},
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
