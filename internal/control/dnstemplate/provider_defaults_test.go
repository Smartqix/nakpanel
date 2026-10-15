package dnstemplate

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"testing"

	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
)

func dnsFixture(t *testing.T) (*sql.DB, *Manager) {
	t.Helper()
	db := removaldb.New(t, "")
	driver := riverdatabasesql.New(db)
	m, err := rivermigrate.New(driver, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Migrate(context.Background(), rivermigrate.DirectionUp, nil); err != nil {
		t.Fatal(err)
	}
	client, err := river.NewClient(driver, &river.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return db, NewManager(db, client)
}

func TestProviderDefaultsTwoNameserversAndMatchingSOA(t *testing.T) {
	template := types.DNSTemplateRevision{Records: []types.DNSTemplateRecord{{StableKey: "apex-a", Scope: "all", HostTemplate: "@", Type: "A", ValueTemplate: "<ip.web>", TTL: 3600}}}
	result, err := withProviderDefaults(template, types.DNSProviderDefaults{PrimaryNameserver: "ns1.provider.test", SecondaryNameserver: "ns2.provider.test"})
	if err != nil {
		t.Fatal(err)
	}
	if result.SOA.PrimaryNameserver != "ns1.provider.test" || len(result.Records) != 3 {
		t.Fatalf("invalid provider defaults: %+v", result)
	}
	for _, record := range result.Records {
		if record.Type == "MX" || record.Type == "TXT" || record.Type == "AAAA" {
			t.Fatal("invented a service record")
		}
	}
}

func TestProviderDefaultsSharedIPWarning(t *testing.T) {
	if !nameserversShareAddress([]net.IP{net.ParseIP("192.0.2.1")}, []net.IP{net.ParseIP("192.0.2.1")}) {
		t.Fatal("shared host was presented as redundant")
	}
	if nameserversShareAddress([]net.IP{net.ParseIP("192.0.2.1")}, []net.IP{net.ParseIP("192.0.2.2")}) {
		t.Fatal("unrelated addresses conflated")
	}
}

func TestProviderDefaultsDoNotChangeExistingZones(t *testing.T) {
	db, manager := dnsFixture(t)
	ctx := context.Background()
	view, err := manager.View(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.SaveProviderDefaults(ctx, 1, view.Template.OptimisticRevision, types.DNSProviderDefaults{PrimaryNameserver: "ns1.provider.test", SecondaryNameserver: "ns2.provider.test"}); err != nil {
		t.Fatal(err)
	}
	var jobs int
	if err = db.QueryRow(`SELECT count(*) FROM river_job`).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatalf("saving defaults queued zone changes: %d %v", jobs, err)
	}
}

func TestStalePreviewLeavesZone(t *testing.T) {
	db, manager := dnsFixture(t)
	ctx := context.Background()
	preview, err := manager.Preview(ctx, 1, "all", 0)
	if err != nil {
		t.Fatal(err)
	}
	view, err := manager.View(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.SaveSettings(ctx, 1, types.DNSTemplateSettingsInput{ExpectedRevision: view.Template.OptimisticRevision, SOA: view.Template.SOA, ZoneStatus: "active", SubdomainPolicy: "parent"})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.ApplyPreview(ctx, 1, preview.ID, preview.PreviewToken, "APPLY DNS TEMPLATE"); !errors.Is(err, ErrStalePreview) {
		t.Fatalf("stale apply: %v", err)
	}
	var jobs int
	if err = db.QueryRow(`SELECT count(*) FROM river_job WHERE kind='sync_dns_template'`).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatalf("stale preview queued a mutation: %d %v", jobs, err)
	}
}
