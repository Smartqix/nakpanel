package ops

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/types"
	"os"
	"path/filepath"
	"testing"
)

func TestRemovalDNSRejectsOlderSharedRevision(t *testing.T) {
	root := t.TempDir()
	reload := &recordingPhase6Reloader{}
	p := NewDNSProvisioner(DNSProvisionerOptions{ZoneDir: filepath.Join(root, "zones"), IncludeDir: filepath.Join(root, "includes"), AggregatePath: filepath.Join(root, "named.conf"), ValidatorRunner: &teardownRunner{}, Reloader: reload})
	old := types.ConfigureDNSZoneReq{SiteID: 1, SubscriptionID: 2, ZoneID: 3, DesiredRevision: 1, Domain: "primary.test", Mode: "primary", Address: "192.0.2.1", Serial: 1, Records: []types.DNSRecord{{Host: "child", Type: "A", Value: "192.0.2.1", TTL: 3600}}}
	if _, err := p.ConfigureDNSZone(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := old
	next.DesiredRevision = 2
	next.Serial = 2
	next.Records = nil
	if _, err := p.ConfigureDNSZone(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, "zones", "db.primary.test"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.ConfigureDNSZone(context.Background(), old); err == nil {
		t.Fatal("paused old shared DNS snapshot resurrected removed child")
	}
	after, err := os.ReadFile(filepath.Join(root, "zones", "db.primary.test"))
	if err != nil || string(before) != string(after) {
		t.Fatal("old revision changed active zone", err)
	}
	next.Records = old.Records
	if _, err = p.ConfigureDNSZone(context.Background(), next); err == nil {
		t.Fatal("different intent reused a captured revision")
	}
}

func TestRemovalDNSFailedRevisionDoesNotBlockRecovery(t *testing.T) {
	root := t.TempDir()
	reload := &recordingPhase6Reloader{}
	p := NewDNSProvisioner(DNSProvisionerOptions{ZoneDir: filepath.Join(root, "zones"), IncludeDir: filepath.Join(root, "includes"), AggregatePath: filepath.Join(root, "named.conf"), ValidatorRunner: &teardownRunner{}, Reloader: reload})
	req := types.ConfigureDNSZoneReq{SiteID: 1, SubscriptionID: 2, ZoneID: 3, DesiredRevision: 1, Domain: "primary.test", Mode: "primary", Address: "192.0.2.1", Serial: 1}
	if _, err := p.ConfigureDNSZone(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	next := req
	next.DesiredRevision = 2
	next.Serial = 2
	reload.err = errors.New("fixture reload failure")
	if _, err := p.ConfigureDNSZone(context.Background(), next); err == nil {
		t.Fatal("reload failure ignored")
	}
	reload.err = nil
	if _, err := p.ConfigureDNSZone(context.Background(), req); err != nil {
		t.Fatal("failed candidate advanced applied marker", err)
	}
	if _, err := p.ConfigureDNSZone(context.Background(), next); err != nil {
		t.Fatal("recovery blocked", err)
	}
	if _, err := p.ConfigureDNSZone(context.Background(), types.ConfigureDNSZoneReq{Domain: req.Domain, Mode: "disabled"}); err != nil {
		t.Fatal(err)
	}
	next.SiteID = 4
	next.ZoneID = 5
	next.DesiredRevision = 1
	if _, err := p.ConfigureDNSZone(context.Background(), next); err != nil {
		t.Fatal("fresh identity blocked by removed marker", err)
	}
}
