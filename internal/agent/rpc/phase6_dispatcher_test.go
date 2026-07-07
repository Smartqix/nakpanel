package rpc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeBackupProvisioner struct {
	req types.CreateBackupReq
}

func (p *fakeBackupProvisioner) CreateBackup(ctx context.Context, req types.CreateBackupReq) (types.CreateBackupResult, error) {
	p.req = req
	return types.CreateBackupResult{ArchivePath: "/var/lib/nakpanel/backups/example.tar.gz", SizeBytes: 42, SHA256: "abc"}, nil
}

type fakeWebmailProvisioner struct {
	req types.ConfigureWebmailReq
}

func (p *fakeWebmailProvisioner) ConfigureWebmail(ctx context.Context, req types.ConfigureWebmailReq) (types.ConfigureWebmailResult, error) {
	p.req = req
	return types.ConfigureWebmailResult{Hostname: req.Hostname, ConfigPath: "/etc/nginx/sites-available/webmail.example.test.conf"}, nil
}

type fakeDNSProvisioner struct {
	req types.ConfigureDNSZoneReq
}

func (p *fakeDNSProvisioner) ConfigureDNSZone(ctx context.Context, req types.ConfigureDNSZoneReq) (types.ConfigureDNSZoneResult, error) {
	p.req = req
	return types.ConfigureDNSZoneResult{Domain: req.Domain, ZonePath: "/etc/bind/zones/db.example.test"}, nil
}

type fakeReconciliationProvisioner struct {
	req types.ReconcileSystemReq
}

func (p *fakeReconciliationProvisioner) ReconcileSystem(ctx context.Context, req types.ReconcileSystemReq) (types.ReconcileSystemResult, error) {
	p.req = req
	return types.ReconcileSystemResult{SitesTotal: len(req.Sites), SitesOK: len(req.Sites)}, nil
}

type fakeRestoreProvisioner struct {
	req types.RestoreBackupReq
}

func (p *fakeRestoreProvisioner) RestoreBackup(ctx context.Context, req types.RestoreBackupReq) (types.RestoreBackupResult, error) {
	p.req = req
	return types.RestoreBackupResult{Domain: req.Domain, RestoredFiles: 2, RestoredDatabases: req.Databases}, nil
}

func TestDispatcherHandlesPhase6Ops(t *testing.T) {
	backup := &fakeBackupProvisioner{}
	webmail := &fakeWebmailProvisioner{}
	dns := &fakeDNSProvisioner{}
	reconcile := &fakeReconciliationProvisioner{}
	restore := &fakeRestoreProvisioner{}
	dispatcher := NewDispatcher(nil, Options{
		BackupProvisioner:         backup,
		WebmailProvisioner:        webmail,
		DNSProvisioner:            dns,
		ReconciliationProvisioner: reconcile,
		RestoreProvisioner:        restore,
	})

	tests := []struct {
		name string
		op   string
		data any
		want string
	}{
		{
			name: "backup",
			op:   types.OpCreateBackup,
			data: types.CreateBackupReq{Domain: "example.test", Username: "npdemo", Docroot: "/home/npdemo/public_html"},
			want: "archive_path",
		},
		{
			name: "webmail",
			op:   types.OpConfigureWebmail,
			data: types.ConfigureWebmailReq{Domain: "example.test", Hostname: "webmail.example.test"},
			want: "hostname",
		},
		{
			name: "dns",
			op:   types.OpConfigureDNSZone,
			data: types.ConfigureDNSZoneReq{Domain: "example.test", Address: "192.0.2.10", Serial: 2026070701},
			want: "zone_path",
		},
		{
			name: "reconcile",
			op:   types.OpReconcileSystem,
			data: types.ReconcileSystemReq{Sites: []types.ReconcileSiteReq{{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3"}}},
			want: "sites_total",
		},
		{
			name: "restore",
			op:   types.OpRestoreBackup,
			data: types.RestoreBackupReq{Domain: "example.test", Username: "npdemo", Docroot: "/home/npdemo/public_html", ArchivePath: "/var/lib/nakpanel/backups/example.tar.gz", Databases: []string{"np_demo"}},
			want: "restored_files",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.data)
			if err != nil {
				t.Fatalf("Marshal returned error: %v", err)
			}
			resp := dispatcher.Dispatch(context.Background(), types.Request{ID: test.name + "-1", Op: test.op, Data: raw})
			if !resp.OK {
				t.Fatalf("Dispatch returned error: %s", resp.Error)
			}
			if !strings.Contains(string(resp.Data), test.want) {
				t.Fatalf("response data %s missing %s", resp.Data, test.want)
			}
		})
	}

	if backup.req.Domain != "example.test" || webmail.req.Hostname != "webmail.example.test" || dns.req.Address != "192.0.2.10" || len(reconcile.req.Sites) != 1 || restore.req.ArchivePath == "" {
		t.Fatalf("phase6 provisioners were not called: backup=%#v webmail=%#v dns=%#v reconcile=%#v restore=%#v", backup.req, webmail.req, dns.req, reconcile.req, restore.req)
	}
}

func TestDispatcherRejectsMalformedPhase6Payload(t *testing.T) {
	dispatcher := NewDispatcher(nil, Options{BackupProvisioner: &fakeBackupProvisioner{}})
	resp := dispatcher.Dispatch(context.Background(), types.Request{
		ID:   "bad-backup",
		Op:   types.OpCreateBackup,
		Data: json.RawMessage(`{"domain":"example.test","unexpected":true}`),
	})
	if resp.OK {
		t.Fatalf("Dispatch OK = true, want validation error")
	}
	if !strings.Contains(resp.Error, "unexpected") {
		t.Fatalf("error = %q, want unexpected field validation", resp.Error)
	}
}
