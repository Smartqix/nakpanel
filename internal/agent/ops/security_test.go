package ops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

// These tests pin the agent-boundary hardening added by the Phase 21
// adversarial suite. Each asserts a hostile input is rejected before any side
// effect — mirroring the integration attacks in security-verify.sh so the
// guarantees are also enforced by `go test ./...`.

func TestValidateCreateSiteRejectsReservedAndHostileUsernames(t *testing.T) {
	for _, name := range []string{"root", "mysql", "nakpanel", "postgres", "bind", "nobody", "admin", "daemon"} {
		if err := site.ValidateUsername(name); err == nil {
			t.Fatalf("reserved username %q was accepted", name)
		}
		err := site.ValidateCreateSiteRequest(types.CreateSiteReq{Username: name, Domain: "ok.example.test", PHPVersion: "8.3"})
		if err == nil {
			t.Fatalf("CreateSite accepted reserved username %q", name)
		}
	}
	// A normal tenant username still passes.
	if err := site.ValidateUsername("npdemo7"); err != nil {
		t.Fatalf("valid username rejected: %v", err)
	}
}

func TestValidateCreateSiteRejectsHostileDomainsAndDocroot(t *testing.T) {
	for _, domain := range []string{"../../etc", "/etc/passwd", "a.b\nc.d", "x.gh;}server{listen 80;root /etc;}", "www.exa mple.test", strings.Repeat("a", 64) + ".test"} {
		if err := site.ValidateCreateSiteRequest(types.CreateSiteReq{Username: "npdemo7", Domain: domain, PHPVersion: "8.3"}); err == nil {
			t.Fatalf("hostile domain %q was accepted", domain)
		}
	}
	// A client-supplied docroot is rejected; the agent derives it.
	if err := site.ValidateCreateSiteRequest(types.CreateSiteReq{Username: "npdemo7", Domain: "ok.example.test", PHPVersion: "8.3", Docroot: "/etc"}); err == nil {
		t.Fatal("client-supplied docroot was accepted")
	}
}

func TestRestoreBackupRejectsDocrootOutsideHome(t *testing.T) {
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	// A real archive is not needed: the docroot constraint must trip during
	// request normalization, before any extraction.
	p := NewRestoreProvisioner(RestoreProvisionerOptions{HomeRoot: homeRoot})
	for _, docroot := range []string{"/etc", filepath.Join(root, "home", "npother", "public_html"), "/tmp/evil"} {
		_, err := p.RestoreBackup(context.Background(), types.RestoreBackupReq{
			Domain: "example.test", Username: "npdemo", Docroot: docroot, ArchivePath: filepath.Join(root, "a.tar.gz"),
		})
		if err == nil || !strings.Contains(err.Error(), "outside the tenant home") {
			t.Fatalf("restore into %q was not rejected as outside home: %v", docroot, err)
		}
	}
}

func TestCreateBackupRejectsDocrootAndOutputEscape(t *testing.T) {
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	backupRoot := filepath.Join(root, "backups")
	if err := os.MkdirAll(filepath.Join(homeRoot, "npdemo", "public_html"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := NewBackupProvisioner(BackupProvisionerOptions{OutputDir: backupRoot, HomeRoot: homeRoot, DatabaseDumper: &fakeDatabaseDumper{}})
	// Docroot escape.
	if _, err := p.CreateBackup(context.Background(), types.CreateBackupReq{Domain: "example.test", Username: "npdemo", Docroot: "/etc"}); err == nil || !strings.Contains(err.Error(), "outside the tenant home") {
		t.Fatalf("backup of /etc was not rejected: %v", err)
	}
	// Output-dir escape.
	if _, err := p.CreateBackup(context.Background(), types.CreateBackupReq{Domain: "example.test", Username: "npdemo", Docroot: filepath.Join(homeRoot, "npdemo", "public_html"), OutputDir: "/tmp/steal"}); err == nil || !strings.Contains(err.Error(), "outside the backup root") {
		t.Fatalf("backup output escape was not rejected: %v", err)
	}
}

func TestDNSRecordValidationRejectsInjectionKeepsUnderscoreHosts(t *testing.T) {
	base := types.DNSRecord{Host: "www", Type: "A", Value: "203.0.113.5", TTL: 3600}
	// Injection attempts must be rejected.
	hostile := []types.DNSRecord{
		{Host: "www 300 IN A 6.6.6.6\nevil", Type: "A", Value: "203.0.113.5", TTL: 3600},
		{Host: "www", Type: "TXT", Value: "ok\"\nevil 300 IN NS attacker.example.", TTL: 3600},
		{Host: "www", Type: "CNAME", Value: "target.example.\nevil 300 IN A 6.6.6.6", TTL: 3600},
		{Host: "b@d", Type: "A", Value: "203.0.113.5", TTL: 3600},
		{Host: "www", Type: "A", Value: "not-an-ip", TTL: 3600},
		{Host: "sip._tcp", Type: "SRV", Value: "sip.example.test", Priority: 10, Weight: 5, Port: 5060, TTL: 3600},
		{Host: "@", Type: "DS", Value: "65536 13 2 " + strings.Repeat("A", 64), TTL: 3600},
		{Host: "@", Type: "DS", Value: "12345 0 2 " + strings.Repeat("A", 64), TTL: 3600},
	}
	for i, rec := range hostile {
		if err := validateDNSRecordAtAgent(rec); err == nil {
			t.Fatalf("hostile DNS record #%d was accepted: %+v", i, rec)
		}
	}
	// Legitimate records — including DKIM/DMARC underscore owners — must pass.
	for _, rec := range []types.DNSRecord{
		base,
		{Host: "@", Type: "MX", Value: "mail.example.test", Priority: 10, TTL: 3600},
		{Host: "@", Type: "TXT", Value: "v=spf1 mx ~all", TTL: 3600},
		{Host: "_dmarc", Type: "TXT", Value: "v=DMARC1; p=quarantine; rua=mailto:postmaster@example.test", TTL: 3600},
		{Host: "nak1._domainkey", Type: "TXT", Value: "v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBg", TTL: 3600},
		{Host: "_sip._tcp", Type: "SRV", Value: "sip.example.test", Priority: 10, Weight: 5, Port: 5060, TTL: 3600},
	} {
		if err := validateDNSRecordAtAgent(rec); err != nil {
			t.Fatalf("legitimate DNS record rejected: %+v: %v", rec, err)
		}
	}
}
