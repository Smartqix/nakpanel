package ops

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type recordingPhase6Reloader struct {
	services []string
	err      error
}

func (r *recordingPhase6Reloader) ReloadService(ctx context.Context, name string) error {
	r.services = append(r.services, name)
	return r.err
}

type fakeDatabaseDumper struct {
	names []string
}

func (d *fakeDatabaseDumper) DumpDatabase(ctx context.Context, name string) ([]byte, error) {
	d.names = append(d.names, name)
	return []byte("-- dump " + name + "\n"), nil
}

type fakeDatabaseRestorer struct {
	names []string
	dumps []string
}

func (r *fakeDatabaseRestorer) RestoreDatabase(ctx context.Context, name string, dump []byte) error {
	r.names = append(r.names, name)
	r.dumps = append(r.dumps, string(dump))
	return nil
}

func TestBackupProvisionerCreatesArchiveWithFilesAndDatabaseDumps(t *testing.T) {
	root := t.TempDir()
	docroot := filepath.Join(root, "home", "npdemo", "public_html")
	if err := os.MkdirAll(filepath.Join(docroot, "nested"), 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "index.php"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile index returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "nested", "app.php"), []byte("app"), 0o644); err != nil {
		t.Fatalf("WriteFile app returned error: %v", err)
	}

	dumper := &fakeDatabaseDumper{}
	provisioner := NewBackupProvisioner(BackupProvisionerOptions{
		OutputDir:      filepath.Join(root, "backups"),
		DatabaseDumper: dumper,
	})
	result, err := provisioner.CreateBackup(context.Background(), types.CreateBackupReq{
		Domain:    "example.test",
		Username:  "npdemo",
		Docroot:   docroot,
		Databases: []string{"np_demo"},
	})
	if err != nil {
		t.Fatalf("CreateBackup returned error: %v", err)
	}
	if result.ArchivePath == "" || result.SizeBytes == 0 || result.SHA256 == "" {
		t.Fatalf("backup result missing archive metadata: %#v", result)
	}
	if dumper.names[0] != "np_demo" {
		t.Fatalf("database dumps = %#v, want np_demo", dumper.names)
	}

	names := readTarGzNames(t, result.ArchivePath)
	for _, want := range []string{"manifest.json", "files/index.php", "files/nested/app.php", "databases/np_demo.sql"} {
		if !slices.Contains(names, want) {
			t.Fatalf("archive names = %#v, missing %s", names, want)
		}
	}
}

func TestRestoreProvisionerRestoresFilesAndDatabaseDumps(t *testing.T) {
	root := t.TempDir()
	docroot := filepath.Join(root, "home", "npdemo", "public_html")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll docroot returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "old.php"), []byte("old"), 0o644); err != nil {
		t.Fatalf("WriteFile old returned error: %v", err)
	}

	backupSource := filepath.Join(root, "backup-source")
	if err := os.MkdirAll(filepath.Join(backupSource, "nested"), 0o755); err != nil {
		t.Fatalf("MkdirAll backup source returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(backupSource, "index.php"), []byte("restored"), 0o644); err != nil {
		t.Fatalf("WriteFile index returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(backupSource, "nested", "app.php"), []byte("app"), 0o644); err != nil {
		t.Fatalf("WriteFile app returned error: %v", err)
	}
	dumper := &fakeDatabaseDumper{}
	backup, err := NewBackupProvisioner(BackupProvisionerOptions{
		OutputDir:      filepath.Join(root, "backups"),
		DatabaseDumper: dumper,
	}).CreateBackup(context.Background(), types.CreateBackupReq{
		Domain:    "example.test",
		Username:  "npdemo",
		Docroot:   backupSource,
		Databases: []string{"np_demo"},
	})
	if err != nil {
		t.Fatalf("CreateBackup returned error: %v", err)
	}

	restorer := &fakeDatabaseRestorer{}
	result, err := NewRestoreProvisioner(RestoreProvisionerOptions{
		DatabaseRestorer: restorer,
	}).RestoreBackup(context.Background(), types.RestoreBackupReq{
		Domain:      "example.test",
		Username:    "npdemo",
		Docroot:     docroot,
		ArchivePath: backup.ArchivePath,
		Databases:   []string{"np_demo"},
	})
	if err != nil {
		t.Fatalf("RestoreBackup returned error: %v", err)
	}
	if result.RestoredFiles != 2 || !slices.Equal(result.RestoredDatabases, []string{"np_demo"}) {
		t.Fatalf("restore result = %#v, want two files and np_demo database", result)
	}
	data, err := os.ReadFile(filepath.Join(docroot, "index.php"))
	if err != nil {
		t.Fatalf("ReadFile restored index returned error: %v", err)
	}
	if string(data) != "restored" {
		t.Fatalf("index.php = %q, want restored", data)
	}
	if _, err := os.Stat(filepath.Join(docroot, "old.php")); !os.IsNotExist(err) {
		t.Fatalf("old.php still exists or stat returned unexpected error: %v", err)
	}
	if len(restorer.names) != 1 || restorer.names[0] != "np_demo" || !strings.Contains(restorer.dumps[0], "-- dump np_demo") {
		t.Fatalf("restored databases names=%#v dumps=%#v, want np_demo dump", restorer.names, restorer.dumps)
	}
}

func TestWebmailProvisionerWritesNginxConfigAndReloads(t *testing.T) {
	root := t.TempDir()
	reloader := &recordingPhase6Reloader{}
	provisioner := NewWebmailProvisioner(WebmailProvisionerOptions{
		NginxAvailableDir: filepath.Join(root, "available"),
		NginxEnabledDir:   filepath.Join(root, "enabled"),
		RoundcubeRoot:     "/usr/share/roundcube",
		Reloader:          reloader,
	})

	result, err := provisioner.ConfigureWebmail(context.Background(), types.ConfigureWebmailReq{
		Domain:   "example.test",
		Hostname: "webmail.example.test",
	})
	if err != nil {
		t.Fatalf("ConfigureWebmail returned error: %v", err)
	}
	config, err := os.ReadFile(result.ConfigPath)
	if err != nil {
		t.Fatalf("ReadFile config returned error: %v", err)
	}
	if !strings.Contains(string(config), "server_name webmail.example.test;") || !strings.Contains(string(config), "root /usr/share/roundcube;") {
		t.Fatalf("webmail config missing expected content:\n%s", config)
	}
	if len(reloader.services) != 1 || reloader.services[0] != "nginx" {
		t.Fatalf("services = %#v, want nginx reload", reloader.services)
	}
	if _, err := os.Lstat(result.EnabledPath); err != nil {
		t.Fatalf("enabled symlink missing: %v", err)
	}
}

func TestDNSProvisionerWritesZoneAndReloadsBind(t *testing.T) {
	root := t.TempDir()
	reloader := &recordingPhase6Reloader{}
	runner := &recordingCommandRunner{}
	provisioner := NewDNSProvisioner(DNSProvisionerOptions{
		ZoneDir:        reloaderSafePath(filepath.Join(root, "zones")),
		IncludeDir:     filepath.Join(root, "zones.d"),
		AggregatePath:  filepath.Join(root, "named.conf.nakpanel"),
		ValidatorRunner: runner,
		Reloader:       reloader,
	})

	result, err := provisioner.ConfigureDNSZone(context.Background(), types.ConfigureDNSZoneReq{
		Domain:  "example.test",
		Address: "192.0.2.10",
		Serial:  2026070701,
	})
	if err != nil {
		t.Fatalf("ConfigureDNSZone returned error: %v", err)
	}
	zone, err := os.ReadFile(result.ZonePath)
	if err != nil {
		t.Fatalf("ReadFile zone returned error: %v", err)
	}
	for _, want := range []string{"$ORIGIN example.test.", "2026070701", "@ IN A 192.0.2.10", "www IN A 192.0.2.10", "webmail IN A 192.0.2.10"} {
		if !strings.Contains(string(zone), want) {
			t.Fatalf("zone missing %q:\n%s", want, zone)
		}
	}
	include, err := os.ReadFile(result.IncludePath)
	if err != nil {
		t.Fatalf("ReadFile include returned error: %v", err)
	}
	if !strings.Contains(string(include), `zone "example.test"`) || !strings.Contains(string(include), result.ZonePath) {
		t.Fatalf("include missing zone stanza:\n%s", include)
	}
	aggregate, err := os.ReadFile(filepath.Join(root, "named.conf.nakpanel"))
	if err != nil {
		t.Fatalf("ReadFile aggregate returned error: %v", err)
	}
	if !strings.Contains(string(aggregate), result.IncludePath) {
		t.Fatalf("aggregate missing include path:\n%s", aggregate)
	}
	if !runner.sawCommand("named-checkzone") || !runner.sawCommand("named-checkconf") {
		t.Fatalf("validator commands = %#v, want named-checkzone and named-checkconf", runner.calls)
	}
	if len(reloader.services) != 1 || reloader.services[0] != "named.service" {
		t.Fatalf("services = %#v, want named.service reload", reloader.services)
	}
}

func TestReconciliationProvisionerRegeneratesSiteWebmailAndDNS(t *testing.T) {
	site := &recordingSiteProvisioner{}
	webmail := &recordingWebmailProvisioner{}
	dns := &recordingDNSProvisioner{}
	provisioner := NewReconciliationProvisioner(site, webmail, dns)

	result, err := provisioner.ReconcileSystem(context.Background(), types.ReconcileSystemReq{
		Sites: []types.ReconcileSiteReq{{
			Username:      "npdemo",
			Domain:        "example.test",
			PHPVersion:    "8.3",
			EnableWebmail: true,
			EnableDNS:     true,
			Address:       "192.0.2.10",
		}},
	})
	if err != nil {
		t.Fatalf("ReconcileSystem returned error: %v", err)
	}
	if result.SitesTotal != 1 || result.SitesOK != 1 {
		t.Fatalf("result = %#v, want one reconciled site", result)
	}
	if site.req.Domain != "example.test" || webmail.req.Hostname != "webmail.example.test" || dns.req.Address != "192.0.2.10" {
		t.Fatalf("site=%#v webmail=%#v dns=%#v, want all phase6 regenerators called", site.req, webmail.req, dns.req)
	}
}

func readTarGzNames(t *testing.T, path string) []string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open archive returned error: %v", err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("gzip.NewReader returned error: %v", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	var names []string
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("tar Next returned error: %v", err)
		}
		names = append(names, header.Name)
	}
	return names
}

func reloaderSafePath(path string) string {
	return path
}

type recordingSiteProvisioner struct {
	req types.CreateSiteReq
}

func (p *recordingSiteProvisioner) CreateSite(ctx context.Context, req types.CreateSiteReq) error {
	p.req = req
	return nil
}

type recordingWebmailProvisioner struct {
	req types.ConfigureWebmailReq
}

func (p *recordingWebmailProvisioner) ConfigureWebmail(ctx context.Context, req types.ConfigureWebmailReq) (types.ConfigureWebmailResult, error) {
	p.req = req
	return types.ConfigureWebmailResult{Hostname: req.Hostname, ConfigPath: "/tmp/webmail.conf"}, nil
}

type recordingDNSProvisioner struct {
	req types.ConfigureDNSZoneReq
}

func (p *recordingDNSProvisioner) ConfigureDNSZone(ctx context.Context, req types.ConfigureDNSZoneReq) (types.ConfigureDNSZoneResult, error) {
	p.req = req
	return types.ConfigureDNSZoneResult{Domain: req.Domain, ZonePath: "/tmp/db.example.test"}, nil
}

type commandCall struct {
	name string
	args []string
}

type recordingCommandRunner struct {
	calls []commandCall
}

func (r *recordingCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, commandCall{name: name, args: append([]string(nil), args...)})
	return []byte("ok"), nil
}

func (r *recordingCommandRunner) sawCommand(name string) bool {
	for _, call := range r.calls {
		if call.name == name {
			return true
		}
	}
	return false
}
