package ops

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
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

func TestDeleteBackupProvisionerDeletesTrackedArchive(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "example.test-20260712T020000Z.tar.gz")
	if err := os.WriteFile(archive, []byte("backup"), 0o640); err != nil {
		t.Fatal(err)
	}
	result, err := NewDeleteBackupProvisioner(root).DeleteBackup(context.Background(), types.DeleteBackupReq{ArchivePath: archive})
	if err != nil {
		t.Fatalf("DeleteBackup returned error: %v", err)
	}
	if filepath.Base(result.ArchivePath) != filepath.Base(archive) || !result.Deleted {
		t.Fatalf("DeleteBackup result = %#v", result)
	}
	if _, err := os.Lstat(archive); !os.IsNotExist(err) {
		t.Fatalf("archive still exists: %v", err)
	}
}

func TestDeleteBackupProvisionerTreatsMissingArchiveAsSuccess(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "missing.tar.gz")
	result, err := NewDeleteBackupProvisioner(root).DeleteBackup(context.Background(), types.DeleteBackupReq{ArchivePath: archive})
	if err != nil || result.Deleted {
		t.Fatalf("DeleteBackup result=%#v err=%v, want idempotent success", result, err)
	}
}

func TestDeleteBackupProvisionerRejectsUnsafePaths(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.tar.gz")
	if err := os.WriteFile(outside, []byte("outside"), 0o640); err != nil {
		t.Fatal(err)
	}
	nestedDir := filepath.Join(root, "nested")
	if err := os.Mkdir(nestedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(nestedDir, "nested.tar.gz")
	if err := os.WriteFile(nested, []byte("nested"), 0o640); err != nil {
		t.Fatal(err)
	}
	nonArchive := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(nonArchive, []byte("notes"), 0o640); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "directory.tar.gz")
	if err := os.Mkdir(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "linked.tar.gz")
	if err := os.Symlink(outside, symlink); err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		"outside root": outside,
		"traversal":    filepath.Join(root, "..", filepath.Base(filepath.Dir(outside)), filepath.Base(outside)),
		"nested":       nested,
		"non archive":  nonArchive,
		"directory":    directory,
		"symlink":      symlink,
		"relative":     "relative.tar.gz",
	}
	for name, archive := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewDeleteBackupProvisioner(root).DeleteBackup(context.Background(), types.DeleteBackupReq{ArchivePath: archive}); err == nil {
				t.Fatal("DeleteBackup returned nil error")
			}
		})
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "outside" {
		t.Fatalf("outside file changed: data=%q err=%v", data, err)
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
		ZoneDir:         reloaderSafePath(filepath.Join(root, "zones")),
		IncludeDir:      filepath.Join(root, "zones.d"),
		AggregatePath:   filepath.Join(root, "named.conf.nakpanel"),
		ValidatorRunner: runner,
		Reloader:        reloader,
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

func TestDNSZoneDriftDetectsHandEditedZone(t *testing.T) {
	root := t.TempDir()
	p := NewDNSProvisioner(DNSProvisionerOptions{ZoneDir: reloaderSafePath(filepath.Join(root, "zones")), IncludeDir: filepath.Join(root, "zones.d"), AggregatePath: filepath.Join(root, "named.conf.nakpanel"), ValidatorRunner: &recordingCommandRunner{}, Reloader: &recordingPhase6Reloader{}})
	req := types.ConfigureDNSZoneReq{Domain: "example.test", Address: "192.0.2.10", Serial: 2026071201, Records: []types.DNSRecord{{Host: "@", Type: "A", Value: "192.0.2.10", TTL: 3600}}}
	result, err := p.ConfigureDNSZone(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	drift, err := p.DNSZoneDrift(req)
	if err != nil || drift {
		t.Fatalf("drift=%v err=%v after configure", drift, err)
	}
	if err = os.WriteFile(result.ZonePath, []byte("hand edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	drift, err = p.DNSZoneDrift(req)
	if err != nil || !drift {
		t.Fatalf("drift=%v err=%v, want detected", drift, err)
	}
}

func TestDNSProvisionerRestoresFilesWhenValidationFails(t *testing.T) {
	root := t.TempDir()
	zoneDir := filepath.Join(root, "zones")
	includeDir := filepath.Join(root, "zones.d")
	aggregatePath := filepath.Join(root, "named.conf.nakpanel")
	if err := os.MkdirAll(zoneDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(includeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	zonePath := filepath.Join(zoneDir, "db.example.test")
	includePath := filepath.Join(includeDir, "example.test.conf")
	oldZone, oldInclude, oldAggregate := "old zone\n", "old include\n", "old aggregate\n"
	for path, content := range map[string]string{zonePath: oldZone, includePath: oldInclude, aggregatePath: oldAggregate} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &recordingCommandRunner{failName: "named-checkzone"}
	reloader := &recordingPhase6Reloader{}
	provisioner := NewDNSProvisioner(DNSProvisionerOptions{ZoneDir: zoneDir, IncludeDir: includeDir, AggregatePath: aggregatePath, ValidatorRunner: runner, Reloader: reloader})
	_, err := provisioner.ConfigureDNSZone(context.Background(), types.ConfigureDNSZoneReq{Domain: "example.test", Address: "192.0.2.20", Serial: 2})
	if err == nil {
		t.Fatal("ConfigureDNSZone returned nil, want validation failure")
	}
	for path, want := range map[string]string{zonePath: oldZone, includePath: oldInclude, aggregatePath: oldAggregate} {
		got, readErr := os.ReadFile(path)
		if readErr != nil || string(got) != want {
			t.Fatalf("restored %s = %q, %v; want %q", path, got, readErr, want)
		}
	}
	if len(reloader.services) != 0 {
		t.Fatalf("services = %v, want no reload after failed validation", reloader.services)
	}
}

func TestRenderDNSZoneUsesCompleteStoredRecordSet(t *testing.T) {
	zone := RenderDNSZone(types.ConfigureDNSZoneReq{Domain: "example.test", Address: "192.0.2.10", Serial: 7, Records: []types.DNSRecord{
		{Host: "@", Type: "A", Value: "192.0.2.20", TTL: 3600},
		{Host: "www", Type: "AAAA", Value: "2001:db8::20", TTL: 600},
		{Host: "shop", Type: "CNAME", Value: "shops.example.net", TTL: 300},
		{Host: "@", Type: "MX", Value: "mail.example.test", Priority: 10, TTL: 3600},
		{Host: "@", Type: "TXT", Value: "v=spf1 -all", TTL: 3600},
	}})
	for _, want := range []string{"@ 3600 IN A 192.0.2.20", "www 600 IN AAAA 2001:db8::20", "shop 300 IN CNAME shops.example.net.", "@ 3600 IN MX 10 mail.example.test.", `@ 3600 IN TXT "v=spf1 -all"`} {
		if !strings.Contains(zone, want) {
			t.Fatalf("rendered zone missing %q:\n%s", want, zone)
		}
	}
	if strings.Contains(zone, "www IN A 192.0.2.10") {
		t.Fatalf("rendered zone retained legacy default records:\n%s", zone)
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

type missingDatabaseChecker struct{}

func (missingDatabaseChecker) DatabaseExists(context.Context, string) (bool, error) {
	return false, nil
}

func TestReconciliationProvisionerReportsMissingDatabaseAsAttention(t *testing.T) {
	provisioner := NewReconciliationProvisioner(nil, nil, nil, missingDatabaseChecker{})
	result, err := provisioner.ReconcileSystem(context.Background(), types.ReconcileSystemReq{Databases: []types.ReconcileDatabaseReq{{DatabaseID: 9, Name: "np_missing"}}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Failed != 0 || result.Attention != 1 || len(result.Resources) != 1 || result.Resources[0].Outcome != "detected_only" {
		t.Fatalf("result=%#v, want one detect-only attention", result)
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
	calls    []commandCall
	failName string
}

func (r *recordingCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, commandCall{name: name, args: append([]string(nil), args...)})
	if name == r.failName {
		return nil, errors.New("injected command failure")
	}
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
