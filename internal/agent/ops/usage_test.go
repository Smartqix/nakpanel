package ops

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeRuntimeCapabilityProbe struct {
	paths         map[string]string
	outputs       map[string][]byte
	errors        map[string]error
	startErrors   map[string]error
	exitDelays    map[string]time.Duration
	exitErrors    map[string]error
	fpmConfigs    []string
	startedPaths  []string
	socketPaths   []string
	processes     []*fakeRuntimeCapabilityProcess
	startDeadline time.Time
}

type fakeRuntimeCapabilityProcess struct {
	done        chan error
	listener    net.Listener
	once        sync.Once
	signalCount atomic.Int32
	killCount   atomic.Int32
	waitCount   atomic.Int32
}

func (p *fakeRuntimeCapabilityProcess) Wait() error {
	err := <-p.done
	p.waitCount.Add(1)
	return err
}

func (p *fakeRuntimeCapabilityProcess) Signal(os.Signal) error {
	p.signalCount.Add(1)
	p.stop(nil)
	return nil
}

func (p *fakeRuntimeCapabilityProcess) Kill() error {
	p.killCount.Add(1)
	p.stop(errors.New("killed"))
	return nil
}

func (p *fakeRuntimeCapabilityProcess) Output() []byte {
	return nil
}

func (p *fakeRuntimeCapabilityProcess) stop(err error) {
	p.once.Do(func() {
		if p.listener != nil {
			_ = p.listener.Close()
		}
		p.done <- err
	})
}

func (p *fakeRuntimeCapabilityProbe) LookPath(name string) (string, error) {
	path, ok := p.paths[name]
	if !ok {
		return "", fmt.Errorf("%s not found", name)
	}
	return path, nil
}

func (p *fakeRuntimeCapabilityProbe) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), "\x00")
	if strings.Contains(filepath.Base(name), "php-fpm") && len(args) == 3 && args[0] == "-t" && args[1] == "-y" {
		config, err := os.ReadFile(args[2])
		if err != nil {
			return nil, err
		}
		p.fpmConfigs = append(p.fpmConfigs, string(config))
		key = runtimeCommandKey(name, "-t", "-y")
	}
	return p.outputs[key], p.errors[key]
}

func (p *fakeRuntimeCapabilityProbe) Start(ctx context.Context, name string, args ...string) (RuntimeCapabilityProcess, error) {
	key := runtimeCommandKey(name, "-F", "-y")
	if err := p.startErrors[key]; err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		p.startDeadline = deadline
	}
	if len(args) != 3 || args[0] != "-F" || args[1] != "-y" {
		return nil, fmt.Errorf("unexpected FPM start args: %#v", args)
	}
	config, err := os.ReadFile(args[2])
	if err != nil {
		return nil, err
	}
	socketPath := ""
	for _, line := range strings.Split(string(config), "\n") {
		if strings.HasPrefix(line, "listen = ") {
			socketPath = strings.TrimSpace(strings.TrimPrefix(line, "listen = "))
			break
		}
	}
	if socketPath == "" {
		return nil, errors.New("probe config has no listen socket")
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	process := &fakeRuntimeCapabilityProcess{done: make(chan error, 1), listener: listener}
	p.startedPaths = append(p.startedPaths, args[2])
	p.socketPaths = append(p.socketPaths, socketPath)
	p.processes = append(p.processes, process)
	if delay := p.exitDelays[key]; delay > 0 {
		exitErr := p.exitErrors[key]
		time.AfterFunc(delay, func() {
			process.stop(exitErr)
		})
	}
	return process, nil
}

func runtimeCommandKey(name string, args ...string) string {
	return strings.Join(append([]string{name}, args...), "\x00")
}

func completeRuntimeProbe(versions ...string) *fakeRuntimeCapabilityProbe {
	probe := &fakeRuntimeCapabilityProbe{
		paths:       make(map[string]string),
		outputs:     make(map[string][]byte),
		errors:      make(map[string]error),
		startErrors: make(map[string]error),
		exitDelays:  make(map[string]time.Duration),
		exitErrors:  make(map[string]error),
	}
	extensions := "[PHP Modules]\nBCMath\ncURL\ndom\nexif\nfileinfo\ngd\nimagick\nintl\nmbstring\nmysqli\nOpenSSL\nredis\nSimpleXML\nsoap\nxml\nzip\n[Zend Modules]\nZend OPcache\n"
	for _, version := range versions {
		php := "/usr/bin/php" + version
		fpm := "/usr/sbin/php-fpm" + version
		probe.paths["php"+version] = php
		probe.paths["php-fpm"+version] = fpm
		probe.outputs[runtimeCommandKey(php, "-r", `echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;`)] = []byte(version)
		probe.outputs[runtimeCommandKey(php, "-m")] = []byte(extensions)
		probe.outputs[runtimeCommandKey(fpm, "-v")] = []byte("PHP " + version + ".12 (fpm-fcgi)\n")
		probe.outputs[runtimeCommandKey(fpm, "-t", "-y")] = nil
	}
	return probe
}

func (p *fakeRuntimeCapabilityProbe) addTool(name, path string, output []byte) {
	p.paths[name] = path
	p.outputs[runtimeCommandKey(path, "--no-plugins", "--no-scripts", "--version", "--no-ansi")] = output
	p.outputs[runtimeCommandKey(path, "--version", "--allow-root")] = output
}

func findPHPRuntime(t *testing.T, runtimes []types.PHPRuntimeCapability, version string) types.PHPRuntimeCapability {
	t.Helper()
	for _, runtime := range runtimes {
		if runtime.Version == version {
			return runtime
		}
	}
	t.Fatalf("PHP runtime %s not found in %#v", version, runtimes)
	return types.PHPRuntimeCapability{}
}

func TestRuntimeCapabilitiesReportsOnlyFullyReadyPHPVersions(t *testing.T) {
	probe := completeRuntimeProbe("8.3", "8.4", "8.5")
	probe.addTool("composer", "/usr/local/bin/composer", []byte("Composer version 2.8.11 2025-08-21 11:29:39\n"))
	probe.addTool("wp", "/usr/local/bin/wp", []byte("WP-CLI 2.12.0\n"))
	php83 := probe.paths["php8.3"]
	probe.outputs[runtimeCommandKey(php83, "-m")] = []byte("bcmath\ncurl\ndom\nexif\nfileinfo\ngd\nimagick\nintl\nmbstring\nmysqli\nopenssl\nredis\nSimpleXML\nsoap\nxml\nZend OPcache\n")

	collector := NewUsageCollector("", "", "", WithRuntimeCapabilityProbe(probe))
	got, err := collector.RuntimeCapabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"8.5", "8.4"}; !reflect.DeepEqual(got.PHPVersions, want) {
		t.Fatalf("PHPVersions = %#v, want %#v", got.PHPVersions, want)
	}
	if len(got.PHPRuntimes) != 3 {
		t.Fatalf("PHPRuntimes = %#v, want three discovered runtimes", got.PHPRuntimes)
	}
	if runtime := findPHPRuntime(t, got.PHPRuntimes, "8.5"); !runtime.Ready || runtime.SupportStatus != types.PHPSupportActive {
		t.Fatalf("PHP 8.5 runtime = %#v, want ready and active", runtime)
	}
	if runtime := findPHPRuntime(t, got.PHPRuntimes, "8.5"); runtime.CLIPath != "/usr/bin/php8.5" || runtime.FPMPath != "/usr/sbin/php-fpm8.5" {
		t.Fatalf("PHP 8.5 binary paths = CLI %q FPM %q", runtime.CLIPath, runtime.FPMPath)
	}
	if runtime := findPHPRuntime(t, got.PHPRuntimes, "8.4"); !runtime.Ready || runtime.SupportStatus != types.PHPSupportActive {
		t.Fatalf("PHP 8.4 runtime = %#v, want ready and active", runtime)
	}
	runtime83 := findPHPRuntime(t, got.PHPRuntimes, "8.3")
	if runtime83.Ready || runtime83.SupportStatus != types.PHPSupportSecuritySupported {
		t.Fatalf("PHP 8.3 runtime = %#v, want degraded and security-supported", runtime83)
	}
	if want := []string{"zip"}; !reflect.DeepEqual(runtime83.MissingExtensions, want) {
		t.Fatalf("PHP 8.3 missing extensions = %#v, want %#v", runtime83.MissingExtensions, want)
	}
	if len(runtime83.ValidationErrors) != 1 || !strings.Contains(runtime83.ValidationErrors[0], "zip") {
		t.Fatalf("PHP 8.3 validation errors = %#v, want an individual zip error", runtime83.ValidationErrors)
	}
	if !got.ComposerAvailable || got.ComposerVersion != "2.8.11" {
		t.Fatalf("Composer capability = available %t version %q", got.ComposerAvailable, got.ComposerVersion)
	}
	if !got.WPCLIAvailable || got.WPCLIVersion != "2.12.0" {
		t.Fatalf("WP-CLI capability = available %t version %q", got.WPCLIAvailable, got.WPCLIVersion)
	}
}

func TestRuntimeCapabilitiesValidatesGeneratedIsolatedFPMConfig(t *testing.T) {
	probe := completeRuntimeProbe("8.4")
	collector := NewUsageCollector("", "", "", WithRuntimeCapabilityProbe(probe))

	got, err := collector.RuntimeCapabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if runtime := findPHPRuntime(t, got.PHPRuntimes, "8.4"); !runtime.FPMConfigValid {
		t.Fatalf("PHP 8.4 runtime = %#v, want valid FPM config", runtime)
	}
	if len(probe.fpmConfigs) != 1 {
		t.Fatalf("validated FPM configs = %d, want 1", len(probe.fpmConfigs))
	}
	config := probe.fpmConfigs[0]
	for _, want := range []string{"[global]", "daemonize = no", "[nakpanel-probe]", "pm.max_children = 1"} {
		if !strings.Contains(config, want) {
			t.Fatalf("generated FPM config is missing %q:\n%s", want, config)
		}
	}
	if strings.Contains(config, "include=") || strings.Contains(config, "pool.d") {
		t.Fatalf("generated FPM config is not isolated:\n%s", config)
	}
	if len(probe.processes) != 1 {
		t.Fatalf("started FPM processes = %d, want 1", len(probe.processes))
	}
	process := probe.processes[0]
	if process.signalCount.Load() != 1 || process.waitCount.Load() != 1 || process.killCount.Load() != 0 {
		t.Fatalf("FPM cleanup signal=%d wait=%d kill=%d", process.signalCount.Load(), process.waitCount.Load(), process.killCount.Load())
	}
	if probe.startDeadline.IsZero() || time.Until(probe.startDeadline) > 4*time.Second {
		t.Fatalf("FPM probe deadline = %v, want a bounded internal timeout", probe.startDeadline)
	}
	for _, path := range append(append([]string(nil), probe.startedPaths...), probe.socketPaths...) {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("FPM probe artifact %s remains after cleanup: %v", path, err)
		}
	}
}

func TestRuntimeCapabilitiesRejectsWrongVersionFPMBinary(t *testing.T) {
	probe := completeRuntimeProbe("8.4")
	fpm := probe.paths["php-fpm8.4"]
	probe.outputs[runtimeCommandKey(fpm, "-v")] = []byte("PHP 8.3.27 (fpm-fcgi)\n")

	collector := NewUsageCollector("", "", "", WithRuntimeCapabilityProbe(probe))
	got, err := collector.RuntimeCapabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	runtime := findPHPRuntime(t, got.PHPRuntimes, "8.4")
	if runtime.Ready || len(got.PHPVersions) != 0 {
		t.Fatalf("wrong-version FPM runtime = %#v, PHPVersions = %#v", runtime, got.PHPVersions)
	}
	if !strings.Contains(strings.Join(runtime.ValidationErrors, "\n"), "FPM reported") || len(probe.processes) != 0 {
		t.Fatalf("wrong-version FPM errors = %#v, started processes = %d", runtime.ValidationErrors, len(probe.processes))
	}
}

func TestRuntimeCapabilitiesRejectsFPMStartupFailureAfterValidConfig(t *testing.T) {
	probe := completeRuntimeProbe("8.4")
	fpm := probe.paths["php-fpm8.4"]
	probe.startErrors[runtimeCommandKey(fpm, "-F", "-y")] = errors.New("worker spawn failed")

	collector := NewUsageCollector("", "", "", WithRuntimeCapabilityProbe(probe))
	got, err := collector.RuntimeCapabilities(context.Background())
	if err != nil {
		t.Fatalf("RuntimeCapabilities returned a top-level error: %v", err)
	}
	runtime := findPHPRuntime(t, got.PHPRuntimes, "8.4")
	if runtime.Ready || !runtime.FPMConfigValid || len(got.PHPVersions) != 0 {
		t.Fatalf("startup-failed FPM runtime = %#v, PHPVersions = %#v", runtime, got.PHPVersions)
	}
	if !strings.Contains(strings.Join(runtime.ValidationErrors, "\n"), "worker spawn failed") {
		t.Fatalf("startup failure errors = %#v", runtime.ValidationErrors)
	}
	if len(probe.startedPaths) != 0 {
		t.Fatalf("successful FPM starts = %#v, want none", probe.startedPaths)
	}
}

func TestRuntimeCapabilitiesRejectsFPMThatExitsAfterCreatingSocket(t *testing.T) {
	probe := completeRuntimeProbe("8.4")
	fpm := probe.paths["php-fpm8.4"]
	key := runtimeCommandKey(fpm, "-F", "-y")
	probe.exitDelays[key] = 10 * time.Millisecond
	probe.exitErrors[key] = errors.New("worker exited during startup")

	collector := NewUsageCollector("", "", "", WithRuntimeCapabilityProbe(probe))
	got, err := collector.RuntimeCapabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	runtime := findPHPRuntime(t, got.PHPRuntimes, "8.4")
	if runtime.Ready || len(got.PHPVersions) != 0 {
		t.Fatalf("unstable FPM runtime = %#v, PHPVersions = %#v", runtime, got.PHPVersions)
	}
	if !strings.Contains(strings.Join(runtime.ValidationErrors, "\n"), "worker exited during startup") {
		t.Fatalf("unstable FPM errors = %#v", runtime.ValidationErrors)
	}
}

func TestRuntimeCapabilitiesKeepsValidationFailuresInsideRuntimeRecord(t *testing.T) {
	probe := completeRuntimeProbe("8.3", "8.4")
	php84 := probe.paths["php8.4"]
	fpm84 := probe.paths["php-fpm8.4"]
	probe.outputs[runtimeCommandKey(php84, "-r", `echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;`)] = []byte("8.3")
	probe.errors[runtimeCommandKey(fpm84, "-t", "-y")] = errors.New("configuration rejected")

	collector := NewUsageCollector("", "", "", WithRuntimeCapabilityProbe(probe))
	got, err := collector.RuntimeCapabilities(context.Background())
	if err != nil {
		t.Fatalf("RuntimeCapabilities returned a top-level error: %v", err)
	}
	runtime := findPHPRuntime(t, got.PHPRuntimes, "8.4")
	if runtime.Ready || runtime.FPMConfigValid {
		t.Fatalf("PHP 8.4 runtime = %#v, want not ready", runtime)
	}
	joined := strings.Join(runtime.ValidationErrors, "\n")
	for _, want := range []string{"expected 8.4", "configuration rejected"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("PHP 8.4 validation errors = %#v, want %q", runtime.ValidationErrors, want)
		}
	}
	if want := []string{"8.3"}; !reflect.DeepEqual(got.PHPVersions, want) {
		t.Fatalf("PHPVersions = %#v, want %#v", got.PHPVersions, want)
	}
}

func TestRuntimeCapabilitiesDescribesPartiallyInstalledRuntime(t *testing.T) {
	probe := completeRuntimeProbe("8.5")
	delete(probe.paths, "php8.5")

	collector := NewUsageCollector("", "", "", WithRuntimeCapabilityProbe(probe))
	got, err := collector.RuntimeCapabilities(context.Background())
	if err != nil {
		t.Fatalf("RuntimeCapabilities returned a top-level error: %v", err)
	}
	runtime := findPHPRuntime(t, got.PHPRuntimes, "8.5")
	if runtime.Ready || runtime.CLIAvailable || !runtime.FPMAvailable || !runtime.FPMConfigValid {
		t.Fatalf("partially installed PHP 8.5 runtime = %#v", runtime)
	}
	if !reflect.DeepEqual(runtime.MissingExtensions, requiredPHPExtensions) {
		t.Fatalf("missing extensions = %#v, want full baseline %#v", runtime.MissingExtensions, requiredPHPExtensions)
	}
	if runtime.CLIPath != "" || runtime.FPMPath != "/usr/sbin/php-fpm8.5" {
		t.Fatalf("partial runtime paths = CLI %q FPM %q", runtime.CLIPath, runtime.FPMPath)
	}
	if len(got.PHPVersions) != 0 {
		t.Fatalf("PHPVersions = %#v, want none", got.PHPVersions)
	}
}

func TestUsageCollectorMeasuresHomeAndIncrementalNginxTraffic(t *testing.T) {
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	logRoot := filepath.Join(root, "logs")
	if err := os.MkdirAll(filepath.Join(homeRoot, "acct"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(homeRoot, "acct", "index.html"), []byte("123456"), 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(logRoot, "acct-example-test.access.log")
	first := `127.0.0.1 - - [10/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 120 "-" "curl"` + "\n"
	if err := os.WriteFile(logPath, []byte(first), 0o644); err != nil {
		t.Fatal(err)
	}
	collector := NewUsageCollector(homeRoot, logRoot, "")
	period := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	result, err := collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath)}}, PeriodStart: period})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 1 || result.Sites[0].HomeBytes != 6 || result.Sites[0].TrafficBytes != 120 {
		t.Fatalf("usage result = %#v", result)
	}
	second := `127.0.0.1 - - [10/Jul/2026:12:01:00 +0000] "GET /a HTTP/1.1" 200 80 "-" "curl"` + "\n"
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString(second)
	_ = file.Close()
	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatal(err)
	}
	third := `127.0.0.1 - - [10/Jul/2026:12:02:00 +0000] "GET /b HTTP/1.1" 200 30 "-" "curl"` + "\n"
	if err := os.WriteFile(logPath, []byte(third), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err = collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath), Cursor: result.Sites[0].Cursor}}, PeriodStart: period})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Sites[0].TrafficBytes; got != 110 {
		t.Fatalf("traffic delta = %d, want 110", got)
	}
}

func TestUsageCollectorCountsManagedPHPStorageOnceAtAccountScope(t *testing.T) {
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	logRoot := filepath.Join(root, "logs")
	publicRoot := filepath.Join(homeRoot, "acct", "domains", "example.test", "public_html")
	managedRoot := filepath.Join(homeRoot, "acct", ".nakpanel", "php", "site-7")
	for path, contents := range map[string]string{
		filepath.Join(publicRoot, "index.php"):                  "public",
		filepath.Join(managedRoot, "releases", "22", "app.php"): "release-bytes",
		filepath.Join(managedRoot, "shared", "cache.bin"):       "shared-bytes",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(logRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	collector := NewUsageCollector(homeRoot, logRoot, "")
	result, err := collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{
		SiteID: 7, Username: "acct", Domain: "example.test", AccessLog: "example.test.access.log",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 1 || result.Sites[0].HomeBytes != int64(len("public")) {
		t.Fatalf("per-site document-root usage = %#v", result.Sites)
	}
	wantAccount := int64(len("public") + len("release-bytes") + len("shared-bytes"))
	if result.AccountBytes != wantAccount {
		t.Fatalf("account bytes = %d, want %d with managed storage counted once", result.AccountBytes, wantAccount)
	}
}

func TestUsageCollectorMonthlyResetIgnoresPriorLogEntries(t *testing.T) {
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	logRoot := filepath.Join(root, "logs")
	if err := os.MkdirAll(filepath.Join(homeRoot, "acct"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(logRoot, "acct-example-test.access.log")
	log := `127.0.0.1 - - [30/Jun/2026:23:59:59 +0000] "GET /old HTTP/1.1" 200 900 "-" "curl"` + "\n" +
		`127.0.0.1 - - [01/Jul/2026:00:00:01 +0000] "GET /new HTTP/1.1" 200 100 "-" "curl"` + "\n"
	if err := os.WriteFile(logPath, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	collector := NewUsageCollector(homeRoot, logRoot, "")
	result, err := collector.CollectUsage(context.Background(), types.CollectUsageReq{
		Sites:       []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath)}},
		PeriodStart: time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Sites[0].TrafficBytes; got != 100 {
		t.Fatalf("July traffic = %d, want 100", got)
	}
}

func TestUsageCollectorDoesNotAdvancePastPartialLogLine(t *testing.T) {
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	logRoot := filepath.Join(root, "logs")
	if err := os.MkdirAll(filepath.Join(homeRoot, "acct"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(logRoot, "acct-example-test.access.log")
	complete := `127.0.0.1 - - [10/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 120 "-" "curl"` + "\n"
	partial := `127.0.0.1 - - [10/Jul/2026:12:01:00 +0000] "GET /partial HTTP/1.1" 200 80 "-" "curl"`
	if err := os.WriteFile(logPath, []byte(complete+partial), 0o644); err != nil {
		t.Fatal(err)
	}
	collector := NewUsageCollector(homeRoot, logRoot, "")
	period := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	first, err := collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath)}}, PeriodStart: period})
	if err != nil {
		t.Fatal(err)
	}
	if got := first.Sites[0].TrafficBytes; got != 120 {
		t.Fatalf("first traffic = %d, want 120", got)
	}
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString("\n")
	_ = file.Close()
	second, err := collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath), Cursor: first.Sites[0].Cursor}}, PeriodStart: period})
	if err != nil {
		t.Fatal(err)
	}
	if got := second.Sites[0].TrafficBytes; got != 80 {
		t.Fatalf("completed partial traffic = %d, want 80", got)
	}
}

func TestUsageCollectorRejectsUnrecoverableLogRotation(t *testing.T) {
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	logRoot := filepath.Join(root, "logs")
	if err := os.MkdirAll(filepath.Join(homeRoot, "acct"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(logRoot, "acct-example-test.access.log")
	line := `127.0.0.1 - - [10/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 120 "-" "curl"` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	collector := NewUsageCollector(homeRoot, logRoot, "")
	period := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	first, err := collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath)}}, PeriodStart: period})
	if err != nil {
		t.Fatal(err)
	}
	oldLog, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer oldLog.Close()
	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath), Cursor: first.Sites[0].Cursor}}, PeriodStart: period})
	if err == nil || !strings.Contains(err.Error(), "cursor gap") {
		t.Fatalf("CollectUsage error = %v, want cursor gap", err)
	}
}

func TestUsageCollectorRejectsLogOutsideManagedRoot(t *testing.T) {
	collector := NewUsageCollector(t.TempDir(), t.TempDir(), "")
	_, err := collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: "/tmp/outside.log"}}})
	if err == nil {
		t.Fatal("CollectUsage returned nil error")
	}
}
