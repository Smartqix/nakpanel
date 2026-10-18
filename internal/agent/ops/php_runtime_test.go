package ops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestInstalledPHPProfileRejectsUnavailableVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "platform.json")
	if err := os.WriteFile(path, []byte(`{"os_id":"ubuntu","version_id":"26.04","codename":"resolute","architecture":"amd64","profile":"ubuntu-26.04-native","internal_php_version":"8.5","hosting_php_versions":["8.5"],"bootstrap_pending":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	resolver := installedPHPRuntimeResolver{path: path, ownerUID: uint32(os.Getuid())}
	if _, err := resolver.ResolvePHP("8.3"); err == nil {
		t.Fatal("native profile accepted unavailable PHP 8.3")
	}
	runtime, err := resolver.ResolvePHP("8.5")
	if err != nil || runtime.CLIPath != "/usr/bin/php8.5" || runtime.FPMINIPath != "/etc/php/8.5/fpm/php.ini" {
		t.Fatalf("runtime=%+v err=%v", runtime, err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolvePHP("8.5"); err == nil {
		t.Fatal("accepted writable installed profile")
	}
}

func TestPrivatePHPRuntimeUsesSameDescriptorForSiteWorkerAndProbe(t *testing.T) {
	runtime := privatePHPRuntime("8.4")
	resolver := fixedPHPResolver{runtime}
	plan, err := NewSitePlan(types.CreateSiteReq{SiteID: 7, Username: "npdemo", Domain: "example.test", PHPVersion: "8.4"}, SitePathConfig{RuntimeResolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	unit := RenderPHPFPMUnit(plan)
	for _, want := range []string{"/opt/nakpanel/php/8.4/sbin/php-fpm", "-c /opt/nakpanel/php/8.4/etc/fpm/php.ini", "PHP_INI_SCAN_DIR=/opt/nakpanel/php/8.4/etc/fpm/conf.d", "ProtectSystem=strict", "PrivateTmp=yes"} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit lacks %q:\n%s", want, unit)
		}
	}
	command, args := runtime.CLICommand("-m")
	if command != "/usr/bin/env" || strings.Join(args, " ") != "PHP_INI_SCAN_DIR=/opt/nakpanel/php/8.4/etc/cli/conf.d /opt/nakpanel/php/8.4/bin/php -c /opt/nakpanel/php/8.4/etc/cli/php.ini -d extension_dir=/opt/nakpanel/php/8.4/lib/php/extensions -m" {
		t.Fatalf("command=%s %v", command, args)
	}
	probe := &descriptorProbe{fakeRuntimeCapabilityProbe: completeRuntimeProbe("8.4")}
	capability, discovered := probePHPRuntimeWithResolver(context.Background(), probe, resolver, "8.4", types.PHPSupportActive)
	if !discovered || !capability.Ready || capability.CLIPath != "/opt/nakpanel/php/8.4/bin/php" || capability.FPMPath != "/opt/nakpanel/php/8.4/sbin/php-fpm" {
		t.Fatalf("private runtime was not ready: %+v", capability)
	}
	if len(probe.calls) == 0 || probe.calls[0] != command+" "+strings.Join(append(args[:len(args)-1], "-r", `echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;`), " ") {
		t.Fatalf("probe commands=%v", probe.calls)
	}
}

type fixedPHPResolver struct{ runtime PHPRuntimeDescriptor }

func (f fixedPHPResolver) ResolvePHP(version string) (PHPRuntimeDescriptor, error) {
	return f.runtime, f.runtime.Validate()
}

type descriptorProbe struct {
	*fakeRuntimeCapabilityProbe
	calls []string
}

func (p *descriptorProbe) LookPath(name string) (string, error) { return name, nil }
func (p *descriptorProbe) unwrap(name string, args []string) (string, []string) {
	if name != "/usr/bin/env" || len(args) < 7 {
		return name, args
	}
	switch args[1] {
	case "/opt/nakpanel/php/8.4/bin/php":
		if args[0] != "PHP_INI_SCAN_DIR=/opt/nakpanel/php/8.4/etc/cli/conf.d" || args[3] != "/opt/nakpanel/php/8.4/etc/cli/php.ini" {
			return "invalid", nil
		}
		return "/usr/bin/php8.4", args[6:]
	case "/opt/nakpanel/php/8.4/sbin/php-fpm":
		if args[0] != "PHP_INI_SCAN_DIR=/opt/nakpanel/php/8.4/etc/fpm/conf.d" || args[3] != "/opt/nakpanel/php/8.4/etc/fpm/php.ini" {
			return "invalid", nil
		}
		return "/usr/sbin/php-fpm8.4", args[6:]
	}
	return "invalid", nil
}
func (p *descriptorProbe) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	p.calls = append(p.calls, name+" "+strings.Join(args, " "))
	name, args = p.unwrap(name, args)
	return p.fakeRuntimeCapabilityProbe.Run(ctx, name, args...)
}
func (p *descriptorProbe) Start(ctx context.Context, name string, args ...string) (RuntimeCapabilityProcess, error) {
	p.calls = append(p.calls, name+" "+strings.Join(args, " "))
	name, args = p.unwrap(name, args)
	return p.fakeRuntimeCapabilityProbe.Start(ctx, name, args...)
}

func TestPrivatePHPRuntimeWorkerAndManagedUnitsRetainConfinement(t *testing.T) {
	resolver := fixedPHPResolver{privatePHPRuntime("8.4")}
	spec := managedPHPSpec()
	worker := types.PHPWorker{ID: 33, SubscriptionID: 4, ApplicationID: 9, Name: "queue", Script: "artisan", Arguments: []string{"queue:work"}, Processes: 1, DesiredState: "running"}
	unit, err := renderPHPWorkerUnit(spec, worker, "/release", "/env", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(unit, "ExecStart=/usr/bin/env PHP_INI_SCAN_DIR=/opt/nakpanel/php/8.4/etc/cli/conf.d /opt/nakpanel/php/8.4/bin/php") {
		t.Fatalf("worker command diverges: %s", unit)
	}
	for _, candidate := range []bool{false, true} {
		unit := renderManagedFPMUnit(spec, "/fpm.conf", "/env", "/releases/1", "/run/nakpanel-php/site-7.sock", candidate, resolver)
		for _, want := range []string{"ExecStartPre=/opt/nakpanel/php/8.4/sbin/php-fpm -c /opt/nakpanel/php/8.4/etc/fpm/php.ini", "Environment=PHP_INI_SCAN_DIR=/opt/nakpanel/php/8.4/etc/fpm/conf.d", "ProtectSystem=strict", "PrivateTmp=yes", "ReadWritePaths=/shared /var/log/php-fpm /run/nakpanel-php /var/lib/php/sessions"} {
			if !strings.Contains(unit, want) {
				t.Fatalf("managed FPM missing %q: %s", want, unit)
			}
		}
	}
}

func TestPHPProbeRejectsPATHShadowing(t *testing.T) {
	probe := completeRuntimeProbe("8.4")
	probe.paths["php8.4"] = "/tmp/php8.4"
	probe.paths["php-fpm8.4"] = "/tmp/php-fpm8.4"
	runtime, _ := probePHPRuntime(context.Background(), probe, "8.4", types.PHPSupportActive)
	if runtime.Ready || runtime.CLIPath != "" || runtime.FPMPath != "" {
		t.Fatalf("untrusted PATH entry accepted: %+v", runtime)
	}
}

func TestPHPConfigTesterExecutesTrustedAbsoluteRuntime(t *testing.T) {
	runner := &fakeRunner{}
	tester := NewCommandPHPConfigTester(runner)
	if err := tester.TestPHPConfig(context.Background(), "8.5", "/tmp/pool.conf"); err != nil {
		t.Fatal(err)
	}
	if runner.name != "/usr/sbin/php-fpm8.5" {
		t.Fatalf("validator used %q", runner.name)
	}
}

func TestWordPressUsesSitePHPInsteadOfGlobalAlternative(t *testing.T) {
	runner := &wordpressRunner{}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, err := p.documentRoot(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0750); err != nil {
		t.Fatal(err)
	}
	if _, err := p.runWPAtPath(context.Background(), spec, root, "core", "version"); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 || !strings.Contains(strings.Join(runner.commands[0].args, " "), "-- /usr/bin/php8.4 /usr/local/bin/wp --path=") {
		t.Fatalf("WP-CLI did not select site interpreter: %+v", runner.commands)
	}
}

func TestPHPRuntimeDescriptorRejectsInjectedExecutableAndConfigPaths(t *testing.T) {
	runtime := privatePHPRuntime("8.4")
	for _, mutate := range []func(*PHPRuntimeDescriptor){
		func(d *PHPRuntimeDescriptor) { d.CLIPath = "/tmp/php" },
		func(d *PHPRuntimeDescriptor) { d.FPMINIPath = "/tmp/php.ini" },
		func(d *PHPRuntimeDescriptor) { d.ExtensionDir = "/home/tenant/extensions" },
		func(d *PHPRuntimeDescriptor) { d.ManagedSocket = "/run/another.sock" },
		func(d *PHPRuntimeDescriptor) { d.Version = "8.4;id" },
	} {
		candidate := runtime
		mutate(&candidate)
		if _, err := resolvePHPRuntime(fixedPHPResolver{candidate}, "8.4"); err == nil {
			t.Fatalf("unsafe descriptor accepted: %+v", candidate)
		}
	}
}

func TestSiteProvisionerTestsTheRuntimeItRendered(t *testing.T) {
	runner := &fakeRunner{}
	p := NewSiteProvisioner(SiteProvisionerOptions{PHPTester: NewCommandPHPConfigTester(runner)})
	plan, err := NewSitePlan(types.CreateSiteReq{SiteID: 7, Username: "npdemo", Domain: "example.test", PHPVersion: "8.4"}, SitePathConfig{RuntimeResolver: fixedPHPResolver{privatePHPRuntime("8.4")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.validateSiteConfig(context.Background(), plan, true); err != nil {
		t.Fatal(err)
	}
	if runner.name != "/usr/bin/env" || !strings.Contains(strings.Join(runner.args, " "), "/opt/nakpanel/php/8.4/sbin/php-fpm -c /opt/nakpanel/php/8.4/etc/fpm/php.ini") {
		t.Fatalf("config test diverges from rendered unit: %s %v", runner.name, runner.args)
	}
}

func TestRuntimeCapabilitiesPreserveRPCFieldsForPrivateDescriptor(t *testing.T) {
	collector := NewUsageCollector("", "", "", WithPHPRuntimeResolver(fixedPHPResolver{privatePHPRuntime("8.4")}), WithRuntimeCapabilityProbe(&descriptorProbe{fakeRuntimeCapabilityProbe: completeRuntimeProbe("8.4")}))
	capability, err := collector.RuntimeCapabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(capability.PHPVersions) != 1 || capability.PHPVersions[0] != "8.4" || len(capability.PHPRuntimes) != 1 || !capability.PHPRuntimes[0].Ready || capability.PHPRuntimes[0].CLIPath != "/opt/nakpanel/php/8.4/bin/php" {
		t.Fatalf("private runtime RPC capability=%+v", capability)
	}
}

func TestPHPEnvironmentCannotOverrideTrustedRuntimeConfiguration(t *testing.T) {
	for _, name := range []string{"PHPRC", "PHP_INI_SCAN_DIR", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES"} {
		t.Run(name, func(t *testing.T) {
			if _, err := renderPHPEnvironmentFile([]types.PHPEnvironmentPayload{{Name: name, Value: "/home/tenant/override"}}); err == nil {
				t.Fatalf("request-controlled runtime configuration %s accepted", name)
			}
		})
	}
	if _, err := renderPHPEnvironmentFile([]types.PHPEnvironmentPayload{{Name: "APP_ENV", Value: "production"}}); err != nil {
		t.Fatalf("ordinary application environment rejected: %v", err)
	}
}

func TestPrivatePHPRuntimeComposerAndWPCLIExecuteWithMatchingCLIConfiguration(t *testing.T) {
	resolver := fixedPHPResolver{privatePHPRuntime("8.4")}
	runner := &scriptedPHPAppRunner{}
	release := t.TempDir()
	for _, name := range []string{"composer.json", "composer.lock"} {
		if err := os.WriteFile(filepath.Join(release, name), []byte("{}"), 0640); err != nil {
			t.Fatal(err)
		}
	}
	p := NewPHPApplicationProvisioner(PHPApplicationProvisionerOptions{RuntimeResolver: resolver, Runner: runner})
	if _, err := p.runComposer(context.Background(), managedPHPSpec(), release, t.TempDir(), nil); err != nil {
		t.Fatal(err)
	}
	composerRuns := 0
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "systemd-run ") {
			composerRuns++
		}
		if strings.HasPrefix(call, "systemd-run ") && !strings.Contains(call, "/usr/bin/env PHP_INI_SCAN_DIR=/opt/nakpanel/php/8.4/etc/cli/conf.d /opt/nakpanel/php/8.4/bin/php -c /opt/nakpanel/php/8.4/etc/cli/php.ini -d extension_dir=/opt/nakpanel/php/8.4/lib/php/extensions /usr/local/lib/nakpanel/composer.phar") {
			t.Fatalf("Composer interpreter/configuration diverged: %s", call)
		}
	}
	if composerRuns == 0 {
		t.Fatal("Composer did not execute")
	}
	wpRunner := &wordpressRunner{}
	wp := newWordPressProvisionerForTest(t, wpRunner)
	wp.runtimeResolver = resolver
	spec := wordpressSpec()
	root, err := wp.documentRoot(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0750); err != nil {
		t.Fatal(err)
	}
	if _, err := wp.runWPAtPathInput(context.Background(), spec, root, []byte("protected-input\n"), "core", "version"); err != nil {
		t.Fatal(err)
	}
	if len(wpRunner.commands) != 1 || !strings.Contains(strings.Join(wpRunner.commands[0].args, " "), "-- /usr/bin/env PHP_INI_SCAN_DIR=/opt/nakpanel/php/8.4/etc/cli/conf.d /opt/nakpanel/php/8.4/bin/php -c /opt/nakpanel/php/8.4/etc/cli/php.ini -d extension_dir=/opt/nakpanel/php/8.4/lib/php/extensions /usr/local/bin/wp") {
		t.Fatalf("WP-CLI interpreter/configuration diverged: %+v", wpRunner.commands)
	}
}

func TestPendingNativeBootstrapStillReportsValidatedReadyPHP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "platform.json")
	profile := `{"os_id":"ubuntu","version_id":"26.04","codename":"resolute","architecture":"arm64","profile":"ubuntu-26.04-native","internal_php_version":"8.5","hosting_php_versions":["8.5"],"bootstrap_pending":true}`
	if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}
	resolver := installedPHPRuntimeResolver{path: path, ownerUID: uint32(os.Getuid())}
	collector := NewUsageCollector("", "", "", WithPHPRuntimeResolver(resolver), WithRuntimeCapabilityProbe(completeRuntimeProbe("8.5")))
	capabilities, err := collector.RuntimeCapabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(capabilities.PHPVersions) != 1 || capabilities.PHPVersions[0] != "8.5" || len(capabilities.PHPRuntimes) != 1 || !capabilities.PHPRuntimes[0].Ready {
		t.Fatalf("pending plan initialization hid a validated ready native runtime: %+v", capabilities)
	}
	// Runtime execution must select the same descriptor that readiness advertised.
	runtime, err := resolvePHPRuntime(resolver, "8.5")
	if err != nil || runtime.CLIPath != "/usr/bin/php8.5" || runtime.FPMPath != "/usr/sbin/php-fpm8.5" {
		t.Fatalf("pending bootstrap execution descriptor=%+v err=%v", runtime, err)
	}
	if _, err := resolvePHPRuntime(resolver, "8.3"); err == nil {
		t.Fatal("pending native bootstrap accepted unavailable PHP 8.3")
	}
}

const suryPHPProfileFixture = `{"os_id":"ubuntu","version_id":"26.04","codename":"resolute","architecture":"amd64","profile":"ubuntu-26.04-sury","internal_php_version":"8.5","hosting_php_versions":["8.3","8.4","8.5"],"bootstrap_pending":false}`

func TestInstalledSuryPHPProfileResolvesFixedRuntimeMapping(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "platform.json")
			profile := strings.Replace(suryPHPProfileFixture, `"architecture":"amd64"`, `"architecture":"`+architecture+`"`, 1)
			if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
				t.Fatal(err)
			}
			resolver := installedPHPRuntimeResolver{path: path, ownerUID: uint32(os.Getuid())}
			for _, tc := range []struct{ version, cli, fpm, ini, extensions string }{
				{"8.3", "/usr/bin/php8.3", "/usr/sbin/php-fpm8.3", "/etc/php/8.3/fpm/php.ini", "/usr/lib/php/20230831"},
				{"8.4", "/usr/bin/php8.4", "/usr/sbin/php-fpm8.4", "/etc/php/8.4/fpm/php.ini", "/usr/lib/php/20240924"},
				{"8.5", "/usr/bin/php8.5", "/usr/sbin/php-fpm8.5", "/etc/php/8.5/fpm/php.ini", "/usr/lib/php/20250925"},
			} {
				runtime, err := resolvePHPRuntime(resolver, tc.version)
				if err != nil || runtime.Provider != "distro" || runtime.CLIPath != tc.cli || runtime.FPMPath != tc.fpm || runtime.FPMINIPath != tc.ini || runtime.ExtensionDir != tc.extensions {
					t.Fatalf("Sury PHP%s mapping=%+v err=%v", tc.version, runtime, err)
				}
			}
			collector := NewUsageCollector("", "", "", WithPHPRuntimeResolver(resolver), WithRuntimeCapabilityProbe(completeRuntimeProbe("8.3", "8.4", "8.5")))
			capabilities, err := collector.RuntimeCapabilities(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(capabilities.PHPVersions, ",") != "8.5,8.4,8.3" || len(capabilities.PHPRuntimes) != 3 {
				t.Fatalf("Sury profile capabilities=%+v", capabilities)
			}
		})
	}
}

func TestInstalledSuryPHPProfileRejectsWrongIdentityAndVersionList(t *testing.T) {
	for _, tc := range []struct{ name, old, replacement string }{
		{"wrong OS", `"os_id":"ubuntu"`, `"os_id":"debian"`},
		{"wrong release", `"version_id":"26.04"`, `"version_id":"24.04"`},
		{"wrong codename", `"codename":"resolute"`, `"codename":"noble"`},
		{"wrong architecture", `"architecture":"amd64"`, `"architecture":"riscv64"`},
		{"wrong internal", `"internal_php_version":"8.5"`, `"internal_php_version":"8.3"`},
		{"missing hosted versions", `["8.3","8.4","8.5"]`, `["8.5"]`},
		{"empty hosted versions", `["8.3","8.4","8.5"]`, `[]`},
		{"unsupported hosted version", `["8.3","8.4","8.5"]`, `["8.2","8.4","8.5"]`},
		{"duplicate hosted version", `["8.3","8.4","8.5"]`, `["8.4","8.4","8.5"]`},
		{"extra hosted version", `["8.3","8.4","8.5"]`, `["8.2","8.3","8.4","8.5"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "platform.json")
			if err := os.WriteFile(path, []byte(strings.Replace(suryPHPProfileFixture, tc.old, tc.replacement, 1)), 0600); err != nil {
				t.Fatal(err)
			}
			resolver := installedPHPRuntimeResolver{path: path, ownerUID: uint32(os.Getuid())}
			if _, err := resolvePHPRuntime(resolver, "8.5"); err == nil {
				t.Fatal("invalid Sury profile accepted")
			}
		})
	}
}
