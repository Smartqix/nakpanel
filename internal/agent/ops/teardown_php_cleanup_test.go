package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type purgeInstalledProfileRunner struct {
	rootlessTeardownRunner
	activeVersion       string
	failFPM, failReload bool
}

func (r *purgeInstalledProfileRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "systemctl" && len(args) > 1 && args[0] == "show" && args[1] == "--property=LoadState" {
		r.calls = append(r.calls, append([]string{name}, args...))
		if args[len(args)-1] == "php"+r.activeVersion+"-fpm.service" {
			return []byte("LoadState=loaded\nActiveState=active\n"), nil
		}
		return []byte("LoadState=not-found\nActiveState=inactive\n"), nil
	}
	if r.failFPM && (strings.HasPrefix(name, "/usr/sbin/php-fpm") || name == "/usr/bin/env" && strings.Contains(strings.Join(args, " "), "/sbin/php-fpm")) || r.failReload && name == "systemctl" && len(args) > 0 && args[0] == "reload" && strings.HasPrefix(args[len(args)-1], "php") {
		r.calls = append(r.calls, append([]string{name}, args...))
		return nil, errors.New("injected active PHP failure")
	}
	return r.rootlessTeardownRunner.Run(ctx, name, args...)
}

func TestNativePurgeInstalledProfileDoesNotNeedUnavailablePHP(t *testing.T) {
	for _, tc := range []struct{ name, release, codename, internal, hosting string }{
		{"noble", "24.04", "noble", "8.3", `["8.3","8.4","8.5"]`},
		{"native26", "26.04", "resolute", "8.5", `["8.5"]`},
		{"sury26", "26.04", "resolute", "8.5", `["8.3","8.4","8.5"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			activeVersion := "8.3"
			if tc.name == "native26" {
				activeVersion = "8.5"
			}
			runner := &purgeInstalledProfileRunner{rootlessTeardownRunner: rootlessTeardownRunner{uid: "995"}, activeVersion: activeVersion}
			p, req, _ := rootlessTeardownFixture(t, runner)
			root := filepath.Dir(p.homeRoot)
			if err := os.WriteFile(filepath.Join(p.containerStateRoot, "sub-5", "sentinel"), []byte("peer must remain"), 0600); err != nil {
				t.Fatal(err)
			}
			p.gitRoot = filepath.Join(root, "git")
			p.stagingRoot = filepath.Join(root, "staging")
			p.phpApplicationStateRoot = filepath.Join(root, "php-applications")
			p.valkeyConfigRoot = filepath.Join(root, "valkey-config")
			p.valkeyRuntimeRoot = filepath.Join(root, "valkey-run")
			req.Domains = []string{"purge.example.test"}
			req.SiteIDs = []int64{17}
			profile := "ubuntu-24.04"
			if tc.name == "native26" {
				profile = "ubuntu-26.04-native"
			}
			if tc.name == "sury26" {
				profile = "ubuntu-26.04-sury"
			}
			file := filepath.Join(root, "platform.json")
			data := fmt.Sprintf(`{"os_id":"ubuntu","version_id":%q,"codename":%q,"architecture":"arm64","profile":%q,"internal_php_version":%q,"hosting_php_versions":%s}`, tc.release, tc.codename, profile, tc.internal, tc.hosting)
			if err := os.WriteFile(file, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			p.paths.RuntimeResolver = installedPHPRuntimeResolver{path: file, ownerUID: uint32(os.Getuid())}
			p.paths.NginxAvailableDir = filepath.Join(root, "nginx-available")
			p.paths.NginxEnabledDir = filepath.Join(root, "nginx-enabled")
			p.paths.NginxConfDir = filepath.Join(root, "nginx-conf")
			p.paths.PHPFPMPoolDir = filepath.Join(root, "php-pools")
			if _, err := NewSitePlan(types.CreateSiteReq{Username: req.Username, Domain: req.Domains[0], PHPVersion: "8.2", SharedAccount: true}, p.paths); err == nil {
				t.Fatal("execution accepted unavailable historical PHP8.2")
			}
			if _, err := p.TeardownSubscription(context.Background(), req); err != nil {
				t.Fatalf("purge of valid owned site must not require an unavailable legacy PHP executable: %v", err)
			}
			sawReload := false
			for _, call := range runner.calls {
				if strings.Join(call, " ") == "systemctl reload php"+activeVersion+"-fpm.service" {
					sawReload = true
				}
				if strings.Contains(strings.Join(call, " "), "php-fpm8.2") || strings.Join(call, " ") == "systemctl reload php8.2-fpm.service" {
					t.Fatal("executed absent historical PHP8.2")
				}
			}
			if !sawReload {
				t.Fatalf("active PHP reload missing: %v", runner.calls)
			}
			if _, err := os.Stat(req.HomePath); !os.IsNotExist(err) {
				t.Fatalf("owned home remains: %v", err)
			}
			if _, err := os.Stat(filepath.Join(p.containerStateRoot, "sub-5", "sentinel")); err != nil {
				t.Fatalf("peer state damaged: %v", err)
			}
		})
	}
}

func TestSiteTeardownUnavailableHistoricalPHPKeepsSibling(t *testing.T) {
	for _, profile := range []string{"ubuntu-24.04", "ubuntu-26.04-native", "ubuntu-26.04-sury"} {
		t.Run(profile, func(t *testing.T) {
			f := newSiteTeardownFixture(t)
			root := t.TempDir()
			release, codename, internal, hosting := "24.04", "noble", "8.3", `["8.3","8.4","8.5"]`
			if profile != "ubuntu-24.04" {
				release, codename, internal = "26.04", "resolute", "8.5"
			}
			if profile == "ubuntu-26.04-native" {
				hosting = `["8.5"]`
			}
			path := filepath.Join(root, "platform.json")
			if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"os_id":"ubuntu","version_id":%q,"codename":%q,"architecture":"arm64","profile":%q,"internal_php_version":%q,"hosting_php_versions":%s}`, release, codename, profile, internal, hosting)), 0600); err != nil {
				t.Fatal(err)
			}
			// The dedicated paths do not depend on the retired version, but the
			// snapshot and an old shared pool still carry its historical identity.
			legacy, err := NewSitePlan(types.CreateSiteReq{Username: "nps2", Domain: "addon.test", PHPVersion: "8.2", SharedAccount: true}, f.opts.Paths)
			if err != nil {
				t.Fatal(err)
			}
			writeRemovalFixture(t, legacy.PHPFPMConfig)
			f.request.Snapshot.Sites[0].PHPVersion = "8.2"
			f.opts.Paths.RuntimeResolver = installedPHPRuntimeResolver{path: path, ownerUID: uint32(os.Getuid())}
			runner := &cleanupPHPTestRunner{teardownRunner: *f.runner}
			f.opts.Runner = runner
			p := NewSiteTeardownProvisioner(f.opts)
			if _, err = p.TeardownSite(context.Background(), f.request); err != nil {
				t.Fatalf("historical runtime prevented stop: %v", err)
			}
			f.request.Stage = types.RemovalHosting
			if _, err = p.TeardownSite(context.Background(), f.request); err != nil {
				t.Fatalf("historical runtime prevented cleanup: %v", err)
			}
			if _, err = os.Stat(legacy.PHPFPMConfig); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("historical pool remains: %v", err)
			}
			for _, path := range f.kept {
				if data, err := os.ReadFile(path); err != nil || string(data) != "fixture-original" {
					t.Fatalf("neighbor changed: %s %v", path, err)
				}
			}
			for _, call := range runner.calls {
				if strings.Contains(strings.Join(call, " "), "php-fpm8.2") || strings.Contains(strings.Join(call, " "), "reload php8.2-fpm") {
					t.Fatalf("executed retired runtime: %v", call)
				}
			}
		})
	}
}

type cleanupPHPTestRunner struct {
	teardownRunner
	activeVersion       string
	failFPM, failReload bool
}

func (r *cleanupPHPTestRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	if name == "systemctl" && len(args) > 0 && args[0] == "show" && strings.HasPrefix(args[len(args)-1], "php") {
		r.calls = append(r.calls, append([]string{name}, args...))
		if args[len(args)-1] == "php"+r.activeVersion+"-fpm.service" {
			return []byte("LoadState=loaded\nActiveState=active\n"), nil
		}
		return []byte("LoadState=not-found\nActiveState=inactive\n"), nil
	}
	if r.failFPM && (strings.HasPrefix(name, "/usr/sbin/php-fpm") || name == "/usr/bin/env" && strings.Contains(joined, "/sbin/php-fpm")) || r.failReload && name == "systemctl" && strings.HasPrefix(joined, "reload php") {
		r.calls = append(r.calls, append([]string{name}, args...))
		return nil, errors.New("injected active PHP failure")
	}
	return r.teardownRunner.Run(ctx, name, args...)
}
func TestSiteTeardownUsesConfiguredPrivateRuntimeAndPropagatesFailure(t *testing.T) {
	for _, failure := range []string{"none", "config", "reload"} {
		t.Run(failure, func(t *testing.T) {
			f := newSiteTeardownFixture(t)
			runtime := privatePHPRuntime("8.4")
			f.opts.Paths.RuntimeResolver = fixedPHPResolver{runtime}
			legacy, err := NewSitePlan(types.CreateSiteReq{Username: "nps2", Domain: "addon.test", PHPVersion: "8.4", SharedAccount: true}, f.opts.Paths)
			if err != nil {
				t.Fatal(err)
			}
			writeRemovalFixture(t, legacy.PHPFPMConfig)
			runner := &cleanupPHPTestRunner{teardownRunner: *f.runner, activeVersion: "8.4", failFPM: failure == "config", failReload: failure == "reload"}
			f.opts.Runner = runner
			p := NewSiteTeardownProvisioner(f.opts)
			if _, err = p.TeardownSite(context.Background(), f.request); err != nil {
				t.Fatal(err)
			}
			f.request.Stage = types.RemovalHosting
			_, err = p.TeardownSite(context.Background(), f.request)
			if failure == "none" && err != nil || failure != "none" && err == nil {
				t.Fatalf("active runtime failure contract: %v", err)
			}
			name, args := runtime.FPMCommand("-t")
			if !runner.saw(append([]string{name}, args...)...) {
				t.Fatalf("private descriptor not used: %v", runner.calls)
			}
			if failure != "config" && !runner.saw("systemctl", "reload", "php8.4-fpm.service") {
				t.Fatal("active PHP was not reloaded")
			}
			if failure != "none" {
				runner.failFPM = false
				runner.failReload = false
				if _, err = p.TeardownSite(context.Background(), f.request); err != nil {
					t.Fatalf("journal retry lost active reload: %v", err)
				}
			}
		})
	}
}

func TestSubscriptionTeardownActivePHPFailureMustRetryBeforeAccountDeletion(t *testing.T) {
	for _, failure := range []string{"config", "reload"} {
		t.Run(failure, func(t *testing.T) {
			runner := &purgeInstalledProfileRunner{rootlessTeardownRunner: rootlessTeardownRunner{uid: "995"}, activeVersion: "8.4", failFPM: failure == "config", failReload: failure == "reload"}
			p, req, _ := rootlessTeardownFixture(t, runner)
			root := filepath.Dir(p.homeRoot)
			p.paths.RuntimeResolver = fixedPHPResolver{privatePHPRuntime("8.4")}
			p.paths.NginxAvailableDir = filepath.Join(root, "nginx-available")
			p.paths.NginxEnabledDir = filepath.Join(root, "nginx-enabled")
			p.paths.NginxConfDir = filepath.Join(root, "nginx-conf")
			p.paths.PHPFPMPoolDir = filepath.Join(root, "php-pools")
			p.gitRoot = filepath.Join(root, "git")
			p.stagingRoot = filepath.Join(root, "staging")
			p.phpApplicationStateRoot = filepath.Join(root, "php-applications")
			req.Domains = []string{"purge.example.test"}
			req.SiteIDs = []int64{17}
			if _, err := p.TeardownSubscription(context.Background(), req); err == nil {
				t.Fatal("active PHP failure ignored")
			}
			if _, err := os.Stat(req.HomePath); err != nil {
				t.Fatalf("deleted account before active reload: %v", err)
			}
			runner.failFPM = false
			runner.failReload = false
			if _, err := p.TeardownSubscription(context.Background(), req); err != nil {
				t.Fatalf("active reload retry failed: %v", err)
			}
			if _, err := os.Stat(req.HomePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("retry retained account: %v", err)
			}
		})
	}
}

func TestCleanupPathsMatchCanonicalProvidersWithoutGrantingExecution(t *testing.T) {
	id := types.SiteIdentity{SiteID: 7, SubscriptionID: 4, Username: "npaccount", Domain: "example.test"}
	for _, runtime := range []PHPRuntimeDescriptor{distroPHPRuntime("8.4"), privatePHPRuntime("8.4")} {
		live, err := NewSitePlan(types.CreateSiteReq{Username: id.Username, Domain: id.Domain, PHPVersion: "8.4", SharedAccount: true}, SitePathConfig{RuntimeResolver: fixedPHPResolver{runtime}})
		if err != nil {
			t.Fatal(err)
		}
		cleanup, err := legacySiteCleanupPlans(id, "8.4", SitePathConfig{})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, plan := range cleanup {
			if plan.PHPFPMConfig == live.PHPFPMConfig {
				found = true
			}
			if !strings.HasPrefix(plan.PHPFPMConfig, "/etc/php/8.4/fpm/pool.d/") && !strings.HasPrefix(plan.PHPFPMConfig, "/opt/nakpanel/php/8.4/etc/fpm/pool.d/") {
				t.Fatalf("unbounded historical pool: %s", plan.PHPFPMConfig)
			}
		}
		if !found {
			t.Fatalf("cleanup missed trusted %s provider path %s", runtime.Provider, live.PHPFPMConfig)
		}
	}
	plan, err := newSiteCleanupPlan(id, "", SitePathConfig{}, "")
	if err != nil || plan.PHPServiceName != "nakpanel-php-fpm@7.service" || plan.PHPFPMConfig != "/etc/nakpanel/php-fpm/sites/7.conf" {
		t.Fatalf("dedicated identity depends on runtime: %+v %v", plan, err)
	}
	for _, version := range []string{"../8.2", "8.2/../../etc", "8.2;id", ""} {
		if _, err := legacySiteCleanupPlans(id, version, SitePathConfig{}); err == nil {
			t.Fatalf("unsafe cleanup version accepted: %q", version)
		}
	}
	for _, bad := range []types.SiteIdentity{{Username: "root", Domain: id.Domain}, {Username: id.Username, Domain: "../outside"}, {Username: "../outside", Domain: id.Domain}} {
		if _, err := legacySiteCleanupPlans(bad, "8.2", SitePathConfig{}); err == nil {
			t.Fatalf("unsafe cleanup identity accepted: %+v", bad)
		}
	}
}

func TestSubscriptionCleanupRejectsSymlinkPoolBeforeAnyCommands(t *testing.T) {
	runner := &purgeInstalledProfileRunner{rootlessTeardownRunner: rootlessTeardownRunner{uid: "995"}}
	p, req, _ := rootlessTeardownFixture(t, runner)
	root := t.TempDir()
	outside := t.TempDir()
	p.paths.NginxAvailableDir = filepath.Join(root, "available")
	p.paths.NginxEnabledDir = filepath.Join(root, "enabled")
	p.paths.NginxConfDir = filepath.Join(root, "conf.d")
	p.paths.PHPFPMPoolDir = filepath.Join(root, "pools")
	if err := os.Symlink(outside, p.paths.PHPFPMPoolDir); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(outside, "nakpanel-"+req.Username+"-purge-example-test.conf")
	writeRemovalFixture(t, sentinel)
	req.Domains = []string{"purge.example.test"}
	req.SiteIDs = []int64{17}
	if _, err := p.TeardownSubscription(context.Background(), req); err == nil {
		t.Fatal("symlink historical root accepted")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("commands before complete path preflight: %v", runner.calls)
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "fixture-original" {
		t.Fatal("outside pool changed")
	}
}

func TestHistoricalReloadRequiresStableActiveAuthoritativeRuntime(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		active      bool
	}{
		{"absent", "LoadState=not-found\nActiveState=inactive\n", false},
		{"retired inactive", "LoadState=loaded\nActiveState=inactive\n", false},
		{"retired failed", "LoadState=loaded\nActiveState=failed\n", false},
		{"active unavailable", "LoadState=loaded\nActiveState=active\n", true},
		{"unstable", "LoadState=loaded\nActiveState=activating\n", true},
		{"incomplete", "LoadState=loaded\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &teardownRunner{outputs: map[string][]byte{"systemctl": []byte(tc.state)}}
			err := reloadActivePHPAfterCleanup(context.Background(), runner, fixedPHPResolver{distroPHPRuntime("8.5")}, "8.2")
			if tc.active && err == nil || !tc.active && err != nil {
				t.Fatalf("historical service boundary: %v", err)
			}
			if len(runner.calls) != 1 || runner.calls[0][0] != "systemctl" || runner.calls[0][1] != "show" {
				t.Fatalf("untrusted historical runtime executed: %v", runner.calls)
			}
		})
	}
}

func TestUnavailableActivePHPCannotMutateAccountOrSiteBeforePreflight(t *testing.T) {
	t.Run("account", func(t *testing.T) {
		runner := &purgeInstalledProfileRunner{rootlessTeardownRunner: rootlessTeardownRunner{uid: "995"}, activeVersion: "8.2"}
		p, req, _ := rootlessTeardownFixture(t, runner)
		root := t.TempDir()
		p.paths.NginxAvailableDir = filepath.Join(root, "available")
		p.paths.NginxEnabledDir = filepath.Join(root, "enabled")
		p.paths.NginxConfDir = filepath.Join(root, "conf.d")
		p.paths.PHPFPMPoolDir = filepath.Join(root, "pools")
		p.paths.RuntimeResolver = fixedPHPResolver{distroPHPRuntime("8.5")}
		req.Domains = []string{"purge.example.test"}
		req.SiteIDs = []int64{17}
		config := filepath.Join(p.paths.PHPFPMPoolDir, "nakpanel-"+req.Username+"-purge-example-test.conf")
		writeRemovalFixture(t, config)
		if _, err := p.TeardownSubscription(context.Background(), req); err == nil {
			t.Fatal("active unavailable runtime accepted")
		}
		if data, err := os.ReadFile(config); err != nil || string(data) != "fixture-original" {
			t.Fatal("config removed before active runtime trust preflight")
		}
		if _, err := os.Stat(req.HomePath); err != nil {
			t.Fatal("account removed before active runtime trust preflight")
		}
		for _, call := range runner.calls {
			if call[0] != "systemctl" || call[1] != "show" {
				t.Fatalf("non-preflight command: %v", call)
			}
		}
	})
	t.Run("site", func(t *testing.T) {
		f := newSiteTeardownFixture(t)
		legacy, err := NewSitePlan(types.CreateSiteReq{Username: "nps2", Domain: "addon.test", PHPVersion: "8.2", SharedAccount: true}, f.opts.Paths)
		if err != nil {
			t.Fatal(err)
		}
		writeRemovalFixture(t, legacy.PHPFPMConfig)
		f.request.Snapshot.Sites[0].PHPVersion = "8.2"
		f.opts.Paths.RuntimeResolver = fixedPHPResolver{distroPHPRuntime("8.5")}
		runner := &cleanupPHPTestRunner{teardownRunner: *f.runner, activeVersion: "8.2"}
		f.opts.Runner = runner
		if _, err = NewSiteTeardownProvisioner(f.opts).TeardownSite(context.Background(), f.request); err == nil {
			t.Fatal("active unavailable runtime reached site mutation")
		}
		if data, err := os.ReadFile(legacy.PHPFPMConfig); err != nil || string(data) != "fixture-original" {
			t.Fatal("legacy config changed before trust preflight")
		}
		for _, call := range runner.calls {
			if call[0] != "systemctl" || call[1] != "show" {
				t.Fatalf("non-preflight command: %v", call)
			}
		}
	})
}

func TestCanonicalHistoricalPoolBoundaryRejectsIntermediateAliases(t *testing.T) {
	for _, component := range []string{"nakpanel", "nakpanel/php", "nakpanel/php/8.2", "nakpanel/php/8.2/etc"} {
		t.Run(component, func(t *testing.T) {
			root, outside := t.TempDir(), t.TempDir()
			alias := filepath.Join(root, component)
			if err := os.MkdirAll(filepath.Dir(alias), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, alias); err != nil {
				t.Fatal(err)
			}
			pool := filepath.Join(root, "nakpanel/php/8.2/etc/fpm/pool.d")
			if err := os.MkdirAll(pool, 0755); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(pool, "nakpanel-npaccount-example-test.conf")
			writeRemovalFixture(t, sentinel)
			if err := validateHistoricalPHPPoolRoot(root, pool); err == nil {
				t.Fatal("intermediate provider/version alias escaped trusted root")
			}
			if data, err := os.ReadFile(sentinel); err != nil || string(data) != "fixture-original" {
				t.Fatal("outside pool changed during preflight")
			}
		})
	}
}

func TestSiteRetryPreflightsJournaledReloadAfterPoolWasRemoved(t *testing.T) {
	f := newSiteTeardownFixture(t)
	runner := &cleanupPHPTestRunner{teardownRunner: *f.runner, activeVersion: "8.4"}
	f.opts.Runner = runner
	p := NewSiteTeardownProvisioner(f.opts)
	if _, err := p.TeardownSite(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.opts.IdentityRegistry.root, "removal-10.json")
	journal, err := p.readRemovalJournal(path, f.request)
	if err != nil {
		t.Fatal(err)
	}
	// Crash point: shared pool unlink already happened and its durable reload
	// intent exists, while the dedicated and remaining artifacts still exist.
	journal.Checkpoints = append(journal.Checkpoints, "legacy-php-reload:8.4")
	if err = p.writeRemovalJournal(path, journal); err != nil {
		t.Fatal(err)
	}
	f.request.Stage = types.RemovalHosting
	p.options.Paths.RuntimeResolver = fixedPHPResolver{distroPHPRuntime("8.5")}
	if _, err = p.TeardownSite(context.Background(), f.request); err == nil {
		t.Fatal("untrusted journaled active reload accepted")
	}
	if data, err := os.ReadFile(f.target.PHPFPMConfig); err != nil || string(data) != "fixture-original" {
		t.Fatal("remaining artifact removed before journaled provider preflight")
	}
}
