package ops

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type siteTeardownFixture struct {
	opts                     SiteTeardownOptions
	request                  types.TeardownSiteReq
	runner                   *teardownRunner
	target, sibling, foreign SitePlan
	kept                     []string
}

func newSiteTeardownFixture(t *testing.T) siteTeardownFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	paths := SitePathConfig{HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "nginx", "available"), NginxEnabledDir: filepath.Join(root, "nginx", "enabled"), NginxConfDir: filepath.Join(root, "nginx", "conf.d"), NginxLogDir: filepath.Join(root, "logs", "nginx"), NginxCacheDir: filepath.Join(root, "cache"), NginxProtectedDir: filepath.Join(root, "nginx", "protected"), ACMEChallengeRoot: filepath.Join(root, "acme"), PHPFPMPoolDir: filepath.Join(root, "php", "pools"), PHPFPMDedicatedDir: filepath.Join(root, "php", "sites"), PHPFPMDedicatedRunDir: filepath.Join(root, "run", "php"), PHPFPMLogDir: filepath.Join(root, "logs", "php"), SystemdUnitDir: filepath.Join(root, "systemd")}
	registry := NewSiteIdentityRegistry(filepath.Join(root, "identities"))
	runner := &teardownRunner{outputs: map[string][]byte{"systemctl": []byte("LoadState=loaded\nActiveState=active\n")}}
	opts := SiteTeardownOptions{Paths: paths, IdentityRegistry: registry, Runner: runner, CertRoot: filepath.Join(root, "certs"), GitRoot: filepath.Join(root, "git"), StagingRoot: filepath.Join(root, "staging"), TaskStateRoot: filepath.Join(root, "tasks"), PHPApplicationStateRoot: filepath.Join(root, "php-applications"), ContainerStateRoot: filepath.Join(root, "containers"), ContainerRuntimeRoot: filepath.Join(root, "container-run"), StatisticsRoot: filepath.Join(root, "statistics")}
	fixture := siteTeardownFixture{opts: opts, runner: runner}
	identities := []types.SiteIdentity{{SiteID: 1, SubscriptionID: 2, Username: "nps2", Domain: "primary.test"}, {SiteID: 2, SubscriptionID: 2, Username: "nps2", Domain: "addon.test"}, {SiteID: 3, SubscriptionID: 3, Username: "nps3", Domain: "foreign.test"}}
	if err := registry.WithCreation(context.Background(), identities, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, id := range identities {
		plan, err := NewSitePlan(types.CreateSiteReq{SiteID: id.SiteID, SubscriptionID: id.SubscriptionID, Username: id.Username, Domain: id.Domain, PHPVersion: "8.4", SharedAccount: true}, paths)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{filepath.Join(plan.Docroot, "index.php"), plan.NginxConfig, plan.PHPFPMConfig, plan.PHPServiceUnit, plan.NginxAccessLog, plan.PHPFPMErrorLog, plan.PHPFPMSocket, filepath.Join(opts.CertRoot, id.Domain, "fullchain.pem")} {
			writeRemovalFixture(t, path)
			if id.SiteID != 2 {
				fixture.kept = append(fixture.kept, path)
			}
		}
		os.MkdirAll(filepath.Dir(plan.NginxEnabled), 0755)
		if err := os.Symlink(plan.NginxConfig, plan.NginxEnabled); err != nil {
			t.Fatal(err)
		}
		switch id.SiteID {
		case 1:
			fixture.sibling = plan
		case 2:
			fixture.target = plan
		case 3:
			fixture.foreign = plan
		}
	}
	for _, path := range []string{filepath.Join(paths.HomeRoot, "nps2", ".primary-access"), filepath.Join(opts.ContainerStateRoot, "sub-2", "data", "shared"), filepath.Join(root, "valkey", "sub-2", "config"), filepath.Join(root, "backups", "retained.tar.gz")} {
		writeRemovalFixture(t, path)
		fixture.kept = append(fixture.kept, path)
	}
	fixture.request = types.TeardownSiteReq{OperationID: 10, Revision: 1, SubscriptionID: 2, Stage: types.RemovalStopServices, Snapshot: types.SiteRemovalSnapshot{SchemaVersion: 1, Sites: []types.SiteRemovalSite{{SiteID: 2, SubscriptionID: 2, CustomerID: 1, Username: "nps2", Domain: "addon.test", PHPVersion: "8.4"}}, Databases: []types.SiteRemovalDatabase{{ID: 50, SiteID: 2, SubscriptionID: 2, Name: "np2_fixture", Principal: "np2_principal", DeletionEligible: true}}, Backups: []types.SiteRemovalResource{{Kind: "backup", ID: 70, SiteID: 2, Name: "addon.test"}}}}
	return fixture
}
func writeRemovalFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture-original"), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestTeardownSiteKeepsSiblingAndSharedAccount(t *testing.T) {
	fixture := newSiteTeardownFixture(t)
	provisioner := NewSiteTeardownProvisioner(fixture.opts)
	result, err := provisioner.TeardownSite(context.Background(), fixture.request)
	if err != nil || !slices.Contains(result.Checkpoints, string(types.RemovalStopServices)) {
		t.Fatalf("stop=%#v %v", result, err)
	}
	fixture.request.Stage = types.RemovalHosting
	result, err = provisioner.TeardownSite(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range fixture.kept {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "fixture-original" {
			t.Fatalf("sibling/shared file changed: %s %v", path, err)
		}
	}
	for _, path := range []string{filepath.Dir(fixture.target.Docroot), fixture.target.NginxConfig, fixture.target.NginxEnabled, fixture.target.PHPServiceUnit, fixture.target.PHPFPMConfig, fixture.target.NginxAccessLog, fixture.target.PHPFPMSocket} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("target artifact remains: %s %v", path, err)
		}
	}
	for _, call := range fixture.runner.calls {
		joined := strings.Join(call, " ")
		for _, unsafe := range []string{"userdel", "pkill", "setquota", "system prune", "rm --all", "nakpanel-php-fpm@1.service", "nakpanel-php-fpm@3.service"} {
			if strings.Contains(joined, unsafe) {
				t.Fatalf("account-wide or sibling command: %s", joined)
			}
		}
	}
	count := len(fixture.runner.calls)
	if _, err = NewSiteTeardownProvisioner(fixture.opts).TeardownSite(context.Background(), fixture.request); err != nil || len(fixture.runner.calls) != count {
		t.Fatalf("completed stage replayed: %v", err)
	}
}
func TestTeardownSiteRejectsSymlinkEscape(t *testing.T) {
	for _, artifact := range []string{"domain", "unit", "logs", "state"} {
		t.Run(artifact, func(t *testing.T) {
			fixture := newSiteTeardownFixture(t)
			outside := t.TempDir()
			file := filepath.Join(outside, "keep")
			writeRemovalFixture(t, file)
			path := filepath.Dir(fixture.target.Docroot)
			switch artifact {
			case "unit":
				path = fixture.target.PHPServiceUnit
			case "logs":
				path = fixture.target.NginxAccessLog
			case "state":
				path = fixture.opts.GitRoot
			}
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			os.MkdirAll(filepath.Dir(path), 0755)
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
			if _, err := NewSiteTeardownProvisioner(fixture.opts).TeardownSite(context.Background(), fixture.request); err == nil {
				t.Fatal("symlink escape accepted")
			}
			if len(fixture.runner.calls) != 0 {
				t.Fatal("side effects before path validation")
			}
			if data, err := os.ReadFile(file); err != nil || string(data) != "fixture-original" {
				t.Fatal("outside data changed")
			}
		})
	}
}
func TestTeardownSiteDoesNotDeleteBeforeServicesStop(t *testing.T) {
	fixture := newSiteTeardownFixture(t)
	fixture.request.Stage = types.RemovalHosting
	if _, err := NewSiteTeardownProvisioner(fixture.opts).TeardownSite(context.Background(), fixture.request); err == nil {
		t.Fatal("hosting cleanup skipped stop stage")
	}
	if _, err := os.Stat(fixture.target.Docroot); err != nil {
		t.Fatal("content deleted out of order")
	}
}

func TestTeardownSiteStopsOnlyApprovedUnits(t *testing.T) {
	fixture := newSiteTeardownFixture(t)
	fixture.request.Snapshot.Resources = []types.SiteRemovalResource{{Kind: "php_application", ID: 10, SiteID: 2}, {Kind: "php_worker", ID: 20, SiteID: 2, ParentID: 10}, {Kind: "php_deployment", ID: 30, SiteID: 2, ParentID: 10}, {Kind: "application", ID: 40, SiteID: 2, Name: "test-app"}, {Kind: "application_generation", ID: 41, SiteID: 2, ParentID: 40, Revision: 1}, {Kind: "task", ID: 50, SiteID: 2}}
	for _, unit := range []string{"nakpanel-php-worker@20.service", "nakpanel-php-worker@20-2.service", "nakpanel-php-worker@201.service", "nakpanel-php-fpm-candidate@2-30.service", "nakpanel-app-40-g1.service", "nakpanel-task-50.timer", "nakpanel-task-50.service"} {
		writeRemovalFixture(t, filepath.Join(fixture.opts.Paths.SystemdUnitDir, unit))
	}
	if _, err := NewSiteTeardownProvisioner(fixture.opts).TeardownSite(context.Background(), fixture.request); err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{"nakpanel-php-worker@20.service", "nakpanel-php-worker@20-2.service", "nakpanel-php-fpm-candidate@2-30.service", "nakpanel-app-40-g1.service", "nakpanel-task-50.timer", "nakpanel-task-50.service"} {
		if !fixture.runner.saw("systemctl", "disable", "--now", unit) {
			t.Errorf("selected service not stopped: %s", unit)
		}
	}
	foundContainerStop := false
	for _, call := range fixture.runner.calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "/usr/bin/podman stop --ignore nakpanel-app-40-g1") {
			foundContainerStop = true
		}
	}
	if !foundContainerStop {
		t.Fatal("candidate/unsupervised application container was not stopped")
	}
	if fixture.runner.saw("systemctl", "disable", "--now", "nakpanel-php-worker@201.service") {
		t.Fatal("worker ID prefix confused with sibling ID")
	}
}
func TestTeardownSiteMissingUnitIsIdempotent(t *testing.T) {
	fixture := newSiteTeardownFixture(t)
	fixture.runner.outputs["systemctl"] = []byte("LoadState=not-found\nActiveState=inactive\n")
	if _, err := NewSiteTeardownProvisioner(fixture.opts).TeardownSite(context.Background(), fixture.request); err != nil {
		t.Fatal(err)
	}
	if fixture.runner.saw("systemctl", "disable", "--now", fixture.target.PHPServiceName) {
		t.Fatal("missing unit disabled instead of skipped")
	}
}
func TestTeardownSiteRetryKeepsApprovalAndContentOnStopFailure(t *testing.T) {
	fixture := newSiteTeardownFixture(t)
	fixture.runner.failName = "systemctl"
	if _, err := NewSiteTeardownProvisioner(fixture.opts).TeardownSite(context.Background(), fixture.request); err == nil {
		t.Fatal("stop failure ignored")
	}
	if _, err := os.Stat(fixture.target.Docroot); err != nil {
		t.Fatal("content deleted before failed stop completed")
	}
	fixture.runner.failName = ""
	fixture.request.Revision++
	result, err := NewSiteTeardownProvisioner(fixture.opts).TeardownSite(context.Background(), fixture.request)
	if err != nil || !slices.Contains(result.Checkpoints, string(types.RemovalStopServices)) {
		t.Fatalf("retry=%#v %v", result, err)
	}
	changed := fixture.request
	changed.Snapshot.Sites = append([]types.SiteRemovalSite(nil), changed.Snapshot.Sites...)
	changed.Snapshot.Sites[0].Domain = "different.test"
	if _, err := NewSiteTeardownProvisioner(fixture.opts).TeardownSite(context.Background(), changed); err == nil {
		t.Fatal("altered approval accepted during retry")
	}
}

func TestTeardownSiteRemovesOnlySelectedRuntimeArtifacts(t *testing.T) {
	fixture := newSiteTeardownFixture(t)
	fixture.request.Snapshot.Resources = []types.SiteRemovalResource{{Kind: "php_application", ID: 10, SiteID: 2}, {Kind: "php_worker", ID: 20, SiteID: 2, ParentID: 10}, {Kind: "php_deployment", ID: 30, SiteID: 2, ParentID: 10}, {Kind: "application", ID: 40, SiteID: 2, Name: "test-app"}, {Kind: "application_generation", ID: 41, SiteID: 2, ParentID: 40, Revision: 1}, {Kind: "git", ID: 60, SiteID: 2}, {Kind: "staging", ID: 70, SiteID: 2, ParentID: 1}, {Kind: "statistics", ID: 2, SiteID: 2, Revision: 1}}
	removed := []string{filepath.Join(fixture.opts.PHPApplicationStateRoot, "app-10", "environments", "environment.conf"), filepath.Join(fixture.opts.ContainerStateRoot, "sub-2", "apps", "40", "volumes", "data", "content"), filepath.Join(fixture.opts.GitRoot, "site-2", "deploy-key"), filepath.Join(fixture.opts.StatisticsRoot, "site-2-generation-1", "report.html"), filepath.Join(fixture.opts.StagingRoot, "site-1-operation-70-100.tar.gz"), filepath.Join(fixture.opts.Paths.NginxConfDir, "90-nakpanel-php-candidate-2-30.conf"), filepath.Join(fixture.opts.Paths.PHPFPMDedicatedRunDir, "candidate-2-30.sock"), filepath.Join(fixture.opts.Paths.NginxLogDir, filepath.Base(fixture.target.NginxAccessLog)+".1.gz")}
	for _, path := range removed {
		writeRemovalFixture(t, path)
	}
	if err := os.WriteFile(removed[0], []byte("runtime-test-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	kept := []string{filepath.Join(fixture.opts.PHPApplicationStateRoot, "app-11", "environments", "environment.conf"), filepath.Join(fixture.opts.ContainerStateRoot, "sub-2", "apps", "401", "volumes", "data", "content"), filepath.Join(fixture.opts.StatisticsRoot, "site-21-generation-1", "report.html"), filepath.Join(fixture.opts.StagingRoot, "site-1-operation-71-100.tar.gz")}
	for _, path := range kept {
		writeRemovalFixture(t, path)
	}
	provisioner := NewSiteTeardownProvisioner(fixture.opts)
	if _, err := provisioner.TeardownSite(context.Background(), fixture.request); err != nil {
		t.Fatal(err)
	}
	fixture.request.Stage = types.RemovalHosting
	result, err := provisioner.TeardownSite(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range removed {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("selected artifact remains: %s %v", path, err)
		}
	}
	for _, path := range kept {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "fixture-original" {
			t.Fatalf("unrelated runtime artifact changed: %s %v", path, err)
		}
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "runtime-test-secret") {
		t.Fatal("runtime secret leaked into result")
	}
}
