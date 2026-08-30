package ops

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func writeSymlinkTar(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	writer := tar.NewWriter(file)
	if err := writer.WriteHeader(&tar.Header{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: "../outside", Mode: 0o777}); err != nil {
		_ = file.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func managedPHPSpec() types.PHPApplicationSpec {
	return types.PHPApplicationSpec{
		ApplicationID: 9, SubscriptionID: 4, SiteID: 7, DesiredRevision: 3,
		Username: "clientabc", Domain: "example.test", HostingMode: types.PHPHostingModeManaged,
		PHPVersion: "8.4", RepositoryID: 12, RepositoryRef: "main",
		FrameworkProfile: types.PHPFrameworkLaravel, PublicPath: "public", HealthPath: "/up",
		SharedPaths: []string{"storage", "bootstrap/cache"}, DesiredState: "active", ReleaseRetention: 3,
		Composer: types.PHPComposerSpec{Install: true},
		Workers:  []types.PHPWorkerSpec{{WorkerID: 18, Name: "queue", Script: "artisan", Arguments: []string{"queue:work"}, Processes: 2, DesiredState: "running"}},
		Policy: types.HostingPolicy{SchemaVersion: 3,
			Permissions: types.HostingPermissionPolicy{Hosting: true, Git: true, Composer: true, ManagedPHPDeployments: true, PHPWorkers: true},
			Resources:   types.HostingResourcePolicy{MaxPHPReleases: 3, MaxPHPWorkers: 4, MemoryMB: 512, CPUPercent: 100, MaxTasks: 64},
			PHP:         types.HostingPHPPolicy{AllowedVersions: []string{"8.4"}},
		},
	}
}

func TestValidatePHPApplicationSpecAppliesProfileDefaultsAndRejectsUnsafePaths(t *testing.T) {
	plain := managedPHPSpec()
	plain.FrameworkProfile = types.PHPFrameworkPlain
	plain.PublicPath, plain.HealthPath, plain.SharedPaths = "", "", nil
	normalized, err := validatePHPApplicationSpec(plain)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.HealthPath != "/" || normalized.PublicPath != "" || len(normalized.SharedPaths) != 0 {
		t.Fatalf("plain defaults = %#v", normalized)
	}

	laravel := managedPHPSpec()
	laravel.PublicPath, laravel.HealthPath, laravel.SharedPaths = "", "", nil
	normalized, err = validatePHPApplicationSpec(laravel)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.PublicPath != "public" || normalized.HealthPath != "/up" || !reflect.DeepEqual(normalized.SharedPaths, []string{"storage", "bootstrap/cache"}) {
		t.Fatalf("Laravel defaults = %#v", normalized)
	}

	for name, mutate := range map[string]func(*types.PHPApplicationSpec){
		"absolute public":          func(s *types.PHPApplicationSpec) { s.PublicPath = "/srv/www" },
		"public traversal":         func(s *types.PHPApplicationSpec) { s.PublicPath = "../public" },
		"health traversal":         func(s *types.PHPApplicationSpec) { s.HealthPath = "/../secret" },
		"shared traversal":         func(s *types.PHPApplicationSpec) { s.SharedPaths = []string{"storage", "../secret"} },
		"shared duplicate":         func(s *types.PHPApplicationSpec) { s.SharedPaths = []string{"storage", "storage"} },
		"shared overlap":           func(s *types.PHPApplicationSpec) { s.SharedPaths = []string{"storage", "storage/cache"} },
		"shared public root":       func(s *types.PHPApplicationSpec) { s.SharedPaths = []string{"public"} },
		"shared above public root": func(s *types.PHPApplicationSpec) { s.PublicPath, s.SharedPaths = "public/web", []string{"public"} },
		"encoded health traversal": func(s *types.PHPApplicationSpec) { s.HealthPath = "/%2e%2e/secret" },
		"unknown profile":          func(s *types.PHPApplicationSpec) { s.FrameworkProfile = "wordpress" },
		"version outside policy":   func(s *types.PHPApplicationSpec) { s.PHPVersion = "8.5" },
		"permission denied":        func(s *types.PHPApplicationSpec) { s.Policy.Permissions.ManagedPHPDeployments = false },
		"too much retention":       func(s *types.PHPApplicationSpec) { s.ReleaseRetention = 4 },
	} {
		t.Run(name, func(t *testing.T) {
			spec := managedPHPSpec()
			mutate(&spec)
			if _, err := validatePHPApplicationSpec(spec); err == nil {
				t.Fatal("unsafe specification accepted")
			}
		})
	}
}

func TestPHPComposerCommandsUseDirectArgvAndNoSecrets(t *testing.T) {
	spec := managedPHPSpec()
	commands := phpComposerCommands(spec, "/release")
	joined := fmt.Sprint(commands)
	for _, flag := range []string{"validate", "install", "--no-dev", "--prefer-dist", "--optimize-autoloader", "--no-interaction", "audit", "--locked"} {
		if !strings.Contains(joined, flag) {
			t.Fatalf("Composer commands %s omit %s", joined, flag)
		}
	}
	if !strings.Contains(joined, "--no-scripts") || !strings.Contains(joined, "--no-plugins") {
		t.Fatalf("Composer commands permit code execution: %s", joined)
	}
	spec.Policy.Permissions.ComposerCodeExecution = true
	spec.Composer.AllowScripts = true
	spec.Composer.AllowPlugins = true
	joined = fmt.Sprint(phpComposerCommands(spec, "/release"))
	if strings.Contains(joined, "--no-scripts") || strings.Contains(joined, "--no-plugins") {
		t.Fatalf("Composer code-execution grant ignored: %s", joined)
	}
	if strings.Contains(joined, "APP_KEY") || strings.Contains(joined, "secret") || strings.Contains(joined, "sh -c") {
		t.Fatalf("Composer commands contain secret or shell: %s", joined)
	}
}

func TestValidatePHPEnvironmentIsBounded(t *testing.T) {
	bindings := make([]types.PHPEnvironmentPayload, 129)
	for index := range bindings {
		bindings[index] = types.PHPEnvironmentPayload{Name: fmt.Sprintf("KEY_%d", index), Value: "value"}
	}
	if err := validatePHPEnvironment(bindings); err == nil {
		t.Fatal("more than 128 environment bindings were accepted")
	}
	if err := validatePHPEnvironment([]types.PHPEnvironmentPayload{{Name: "LARGE", Value: strings.Repeat("x", 256<<10)}}); err == nil {
		t.Fatal("oversized aggregate environment was accepted")
	}
}

func TestComposerAuditBlocksHighCriticalMalwareAndMalformed(t *testing.T) {
	for _, raw := range []string{
		`{"advisories":{"pkg":[{"severity":"high","title":"RCE"}]}}`,
		`{"advisories":{"pkg":[{"severity":"critical","title":"RCE"}]}}`,
		`{"advisories":{"pkg":[{"severity":"low","title":"malware package"}]}}`,
		`not-json`,
	} {
		if _, err := parseComposerAudit([]byte(raw)); err == nil {
			t.Fatalf("audit accepted %q", raw)
		}
	}
	summary, err := parseComposerAudit([]byte(`{"advisories":{"pkg":[{"severity":"moderate","title":"XSS"}]},"abandoned":["old/pkg"]}`))
	if err != nil || !strings.Contains(summary, "moderate=1") || !strings.Contains(summary, "abandoned=1") {
		t.Fatalf("audit summary = %q, %v", summary, err)
	}
}

type composerAuditExitError int

func (e composerAuditExitError) Error() string { return fmt.Sprintf("Composer exited %d", int(e)) }
func (e composerAuditExitError) ExitCode() int { return int(e) }

func TestComposerAuditExecutionStatusFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		output string
		err    error
		ok     bool
	}{
		{name: "clean", output: `{"advisories":{},"abandoned":[]}`, ok: true},
		{name: "moderate advisory status", output: `{"advisories":{"pkg":[{"severity":"moderate"}]},"abandoned":[]}`, err: composerAuditExitError(1), ok: true},
		{name: "abandoned status", output: `{"advisories":{},"abandoned":["old/pkg"]}`, err: composerAuditExitError(2), ok: true},
		{name: "combined status", output: `{"advisories":{"pkg":[{"severity":"low"}]},"abandoned":["old/pkg"]}`, err: composerAuditExitError(3), ok: true},
		{name: "timeout with clean-looking JSON", output: `{"advisories":{},"abandoned":[]}`, err: errors.New("context deadline exceeded")},
		{name: "signal with clean-looking JSON", output: `{"advisories":{},"abandoned":[]}`, err: composerAuditExitError(-1)},
		{name: "unknown status", output: `{"advisories":{},"abandoned":[]}`, err: composerAuditExitError(4)},
		{name: "status unexplained by JSON", output: `{"advisories":{},"abandoned":[]}`, err: composerAuditExitError(1)},
		{name: "malformed output", output: `not-json`, err: composerAuditExitError(1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := evaluateComposerAudit([]byte(test.output), test.err)
			if (err == nil) != test.ok {
				t.Fatalf("evaluateComposerAudit error = %v, want success=%t", err, test.ok)
			}
		})
	}
}

func TestRenderPHPEnvironmentAndWorkerUnitDoNotPermitInjectionOrShell(t *testing.T) {
	environment := []types.PHPEnvironmentPayload{{Name: "APP_ENV", Value: "production"}, {Name: "APP_KEY", Secret: "secret'\nvalue"}}
	rendered, err := renderPHPEnvironmentFile(environment)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered, "\nvalue\n") || !strings.Contains(rendered, `APP_KEY="secret'\nvalue"`) {
		t.Fatalf("unsafe environment rendering: %q", rendered)
	}
	worker := types.PHPWorker{ID: 33, SubscriptionID: 4, ApplicationID: 9, Name: "queue", Script: "artisan", Arguments: []string{"queue:work", "--tries=3"}, Processes: 2, DesiredState: "running"}
	release := "/home/clientabc/domains/example.test/.nakpanel/releases/22"
	unit, err := renderPHPWorkerUnit(managedPHPSpec(), worker, release, "/etc/nakpanel/php-applications/9.env")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(unit, "sh -c") || !strings.Contains(unit, "ExecStart=/usr/bin/php8.4 "+release+"/artisan queue:work --tries=3") ||
		!strings.Contains(unit, "EnvironmentFile=") || !strings.Contains(unit, "Slice=nakpanel-php-app-9.slice") ||
		strings.Contains(unit, "MemoryMax=") || strings.Contains(unit, "CPUQuota=") || strings.Contains(unit, "TasksMax=") ||
		!strings.Contains(unit, "ReadWritePaths=/home/clientabc/domains/example.test/.nakpanel/shared") || strings.Contains(unit, "ReadWritePaths=/home/clientabc/domains/example.test/.nakpanel/releases") {
		t.Fatalf("worker unit = %s", unit)
	}
	worker.Arguments = []string{"ok", "bad\narg"}
	if _, err := renderPHPWorkerUnit(managedPHPSpec(), worker, "/release", "/env"); err == nil {
		t.Fatal("worker control character accepted")
	}
	worker.Arguments = make([]string, 65)
	if _, err := renderPHPWorkerUnit(managedPHPSpec(), worker, "/release", "/env"); err == nil {
		t.Fatal("unbounded worker argument list accepted")
	}
}

func TestManagedPHPFPMUnitPreservesSharedRuntimeDirectory(t *testing.T) {
	unit := renderManagedFPMUnit(managedPHPSpec(), "/config", "/environment", "/release", "/run/nakpanel-php/site-7.sock", false)
	if !strings.Contains(unit, "RuntimeDirectory=nakpanel-php") || !strings.Contains(unit, "RuntimeDirectoryPreserve=yes") ||
		!strings.Contains(unit, "Slice=nakpanel-php-app-9.slice") {
		t.Fatalf("shared PHP runtime directory can be removed when one site stops:\n%s", unit)
	}
}

type scriptedPHPAppRunner struct {
	calls          []string
	fail           string
	failAfter      int
	failHits       int
	candidateUnits map[string]phpCandidateUnitState
}

type loadedCandidateRunner struct {
	calls           []string
	unitName        string
	active          bool
	loaded          bool
	generation      string
	failCleanupStop bool
}

func (r *loadedCandidateRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, call)
	if strings.Contains(call, "rev-parse --verify") {
		return []byte(strings.Repeat("a", 40) + "\n"), nil
	}
	if name != "systemctl" || len(args) == 0 {
		return nil, nil
	}
	switch args[0] {
	case "show":
		loadState, activeState := "not-found", "inactive"
		if r.loaded {
			loadState = "loaded"
		}
		if r.active {
			activeState = "active"
		}
		return []byte("LoadState=" + loadState + "\nActiveState=" + activeState + "\n"), nil
	case "stop":
		if len(args) > 1 && args[1] == r.unitName {
			if r.failCleanupStop {
				return []byte("candidate stop failed"), errors.New("candidate stop failed")
			}
			r.active = false
		}
	case "disable":
		if len(args) > 2 && args[1] == "--now" && args[2] == r.unitName {
			if r.failCleanupStop {
				return []byte("candidate stop failed"), errors.New("candidate stop failed")
			}
			r.active = false
		}
	case "start":
		if len(args) > 1 && args[1] == r.unitName && !r.active {
			r.active, r.loaded, r.generation = true, true, "new"
		}
	case "restart":
		if len(args) > 1 && args[1] == r.unitName {
			r.active, r.loaded, r.generation = true, true, "new"
		}
	}
	return nil, nil
}

func (r *scriptedPHPAppRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, call)
	if r.fail != "" && strings.Contains(call, r.fail) {
		r.failHits++
		if r.failAfter == 0 || r.failHits >= r.failAfter {
			return []byte("failed secret-value"), errors.New("failed")
		}
	}
	if strings.Contains(call, "rev-parse --verify") {
		return []byte(strings.Repeat("a", 40) + "\n"), nil
	}
	if name == "systemctl" && len(args) > 0 {
		if r.candidateUnits == nil {
			r.candidateUnits = make(map[string]phpCandidateUnitState)
		}
		switch args[0] {
		case "show":
			unitName := args[len(args)-1]
			state, ok := r.candidateUnits[unitName]
			if !ok {
				state = phpCandidateUnitState{LoadState: "not-found", ActiveState: "inactive"}
			}
			return []byte("LoadState=" + state.LoadState + "\nActiveState=" + state.ActiveState + "\n"), nil
		case "stop":
			if len(args) > 1 {
				state := r.candidateUnits[args[1]]
				state.LoadState, state.ActiveState = "loaded", "inactive"
				r.candidateUnits[args[1]] = state
			}
		case "restart":
			if len(args) > 1 && strings.Contains(args[1], "candidate@") {
				r.candidateUnits[args[1]] = phpCandidateUnitState{LoadState: "loaded", ActiveState: "active"}
			}
		}
	}
	return nil, nil
}

type phpTestExporter struct{}

func (phpTestExporter) Export(_ context.Context, _ CommandRunner, username, _, revision, target string) error {
	if username != "clientabc" {
		return errors.New("wrong build identity")
	}
	if revision != strings.Repeat("a", 40) {
		return errors.New("wrong revision")
	}
	if err := os.MkdirAll(filepath.Join(target, "public"), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(target, "public", "index.php"), []byte("<?php echo 'ok';"), 0o640); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(target, "artisan"), []byte("<?php"), 0o640)
}

type exportAsUserTestRunner struct {
	calls []string
}

func (r *exportAsUserTestRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, call)
	if name != "runuser" {
		return nil, nil
	}
	for _, argument := range args {
		if !strings.HasPrefix(argument, "--output=") {
			continue
		}
		archivePath := strings.TrimPrefix(argument, "--output=")
		file, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return nil, err
		}
		writer := tar.NewWriter(file)
		if err := writer.WriteHeader(&tar.Header{Name: "index.php", Mode: 0o640, Size: 2}); err != nil {
			_ = file.Close()
			return nil, err
		}
		if _, err := writer.Write([]byte("ok")); err != nil {
			_ = file.Close()
			return nil, err
		}
		return nil, errors.Join(writer.Close(), file.Close())
	}
	return nil, errors.New("Git archive output was not supplied")
}

func TestExportGitRevisionAsUserTransfersArchiveOwnershipBeforeGit(t *testing.T) {
	repository := t.TempDir()
	target := filepath.Join(t.TempDir(), "release")
	runner := &exportAsUserTestRunner{}
	if err := exportGitRevisionAsUser(context.Background(), runner, "clientabc", repository, strings.Repeat("a", 40), target); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls, "\n")
	chownAt := strings.Index(joined, "chown clientabc:clientabc")
	archiveAt := strings.Index(joined, "runuser -u clientabc -- git")
	if chownAt < 0 || archiveAt < 0 || chownAt > archiveAt {
		t.Fatalf("archive was not made writable before user-scoped Git export:\n%s", joined)
	}
	if data, err := os.ReadFile(filepath.Join(target, "index.php")); err != nil || string(data) != "ok" {
		t.Fatalf("exported release data=%q err=%v", data, err)
	}
}

func newPHPApplicationTestProvisioner(t *testing.T, runner CommandRunner, probe func(context.Context, string, string) error) (*PHPApplicationProvisioner, types.PHPApplicationSpec) {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.Mode()&os.ModeSymlink == 0 {
				_ = os.Chmod(path, info.Mode().Perm()|0o700)
			}
			return nil
		})
	})
	home := filepath.Join(root, "home")
	gitRoot := filepath.Join(root, "git")
	state := filepath.Join(root, "state")
	unit := filepath.Join(root, "systemd")
	phpConfig := filepath.Join(root, "php")
	phpRun := filepath.Join(root, "run")
	nginx := filepath.Join(root, "nginx")
	candidate := filepath.Join(root, "nginx-conf")
	for _, directory := range []string{home, gitRoot, state, unit, phpConfig, phpRun, nginx, candidate} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	spec := managedPHPSpec()
	domainRoot := filepath.Join(home, spec.Username, "domains", spec.Domain)
	if err := os.MkdirAll(filepath.Join(domainRoot, "public_html"), 0o750); err != nil {
		t.Fatal(err)
	}
	repository := filepath.Join(gitRoot, fmt.Sprintf("site-%d", spec.SiteID), "repository.git")
	if err := os.MkdirAll(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vhost := "server {\n    listen 80;\n    server_name example.test;\n    root " + filepath.Join(domainRoot, "public_html") + ";\n    location ~ \\.php$ {\n        fastcgi_pass unix:" + filepath.Join(phpRun, "site-7.sock") + ";\n    }\n}\n"
	if err := os.WriteFile(filepath.Join(nginx, spec.Domain+".conf"), []byte(vhost), 0o644); err != nil {
		t.Fatal(err)
	}
	if probe == nil {
		probe = func(context.Context, string, string) error { return nil }
	}
	return NewPHPApplicationProvisioner(PHPApplicationProvisionerOptions{
		HomeRoot: home, GitRoot: gitRoot, StateRoot: state, SystemdUnitDir: unit,
		PHPConfigDir: phpConfig, PHPRunDir: phpRun, NginxAvailableDir: nginx, NginxCandidateDir: candidate,
		Runner: runner, Exporter: phpTestExporter{}, RuntimeReady: func(context.Context, string) error { return nil }, Probe: probe,
	}), spec
}

func TestDeployPHPReleaseHealthGatesActivationAndRedactsSecrets(t *testing.T) {
	runner := &scriptedPHPAppRunner{}
	probes := 0
	expectedHost := "example.test"
	provisioner, spec := newPHPApplicationTestProvisioner(t, runner, func(_ context.Context, address, host string) error {
		probes++
		if host != expectedHost || (!strings.Contains(address, "127.0.0.1:31") && address != "http://127.0.0.1/up") {
			return errors.New("unsafe probe")
		}
		return nil
	})
	secret := "secret-value"
	request := types.DeployPHPReleaseReq{Application: spec, Deployment: types.PHPDeployment{
		ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID,
		RequestedRevision: "main", PreviousDeploymentID: 19,
	}, Environment: []types.PHPEnvironmentPayload{{Name: "APP_KEY", Secret: secret}}}
	result, err := provisioner.DeployPHPRelease(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.DeploymentID != 22 || result.ResolvedRevision != strings.Repeat("a", 40) || probes != 6 {
		t.Fatalf("result=%+v probes=%d", result, probes)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, secret) || strings.Contains(call, "sh -c") {
			t.Fatalf("unsafe command: %s", call)
		}
	}
	joinedCalls := strings.Join(runner.calls, "\n")
	if !strings.Contains(joinedCalls, "chown root:clientabc") {
		t.Fatalf("release management roots were not assigned to the subscription group:\n%s", joinedCalls)
	}
	if scans := strings.Count(joinedCalls, "/usr/bin/clamscan"); scans != 2 {
		t.Fatalf("release must be malware-scanned before and after dependency installation, scans=%d:\n%s", scans, joinedCalls)
	}
	if !strings.Contains(joinedCalls, "nakpanel-php-worker@18.service") || !strings.Contains(joinedCalls, "nakpanel-php-worker@18-2.service") {
		t.Fatalf("worker process units were not reconciled:\n%s", joinedCalls)
	}
	for _, value := range []string{result.HealthMessage, result.ComposerAudit, result.ReleasePath} {
		if strings.Contains(value, secret) {
			t.Fatalf("secret in result: %+v", result)
		}
	}
	marker, err := provisioner.readMarker(spec.ApplicationID)
	if err != nil {
		t.Fatal(err)
	}
	if marker.ActiveDeploymentID != 22 || marker.PreviousDeploymentID != 19 {
		t.Fatalf("marker=%+v", marker)
	}
	if mode := mustStat(t, result.ReleasePath).Mode().Perm(); mode != 0o550 {
		t.Fatalf("release mode=%o", mode)
	}
	sharedStorage := filepath.Join(filepath.Dir(filepath.Dir(result.ReleasePath)), "shared", "storage")
	if mode := mustStat(t, sharedStorage).Mode().Perm(); mode != 0o750 {
		t.Fatalf("shared storage mode=%o", mode)
	}
	if target, err := filepath.EvalSymlinks(filepath.Join(result.ReleasePath, "storage")); err != nil || target != sharedStorage {
		t.Fatalf("release shared path target=%q err=%v", target, err)
	}
	if mode := mustStat(t, provisioner.environmentPath(spec.ApplicationID, request.Deployment.ID, spec.DesiredRevision)).Mode().Perm(); mode != 0o600 {
		t.Fatalf("runtime environment mode=%o", mode)
	}

	again, err := provisioner.DeployPHPRelease(context.Background(), request)
	if err != nil || again.Changed || probes != 6 {
		t.Fatalf("idempotent deploy=%+v err=%v probes=%d", again, err, probes)
	}
}

func TestPHPWebAccessACLsCoverManagedAncestorsAndPublicSharedData(t *testing.T) {
	runner := &scriptedPHPAppRunner{}
	provisioner, spec := newPHPApplicationTestProvisioner(t, runner, nil)
	spec.FrameworkProfile = types.PHPFrameworkCustom
	spec.SharedPaths = []string{"public/uploads"}
	request := types.DeployPHPReleaseReq{Application: spec, Deployment: types.PHPDeployment{
		ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, RequestedRevision: "main",
	}}
	result, err := provisioner.DeployPHPRelease(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	managedRoot := filepath.Dir(filepath.Dir(result.ReleasePath))
	releaseRoot := filepath.Dir(result.ReleasePath)
	sharedRoot := filepath.Join(managedRoot, "shared")
	publicShared := filepath.Join(sharedRoot, "public", "uploads")
	joined := strings.Join(runner.calls, "\n")
	for _, want := range []string{
		"setfacl -m u:www-data:--x " + managedRoot + " " + releaseRoot,
		"setfacl -m u:www-data:--x " + sharedRoot + " " + filepath.Join(sharedRoot, "public"),
		"setfacl -R -m u:www-data:r-X " + publicShared,
		"setfacl -m d:u:www-data:r-X " + publicShared,
		"setfacl -R -m u:www-data:r-X " + filepath.Join(releaseRoot, ".22.candidate"),
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("managed web access omitted %q:\n%s", want, joined)
		}
	}

	runner.calls = nil
	spec.DesiredState = "suspended"
	if _, err := provisioner.ReconcilePHPApplication(context.Background(), types.ReconcilePHPApplicationReq{Application: spec}); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(runner.calls, "\n")
	for _, want := range []string{
		"setfacl -R -x u:www-data " + result.ReleasePath,
		"setfacl -x u:www-data " + managedRoot + " " + releaseRoot,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("suspension did not revoke web access %q:\n%s", want, joined)
		}
	}

	runner.calls = nil
	spec.DesiredState = "active"
	active := types.PHPDeployment{
		ID: request.Deployment.ID, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID,
		ResolvedRevision: result.ResolvedRevision,
	}
	if _, err := provisioner.ReconcilePHPApplication(context.Background(), types.ReconcilePHPApplicationReq{
		Application: spec, ActiveDeployment: &active,
	}); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(runner.calls, "\n")
	for _, want := range []string{
		"setfacl -m u:www-data:--x " + managedRoot + " " + releaseRoot,
		"setfacl -m u:www-data:--x " + sharedRoot + " " + filepath.Join(sharedRoot, "public"),
		"setfacl -R -m u:www-data:r-X " + publicShared,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("reactivation did not restore web access %q:\n%s", want, joined)
		}
	}
}

func TestPHPSharedPathPublicScopeIncludesThePublicDirectoryItself(t *testing.T) {
	for _, test := range []struct {
		publicPath string
		sharedPath string
		want       bool
	}{
		{publicPath: "", sharedPath: "storage", want: true},
		{publicPath: "public", sharedPath: "public", want: true},
		{publicPath: "public", sharedPath: "public/uploads", want: true},
		{publicPath: "public", sharedPath: "storage", want: false},
	} {
		if got := phpSharedPathIsPublic(test.publicPath, test.sharedPath); got != test.want {
			t.Fatalf("phpSharedPathIsPublic(%q, %q) = %t, want %t", test.publicPath, test.sharedPath, got, test.want)
		}
	}
}

func TestDeployPHPReleaseResetsAndFencesStaleCandidateGeneration(t *testing.T) {
	runner := &scriptedPHPAppRunner{}
	probes := 0
	markerObserved := false
	var provisioner *PHPApplicationProvisioner
	var spec types.PHPApplicationSpec
	provisioner, spec = newPHPApplicationTestProvisioner(t, runner, func(context.Context, string, string) error {
		probes++
		if probes == 1 {
			markerPath := provisioner.candidateMarkerPath(spec.ApplicationID, 22)
			data, err := os.ReadFile(markerPath)
			if err != nil || !strings.Contains(string(data), strings.Repeat("a", 40)) {
				return fmt.Errorf("candidate marker was not fenced to the resolved revision: %v: %s", err, data)
			}
			markerObserved = true
		}
		return nil
	})
	unitName := "nakpanel-php-fpm-candidate@7-22.service"
	runner.candidateUnits = map[string]phpCandidateUnitState{
		unitName: {LoadState: "loaded", ActiveState: "active"},
	}
	unitPath := filepath.Join(provisioner.systemdUnitDir, unitName)
	nginxPath := filepath.Join(provisioner.nginxCandidateDir, "90-nakpanel-php-candidate-7-22.conf")
	statePath := filepath.Join(provisioner.stateRoot, "app-9", "candidate-22")
	if err := os.MkdirAll(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{unitPath: "stale-unit", nginxPath: "stale-nginx", filepath.Join(statePath, "candidate.json"): `{"resolved_revision":"stale"}`} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := provisioner.DeployPHPRelease(context.Background(), types.DeployPHPReleaseReq{Application: spec, Deployment: types.PHPDeployment{
		ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, RequestedRevision: "main",
	}}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls, "\n")
	stopAt := strings.Index(joined, "systemctl stop "+unitName)
	startAt := strings.Index(joined, "systemctl restart "+unitName)
	if stopAt < 0 || startAt < 0 || stopAt > startAt || !markerObserved {
		t.Fatalf("stale candidate was not reset/fenced before startup:\n%s", joined)
	}
}

func TestDeployPHPReleaseStopsLoadedCandidateWithoutUnitFileBeforeProbing(t *testing.T) {
	unitName := "nakpanel-php-fpm-candidate@7-22.service"
	runner := &loadedCandidateRunner{unitName: unitName, active: true, loaded: true, generation: "stale"}
	probeCalls := 0
	provisioner, spec := newPHPApplicationTestProvisioner(t, runner, func(context.Context, string, string) error {
		probeCalls++
		if runner.generation != "new" {
			return errors.New("stale candidate process answered the readiness probe")
		}
		return nil
	})
	if _, err := os.Stat(filepath.Join(provisioner.systemdUnitDir, unitName)); !os.IsNotExist(err) {
		t.Fatalf("test requires loaded candidate with no unit file: %v", err)
	}
	if _, err := provisioner.DeployPHPRelease(context.Background(), types.DeployPHPReleaseReq{Application: spec, Deployment: types.PHPDeployment{
		ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, RequestedRevision: "main",
	}}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls, "\n")
	stopAt := strings.Index(joined, "systemctl stop "+unitName)
	restartAt := strings.Index(joined, "systemctl restart "+unitName)
	if stopAt < 0 || restartAt < 0 || stopAt > restartAt || probeCalls != 6 {
		t.Fatalf("loaded no-file candidate was not replaced before probing (probes=%d):\n%s", probeCalls, joined)
	}
}

func TestDeployPHPReleaseSurfacesCandidateCleanupStopFailureAndKeepsUnit(t *testing.T) {
	unitName := "nakpanel-php-fpm-candidate@7-22.service"
	runner := &loadedCandidateRunner{unitName: unitName}
	provisioner, spec := newPHPApplicationTestProvisioner(t, runner, nil)
	probeCalls := 0
	provisioner.probe = func(context.Context, string, string) error {
		probeCalls++
		if probeCalls == 3 {
			runner.failCleanupStop = true
		}
		return nil
	}
	_, err := provisioner.DeployPHPRelease(context.Background(), types.DeployPHPReleaseReq{Application: spec, Deployment: types.PHPDeployment{
		ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, RequestedRevision: "main",
	}})
	if err == nil || !strings.Contains(err.Error(), "candidate stop failed") {
		t.Fatalf("candidate cleanup stop failure was hidden: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(provisioner.systemdUnitDir, unitName)); statErr != nil {
		t.Fatalf("candidate unit was removed after its process failed to stop: %v", statErr)
	}
	if !runner.active {
		t.Fatal("test did not retain the modeled process after the stop failure")
	}
}

func TestCandidateMarkerTamperingFailsHealthGate(t *testing.T) {
	runner := &scriptedPHPAppRunner{}
	probes := 0
	var provisioner *PHPApplicationProvisioner
	var spec types.PHPApplicationSpec
	provisioner, spec = newPHPApplicationTestProvisioner(t, runner, func(context.Context, string, string) error {
		probes++
		if probes == 3 {
			return os.WriteFile(provisioner.candidateMarkerPath(spec.ApplicationID, 22), []byte(`{"application_id":9,"deployment_id":22,"resolved_revision":"tampered"}`), 0o600)
		}
		return nil
	})
	_, err := provisioner.DeployPHPRelease(context.Background(), types.DeployPHPReleaseReq{Application: spec, Deployment: types.PHPDeployment{
		ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, RequestedRevision: "main",
	}})
	if err == nil {
		t.Fatal("tampered candidate marker was accepted")
	}
}

func TestDeployPHPReleaseRequiresThreeCandidateProbes(t *testing.T) {
	runner := &scriptedPHPAppRunner{}
	probes := 0
	provisioner, spec := newPHPApplicationTestProvisioner(t, runner, func(context.Context, string, string) error {
		probes++
		if probes == 3 {
			return errors.New("unhealthy")
		}
		return nil
	})
	_, err := provisioner.DeployPHPRelease(context.Background(), types.DeployPHPReleaseReq{Application: spec, Deployment: types.PHPDeployment{
		ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, RequestedRevision: "main",
	}})
	if err == nil || probes != 3 {
		t.Fatalf("err=%v probes=%d", err, probes)
	}
	if _, err := os.Stat(provisioner.markerPath(spec.ApplicationID)); !os.IsNotExist(err) {
		t.Fatalf("marker exists after failed candidate: %v", err)
	}
}

func TestActivatePHPReleaseRestoresAllFilesWhenNginxReloadFails(t *testing.T) {
	runner := &scriptedPHPAppRunner{fail: "systemctl reload nginx"}
	provisioner, spec := newPHPApplicationTestProvisioner(t, runner, nil)
	paths, err := provisioner.pathsFor(spec, 22)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(paths.release, "public"), 0o750); err != nil {
		t.Fatal(err)
	}
	envPath, err := provisioner.writeEnvironment(spec, 22, nil)
	if err != nil {
		t.Fatal(err)
	}
	nginxPath := filepath.Join(provisioner.nginxAvailableDir, spec.Domain+".conf")
	before, err := os.ReadFile(nginxPath)
	if err != nil {
		t.Fatal(err)
	}
	err = provisioner.activateRelease(context.Background(), spec, phpObservedMarker{
		ApplicationID: spec.ApplicationID, SiteID: spec.SiteID, DesiredRevision: spec.DesiredRevision,
		ActiveDeploymentID: 22, ResolvedRevision: strings.Repeat("a", 40), ReleasePath: paths.release, EnvironmentPath: envPath,
	}, envPath, nil)
	if err == nil {
		t.Fatal("activation unexpectedly succeeded")
	}
	after, err := os.ReadFile(nginxPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("nginx config not restored\nbefore=%s\nafter=%s", before, after)
	}
	if _, err := os.Stat(provisioner.markerPath(spec.ApplicationID)); !os.IsNotExist(err) {
		t.Fatalf("marker exists after rollback: %v", err)
	}
}

type rollbackFailureRunner struct {
	triggered bool
}

func (r *rollbackFailureRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	if !r.triggered && strings.Contains(call, "systemctl reload nginx") {
		r.triggered = true
		return []byte("activation failed"), errors.New("activation failed")
	}
	if r.triggered && strings.Contains(call, "systemctl daemon-reload") {
		return []byte("rollback failed"), errors.New("rollback failed")
	}
	return nil, nil
}

func TestActivatePHPReleaseRollsBackEveryValidationStageAndReportsRollbackFailure(t *testing.T) {
	for _, failure := range []string{
		"php-fpm8.4 -t -y",
		"systemctl daemon-reload",
		"systemctl restart nakpanel-php-fpm@7.service",
		"nginx -t",
		"systemctl reload nginx",
	} {
		t.Run(failure, func(t *testing.T) {
			runner := &scriptedPHPAppRunner{fail: failure}
			provisioner, spec := newPHPApplicationTestProvisioner(t, runner, nil)
			assertActivationRollback(t, provisioner, spec, []types.PHPEnvironmentPayload{{Name: "APP_KEY", Secret: "secret-value"}})
		})
	}
	t.Run("live probe", func(t *testing.T) {
		provisioner, spec := newPHPApplicationTestProvisioner(t, &scriptedPHPAppRunner{}, func(context.Context, string, string) error {
			return errors.New("live probe failed")
		})
		assertActivationRollback(t, provisioner, spec, nil)
	})
	t.Run("rollback command", func(t *testing.T) {
		provisioner, spec := newPHPApplicationTestProvisioner(t, &rollbackFailureRunner{}, nil)
		err := activateTestRelease(t, provisioner, spec, nil)
		if err == nil || !strings.Contains(err.Error(), "rollback failed") {
			t.Fatalf("rollback failure was hidden: %v", err)
		}
	})
}

func TestFailedSecondGenerationRestoresPreviousEnvironmentReference(t *testing.T) {
	stages := []struct {
		name      string
		failure   string
		failAfter int
		liveProbe bool
	}{
		{name: "FPM validation", failure: "php-fpm8.4 -t -y", failAfter: 2},
		{name: "daemon reload", failure: "systemctl daemon-reload", failAfter: 2},
		{name: "FPM restart", failure: "systemctl restart nakpanel-php-fpm@7.service"},
		{name: "nginx validation", failure: "nginx -t", failAfter: 2},
		{name: "nginx reload", failure: "systemctl reload nginx", failAfter: 2},
		{name: "live probe", liveProbe: true},
	}
	for _, stage := range stages {
		t.Run(stage.name, func(t *testing.T) {
			runner := &scriptedPHPAppRunner{}
			probes := 0
			provisioner, spec := newPHPApplicationTestProvisioner(t, runner, func(context.Context, string, string) error {
				probes++
				if stage.liveProbe && probes == 10 {
					return errors.New("second generation live probe failed")
				}
				return nil
			})
			oldSecret, newSecret := "old-generation-secret", "new-generation-secret"
			first := types.DeployPHPReleaseReq{
				Application: spec,
				Deployment:  types.PHPDeployment{ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, RequestedRevision: "main"},
				Environment: []types.PHPEnvironmentPayload{{Name: "APP_KEY", Secret: oldSecret}},
			}
			if _, err := provisioner.DeployPHPRelease(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			oldRevision := spec.DesiredRevision
			oldEnvironment := provisioner.environmentPath(spec.ApplicationID, 22, oldRevision)
			spec.DesiredRevision++
			runner.fail, runner.failAfter, runner.failHits = stage.failure, stage.failAfter, 0
			second := types.DeployPHPReleaseReq{
				Application: spec,
				Deployment: types.PHPDeployment{ID: 23, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID,
					RequestedRevision: "main", PreviousDeploymentID: 22},
				Environment: []types.PHPEnvironmentPayload{{Name: "APP_KEY", Secret: newSecret}},
			}
			if _, err := provisioner.DeployPHPRelease(context.Background(), second); err == nil {
				t.Fatal("second generation unexpectedly activated")
			}
			unit, err := os.ReadFile(filepath.Join(provisioner.systemdUnitDir, "nakpanel-php-fpm@7.service"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(unit), "EnvironmentFile="+oldEnvironment) || strings.Contains(string(unit), provisioner.environmentPath(spec.ApplicationID, 23, spec.DesiredRevision)) ||
				strings.Contains(string(unit), oldSecret) || strings.Contains(string(unit), newSecret) {
				t.Fatalf("previous environment reference was not restored:\n%s", unit)
			}
			oldData, err := os.ReadFile(oldEnvironment)
			if err != nil || !strings.Contains(string(oldData), oldSecret) || strings.Contains(string(oldData), newSecret) {
				t.Fatalf("previous environment changed: %v: %s", err, oldData)
			}
			marker, err := provisioner.readMarker(spec.ApplicationID)
			if err != nil || marker.ActiveDeploymentID != 22 {
				t.Fatalf("previous marker was not restored: %+v %v", marker, err)
			}
		})
	}
}

func assertActivationRollback(t *testing.T, provisioner *PHPApplicationProvisioner, spec types.PHPApplicationSpec, environment []types.PHPEnvironmentPayload) {
	t.Helper()
	nginxPath := filepath.Join(provisioner.nginxAvailableDir, spec.Domain+".conf")
	before, err := os.ReadFile(nginxPath)
	if err != nil {
		t.Fatal(err)
	}
	err = activateTestRelease(t, provisioner, spec, environment)
	if err == nil || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("activation failure was missing or leaked a secret: %v", err)
	}
	after, readErr := os.ReadFile(nginxPath)
	if readErr != nil || string(after) != string(before) {
		t.Fatalf("nginx configuration was not restored: %v\nbefore=%s\nafter=%s", readErr, before, after)
	}
	for _, path := range []string{
		filepath.Join(provisioner.phpConfigDir, strconv.FormatInt(spec.SiteID, 10)+".conf"),
		filepath.Join(provisioner.systemdUnitDir, fmt.Sprintf("nakpanel-php-fpm@%d.service", spec.SiteID)),
		provisioner.markerPath(spec.ApplicationID),
	} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("activation artifact remains after rollback: %s: %v", path, statErr)
		}
	}
}

func activateTestRelease(t *testing.T, provisioner *PHPApplicationProvisioner, spec types.PHPApplicationSpec, environment []types.PHPEnvironmentPayload) error {
	t.Helper()
	paths, err := provisioner.pathsFor(spec, 22)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(paths.release, "public"), 0o750); err != nil {
		t.Fatal(err)
	}
	environmentPath, err := provisioner.writeEnvironment(spec, 22, environment)
	if err != nil {
		t.Fatal(err)
	}
	return provisioner.activateRelease(context.Background(), spec, phpObservedMarker{
		ApplicationID: spec.ApplicationID, SiteID: spec.SiteID, DesiredRevision: spec.DesiredRevision,
		ActiveDeploymentID: 22, ResolvedRevision: strings.Repeat("a", 40), ReleasePath: paths.release, EnvironmentPath: environmentPath,
	}, environmentPath, environment)
}

func TestPHPReleaseRetentionAlwaysKeepsActiveAndPreviousWithinBudget(t *testing.T) {
	provisioner := NewPHPApplicationProvisioner(PHPApplicationProvisionerOptions{})
	root := t.TempDir()
	for id := int64(1); id <= 5; id++ {
		if err := os.Mkdir(filepath.Join(root, strconv.FormatInt(id, 10)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := provisioner.pruneReleases(root, 3, 1, 2); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{1, 2, 5} {
		if _, err := os.Stat(filepath.Join(root, strconv.FormatInt(id, 10))); err != nil {
			t.Fatalf("release %d was not retained: %v", id, err)
		}
	}
	for _, id := range []int64{3, 4} {
		if _, err := os.Stat(filepath.Join(root, strconv.FormatInt(id, 10))); !os.IsNotExist(err) {
			t.Fatalf("release %d remains: %v", id, err)
		}
	}
}

func TestReconcilePHPApplicationSuspensionStopsFPMAndWorkers(t *testing.T) {
	runner := &scriptedPHPAppRunner{}
	provisioner, spec := newPHPApplicationTestProvisioner(t, runner, nil)
	request := types.DeployPHPReleaseReq{Application: spec, Deployment: types.PHPDeployment{
		ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, RequestedRevision: "main",
	}}
	if _, err := provisioner.DeployPHPRelease(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	candidateUnit := filepath.Join(provisioner.systemdUnitDir, "nakpanel-php-fpm-candidate@7-999.service")
	candidateNginx := filepath.Join(provisioner.nginxCandidateDir, "90-nakpanel-php-candidate-7-999.conf")
	if err := os.WriteFile(candidateUnit, []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidateNginx, []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	spec.DesiredState = "suspended"
	result, err := provisioner.ReconcilePHPApplication(context.Background(), types.ReconcilePHPApplicationReq{Application: spec})
	if err != nil || result.ObservedState != "suspended" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	joined := strings.Join(runner.calls, "\n")
	for _, want := range []string{"disable --now nakpanel-php-fpm-candidate@7-999.service", "systemctl stop nakpanel-php-fpm@7.service", "disable --now nakpanel-php-worker@18.service", "disable --now nakpanel-php-worker@18-2.service"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("suspension omitted %q:\n%s", want, joined)
		}
	}
	for _, path := range []string{candidateUnit, candidateNginx} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("candidate artifact remains after suspension: %s: %v", path, err)
		}
	}
}

func TestReconcilePHPApplicationSuspensionReportsAndRedactsFPMFailure(t *testing.T) {
	runner := &scriptedPHPAppRunner{fail: "systemctl stop nakpanel-php-fpm@7.service"}
	provisioner, spec := newPHPApplicationTestProvisioner(t, runner, nil)
	spec.DesiredState = "suspended"
	secret := "secret-value"
	_, err := provisioner.ReconcilePHPApplication(context.Background(), types.ReconcilePHPApplicationReq{
		Application: spec, Environment: []types.PHPEnvironmentPayload{{Name: "APP_KEY", Secret: secret}},
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("FPM suspension failure was hidden or leaked a secret: %v", err)
	}
}

func TestReconcilePHPApplicationRepairsImmutableReleasePermissions(t *testing.T) {
	runner := &scriptedPHPAppRunner{}
	provisioner, spec := newPHPApplicationTestProvisioner(t, runner, nil)
	request := types.DeployPHPReleaseReq{Application: spec, Deployment: types.PHPDeployment{
		ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, RequestedRevision: "main",
	}}
	result, err := provisioner.DeployPHPRelease(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(result.ReleasePath, 0o777); err != nil {
		t.Fatal(err)
	}
	active := request.Deployment
	active.ResolvedRevision = result.ResolvedRevision
	if _, err := provisioner.ReconcilePHPApplication(context.Background(), types.ReconcilePHPApplicationReq{Application: spec, ActiveDeployment: &active}); err != nil {
		t.Fatal(err)
	}
	if mode := mustStat(t, result.ReleasePath).Mode().Perm(); mode != 0o550 {
		t.Fatalf("reconciliation left mutable release mode %o", mode)
	}
}

func TestPHPSharedStorageRejectsSymlinkedManagedPaths(t *testing.T) {
	provisioner, spec := newPHPApplicationTestProvisioner(t, &scriptedPHPAppRunner{}, nil)
	domainRoot := filepath.Join(provisioner.homeRoot, spec.Username, "domains", spec.Domain)
	managedRoot := filepath.Join(domainRoot, ".nakpanel")
	outside := t.TempDir()
	if err := os.Mkdir(managedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(managedRoot, "shared")); err != nil {
		t.Fatal(err)
	}
	if err := provisioner.prepareSharedPaths(context.Background(), spec, filepath.Join(managedRoot, "candidate"), filepath.Join(managedRoot, "shared"), nil); err == nil {
		t.Fatal("symlinked shared root was accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "storage")); !os.IsNotExist(err) {
		t.Fatalf("shared data escaped the managed root: %v", err)
	}

	if err := os.RemoveAll(managedRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, managedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := provisioner.pathsFor(spec, 22); err == nil {
		t.Fatal("symlinked application root was accepted")
	}
}

func TestPHPWorkerReconcileBoundsDefinitionsAndRedactsServiceErrors(t *testing.T) {
	runner := &scriptedPHPAppRunner{fail: "systemctl restart nakpanel-php-worker@18.service"}
	provisioner, spec := newPHPApplicationTestProvisioner(t, runner, nil)
	secret := "secret-value"
	_, err := provisioner.DeployPHPRelease(context.Background(), types.DeployPHPReleaseReq{
		Application: spec,
		Deployment:  types.PHPDeployment{ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, RequestedRevision: "main"},
		Environment: []types.PHPEnvironmentPayload{{Name: "APP_KEY", Secret: secret}},
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("worker error was not safely redacted: %v", err)
	}

	workers := make([]types.PHPWorker, 65)
	for index := range workers {
		workers[index] = types.PHPWorker{
			ID: int64(index + 1), SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID,
			Name: fmt.Sprintf("worker-%d", index+1), Script: "artisan", Processes: 1, DesiredState: "running",
		}
	}
	if _, err := provisioner.reconcileWorkerRecords(context.Background(), spec, workers, nil, "/env", "/release"); err == nil {
		t.Fatal("more than 64 worker definitions were accepted")
	}
}

func TestPHPWorkersReloadBeforeRestartAndShareOneAggregateSlice(t *testing.T) {
	runner := &scriptedPHPAppRunner{}
	provisioner, spec := newPHPApplicationTestProvisioner(t, runner, nil)
	first := types.DeployPHPReleaseReq{Application: spec, Deployment: types.PHPDeployment{
		ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, RequestedRevision: "main",
	}}
	if _, err := provisioner.DeployPHPRelease(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	spec.DesiredRevision++
	second := types.DeployPHPReleaseReq{Application: spec, Deployment: types.PHPDeployment{
		ID: 23, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, RequestedRevision: "main", PreviousDeploymentID: 22,
	}}
	if _, err := provisioner.DeployPHPRelease(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	secondPaths, err := provisioner.pathsFor(spec, 23)
	if err != nil {
		t.Fatal(err)
	}
	workerUnit := filepath.Join(provisioner.systemdUnitDir, "nakpanel-php-worker@18.service")
	replicaUnit := filepath.Join(provisioner.systemdUnitDir, "nakpanel-php-worker@18-2.service")
	for _, path := range []string{workerUnit, replicaUnit} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), filepath.Join(secondPaths.release, "artisan")) ||
			!strings.Contains(string(data), "Slice=nakpanel-php-app-9.slice") || strings.Contains(string(data), "MemoryMax=") {
			t.Fatalf("worker unit does not use the new release and aggregate slice:\n%s", data)
		}
	}
	sliceData, err := os.ReadFile(filepath.Join(provisioner.systemdUnitDir, "nakpanel-php-app-9.slice"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MemoryMax=512M", "CPUQuota=100%", "TasksMax=64"} {
		if strings.Count(string(sliceData), want) != 1 {
			t.Fatalf("aggregate slice omitted or duplicated %q:\n%s", want, sliceData)
		}
	}
	reloadAt, restartAt := -1, -1
	for index, call := range runner.calls {
		if call == "systemctl daemon-reload" {
			reloadAt = index
		}
		if call == "systemctl restart nakpanel-php-worker@18.service" {
			restartAt = index
			break
		}
	}
	if reloadAt < 0 || restartAt < 0 || reloadAt > restartAt {
		t.Fatalf("worker unit was not loaded before restart:\n%s", strings.Join(runner.calls, "\n"))
	}
}

func TestPHPWorkerCleanupMatchesExactIDs(t *testing.T) {
	runner := &scriptedPHPAppRunner{}
	provisioner, spec := newPHPApplicationTestProvisioner(t, runner, nil)
	for _, name := range []string{
		"nakpanel-php-worker@1.service",
		"nakpanel-php-worker@1-2.service",
		"nakpanel-php-worker@10.service",
		"nakpanel-php-worker@11-2.service",
	} {
		if err := os.WriteFile(filepath.Join(provisioner.systemdUnitDir, name), []byte("unit"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := pWriteWorkerStateForTest(provisioner, spec.ApplicationID, 1); err != nil {
		t.Fatal(err)
	}
	if err := provisioner.stopApplicationWorkers(context.Background(), spec.ApplicationID, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{"nakpanel-php-worker@1.service", "nakpanel-php-worker@1-2.service"} {
		if _, err := os.Stat(filepath.Join(provisioner.systemdUnitDir, removed)); !os.IsNotExist(err) {
			t.Fatalf("worker %s was not removed: %v", removed, err)
		}
	}
	for _, retained := range []string{"nakpanel-php-worker@10.service", "nakpanel-php-worker@11-2.service"} {
		if _, err := os.Stat(filepath.Join(provisioner.systemdUnitDir, retained)); err != nil {
			t.Fatalf("unrelated worker %s was removed: %v", retained, err)
		}
	}
}

func pWriteWorkerStateForTest(provisioner *PHPApplicationProvisioner, applicationID, workerID int64) error {
	return provisioner.writeWorkerState(applicationID, map[int64]struct{}{workerID: {}})
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestExportGitRevisionUsesExactImmutableRevisionAndRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		cmd := append([]string{"-C", work}, args...)
		if output, err := (ExecRunner{}).Run(context.Background(), "git", cmd...); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}
	run("init", "-q")
	run("config", "user.email", "test@example.test")
	run("config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(work, "index.php"), []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "index.php")
	run("commit", "-qm", "first")
	first, err := (ExecRunner{}).Run(context.Background(), "git", "-C", work, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "index.php"), []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("commit", "-qam", "second")
	if output, err := (ExecRunner{}).Run(context.Background(), "git", "clone", "-q", "--bare", work, repo); err != nil {
		t.Fatalf("clone: %v: %s", err, output)
	}
	target := filepath.Join(root, "release")
	if err := exportGitRevision(context.Background(), ExecRunner{}, repo, strings.TrimSpace(string(first)), target); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(target, "index.php"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first" {
		t.Fatalf("exported %q, want first", got)
	}
	if _, err := os.Stat(filepath.Join(target, ".git")); !os.IsNotExist(err) {
		t.Fatalf(".git exported: %v", err)
	}

	badTar := filepath.Join(root, "bad.tar")
	if err := writeSymlinkTar(badTar); err != nil {
		t.Fatal(err)
	}
	if err := extractPHPReleaseTar(badTar, filepath.Join(root, "bad")); err == nil {
		t.Fatal("symlink archive accepted")
	}
}
