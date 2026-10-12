package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

type teardownExitError int

func (e teardownExitError) Error() string { return "injected command exit" }
func (e teardownExitError) ExitCode() int { return int(e) }

type rootlessTeardownRunner struct {
	uid          string
	pause        bool
	missing      bool
	failKill     bool
	ignoreTERM   bool
	unitUsers    map[string]string
	loadedUnits  string
	failUnitStop bool
	failPodman   bool
	calls        [][]string
}

func (r *rootlessTeardownRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	switch name {
	case "runuser":
		if r.failPodman {
			return nil, errors.New("rootless environment already removed")
		}
	case "systemctl":
		if len(args) > 0 && args[0] == "list-units" && args[len(args)-1] == "nakpanel-app-*.service" {
			return []byte(r.loadedUnits), nil
		}
		if len(args) > 1 && args[0] == "show" && args[1] == "--property=User" {
			return []byte(r.unitUsers[args[len(args)-1]]), nil
		}
		if len(args) > 0 && args[0] == "disable" && r.failUnitStop {
			return nil, errors.New("injected unit stop failure")
		}
	case "id":
		if r.missing {
			return nil, teardownExitError(1)
		}
		return []byte(r.uid + "\n"), nil
	case "getent":
		return nil, teardownExitError(2)
	case "pgrep":
		if r.pause {
			return []byte("1379290\n"), nil
		}
		return nil, teardownExitError(1)
	case "pkill":
		if r.failKill {
			return nil, teardownExitError(2)
		}
		if !r.ignoreTERM || strings.Contains(strings.Join(args, " "), "KILL") {
			r.pause = false
		}
	case "userdel":
		if r.pause {
			return []byte("user currently used by pause process"), errors.New("user busy")
		}
		r.missing = true
	}
	return nil, nil
}

func TestTeardownMissingRootlessStateSkipsPodmanAndFinishes(t *testing.T) {
	runner := &rootlessTeardownRunner{uid: "990", pause: true, failPodman: true}
	p, req, paths := rootlessTeardownFixture(t, runner)
	req.Applications = []types.TeardownApplication{{ID: 29, Name: "wordpress"}}
	for _, path := range paths[1:] {
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.TeardownSubscription(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if call[0] == "runuser" {
			t.Fatal("missing rootless state was recreated by Podman")
		}
	}
}

func TestTeardownStopsOwnedOCIUnitsWithoutApplicationRecords(t *testing.T) {
	runner := &rootlessTeardownRunner{uid: "990", pause: true, unitUsers: map[string]string{
		"nakpanel-app-29-g4.service": "nps4\n",
		"nakpanel-app-29.service":    "nps4\n",
		"nakpanel-app-30-g2.service": "nps5\n",
	}, loadedUnits: "nakpanel-app-29-g4.service loaded active running\nnakpanel-app-30-g2.service loaded active running\n"}
	p, req, _ := rootlessTeardownFixture(t, runner)
	if err := os.MkdirAll(p.systemdUnitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{"nakpanel-app-29.service", "nakpanel-app-30-g2.service"} {
		if err := os.WriteFile(filepath.Join(p.systemdUnitDir, unit), []byte("[Service]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.TeardownSubscription(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	stopped := map[string]bool{}
	for _, call := range runner.calls {
		if len(call) > 3 && call[0] == "systemctl" && call[1] == "disable" {
			stopped[call[len(call)-1]] = true
		}
		if call[0] == "pkill" && (!stopped["nakpanel-app-29.service"] || !stopped["nakpanel-app-29-g4.service"]) {
			t.Fatal("UID killed before restarting OCI units stopped")
		}
	}
	if !stopped["nakpanel-app-29.service"] || !stopped["nakpanel-app-29-g4.service"] || stopped["nakpanel-app-30-g2.service"] {
		t.Fatalf("unbounded or incomplete OCI shutdown: %v", stopped)
	}
	if _, err := os.Stat(filepath.Join(p.systemdUnitDir, "nakpanel-app-30-g2.service")); err != nil {
		t.Fatal("other tenant unit removed")
	}
}

func TestTeardownOCIStopFailurePreservesAccount(t *testing.T) {
	runner := &rootlessTeardownRunner{uid: "990", pause: true, failUnitStop: true, unitUsers: map[string]string{"nakpanel-app-29-g4.service": "nps4"}, loadedUnits: "nakpanel-app-29-g4.service loaded active running\n"}
	p, req, paths := rootlessTeardownFixture(t, runner)
	if _, err := p.TeardownSubscription(context.Background(), req); err == nil {
		t.Fatal("OCI unit shutdown failure ignored")
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("failed OCI shutdown deleted account data")
		}
	}
	for _, call := range runner.calls {
		if call[0] == "pkill" || call[0] == "userdel" {
			t.Fatal("UID teardown bypassed restarting unit failure")
		}
	}
}

func TestTeardownOCIUsesDedicatedRootlessEnvironment(t *testing.T) {
	runner := &rootlessTeardownRunner{uid: "990"}
	p, req, _ := rootlessTeardownFixture(t, runner)
	req.Applications = []types.TeardownApplication{{ID: 29, Name: "wordpress"}}
	if _, err := p.TeardownSubscription(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, call := range runner.calls {
		if call[0] != "runuser" {
			continue
		}
		seen = true
		command := strings.Join(call, " ")
		for _, env := range []string{"-- env", "HOME=" + filepath.Join(p.containerStateRoot, "sub-4", "home"), "XDG_DATA_HOME=" + filepath.Join(p.containerStateRoot, "sub-4", "data"), "XDG_CONFIG_HOME=" + filepath.Join(p.containerStateRoot, "sub-4", "config"), "XDG_RUNTIME_DIR=" + filepath.Join(p.containerRuntimeRoot, "sub-4")} {
			if !strings.Contains(command, env) {
				t.Fatalf("Podman cleanup missing %s: %v", env, call)
			}
		}
	}
	if !seen {
		t.Fatal("active OCI cleanup missing")
	}
}

func rootlessTeardownFixture(t *testing.T, runner CommandRunner) (*SubscriptionTeardownProvisioner, types.TeardownSubscriptionReq, []string) {
	t.Helper()
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	home := filepath.Join(homeRoot, "nps4")
	state := filepath.Join(root, "containers")
	runtime := filepath.Join(root, "run")
	paths := []string{home, filepath.Join(state, "sub-4"), filepath.Join(runtime, "sub-4")}
	for _, path := range paths {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "sentinel"), []byte("private"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(state, "sub-5"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := NewSubscriptionTeardownProvisioner(SubscriptionTeardownOptions{HomeRoot: homeRoot, ContainerStateRoot: state, ContainerRuntimeRoot: runtime, SystemdUnitDir: filepath.Join(root, "units"), TaskStateDir: filepath.Join(root, "tasks"), SSHConfigDir: filepath.Join(root, "ssh"), AuthorizedKeysDir: filepath.Join(root, "keys"), Runner: runner})
	return p, types.TeardownSubscriptionReq{SubscriptionID: 4, Username: "nps4", HomePath: home}, paths
}

func TestTeardownStopsOrphanedRootlessPauseWithoutApplicationRecords(t *testing.T) {
	runner := &rootlessTeardownRunner{uid: "990", pause: true}
	p, req, paths := rootlessTeardownFixture(t, runner)
	if _, err := p.TeardownSubscription(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("account data remains: %s, %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(p.containerStateRoot, "sub-5")); err != nil {
		t.Fatal("another subscription's rootless state was removed")
	}
	seenKill, seenDelete := false, false
	for _, call := range runner.calls {
		if call[0] == "pkill" {
			if !strings.Contains(strings.Join(call, " "), "--uid 990") {
				t.Fatalf("shutdown is not UID bounded: %v", call)
			}
			seenKill = true
		}
		if call[0] == "userdel" {
			if !seenKill || strings.Join(call, " ") != "userdel -- nps4" {
				t.Fatalf("unsafe/early user deletion: %v", call)
			}
			seenDelete = true
		}
	}
	if !seenKill || !seenDelete {
		t.Fatalf("pause cleanup/user deletion missing: %v", runner.calls)
	}
}

func TestTeardownRejectsUnsafeUIDBeforeDeletion(t *testing.T) {
	for _, uid := range []string{"0", "-1", "4294967295", "not-a-uid", ""} {
		runner := &rootlessTeardownRunner{uid: uid}
		p, req, paths := rootlessTeardownFixture(t, runner)
		if _, err := p.TeardownSubscription(context.Background(), req); err == nil {
			t.Fatalf("unsafe UID %q accepted", uid)
		}
		for _, path := range paths {
			if _, err := os.Stat(path); err != nil {
				t.Fatal("identity failure removed account data")
			}
		}
		for _, call := range runner.calls {
			if call[0] == "pkill" || call[0] == "userdel" {
				t.Fatalf("unsafe UID reached destructive command: %v", call)
			}
		}
	}
}

func TestTeardownProcessShutdownEscalatesOnlyValidatedUID(t *testing.T) {
	runner := &rootlessTeardownRunner{uid: "990", pause: true, ignoreTERM: true}
	p, _, _ := rootlessTeardownFixture(t, runner)
	if err := p.stopAccountProcesses(context.Background(), "nps4", 990, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	var signals []string
	for _, call := range runner.calls {
		if call[0] == "pkill" {
			if strings.Join(call[3:], " ") != "--uid 990 --" {
				t.Fatalf("unbounded escalation: %v", call)
			}
			signals = append(signals, call[2])
		}
	}
	if strings.Join(signals, " ") != "TERM KILL" {
		t.Fatalf("unexpected escalation: %v", signals)
	}
}

func TestTeardownProcessShutdownRejectsChangedUID(t *testing.T) {
	runner := &rootlessTeardownRunner{uid: "991", pause: true}
	p, _, _ := rootlessTeardownFixture(t, runner)
	if err := p.stopAccountProcesses(context.Background(), "nps4", 990, time.Millisecond); err == nil {
		t.Fatal("changed UID accepted")
	}
	for _, call := range runner.calls {
		if call[0] != "id" {
			t.Fatalf("changed UID reached shutdown: %v", call)
		}
	}
}

func TestTeardownRejectsSymlinkedRootlessState(t *testing.T) {
	runner := &rootlessTeardownRunner{uid: "990"}
	p, req, _ := rootlessTeardownFixture(t, runner)
	path := filepath.Join(p.containerStateRoot, "sub-4")
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := p.TeardownSubscription(context.Background(), req); err == nil {
		t.Fatal("symlinked rootless state accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "secret")); err != nil {
		t.Fatal("outside state removed")
	}
	if _, err := os.Stat(req.HomePath); err != nil {
		t.Fatal("home removed before rootless validation")
	}
}

func TestTeardownRejectsUnsafeOCIFilesAndRoots(t *testing.T) {
	for _, kind := range []string{"unit-symlink", "unit-directory", "systemd-root-symlink", "state-root-relative", "runtime-root-slash"} {
		t.Run(kind, func(t *testing.T) {
			runner := &rootlessTeardownRunner{uid: "990", unitUsers: map[string]string{"nakpanel-app-29.service": "nps4"}}
			p, req, paths := rootlessTeardownFixture(t, runner)
			outside := t.TempDir()
			secret := filepath.Join(outside, "secret")
			if err := os.WriteFile(secret, []byte("private"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(p.systemdUnitDir, 0o755); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "unit-symlink":
				if err := os.Symlink(secret, filepath.Join(p.systemdUnitDir, "nakpanel-app-29.service")); err != nil {
					t.Fatal(err)
				}
			case "unit-directory":
				if err := os.Mkdir(filepath.Join(p.systemdUnitDir, "nakpanel-app-29.service"), 0o755); err != nil {
					t.Fatal(err)
				}
			case "systemd-root-symlink":
				if err := os.Remove(p.systemdUnitDir); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, p.systemdUnitDir); err != nil {
					t.Fatal(err)
				}
			case "state-root-relative":
				p.containerStateRoot = "relative"
			case "runtime-root-slash":
				p.containerRuntimeRoot = "/"
			}
			if _, err := p.TeardownSubscription(context.Background(), req); err == nil {
				t.Fatal("unsafe OCI filesystem accepted")
			}
			for _, path := range append(paths, secret) {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("guard lost data %s: %v", path, err)
				}
			}
			for _, call := range runner.calls {
				if call[0] == "pkill" || call[0] == "userdel" || call[0] == "runuser" || (call[0] == "systemctl" && call[1] == "disable") {
					t.Fatalf("unsafe path reached teardown: %v", call)
				}
			}
		})
	}
}

func TestTeardownProcessShutdownFailurePreservesDataAndUser(t *testing.T) {
	runner := &rootlessTeardownRunner{uid: "990", pause: true, failKill: true}
	p, req, paths := rootlessTeardownFixture(t, runner)
	if _, err := p.TeardownSubscription(context.Background(), req); err == nil {
		t.Fatal("shutdown failure ignored")
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("shutdown failure lost data: %s", path)
		}
	}
	for _, call := range runner.calls {
		if call[0] == "userdel" {
			t.Fatal("user deletion bypassed failed process shutdown")
		}
	}
}

func TestTeardownAbsentUserAndHomeStillRemovesRootlessState(t *testing.T) {
	runner := &rootlessTeardownRunner{uid: "990", missing: true}
	p, req, paths := rootlessTeardownFixture(t, runner)
	if err := os.RemoveAll(req.HomePath); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		if _, err := p.TeardownSubscription(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("retry left data: %s", path)
		}
	}
	for _, call := range runner.calls {
		if call[0] == "pkill" || call[0] == "userdel" {
			t.Fatal("absent user retry targeted a possibly reused UID")
		}
	}
}
