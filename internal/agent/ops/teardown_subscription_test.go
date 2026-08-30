package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestSubscriptionTeardownDeletesOnlyValidatedAccountHome(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "npaccount")
	if err := os.MkdirAll(filepath.Join(home, "domains", "example.test"), 0o750); err != nil {
		t.Fatal(err)
	}
	runner := &teardownRunner{outputs: map[string][]byte{
		"systemctl show --property=LoadState --value --no-pager nakpanel-php-fpm-candidate@17-42.service": []byte("loaded\n"),
	}}
	stateRoot := t.TempDir()
	systemdRoot := filepath.Join(stateRoot, "systemd")
	if err := os.MkdirAll(systemdRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{
		"nakpanel-php-fpm@17.service",
		"nakpanel-php-fpm-candidate@17-41.service",
		"nakpanel-php-worker@51.service",
		"nakpanel-php-worker@51-2.service",
		"nakpanel-php-app-31.slice",
		"nakpanel-task-23.service",
		"nakpanel-task-23.timer",
		"nakpanel-valkey@4.service",
	} {
		if err := os.WriteFile(filepath.Join(systemdRoot, unit), []byte("[Unit]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	phpStateRoot := filepath.Join(stateRoot, "php-applications")
	if err := os.MkdirAll(filepath.Join(phpStateRoot, "app-31", "candidate-41"), 0o700); err != nil {
		t.Fatal(err)
	}
	nginxCandidateRoot := t.TempDir()
	phpRunRoot := t.TempDir()
	for _, path := range []string{
		filepath.Join(nginxCandidateRoot, "90-nakpanel-php-candidate-17-41.conf"),
		filepath.Join(phpRunRoot, "candidate-17-41.sock"),
	} {
		if err := os.WriteFile(path, []byte("candidate"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := NewSubscriptionTeardownProvisioner(SubscriptionTeardownOptions{
		HomeRoot: root, SystemdUnitDir: systemdRoot, TaskStateDir: filepath.Join(stateRoot, "tasks"),
		ValkeyConfigRoot: filepath.Join(stateRoot, "valkey-config"), ValkeyRuntimeRoot: filepath.Join(stateRoot, "valkey-runtime"),
		PHPApplicationStateRoot: phpStateRoot,
		GitRoot:                 filepath.Join(stateRoot, "git"), StagingRoot: filepath.Join(stateRoot, "staging"), PodmanBinary: "/usr/bin/podman",
		Paths:  SitePathConfig{HomeRoot: root, NginxAvailableDir: t.TempDir(), NginxEnabledDir: t.TempDir(), NginxConfDir: nginxCandidateRoot, PHPFPMPoolDir: t.TempDir(), PHPFPMDedicatedRunDir: phpRunRoot},
		Runner: runner,
	})
	result, err := p.TeardownSubscription(context.Background(), types.TeardownSubscriptionReq{
		SubscriptionID: 4, Username: "npaccount", HomePath: home, SiteIDs: []int64{17}, Domains: []string{"example.test"},
		DatabaseNames: []string{"np_4_app"}, TaskIDs: []int64{23}, StagingOperationIDs: []int64{31},
		PHPApplicationIDs: []int64{31}, PHPWorkerIDs: []int64{51},
		PHPDeployments: []types.TeardownPHPDeployment{{SiteID: 17, DeploymentID: 42}},
		Applications:   []types.TeardownApplication{{ID: 29, Name: "wordpress"}}, ValkeyPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(home); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("home still exists: %v", err)
	}
	if len(result.Removed) == 0 {
		t.Fatal("missing per-resource progress")
	}
	if !runner.saw("userdel", "--", "npaccount") {
		t.Fatalf("userdel not bounded to account: %#v", runner.calls)
	}
	if !runner.saw("systemctl", "disable", "--now", "nakpanel-php-fpm@17.service") ||
		!runner.saw("systemctl", "daemon-reload") {
		t.Fatalf("dedicated PHP service was not removed: %#v", runner.calls)
	}
	for _, unit := range []string{"nakpanel-php-fpm-candidate@17-41.service", "nakpanel-php-worker@51.service", "nakpanel-php-worker@51-2.service"} {
		if !runner.saw("systemctl", "disable", "--now", unit) {
			t.Fatalf("managed PHP teardown did not stop %s: %#v", unit, runner.calls)
		}
		if _, statErr := os.Stat(filepath.Join(systemdRoot, unit)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("managed PHP unit %s remains: %v", unit, statErr)
		}
	}
	if !runner.saw("systemctl", "disable", "--now", "nakpanel-php-fpm-candidate@17-42.service") {
		t.Fatalf("loaded PHP candidate without a unit file was not stopped: %#v", runner.calls)
	}
	if _, statErr := os.Stat(filepath.Join(systemdRoot, "nakpanel-php-app-31.slice")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("managed PHP slice remains: %v", statErr)
	}
	for _, path := range []string{
		filepath.Join(phpStateRoot, "app-31"),
		filepath.Join(nginxCandidateRoot, "90-nakpanel-php-candidate-17-41.conf"),
		filepath.Join(phpRunRoot, "candidate-17-41.sock"),
	} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("managed PHP teardown artifact remains at %s: %v", path, statErr)
		}
	}
	if !runner.saw("runuser", "-u", "npaccount", "--", "/usr/bin/podman", "rm", "--force", "--ignore", "nakpanel-app-29") ||
		!runner.saw("runuser", "-u", "npaccount", "--", "/usr/bin/podman", "rm", "--force", "--ignore", "nakpanel-app-29-candidate") ||
		!runner.saw("runuser", "-u", "npaccount", "--", "/usr/bin/podman", "rm", "--force", "--ignore", "nakpanel-app-29-previous") ||
		!runner.saw("runuser", "-u", "npaccount", "--", "/usr/bin/podman", "rm", "--force", "--ignore", "nakpanel-29-wordpress") ||
		!runner.saw("systemctl", "disable", "--now", "nakpanel-valkey@4.service") {
		t.Fatalf("application or Valkey state was not removed: %#v", runner.calls)
	}
	if !runner.saw("systemctl", "disable", "--now", "nakpanel-task-23.timer") {
		t.Fatalf("scheduled task service was not removed: %#v", runner.calls)
	}
	if !runner.saw("setfacl", "-x", "u:npaccount", stateRoot) {
		t.Fatalf("subscription cache traversal ACL was not removed: %#v", runner.calls)
	}
}

func TestSubscriptionTeardownRejectsTraversalAndSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "npaccount")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	p := NewSubscriptionTeardownProvisioner(SubscriptionTeardownOptions{HomeRoot: root, Runner: &teardownRunner{}})
	requests := []types.TeardownSubscriptionReq{
		{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "..", "outside")},
		{SubscriptionID: 1, Username: "npaccount;rm", HomePath: filepath.Join(root, "npaccount;rm")},
		{SubscriptionID: 1, Username: "npaccount", HomePath: link},
		{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "npaccount"), Domains: []string{"../bad"}},
		{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "npaccount"), SiteIDs: []int64{1}},
		{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "npaccount"), SiteIDs: []int64{0}, Domains: []string{"example.test"}},
		{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "npaccount"), DatabaseNames: []string{"db;DROP"}},
		{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "npaccount"), TaskIDs: []int64{0}},
		{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "npaccount"), PHPApplicationIDs: []int64{0}},
		{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "npaccount"), PHPWorkerIDs: []int64{0}},
		{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "npaccount"), PHPDeployments: []types.TeardownPHPDeployment{{SiteID: 1}}},
		{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "npaccount"), Applications: []types.TeardownApplication{{ID: 1, Name: "../bad"}}},
	}
	for i, req := range requests {
		if _, err := p.TeardownSubscription(context.Background(), req); err == nil {
			t.Fatalf("unsafe request %d was accepted", i)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside directory changed: %v", err)
	}
}

func TestSubscriptionTeardownAcceptsConfirmedMissingACLOnRetry(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "npaccount")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	stateRoot := t.TempDir()
	runner := &teardownRunner{failName: "setfacl", outputs: map[string][]byte{
		"getfacl": []byte("user::rwx\ngroup::---\nother::---\n"),
	}}
	p := NewSubscriptionTeardownProvisioner(SubscriptionTeardownOptions{
		HomeRoot:          root,
		SystemdUnitDir:    filepath.Join(stateRoot, "systemd"),
		TaskStateDir:      filepath.Join(stateRoot, "tasks"),
		SSHConfigDir:      filepath.Join(stateRoot, "ssh-config"),
		AuthorizedKeysDir: filepath.Join(stateRoot, "authorized-keys"),
		ValkeyConfigRoot:  filepath.Join(stateRoot, "valkey-config"),
		ValkeyRuntimeRoot: filepath.Join(stateRoot, "valkey-runtime"),
		GitRoot:           filepath.Join(stateRoot, "git"),
		StagingRoot:       filepath.Join(stateRoot, "staging"),
		Runner:            runner,
	})
	_, err := p.TeardownSubscription(context.Background(), types.TeardownSubscriptionReq{
		SubscriptionID: 4, Username: "npaccount", HomePath: home, ValkeyPresent: true,
	})
	if err != nil {
		t.Fatalf("retry teardown failed for already-absent ACL: %v", err)
	}
	if !runner.saw("getfacl", "-cp", stateRoot) {
		t.Fatalf("ACL absence was not verified: %#v", runner.calls)
	}
}

func TestNormalizedPHPVersionDirectoriesIncludesInstalledFutureVersions(t *testing.T) {
	got := normalizedPHPVersionDirectories([]string{"8.3", "8.4", "8.2", "8.4", "../unsafe"})
	if strings.Join(got, ",") != "8.2,8.3,8.4" {
		t.Fatalf("normalized PHP versions = %v", got)
	}
}

type teardownRunner struct {
	calls    [][]string
	failName string
	outputs  map[string][]byte
}

func (r *teardownRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if name == r.failName {
		return []byte("forced failure"), errors.New("forced failure")
	}
	if output, exists := r.outputs[strings.Join(append([]string{name}, args...), " ")]; exists {
		return output, nil
	}
	return r.outputs[name], nil
}
func (r *teardownRunner) saw(want ...string) bool {
	for _, call := range r.calls {
		if len(call) != len(want) {
			continue
		}
		same := true
		for i := range call {
			same = same && call[i] == want[i]
		}
		if same {
			return true
		}
	}
	return false
}
