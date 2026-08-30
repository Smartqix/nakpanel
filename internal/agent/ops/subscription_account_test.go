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

type accountTestRunner struct{ calls []string }

func (r *accountTestRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name == "id" {
		return []byte("1201\n"), nil
	}
	return nil, nil
}

type accountTestUsers struct{ names []string }

func (u *accountTestUsers) EnsureUser(_ context.Context, name string) error {
	u.names = append(u.names, name)
	return nil
}

type accountTestOwnership struct{}

func (accountTestOwnership) ChownRecursive(context.Context, string, string) error { return nil }

type accountTestQuota struct {
	username, path string
	limit          int
}

func (q *accountTestQuota) ApplyUserQuota(_ context.Context, username, path string, limit int) error {
	q.username, q.path, q.limit = username, path, limit
	return nil
}

func validAccountPolicy() types.HostingPolicy {
	return types.HostingPolicy{
		SchemaVersion: 1,
		Resources:     types.HostingResourcePolicy{DiskMB: 1024, CPUPercent: 150, MemoryMB: 512, MaxTasks: 100},
		PHP:           types.HostingPHPPolicy{DefaultVersion: "8.3", AllowedVersions: []string{"8.3"}},
		Mail:          types.HostingMailPolicy{DMARCPolicy: "none"},
		DNS:           types.HostingDNSPolicy{Mode: "authoritative", DefaultTTL: 3600},
		Access:        types.HostingAccessPolicy{ShellMode: "sftp", SFTPOnly: true},
	}
}

func TestEnsureSubscriptionAccountCreatesSharedLayoutAndLimits(t *testing.T) {
	root := t.TempDir()
	units := filepath.Join(root, "units")
	home := filepath.Join(root, "homes", "npaccount")
	runner := &accountTestRunner{}
	users := &accountTestUsers{}
	quota := &accountTestQuota{}
	p := NewSubscriptionAccountProvisioner(SubscriptionAccountProvisionerOptions{
		HomeRoot: filepath.Join(root, "homes"), SystemdUnitDir: units,
		UserManager: users, Ownership: accountTestOwnership{}, DiskQuota: quota, Runner: runner,
	})
	req := types.EnsureSubscriptionAccountReq{
		SubscriptionID: 42, Username: "npaccount", HomePath: home, State: "active", Policy: validAccountPolicy(),
		Domains:        []types.SubscriptionDomain{{SiteID: 7, Domain: "example.test", DocumentRoot: filepath.Join(home, "domains", "example.test", "public_html"), State: "active", Policy: validAccountPolicy()}},
		SFTPIdentities: []types.SFTPAccessIdentity{{ID: 1, Name: "deploy", PublicKey: "ssh-ed25519 YWJjZA== deploy@test", RelativeRoot: "domains/example.test", Enabled: true}},
	}
	result, err := p.EnsureSubscriptionAccount(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.LinuxUID != 1201 || len(users.names) != 1 || quota.limit != 1024 {
		t.Fatalf("result=%#v users=%v quota=%#v", result, users.names, quota)
	}
	keys, err := os.ReadFile(filepath.Join(root, "ssh", "authorized_keys", "npaccount"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(keys), `restrict,command="internal-sftp -d /domains/example.test"`) {
		t.Fatalf("authorized_keys = %q", keys)
	}
	sshConfig, err := os.ReadFile(filepath.Join(root, "ssh", "sshd_config.d", "90-nakpanel-npaccount.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sshConfig), "ChrootDirectory "+home) ||
		!strings.Contains(string(sshConfig), "DisableForwarding yes") {
		t.Fatalf("sshd account config = %q", sshConfig)
	}
	slice, err := os.ReadFile(filepath.Join(units, "user-1201.slice.d", "50-nakpanel.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CPUQuota=150%", "MemoryMax=512M", "TasksMax=100"} {
		if !strings.Contains(string(slice), want) {
			t.Fatalf("slice missing %q: %s", want, slice)
		}
	}
	for _, path := range []string{home, filepath.Join(home, "domains"), filepath.Join(home, "domains", "example.test")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o711 {
			t.Fatalf("%s mode = %o, want 711 traversal-only anchor", path, got)
		}
	}
	for _, path := range []string{
		filepath.Join(home, ".wp-cli", "cache"),
		filepath.Join(home, ".cache", "composer"),
		filepath.Join(home, ".config", "composer"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("hosting tool directory %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Fatalf("%s mode = %o, want 700 account-private", path, got)
		}
	}
}

func TestEnsureSubscriptionAccountRejectsSymlinkedDomainRoot(t *testing.T) {
	root := t.TempDir()
	homeRoot := filepath.Join(root, "homes")
	home := filepath.Join(homeRoot, "npaccount")
	domains := filepath.Join(home, "domains")
	outside := filepath.Join(root, "outside")
	for _, dir := range []string{domains, outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(domains, "example.test")); err != nil {
		t.Fatal(err)
	}
	p := NewSubscriptionAccountProvisioner(SubscriptionAccountProvisionerOptions{
		HomeRoot: homeRoot, SystemdUnitDir: filepath.Join(root, "units"),
		UserManager: &accountTestUsers{}, Ownership: accountTestOwnership{},
		DiskQuota: &accountTestQuota{}, Runner: &accountTestRunner{},
	})
	req := types.EnsureSubscriptionAccountReq{
		SubscriptionID: 42, Username: "npaccount", HomePath: home, State: "active", Policy: validAccountPolicy(),
		Domains: []types.SubscriptionDomain{{
			SiteID: 7, Domain: "example.test",
			DocumentRoot: filepath.Join(domains, "example.test", "public_html"),
			State:        "active", Policy: validAccountPolicy(),
		}},
	}
	if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err == nil {
		t.Fatal("expected symlinked domain root to be rejected")
	}
	if _, err := os.Stat(filepath.Join(outside, "public_html")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside target was modified: %v", err)
	}
}

func TestValidateSubscriptionAccountRejectsEscapesAndInvalidKeys(t *testing.T) {
	root := "/srv/accounts"
	base := types.EnsureSubscriptionAccountReq{SubscriptionID: 1, Username: "npaccount", HomePath: root + "/npaccount", State: "active", Policy: validAccountPolicy()}
	tests := []types.EnsureSubscriptionAccountReq{
		func() types.EnsureSubscriptionAccountReq { r := base; r.HomePath = "/home/root"; return r }(),
		func() types.EnsureSubscriptionAccountReq {
			r := base
			r.Domains = []types.SubscriptionDomain{{Domain: "../bad", DocumentRoot: root + "/npaccount/domains/bad/public_html"}}
			return r
		}(),
		func() types.EnsureSubscriptionAccountReq {
			r := base
			r.SFTPIdentities = []types.SFTPAccessIdentity{{Name: "bad", PublicKey: "ssh-ed25519 bad\ncommand=x", Enabled: true}}
			return r
		}(),
		func() types.EnsureSubscriptionAccountReq {
			r := base
			r.SFTPIdentities = []types.SFTPAccessIdentity{{Name: "bad", PublicKey: "ssh-ed25519 YWJjZA==", RelativeRoot: "../../etc", Enabled: true}}
			return r
		}(),
	}
	for i, req := range tests {
		if err := ValidateSubscriptionAccountRequest(req, root); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

func TestApplyScheduledTasksRejectsUnitInjection(t *testing.T) {
	root := t.TempDir()
	p := NewSubscriptionAccountProvisioner(SubscriptionAccountProvisionerOptions{HomeRoot: root, SystemdUnitDir: filepath.Join(root, "units"), Runner: &accountTestRunner{}})
	err := p.ApplyScheduledTasks(context.Background(), types.ApplyScheduledTasksReq{SubscriptionID: 1, Username: "npaccount", HomePath: filepath.Join(root, "npaccount"), Tasks: []types.ScheduledTask{{ID: 1, Name: "bad\n[Service]", Schedule: "* * * * *", Command: "true", TimeoutSeconds: 10}}})
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestCronToCalendarUsesValidSystemdShape(t *testing.T) {
	tests := map[string]string{
		"0 2 * * *":     "*-*-* 2:0:00",
		"15 4 * * 1-5":  "Mon..Fri *-*-* 4:15:00",
		"30 6 1 1,7 *":  "*-1,7-1 6:30:00",
		"0 0 * * SUN,6": "Sun,Sat *-*-* 0:0:00",
	}
	for cron, want := range tests {
		got, err := cronToCalendar(cron)
		if err != nil || got != want {
			t.Fatalf("cronToCalendar(%q) = %q, %v; want %q", cron, got, err, want)
		}
	}
	for _, invalid := range []string{"*/5 * * * *", "0 2 1 * 1"} {
		if _, err := cronToCalendar(invalid); err == nil {
			t.Fatalf("cronToCalendar(%q) accepted unsupported semantics", invalid)
		}
	}
}

func TestApplyScheduledTasksRetiresLegacyTimersForRiverScheduling(t *testing.T) {
	root := t.TempDir()
	units := filepath.Join(root, "units")
	state := filepath.Join(root, "state")
	runner := &accountTestRunner{}
	p := NewSubscriptionAccountProvisioner(SubscriptionAccountProvisionerOptions{
		HomeRoot: root, SystemdUnitDir: units, TaskStateDir: state, Runner: runner,
	})
	req := types.ApplyScheduledTasksReq{
		SubscriptionID: 7, Username: "npaccount", HomePath: filepath.Join(root, "npaccount"),
		Tasks: []types.ScheduledTask{{ID: 41, Name: "daily", Schedule: "0 2 * * *", Command: "true", TimeoutSeconds: 30, Enabled: true}},
	}
	if err := p.ApplyScheduledTasks(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".service", ".timer"} {
		if _, err := os.Stat(filepath.Join(units, "nakpanel-task-41"+suffix)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("legacy task unit exists after River migration: %v", err)
		}
	}
	req.Tasks = nil
	if err := p.ApplyScheduledTasks(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".service", ".timer"} {
		if _, err := os.Stat(filepath.Join(units, "nakpanel-task-41"+suffix)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("removed task unit still exists: %v", err)
		}
	}
	if !strings.Contains(strings.Join(runner.calls, "\n"), "systemctl disable --now nakpanel-task-41.timer") {
		t.Fatalf("legacy timer was not disabled: %v", runner.calls)
	}
}

func TestCleanupLegacyHomesDeletesOnlyDirectChildren(t *testing.T) {
	root := t.TempDir()
	active := filepath.Join(root, "active")
	legacy := filepath.Join(root, "legacy")
	outside := filepath.Join(t.TempDir(), "outside")
	for _, path := range []string{active, legacy, outside} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	p := NewSubscriptionAccountProvisioner(SubscriptionAccountProvisionerOptions{HomeRoot: root})
	result, err := p.CleanupLegacyHomes(context.Background(), types.CleanupLegacyHomesReq{SubscriptionID: 1, ActiveHome: active, LegacyHomes: []string{legacy}})
	if err != nil || len(result.Deleted) != 1 {
		t.Fatalf("cleanup result=%#v err=%v", result, err)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy home still exists: %v", err)
	}
	for _, unsafe := range []string{active, outside, root} {
		if _, err := p.CleanupLegacyHomes(context.Background(), types.CleanupLegacyHomesReq{SubscriptionID: 1, ActiveHome: active, LegacyHomes: []string{unsafe}}); err == nil {
			t.Fatalf("unsafe path %q was accepted", unsafe)
		}
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CleanupLegacyHomes(context.Background(), types.CleanupLegacyHomesReq{SubscriptionID: 1, ActiveHome: active, LegacyHomes: []string{link}}); err == nil {
		t.Fatal("symlink legacy home was accepted")
	}
}

func TestCopyMigrationTreeRejectsNestedTargetSymlink(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	outside := filepath.Join(root, "outside")
	for _, path := range []string{filepath.Join(source, "assets"), target, outside} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "assets", "index.html"), []byte("new content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "index.html"), []byte("outside content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, "assets")); err != nil {
		t.Fatal(err)
	}

	if err := copyMigrationTree(source, target); err == nil {
		t.Fatal("nested target symlink was accepted")
	}
	content, err := os.ReadFile(filepath.Join(outside, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "outside content" {
		t.Fatalf("outside file was changed: %q", content)
	}
}

func TestEnsureNoSymlinkComponentsRejectsAccountPathEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "account")); err != nil {
		t.Fatal(err)
	}
	if err := ensureNoSymlinkComponents(root, filepath.Join(root, "account", "domains", "example.test", "public_html")); err == nil {
		t.Fatal("symlink account path was accepted")
	}
}
