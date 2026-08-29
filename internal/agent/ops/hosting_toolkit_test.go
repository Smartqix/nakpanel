package ops

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
	"golang.org/x/crypto/bcrypt"
)

type toolkitRunner struct {
	failName string
	calls    []string
}

func (r *toolkitRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name == r.failName {
		return []byte("forced failure"), errors.New("forced failure")
	}
	return nil, nil
}

type emptyHostedGitRunner struct {
	toolkitRunner
}

func (r *emptyHostedGitRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if strings.Contains(call, " rev-parse refs/heads/main") {
		return []byte("fatal: unknown revision"), errors.New("exit status 128")
	}
	if strings.Contains(call, " for-each-ref ") {
		return nil, nil
	}
	return nil, nil
}

func TestRunStagingOperationCopiesFilesAndCreatesRollbackPoint(t *testing.T) {
	home := t.TempDir()
	staging := t.TempDir()
	source := filepath.Join(home, "siteusr", "domains", "source.test", "public_html")
	target := filepath.Join(home, "siteusr", "domains", "target.test", "public_html")
	for _, path := range []string{source, target} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "index.txt"), []byte("source"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "index.txt"), []byte("target"), 0o640); err != nil {
		t.Fatal(err)
	}
	runner := &toolkitRunner{}
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{HomeRoot: home, StagingRoot: staging, Runner: runner})
	result, err := provisioner.RunStagingOperation(context.Background(), types.RunStagingOperationReq{
		OperationID: 1, SourceSiteID: 10, TargetSiteID: 20, Username: "siteusr",
		SourceDomain: "source.test", TargetDomain: "target.test", Direction: "copy_to_staging",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.SnapshotPath == "" || !strings.HasPrefix(result.SnapshotPath, staging+string(filepath.Separator)) {
		t.Fatalf("snapshot path = %q", result.SnapshotPath)
	}
	got, err := os.ReadFile(filepath.Join(target, "index.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "source" {
		t.Fatalf("target content = %q", got)
	}
}

func TestRunStagingOperationRetryUsesDistinctRollbackPoint(t *testing.T) {
	home := t.TempDir()
	staging := t.TempDir()
	source := filepath.Join(home, "siteusr", "domains", "source.test", "public_html")
	target := filepath.Join(home, "siteusr", "domains", "target.test", "public_html")
	for _, path := range []string{source, target} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "index.txt"), []byte("source"), 0o640); err != nil {
		t.Fatal(err)
	}
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{HomeRoot: home, StagingRoot: staging, Runner: &toolkitRunner{}})
	request := types.RunStagingOperationReq{
		OperationID: 1, SourceSiteID: 10, TargetSiteID: 20, Username: "siteusr",
		SourceDomain: "source.test", TargetDomain: "target.test", Direction: "copy_to_staging",
	}
	first, err := provisioner.RunStagingOperation(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provisioner.RunStagingOperation(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.SnapshotPath == second.SnapshotPath {
		t.Fatalf("staging retry reused rollback point %q", first.SnapshotPath)
	}
}

func TestPruneStagingSnapshotsRetainsConfiguredRollbackPoints(t *testing.T) {
	root := t.TempDir()
	for attempt := 1; attempt <= 5; attempt++ {
		path := filepath.Join(root, fmt.Sprintf("site-20-operation-1-%d.tar.gz", attempt))
		if err := os.WriteFile(path, []byte("snapshot"), 0o600); err != nil {
			t.Fatal(err)
		}
		timestamp := time.Unix(int64(attempt), 0)
		if err := os.Chtimes(path, timestamp, timestamp); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneStagingSnapshots(root, 20, 4); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("retained rollback points = %d, want 4", len(entries))
	}
}

func TestRunStagingOperationRollsFilesBackAfterFailure(t *testing.T) {
	home := t.TempDir()
	source := filepath.Join(home, "siteusr", "domains", "source.test", "public_html")
	target := filepath.Join(home, "siteusr", "domains", "target.test", "public_html")
	for _, path := range []string{source, target} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(source, "index.txt"), []byte("new"), 0o640)
	_ = os.WriteFile(filepath.Join(target, "index.txt"), []byte("original"), 0o640)
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{
		HomeRoot: home, StagingRoot: t.TempDir(), Runner: &toolkitRunner{failName: "chown"},
	})
	_, err := provisioner.RunStagingOperation(context.Background(), types.RunStagingOperationReq{
		OperationID: 2, SourceSiteID: 10, TargetSiteID: 20, Username: "siteusr",
		SourceDomain: "source.test", TargetDomain: "target.test", Direction: "promote",
	})
	if err == nil {
		t.Fatal("expected ownership failure")
	}
	got, readErr := os.ReadFile(filepath.Join(target, "index.txt"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "original" {
		t.Fatalf("rollback content = %q", got)
	}
}

func TestRunStagingOperationFailsClosedWhenDatabaseSizeIsUnknown(t *testing.T) {
	home := t.TempDir()
	source := filepath.Join(home, "siteusr", "domains", "source.test", "public_html")
	target := filepath.Join(home, "siteusr", "domains", "target.test", "public_html")
	for _, path := range []string{source, target} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	original := []byte("leave me unchanged")
	if err := os.WriteFile(filepath.Join(target, "index.txt"), original, 0o640); err != nil {
		t.Fatal(err)
	}
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{
		HomeRoot: home, StagingRoot: t.TempDir(), Runner: &toolkitRunner{failName: "mariadb"},
	})
	_, err := provisioner.RunStagingOperation(context.Background(), types.RunStagingOperationReq{
		OperationID: 3, SourceSiteID: 10, TargetSiteID: 20, Username: "siteusr",
		SourceDomain: "source.test", TargetDomain: "target.test", Direction: "promote",
		Databases: []types.StagingDatabaseCopy{{SourceName: "source_db", TargetName: "target_db"}},
	})
	if err == nil || !strings.Contains(err.Error(), "measure database rollback capacity") {
		t.Fatalf("RunStagingOperation error = %v", err)
	}
	got, readErr := os.ReadFile(filepath.Join(target, "index.txt"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != string(original) {
		t.Fatalf("target changed before capacity was known: %q", got)
	}
}

func TestAddStagingCapacityRejectsOverflow(t *testing.T) {
	if _, err := addStagingCapacity(1<<62, 1<<62); err == nil {
		t.Fatal("overflowing staging capacity was accepted")
	}
	if got, err := addStagingCapacity(10, 20, 30); err != nil || got != 60 {
		t.Fatalf("addStagingCapacity = %d, %v", got, err)
	}
	if _, err := stagingAvailableCapacity(^uint64(0), 4096); err == nil {
		t.Fatal("overflowing available capacity was accepted")
	}
	if got, err := stagingAvailableCapacity(10, 4096); err != nil || got != 40960 {
		t.Fatalf("stagingAvailableCapacity = %d, %v", got, err)
	}
}

func TestSiteContentLocksSerializeGitAndStagingMutations(t *testing.T) {
	siteContentLocks = sync.Map{}
	unlock := lockSiteContentMutations(9002)
	acquired := make(chan struct{})
	go func() {
		release := lockSiteContentMutations(9001, 9002)
		close(acquired)
		release()
	}()
	select {
	case <-acquired:
		t.Fatal("overlapping site mutation acquired the lock early")
	case <-time.After(30 * time.Millisecond):
	}
	unlock()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("overlapping site mutation did not acquire the released lock")
	}
}

type gitRollbackRunner struct {
	calls []string
}

func (r *gitRollbackRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if strings.Contains(call, " diff ") && strings.Contains(call, "--diff-filter=A") {
		return []byte("new-only.txt\x00"), nil
	}
	return nil, nil
}

func TestRollbackGitDeploymentRemovesNewFilesAndRestoresPriorRevision(t *testing.T) {
	runner := &gitRollbackRunner{}
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{Runner: runner})
	previous := strings.Repeat("a", 40)
	revision := strings.Repeat("b", 40)
	if err := provisioner.rollbackGitDeployment("siteusr", "/repo.git", "/site", previous, revision); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, "diff --no-renames --name-only --diff-filter=A") ||
		!strings.Contains(joined, "rm -rf -- /site/new-only.txt") ||
		!strings.Contains(joined, "checkout -f "+previous+" -- .") {
		t.Fatalf("Git rollback did not restore the complete prior tree:\n%s", joined)
	}
}

type gitPreDeleteFailureRunner struct {
	calls   []string
	removes int
}

func (r *gitPreDeleteFailureRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if strings.Contains(call, "diff --no-renames --name-only --diff-filter=D") {
		return []byte("first.txt\x00second.txt\x00"), nil
	}
	if strings.Contains(call, " rm -rf -- ") {
		r.removes++
		if r.removes == 2 {
			return []byte("forced failure"), errors.New("forced failure")
		}
	}
	return nil, nil
}

func TestPrepareGitDeploymentRestoresPriorRevisionAfterPartialDelete(t *testing.T) {
	runner := &gitPreDeleteFailureRunner{}
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{Runner: runner})
	previous := strings.Repeat("a", 40)
	revision := strings.Repeat("b", 40)
	err := provisioner.prepareGitDeployment(context.Background(), "siteusr", "/repo.git", "/site", previous, revision)
	if err == nil {
		t.Fatal("expected second stale-file removal to fail")
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, "checkout -f "+previous+" -- .") {
		t.Fatalf("partial pre-delete did not restore the prior revision:\n%s", joined)
	}
}

type valkeyRollbackRunner struct {
	calls         []string
	daemonReloads int
}

type valkeyStateFailureRunner struct{}

func (*valkeyStateFailureRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "systemctl" && len(args) > 0 && args[0] == "is-enabled" {
		return nil, errors.New("systemd unavailable")
	}
	return nil, nil
}

func TestValkeyStateInspectionFailsClosed(t *testing.T) {
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{Runner: &valkeyStateFailureRunner{}})
	if _, _, err := provisioner.valkeyUnitState(context.Background(), "nakpanel-valkey@77.service"); err == nil {
		t.Fatal("missing systemd state was treated as disabled")
	}
}

type valkeyFailedUnitRunner struct{}

func (*valkeyFailedUnitRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	switch call {
	case "systemctl is-enabled nakpanel-valkey@77.service":
		return []byte("enabled\n"), nil
	case "systemctl is-active nakpanel-valkey@77.service":
		return []byte("failed\n"), errors.New("exit status 3")
	default:
		return nil, nil
	}
}

func TestValkeyFailedUnitIsRecoverableObservedState(t *testing.T) {
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{Runner: &valkeyFailedUnitRunner{}})
	enabled, active, err := provisioner.valkeyUnitState(context.Background(), "nakpanel-valkey@77.service")
	if err != nil {
		t.Fatalf("failed unit must remain reconcilable: %v", err)
	}
	if !enabled || active {
		t.Fatalf("state = enabled %v, active %v; want enabled and inactive", enabled, active)
	}
}

func (r *valkeyRollbackRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if call == "systemctl is-enabled nakpanel-valkey@77.service" {
		return []byte("enabled\n"), nil
	}
	if call == "systemctl is-active nakpanel-valkey@77.service" {
		return []byte("inactive\n"), nil
	}
	if call == "systemctl daemon-reload" {
		r.daemonReloads++
		if r.daemonReloads == 1 {
			return []byte("forced failure"), errors.New("forced failure")
		}
	}
	return nil, nil
}

func TestValkeyRollbackPreservesStoppedEnabledState(t *testing.T) {
	root := t.TempDir()
	configRoot := filepath.Join(root, "config")
	unitRoot := filepath.Join(root, "units")
	runtimeRoot := filepath.Join(root, "runtime")
	base := filepath.Join(configRoot, "sub-77")
	if err := os.MkdirAll(base, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(unitRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		filepath.Join(base, "users.acl"):                      "old acl\n",
		filepath.Join(base, "valkey.conf"):                    "old config\n",
		filepath.Join(unitRoot, "nakpanel-valkey@77.service"): "old unit\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	runner := &valkeyRollbackRunner{}
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{
		ValkeyConfigRoot: configRoot, ValkeyRuntimeRoot: runtimeRoot, SystemdUnitDir: unitRoot,
		ValkeyImage: "registry.example.test/valkey@sha256:" + strings.Repeat("a", 64), Runner: runner,
	})
	provisioner.lookupUser = func(string) (*user.User, error) {
		return &user.User{Username: "npaccount", Uid: "1000", Gid: "1000"}, nil
	}
	_, err := provisioner.EnsureValkey(context.Background(), types.EnsureValkeyReq{
		SubscriptionID: 77, Username: "npaccount", State: "enabled",
		MemoryMB: 64, MaxClients: 20, CPUPercent: 25, ProcessLimit: 32,
		ACLHash: strings.Repeat("b", 64),
	})
	if err == nil {
		t.Fatal("expected Valkey daemon-reload failure")
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, "systemctl enable nakpanel-valkey@77.service") ||
		!strings.Contains(joined, "systemctl stop nakpanel-valkey@77.service") ||
		strings.Contains(joined, "systemctl restart nakpanel-valkey@77.service") {
		t.Fatalf("Valkey rollback changed the prior stopped/enabled state:\n%s", joined)
	}
}

func TestReadSiteLogBoundsOversizedLinesAndCursor(t *testing.T) {
	logRoot := t.TempDir()
	line := strings.Repeat("x", 2<<20) + "\n"
	path := filepath.Join(logRoot, "siteusr-example-test.access.log")
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{NginxLogRoot: logRoot})
	result, err := provisioner.ReadSiteLog(context.Background(), types.SiteLogRequest{
		SiteID: 1, Username: "siteusr", Domain: "example.test", Source: types.SiteLogNginxAccess,
		LineLimit: 10, ByteLimit: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.NextCursor != 4096 || !result.Truncated {
		t.Fatalf("bounded cursor = %d, truncated = %v", result.NextCursor, result.Truncated)
	}
	if len(result.Lines) != 1 || len(result.Lines[0]) > 4096 {
		t.Fatalf("oversized line escaped response bound: lines=%d bytes=%d", len(result.Lines), len(result.Lines[0]))
	}
}

func TestRenderNginxVHostIncludesStructuredControls(t *testing.T) {
	plan, err := NewSitePlan(types.CreateSiteReq{
		SiteID: 4, Username: "siteusr", Domain: "example.test", PHPVersion: "8.3",
		Limits: types.SiteResourceLimits{
			PreferredDomain: "www", RequestBodyLimitMB: 32, Compression: true,
			FastCGIMicrocache: true, RequestRatePerSecond: 5, RequestBurst: 10,
			MaxConnections: 20, ConnectTimeoutSeconds: 4, ReadTimeoutSeconds: 45,
			SecurityHeaderPreset: "balanced", AllowedCIDRs: "192.0.2.0/24",
			ErrorDocument404: "/errors/404.html", ErrorDocument50X: "/errors/50x.html",
		},
	}, SitePathConfig{HomeRoot: t.TempDir(), NginxAvailableDir: t.TempDir(), NginxEnabledDir: t.TempDir(), PHPFPMPoolDir: t.TempDir(), PHPRunDir: t.TempDir(), NginxConfDir: t.TempDir(), NginxCacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	rendered := RenderNginxVHost(plan)
	for _, marker := range []string{
		"server_name example.test www.example.test",
		"return 301 $scheme://www.example.test$request_uri",
		"client_max_body_size 32m",
		"allow 192.0.2.0/24",
		"deny all",
		"error_page 404 /errors/404.html",
		"fastcgi_cache " + plan.NginxCacheZone,
		`fastcgi_cache_key "$scheme$request_method$host$request_uri"`,
		"fastcgi_cache_methods GET HEAD",
		"fastcgi_no_cache $cookie_PHPSESSID $http_authorization",
		"limit_req zone=" + plan.NginxRateZone,
		"include " + plan.NginxProtectedConfig,
	} {
		if !strings.Contains(rendered, marker) {
			t.Errorf("nginx config missing %q:\n%s", marker, rendered)
		}
	}
}

func TestEnsureProtectedDirectoriesWritesBcryptFilesAndRollsBackInvalidCandidate(t *testing.T) {
	root := t.TempDir()
	hash, err := bcrypt.GenerateFromPassword([]byte("Correct-Horse-2026"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	runner := &toolkitRunner{}
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{NginxProtectedRoot: root, Runner: runner})
	request := types.EnsureProtectedDirectoriesReq{
		SiteID: 8, Username: "siteusr", Domain: "example.test",
		Directories: []types.EnsureProtectedDirectory{{ID: 3, Path: "private", Realm: "Members", Username: "member", PasswordHash: string(hash), Enabled: true}},
	}
	result, err := provisioner.EnsureProtectedDirectories(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(result.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "Correct-Horse") || strings.Contains(string(config), "location ^~") ||
		!strings.Contains(string(config), `location "/private/"`) ||
		!strings.Contains(string(config), `location ~ \.php$`) ||
		!strings.Contains(string(config), "fastcgi_pass unix:/run/nakpanel-php/site-8.sock") {
		t.Fatalf("unexpected protected-directory config: %s", config)
	}
	passwordFile := filepath.Join(filepath.Dir(result.ConfigPath), "directory-3.htpasswd")
	info, err := os.Stat(passwordFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("password file mode = %o, want 640", info.Mode().Perm())
	}

	runner.failName = "nginx"
	request.Directories[0].Path = "changed"
	if _, err := provisioner.EnsureProtectedDirectories(context.Background(), request); err == nil {
		t.Fatal("expected nginx validation failure")
	}
	config, err = os.ReadFile(result.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), `"/private/"`) || strings.Contains(string(config), `"/changed/"`) {
		t.Fatalf("failed candidate was not rolled back: %s", config)
	}
}

func TestGitRequestRejectsCredentialsAndUnpinnedSSH(t *testing.T) {
	base := types.EnsureGitRepositoryReq{
		RepositoryID: 1, SiteID: 2, Username: "siteusr", Domain: "example.test",
		Mode: "remote", RemoteURL: "ssh://git@example.test/repo.git", Branch: "main",
		DeployTarget: ".", State: "active",
	}
	if err := validateGitRepositoryRequest(base); err == nil {
		t.Fatal("expected missing host-key rejection")
	}
	base.RemoteURL = "https://user:secret@example.test/repo.git"
	if err := validateGitRepositoryRequest(base); err == nil {
		t.Fatal("expected credential-bearing URL rejection")
	}
	base.RemoteURL = "ssh://git:secret@example.test/repo.git"
	if err := validateGitRepositoryRequest(base); err == nil {
		t.Fatal("expected password-bearing SSH URL rejection")
	}
	base.RemoteURL = "ssh://git@example.test/repo.git"
	base.KnownHostKey = "example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"
	if err := validateGitRepositoryRequest(base); err != nil {
		t.Fatalf("valid pinned SSH repository rejected: %v", err)
	}
}

func TestEnsureHostedGitRepositoryUsesSearchOnlySharedRoot(t *testing.T) {
	root := t.TempDir()
	gitRoot := filepath.Join(root, "git")
	homeRoot := filepath.Join(root, "home")
	siteRoot := filepath.Join(homeRoot, "siteusr", "domains", "example.test", "public_html")
	if err := os.MkdirAll(siteRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{
		HomeRoot: homeRoot,
		GitRoot:  gitRoot,
		Runner:   &toolkitRunner{},
	})
	_, err := provisioner.EnsureGitRepository(context.Background(), types.EnsureGitRepositoryReq{
		RepositoryID: 1, SiteID: 2, Username: "siteusr", Domain: "example.test",
		Mode: "hosted", Branch: "main", DeployTarget: ".", State: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Stat(gitRoot)
	if err != nil {
		t.Fatal(err)
	}
	if got := rootInfo.Mode().Perm(); got != 0o711 {
		t.Fatalf("Git root mode = %o, want 711", got)
	}
	siteInfo, err := os.Stat(filepath.Join(gitRoot, "site-2"))
	if err != nil {
		t.Fatal(err)
	}
	if got := siteInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("site Git directory mode = %o, want 700", got)
	}
}

func TestEnsureAutomaticHostedGitAllowsRepositoryBeforeFirstPush(t *testing.T) {
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	siteRoot := filepath.Join(homeRoot, "siteusr", "domains", "example.test", "public_html")
	if err := os.MkdirAll(siteRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	runner := &emptyHostedGitRunner{}
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{
		HomeRoot: homeRoot, GitRoot: filepath.Join(root, "git"), Runner: runner,
	})
	result, err := provisioner.EnsureGitRepository(context.Background(), types.EnsureGitRepositoryReq{
		RepositoryID: 1, SiteID: 2, Username: "siteusr", Domain: "example.test",
		Mode: "hosted", Branch: "main", DeployTarget: ".", State: "active", Automatic: true, Deploy: true,
	})
	if err != nil {
		t.Fatalf("empty automatic hosted repository: %v", err)
	}
	if result.RepositoryPath == "" || result.Revision != "" {
		t.Fatalf("result = %#v", result)
	}
	if !slices.ContainsFunc(runner.calls, func(call string) bool {
		return strings.Contains(call, " for-each-ref ")
	}) {
		t.Fatalf("calls = %v; want empty-repository inspection", runner.calls)
	}
	if !slices.ContainsFunc(runner.calls, func(call string) bool {
		return strings.Contains(call, "symbolic-ref HEAD refs/heads/main")
	}) {
		t.Fatalf("calls = %v; want configured default branch", runner.calls)
	}
}

func TestEnsureManualRemoteGitDoesNotFetchBeforeDeployment(t *testing.T) {
	root := t.TempDir()
	gitRoot := filepath.Join(root, "git")
	homeRoot := filepath.Join(root, "home")
	siteRoot := filepath.Join(homeRoot, "siteusr", "domains", "example.test", "public_html")
	repositoryRoot := filepath.Join(gitRoot, "site-2")
	if err := os.MkdirAll(siteRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repositoryRoot, "deploy_key"), []byte("private-test-placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repositoryRoot, "deploy_key.pub"), []byte("ssh-ed25519 public-test-placeholder"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &toolkitRunner{}
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{
		HomeRoot: homeRoot, GitRoot: gitRoot, Runner: runner,
	})
	_, err := provisioner.EnsureGitRepository(context.Background(), types.EnsureGitRepositoryReq{
		RepositoryID: 1, SiteID: 2, Username: "siteusr", Domain: "example.test",
		Mode: "remote", RemoteURL: "ssh://git@example.test/repo.git", Branch: "main",
		KnownHostKey: "example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest",
		DeployTarget: ".", State: "active", Deploy: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, " clone ") || strings.Contains(call, " fetch ") ||
			strings.Contains(call, " checkout ") || strings.Contains(call, " rev-parse ") {
			t.Fatalf("manual repository performed deployment work: %s", call)
		}
	}
}

func TestRenderProFTPSRequiresTLSAndDisablesAnonymous(t *testing.T) {
	rendered := renderProFTPD(types.EnsureFTPSReq{
		TLSCertPath: "/etc/nakpanel/tls.crt", TLSKeyPath: "/etc/nakpanel/tls.key",
		PublicAddress: "192.0.2.10",
	}, "/etc/nakpanel/AuthUserFile", "TLSECCertificateFile /etc/nakpanel/tls.crt\nTLSECCertificateKeyFile /etc/nakpanel/tls.key")
	for _, marker := range []string{"LoadModule mod_tls.c", "LoadModule mod_ident.c", "IdentLookups off", "TLSRequired on", "PassivePorts 49152 49252", "MasqueradeAddress 192.0.2.10", "DenyAll", "AuthPAM off", "TLSECCertificateFile /etc/nakpanel/tls.crt"} {
		if !strings.Contains(rendered, marker) {
			t.Errorf("ProFTPD config missing %q", marker)
		}
	}
}

func TestProFTPDKeyDirectiveNamesFollowCertificateAlgorithm(t *testing.T) {
	certName, keyName, err := proFTPDKeyDirectiveNames(&ecdsa.PublicKey{})
	if err != nil || certName != "TLSECCertificateFile" || keyName != "TLSECCertificateKeyFile" {
		t.Fatalf("ECDSA directives = %q, %q, %v", certName, keyName, err)
	}
	certName, keyName, err = proFTPDKeyDirectiveNames(&rsa.PublicKey{})
	if err != nil || certName != "TLSRSACertificateFile" || keyName != "TLSRSACertificateKeyFile" {
		t.Fatalf("RSA directives = %q, %q, %v", certName, keyName, err)
	}
}

func TestScheduledPHPBinaryUsesSelectedSiteVersion(t *testing.T) {
	got, err := scheduledPHPBinary("8.3")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/usr/bin/php8.3" {
		t.Fatalf("scheduled PHP binary = %q, want /usr/bin/php8.3", got)
	}
	if _, err := scheduledPHPBinary("8.3;id"); err == nil {
		t.Fatal("unsafe PHP version was accepted")
	}
}

func TestRenderValkeyUnitAllowsOnlyPodmanStateAndSocketWrites(t *testing.T) {
	rendered := renderValkeyUnit(types.EnsureValkeyReq{
		SubscriptionID: 12,
		MemoryMB:       64,
		CPUPercent:     25,
		ProcessLimit:   64,
	}, "1200", "1200", "/etc/nakpanel/valkey/sub-12", "/run/nakpanel/valkey/sub-12", "valkey@example")
	for _, marker := range []string{
		"Type=notify",
		"Group=1200",
		"RuntimeDirectory=nakpanel/valkey/sub-12",
		"RuntimeDirectoryMode=0770",
		"--pull=never",
		"--rm --replace",
		"--sdnotify=conmon",
		"--network=none",
		"--user 1200:1200",
		"PrivateTmp=yes",
		"ProtectSystem=strict",
		"ReadWritePaths=/var/lib/containers -/run/containers -/run/libpod -/run/lock -/run/crun /run/nakpanel/valkey/sub-12",
		"MemoryMax=96M",
	} {
		if !strings.Contains(rendered, marker) {
			t.Fatalf("Valkey unit missing %q:\n%s", marker, rendered)
		}
	}
	if strings.Contains(rendered, "ExecStartPre=") {
		t.Fatalf("Valkey unit must not rely on ownership changes that systemd reapplies before ExecStart:\n%s", rendered)
	}
}

func TestValkeyApplicationACLAllowsHealthButDeniesAdministration(t *testing.T) {
	hash := strings.Repeat("a", 64)
	acl := renderValkeyACL(hash)
	for _, marker := range []string{"+@read", "+@write", "+ping", "-flushall", "-config", "-module", "-debug", "-monitor", "-shutdown", "-replicaof"} {
		if !strings.Contains(acl, marker) {
			t.Fatalf("Valkey ACL missing %q: %s", marker, acl)
		}
	}
}

func TestRenderProFTPDUnitAllowsOnlyValidatedAccountHomes(t *testing.T) {
	rendered := renderProFTPDUnit("/etc/nakpanel/proftpd.conf", "/home", []types.EnsureFTPSAccount{
		{Username: "npalpha", Enabled: true},
		{Username: "npbeta", SiteID: 12, Domain: "example.test", Enabled: true},
		{Username: "npdisabled", Enabled: false},
	})
	for _, marker := range []string{
		"ProtectHome=read-only",
		"ReadWritePaths=/run /var/log/proftpd /home/npalpha /home/npbeta/domains/example.test/public_html",
	} {
		if !strings.Contains(rendered, marker) {
			t.Fatalf("ProFTPD unit missing %q:\n%s", marker, rendered)
		}
	}
	if strings.Contains(rendered, "/home/npdisabled") {
		t.Fatalf("disabled account home is writable:\n%s", rendered)
	}
}

func TestEnsureFTPSDisabledDoesNotRequireProFTPD(t *testing.T) {
	configRoot := t.TempDir()
	unitRoot := t.TempDir()
	runner := &toolkitRunner{failName: "proftpd"}
	provisioner := NewHostingToolkitProvisioner(HostingToolkitOptions{
		FTPSConfigDir:  configRoot,
		SystemdUnitDir: unitRoot,
		FTPSService:    "nakpanel-proftpd.service",
		Runner:         runner,
	})
	result, err := provisioner.EnsureFTPS(context.Background(), types.EnsureFTPSReq{
		Revision: 1,
		State:    "suspended",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Fatal("a missing disabled FTPS service was reported as changed")
	}
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "proftpd ") {
			t.Fatalf("disabled FTPS invoked ProFTPD: %s", call)
		}
	}
}
