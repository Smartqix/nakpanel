package ops

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestGitKeyPreparationDoesNotChangeRepositoryOrHostTrust(t *testing.T) {
	p, _, req, _ := workspaceGitFixture(t)
	root := filepath.Join(p.gitRoot, "site-1")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	hostFile := filepath.Join(root, "known_hosts")
	if err := os.WriteFile(hostFile, []byte("trusted-host"), 0600); err != nil {
		t.Fatal(err)
	}
	req.Action, req.RepositoryID, req.OperationRevision, req.Mode = "key", 0, 0, "remote"
	req.RemoteURL, req.KnownHostKey = "git@github.com:team/website.git", ""
	result, err := p.EnsureGitRepository(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.DeployPublicKey == "" || result.FetchedRevision != "" || result.DeployedRevision != "" {
		t.Fatalf("unexpected key result: %+v", result)
	}
	raw, err := os.ReadFile(hostFile)
	if err != nil || string(raw) != "trusted-host" {
		t.Fatal("key preparation replaced host trust")
	}
	if _, err := os.Stat(filepath.Join(root, "remote.git")); !os.IsNotExist(err) {
		t.Fatal("key preparation created repository")
	}
}

type workspaceGitRunner struct {
	calls    []string
	revision string
	tree     string
}

type failingPublishRunner struct {
	workspaceGitRunner
	target string
}

func (r *failingPublishRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "runuser" && len(args) > 3 {
		command := args[3]
		rest := args[4:]
		if command == "cp" || command == "rm" {
			return exec.CommandContext(ctx, command, rest...).CombinedOutput()
		}
		if strings.Contains(strings.Join(args, " "), " checkout ") {
			_ = os.WriteFile(filepath.Join(r.target, "index.php"), []byte("partial publication"), 0600)
			return nil, errors.New("forced checkout failure")
		}
	}
	return r.workspaceGitRunner.Run(ctx, name, args...)
}

func TestGitFailedFirstPublicationRestoresActualOriginalFile(t *testing.T) {
	p, base, req, target := workspaceGitFixture(t)
	if _, err := p.EnsureGitRepository(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target, 0750); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(target, "index.php")
	if err := os.WriteFile(file, []byte("original untracked file"), 0640); err != nil {
		t.Fatal(err)
	}
	r := &failingPublishRunner{workspaceGitRunner: *base, target: target}
	r.tree = "100644 blob " + strings.Repeat("b", 40) + "\tindex.php\x00"
	p.runner = r
	req.Action = "deploy"
	req.Revision = r.revision
	req.ConfirmOverwrite = true
	if _, err := p.EnsureGitRepository(context.Background(), req); err == nil {
		t.Fatal("expected checkout failure")
	}
	data, err := os.ReadFile(file)
	if err != nil || string(data) != "original untracked file" {
		t.Fatalf("original file lost: %q %v", data, err)
	}
}

func TestGitWorkspaceRejectsStaleOperationAndChangedRemote(t *testing.T) {
	p, r, req, _ := workspaceGitFixture(t)
	req.OperationRevision = 8
	if _, err := p.EnsureGitRepository(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	req.OperationRevision = 7
	if _, err := p.EnsureGitRepository(context.Background(), req); err == nil {
		t.Fatal("accepted stale operation")
	}
	req.OperationRevision = 9
	req.Action = "preview"
	req.Revision = r.revision
	req.Branch = "different"
	if _, err := p.EnsureGitRepository(context.Background(), req); err == nil {
		t.Fatal("accepted fetched SHA after branch changed")
	}
}

func TestGitDisconnectRejectsManagedSymlink(t *testing.T) {
	p, _, req, _ := workspaceGitFixture(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(p.gitRoot, "site-1")); err != nil {
		t.Fatal(err)
	}
	req.Action = "disconnect"
	if _, err := p.EnsureGitRepository(context.Background(), req); err == nil {
		t.Fatal("accepted symlink repository root")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("disconnect affected symlink target")
	}
}

func TestGitOperationReplayPreservesRollbackPointer(t *testing.T) {
	p, r, req, _ := workspaceGitFixture(t)
	req.OperationRevision = 1
	if _, err := p.EnsureGitRepository(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(p.gitRoot, "site-1")
	before := strings.Repeat("b", 40)
	if err := os.WriteFile(filepath.Join(root, "deployed-revision"), []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	req.OperationRevision = 2
	req.Action = "deploy"
	req.Revision = r.revision
	for i := 0; i < 2; i++ {
		result, err := p.EnsureGitRepository(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if result.PreviousRevision != before {
			t.Fatal("deploy replay lost prior revision")
		}
	}
	req.OperationRevision = 3
	req.Action = "rollback"
	req.Revision = ""
	for i := 0; i < 2; i++ {
		result, err := p.EnsureGitRepository(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if result.DeployedRevision != before {
			t.Fatal("rollback replay changed target")
		}
	}
}

func TestGitOutputBufferIsBounded(t *testing.T) {
	cancelled := false
	b := &gitOutputBuffer{cancel: func() { cancelled = true }}
	input := make([]byte, 9<<20)
	n, err := b.Write(input)
	if err != nil || n != len(input) || b.Len() != 8<<20 || !cancelled || !b.exceeded {
		t.Fatal("output budget not enforced")
	}
}

func (r *workspaceGitRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	switch {
	case strings.Contains(call, " cat -- ") && strings.HasSuffix(call, "deploy_key.pub"):
		return []byte("ssh-ed25519 YWJj test-key"), nil
	case strings.Contains(call, " rev-parse "):
		return []byte(r.revision), nil
	case strings.Contains(call, " ls-tree "):
		return []byte(r.tree), nil
	case strings.Contains(call, " for-each-ref "):
		return []byte("main\nfeature/test\n"), nil
	case strings.Contains(call, " log "):
		return []byte(r.revision + "\x00Initial commit\x00Author\x002026-01-01T00:00:00Z\n"), nil
	}
	return nil, nil
}
func workspaceGitFixture(t *testing.T) (*HostingToolkitProvisioner, *workspaceGitRunner, types.EnsureGitRepositoryReq, string) {
	t.Helper()
	runner := &workspaceGitRunner{revision: strings.Repeat("a", 40)}
	home := t.TempDir()
	root := t.TempDir()
	p := NewHostingToolkitProvisioner(HostingToolkitOptions{Runner: runner, HomeRoot: home, GitRoot: root})
	req := types.EnsureGitRepositoryReq{RepositoryID: 1, SiteID: 1, Username: "siteusr", Domain: "example.test", Mode: "hosted", Branch: "main", DeployTarget: ".", State: "active", Action: "fetch"}
	return p, runner, req, filepath.Join(home, "siteusr", "domains", "example.test", "public_html")
}
func TestGitWorkspaceFetchNeverCreatesPublishedDirectory(t *testing.T) {
	p, r, req, target := workspaceGitFixture(t)
	result, err := p.EnsureGitRepository(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.FetchedRevision != r.revision || len(result.Commits) != 1 {
		t.Fatalf("unexpected result %+v", result)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("fetch touched published directory")
	}
	for _, call := range r.calls {
		if strings.Contains(call, " checkout ") {
			t.Fatal("fetch checked out content")
		}
	}
}
func TestGitWorkspaceRequiresFetchedImmutableSHA(t *testing.T) {
	p, _, req, _ := workspaceGitFixture(t)
	for _, sha := range []string{"main", strings.Repeat("a", 41), strings.Repeat("b", 40)} {
		req.Action = "deploy"
		req.Revision = sha
		if _, err := p.EnsureGitRepository(context.Background(), req); err == nil {
			t.Fatalf("accepted %s", sha)
		}
	}
}
func TestGitWorkspaceConflictsAndDisconnectPreserveContent(t *testing.T) {
	p, r, req, target := workspaceGitFixture(t)
	if _, err := p.EnsureGitRepository(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target, 0750); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(target, "index.php")
	if err := os.WriteFile(file, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	r.tree = "100644 blob " + strings.Repeat("b", 40) + "\tindex.php\x00"
	req.Action = "deploy"
	req.Revision = r.revision
	result, err := p.EnsureGitRepository(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "conflicts" || len(result.Conflicts) != 1 {
		t.Fatalf("expected conflict: %+v", result)
	}
	req.Action = "disconnect"
	if _, err := p.EnsureGitRepository(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil || string(data) != "existing" {
		t.Fatal("disconnect removed published files")
	}
}
func TestGitWorkspaceRejectsSymlinkAndPreservesUploadsOnRollback(t *testing.T) {
	p, r, req, target := workspaceGitFixture(t)
	if _, err := p.EnsureGitRepository(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target, 0750); err != nil {
		t.Fatal(err)
	}
	upload := filepath.Join(target, "upload.jpg")
	if err := os.WriteFile(upload, []byte("user-data"), 0600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(p.gitRoot, "site-1")
	previous := strings.Repeat("b", 40)
	if err := os.WriteFile(filepath.Join(root, "previous-revision"), []byte(previous), 0600); err != nil {
		t.Fatal(err)
	}
	req.Action = "rollback"
	result, err := p.EnsureGitRepository(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.DeployedRevision != previous {
		t.Fatal("wrong rollback revision")
	}
	if data, err := os.ReadFile(upload); err != nil || string(data) != "user-data" {
		t.Fatal("rollback touched uploads")
	}
	r.tree = "120000 blob " + r.revision + "\tlink\x00"
	req.Action = "preview"
	req.Revision = r.revision
	if _, err := p.EnsureGitRepository(context.Background(), req); err == nil {
		t.Fatal("accepted symlink tree")
	}
}
