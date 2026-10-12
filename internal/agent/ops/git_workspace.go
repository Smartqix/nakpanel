package ops

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/nakroteck/nakpanel/internal/gitremote"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (p *HostingToolkitProvisioner) EnsureGitRepository(ctx context.Context, req types.EnsureGitRepositoryReq) (final types.EnsureGitRepositoryResult, finalErr error) {
	if req.Mode == "remote" && req.Action != "disconnect" {
		normalized, err := gitremote.Normalize(req.RemoteURL)
		if err != nil {
			return types.EnsureGitRepositoryResult{}, err
		}
		req.RemoteURL = normalized
	}
	check := req
	if req.Action == "disconnect" {
		check.Mode = "hosted"
	}
	if err := validateGitRepositoryRequest(check); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	unlock := lockSiteContentMutations(req.SiteID)
	defer unlock()
	root := filepath.Join(p.gitRoot, "site-"+strconv.FormatInt(req.SiteID, 10))
	if err := ensureNoSymlinkComponents(p.gitRoot, root); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	if req.Action == "key" {
		req.OperationRevision = 0
	}
	release, err := p.gitOperationFence(req)
	if err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	defer release()
	// Credential preparation is site-scoped and never changes repository intent,
	// host trust, operation revisions, or published content.
	if req.Action == "key" {
		if req.State != "active" || req.Mode != "remote" {
			return types.EnsureGitRepositoryResult{}, errors.New("key preparation requires an active remote site")
		}
		req.Deploy, req.Automatic = false, false
		result, err := p.ensureGitRepositoryLegacy(ctx, req)
		return types.EnsureGitRepositoryResult{DeployPublicKey: result.DeployPublicKey}, err
	}
	if req.OperationRevision > 0 {
		raw, _ := json.Marshal(req)
		identity := fmt.Sprintf("%x", sha256.Sum256(raw))
		cache := filepath.Join(p.gitRoot, "site-"+strconv.FormatInt(req.SiteID, 10)+"-result-"+strconv.FormatInt(req.OperationRevision, 10)+"-"+identity)
		if raw, err := os.ReadFile(cache); err == nil {
			var saved types.EnsureGitRepositoryResult
			if json.Unmarshal(raw, &saved) == nil {
				return saved, nil
			}
		}
		defer func() {
			if finalErr == nil {
				raw, err := json.Marshal(final)
				if err == nil {
					finalErr = writeFileAtomic(cache, raw, 0600)
				}
			}
		}()
	}
	if req.Action == "" {
		return p.ensureGitRepositoryLegacy(ctx, req)
	}
	if req.Action == "disconnect" {
		check := req
		check.Mode = "hosted"
		if err := validateGitRepositoryRequest(check); err != nil {
			return types.EnsureGitRepositoryResult{}, err
		}
		if err := os.RemoveAll(root); err != nil {
			return types.EnsureGitRepositoryResult{}, err
		}
		return types.EnsureGitRepositoryResult{Status: "disconnected", ConnectionStatus: "disconnected", Changed: true}, nil
	}
	if err := validateGitRepositoryRequest(req); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	if req.State != "active" && req.Action != "prepare" {
		return types.EnsureGitRepositoryResult{}, errors.New("Git operations require an active site")
	}
	if req.Action == "prepare" || req.Action == "fetch" {
		req.Deploy = req.Action == "fetch"
		result, err := p.ensureGitRepositoryLegacy(ctx, req)
		if err == nil && result.Status == "" {
			result.Status = "prepared"
			result.ConnectionStatus = "pending"
			if req.Action == "fetch" {
				result.Status = "fetched"
				result.ConnectionStatus = "connected"
				for _, name := range []string{"fetched-revision", "fetched-revisions"} {
					if writeErr := writeFileAtomic(filepath.Join(root, name), nil, 0600); writeErr != nil {
						return result, writeErr
					}
				}
			}
		}
		return result, err
	}
	if req.Action != "preview" && req.Action != "deploy" && req.Action != "rollback" {
		return types.EnsureGitRepositoryResult{}, errors.New("unsupported Git action")
	}
	repository := filepath.Join(root, "remote.git")
	if req.Mode == "hosted" {
		repository = filepath.Join(root, "repository.git")
	}
	if err := ensureNoSymlinkComponents(root, repository); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	current := readDeployedRevision(filepath.Join(root, "deployed-revision"))
	previous := readDeployedRevision(filepath.Join(root, "previous-revision"))
	revision := req.Revision
	if req.Action == "rollback" {
		if req.OperationRevision > 0 {
			plan := filepath.Join(p.gitRoot, "site-"+strconv.FormatInt(req.SiteID, 10)+"-rollback-"+strconv.FormatInt(req.OperationRevision, 10))
			if saved := readDeployedRevision(plan); saved != "" {
				if revision != "" && revision != saved {
					return types.EnsureGitRepositoryResult{}, errors.New("rollback operation revision was reused")
				}
				revision = saved
			} else {
				selected := revision
				if selected == "" {
					selected = previous
				}
				if !gitRevisionRE.MatchString(selected) {
					return types.EnsureGitRepositoryResult{}, errors.New("there is no previous deployment to roll back")
				}
				if err := writeFileAtomic(plan, []byte(selected+"\n"), 0600); err != nil {
					return types.EnsureGitRepositoryResult{}, err
				}
				revision = selected
			}
		}
		if revision != "" && revision == current {
			return types.EnsureGitRepositoryResult{Status: "rolled_back", ConnectionStatus: "connected", RepositoryPath: repository, Revision: current, DeployedRevision: current, PreviousRevision: previous}, nil
		}
		if revision != "" && revision != previous {
			return types.EnsureGitRepositoryResult{}, errors.New("rollback revision is not the previous deployment")
		}
		revision = previous
	}
	if !gitRevisionRE.MatchString(revision) {
		return types.EnsureGitRepositoryResult{}, errors.New("an immutable fetched commit SHA is required")
	}
	allowed, err := readGitState(filepath.Join(root, "fetched-revisions"), 64<<10)
	if err != nil && req.Action != "rollback" {
		return types.EnsureGitRepositoryResult{}, errors.New("fetch the repository before deploying")
	}
	if req.Action != "rollback" && !strings.Contains("\n"+string(allowed), "\n"+revision+"\n") {
		return types.EnsureGitRepositoryResult{}, errors.New("revision was not fetched for this repository")
	}
	if req.Action != "rollback" {
		source, err := readGitState(filepath.Join(root, "fetched-source"), 8192)
		if err != nil || string(source) != gitFetchSource(req) {
			return types.EnsureGitRepositoryResult{}, errors.New("repository settings changed; fetch again before deploying")
		}
	}
	siteRoot := filepath.Join(p.homeRoot, req.Username, "domains", req.Domain, "public_html")
	target := filepath.Join(siteRoot, filepath.Clean(req.DeployTarget))
	if saved, err := readGitState(filepath.Join(root, "deployed-target"), 4096); err == nil && string(saved) != target {
		return types.EnsureGitRepositoryResult{}, errors.New("deployment target changed; disconnect the repository before selecting a different target")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return types.EnsureGitRepositoryResult{}, err
	}
	if err := ensureNoSymlinkComponents(p.homeRoot, target); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	conflicts, err := p.gitDeploymentConflicts(ctx, req.Username, repository, target, current, revision)
	if err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	result := types.EnsureGitRepositoryResult{RepositoryPath: repository, Status: "previewed", ConnectionStatus: "connected", FetchedRevision: readDeployedRevision(filepath.Join(root, "fetched-revision")), DeployedRevision: current, PreviousRevision: previous, Conflicts: conflicts}
	if req.Action == "preview" {
		return result, nil
	}
	if len(conflicts) > 0 && !req.ConfirmOverwrite {
		result.Status = "conflicts"
		return result, nil
	}
	if _, err := p.runner.Run(ctx, "runuser", "-u", req.Username, "--", "mkdir", "-p", "-m", "750", "--", target); err != nil {
		return result, fmt.Errorf("prepare Git deployment directory: %w", err)
	}
	if err := ensureNoSymlinkComponents(p.homeRoot, target); err != nil {
		return result, err
	}
	undo, cleanup, err := p.snapshotGitDeployment(ctx, req.Username, repository, target, current, revision)
	if err != nil {
		return result, err
	}
	fail := func(cause error) (types.EnsureGitRepositoryResult, error) {
		restoreErr := undo()
		if restoreErr == nil {
			cleanup()
		}
		_ = writeFileAtomic(filepath.Join(root, "previous-revision"), []byte(previous+"\n"), 0600)
		_ = writeFileAtomic(filepath.Join(root, "deployed-revision"), []byte(current+"\n"), 0600)
		return result, errors.Join(cause, restoreErr)
	}
	if err := p.removeDeletedGitPaths(ctx, req.Username, repository, target, current, revision); err != nil {
		return fail(err)
	}
	if output, err := p.gitCommand(ctx, req.Username, repository, "--work-tree", target, "checkout", "-f", revision, "--", "."); err != nil {
		return fail(fmt.Errorf("deploy Git revision: %w: %s", err, strings.TrimSpace(string(output))))
	}
	nextPrevious := current
	if revision == current {
		nextPrevious = previous
	}
	if err := writeFileAtomic(filepath.Join(root, "previous-revision"), []byte(nextPrevious+"\n"), 0o600); err != nil {
		return fail(err)
	}
	if err := writeFileAtomic(filepath.Join(root, "deployed-revision"), []byte(revision+"\n"), 0o600); err != nil {
		return fail(err)
	}
	if err := writeFileAtomic(filepath.Join(root, "deployed-target"), []byte(target), 0o600); err != nil {
		return fail(err)
	}
	cleanup()
	result.Status = "deployed"
	if req.Action == "rollback" {
		result.Status = "rolled_back"
	}
	result.Revision = revision
	result.DeployedRevision = revision
	result.PreviousRevision = nextPrevious
	result.Changed = current != revision
	return result, nil
}

func (p *HostingToolkitProvisioner) gitCommand(ctx context.Context, username, repository string, args ...string) ([]byte, error) {
	base := []string{"-u", username, "--", "git", "--git-dir", repository}
	return p.runBoundedGit(ctx, "runuser", append(base, args...)...)
}

func (p *HostingToolkitProvisioner) gitFetchedResult(ctx context.Context, req types.EnsureGitRepositoryReq, repository, revision, key string) (types.EnsureGitRepositoryResult, error) {
	result := types.EnsureGitRepositoryResult{RepositoryPath: repository, Status: "fetched", ConnectionStatus: "connected", FetchedRevision: revision, DeployPublicKey: key, Changed: true}
	branches, err := p.gitCommand(ctx, req.Username, repository, "for-each-ref", "--count=100", "--format=%(refname:short)", "refs/heads/")
	if err != nil {
		return result, err
	}
	for _, branch := range strings.Split(strings.TrimSpace(string(branches)), "\n") {
		if branch != "" && len(result.Branches) < 100 {
			result.Branches = append(result.Branches, branch)
		}
	}
	commits, err := p.gitCommand(ctx, req.Username, repository, "log", "-50", "--format=%H%x00%s%x00%an%x00%aI", revision, "--")
	if err != nil {
		return result, err
	}
	allowed := revision + "\n"
	for _, line := range strings.Split(string(commits), "\n") {
		parts := strings.Split(line, "\x00")
		if len(parts) != 4 || !gitRevisionRE.MatchString(parts[0]) {
			continue
		}
		result.Commits = append(result.Commits, types.GitCommit{Revision: parts[0], Subject: gitBound(parts[1], 512), Author: gitBound(parts[2], 128), AuthoredAt: gitBound(parts[3], 64)})
		allowed += parts[0] + "\n"
		if len(result.Commits) == 50 {
			break
		}
	}
	root := filepath.Dir(repository)
	if err := writeFileAtomic(filepath.Join(root, "fetched-revisions"), []byte(allowed), 0o600); err != nil {
		return result, err
	}
	if err := writeFileAtomic(filepath.Join(root, "fetched-revision"), []byte(revision+"\n"), 0o600); err != nil {
		return result, err
	}
	if err := writeFileAtomic(filepath.Join(root, "fetched-source"), []byte(gitFetchSource(req)), 0o600); err != nil {
		return result, err
	}
	result.DeployedRevision = readDeployedRevision(filepath.Join(root, "deployed-revision"))
	result.PreviousRevision = readDeployedRevision(filepath.Join(root, "previous-revision"))
	return result, nil
}

func gitFetchSource(req types.EnsureGitRepositoryReq) string {
	return req.Mode + "\n" + req.RemoteURL + "\n" + req.Branch
}

func gitBound(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}

func (p *HostingToolkitProvisioner) gitTree(ctx context.Context, username, repository, revision string) (map[string]string, error) {
	files := map[string]string{}
	if revision == "" {
		return files, nil
	}
	output, err := p.gitCommand(ctx, username, repository, "ls-tree", "-r", "-z", revision, "--")
	if err != nil {
		return nil, err
	}
	for _, entry := range strings.Split(string(output), "\x00") {
		if entry == "" {
			continue
		}
		fields := strings.SplitN(entry, "\t", 2)
		if len(fields) != 2 {
			return nil, errors.New("invalid Git tree")
		}
		meta := strings.Fields(fields[0])
		if len(meta) != 3 || meta[1] != "blob" || (meta[0] != "100644" && meta[0] != "100755") {
			return nil, errors.New("Git deployment does not allow symlinks or submodules")
		}
		path := fields[1]
		clean := filepath.Clean(path)
		if clean != path || filepath.IsAbs(path) || clean == ".." || strings.HasPrefix(clean, "../") || clean == "." || strings.Contains(path, "\x00") {
			return nil, errors.New("unsafe Git tree path")
		}
		for _, part := range strings.Split(path, "/") {
			if strings.EqualFold(part, ".git") {
				return nil, errors.New("unsafe Git metadata path")
			}
		}
		files[path] = meta[2]
		if len(files) > 100000 {
			return nil, errors.New("Git tree exceeds deployment file limit")
		}
	}
	return files, nil
}

func (p *HostingToolkitProvisioner) gitDeploymentConflicts(ctx context.Context, username, repository, target, current, revision string) ([]string, error) {
	old, err := p.gitTree(ctx, username, repository, current)
	if err != nil {
		return nil, err
	}
	next, err := p.gitTree(ctx, username, repository, revision)
	if err != nil {
		return nil, err
	}
	paths := map[string]bool{}
	for path := range old {
		paths[path] = true
	}
	for path := range next {
		paths[path] = true
	}
	var conflicts []string
	for path := range paths {
		destination := filepath.Join(target, path)
		if err := ensureNoSymlinkComponents(target, filepath.Dir(destination)); err != nil {
			return nil, err
		}
		info, err := os.Lstat(destination)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("Git deployment would replace a non-regular path")
		}
		conflict := old[path] == ""
		if !conflict {
			output, err := p.gitCommand(ctx, username, repository, "hash-object", "--no-filters", "--", destination)
			if err != nil {
				return nil, err
			}
			conflict = strings.TrimSpace(string(output)) != old[path]
		}
		if conflict && len(conflicts) < 100 {
			conflicts = append(conflicts, path)
		}
	}
	sort.Strings(conflicts)
	return conflicts, nil
}

func (p *HostingToolkitProvisioner) gitOperationFence(req types.EnsureGitRepositoryReq) (func(), error) {
	if err := os.MkdirAll(p.gitRoot, 0711); err != nil {
		return nil, err
	}
	base := filepath.Join(p.gitRoot, "site-"+strconv.FormatInt(req.SiteID, 10)+"-operation")
	fd, err := syscall.Open(base+".lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), base+".lock")
	release := func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = file.Close() }
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		release()
		return nil, err
	}
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		release()
		return nil, errors.New("invalid Git operation lock")
	}
	if req.OperationRevision > 0 {
		raw, err := os.ReadFile(base + ".revision")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			release()
			return nil, err
		}
		last, _ := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if req.OperationRevision < last {
			release()
			return nil, errors.New("stale Git operation revision")
		}
		if req.OperationRevision > last {
			if err := writeFileAtomic(base+".revision", []byte(strconv.FormatInt(req.OperationRevision, 10)+"\n"), 0600); err != nil {
				release()
				return nil, err
			}
		}
	}
	return release, nil
}

func gitRemoteAddress(ctx context.Context, remote string) (string, error) {
	u, err := url.Parse(remote)
	if err != nil {
		return "", err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, u.Hostname())
	if err != nil {
		return "", fmt.Errorf("resolve Git remote: %w", err)
	}
	if len(ips) == 0 {
		return "", errors.New("Git remote has no addresses")
	}
	for _, ip := range ips {
		if !gitremote.PublicIP(ip.IP) {
			return "", errors.New("Git remote must resolve only to public addresses")
		}
	}
	return ips[0].IP.String(), nil
}
