package ops

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	ftpAccountNameRE             = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,31}$`)
	sha512CryptRE                = regexp.MustCompile(`^\$6\$[A-Za-z0-9./]{8,16}\$[A-Za-z0-9./]{86}$`)
	sha256HexRE                  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	pinnedImageRE                = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}$`)
	protectedDirectoryUsernameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$`)
	bcryptPasswordHashRE         = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)
)

var (
	ftpsConfigMutationMu sync.Mutex
	valkeyMutationMu     sync.Mutex
	siteContentLocks     sync.Map
)

func lockToolkitMutation(locks *sync.Map, id int64) func() {
	value, _ := locks.LoadOrStore(id, &sync.Mutex{})
	mutex := value.(*sync.Mutex)
	mutex.Lock()
	return mutex.Unlock
}

func lockSiteContentMutations(siteIDs ...int64) func() {
	ids := append([]int64(nil), siteIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	unlocks := make([]func(), 0, len(ids))
	var previous int64
	for index, id := range ids {
		if index > 0 && id == previous {
			continue
		}
		unlocks = append(unlocks, lockToolkitMutation(&siteContentLocks, id))
		previous = id
	}
	return func() {
		for index := len(unlocks) - 1; index >= 0; index-- {
			unlocks[index]()
		}
	}
}

type HostingToolkitOptions struct {
	HomeRoot           string
	NginxLogRoot       string
	FTPSConfigDir      string
	FTPSService        string
	SystemdUnitDir     string
	ValkeyConfigRoot   string
	ValkeyRuntimeRoot  string
	GitRoot            string
	StagingRoot        string
	NginxProtectedRoot string
	MariaDefaultsFile  string
	ValkeyImage        string
	Runner             CommandRunner
	FTPSPublicAddress  string
	FTPSTLSCertPath    string
	FTPSTLSKeyPath     string
}

type HostingToolkitProvisioner struct {
	homeRoot           string
	nginxLogRoot       string
	ftpsConfigDir      string
	ftpsService        string
	systemdUnitDir     string
	valkeyConfigRoot   string
	valkeyRuntimeRoot  string
	gitRoot            string
	stagingRoot        string
	nginxProtectedRoot string
	mariaDefaultsFile  string
	valkeyImage        string
	runner             CommandRunner
	lookupUser         func(string) (*user.User, error)
	ftpsPublicAddress  string
	ftpsTLSCertPath    string
	ftpsTLSKeyPath     string
}

func NewHostingToolkitProvisioner(opts HostingToolkitOptions) *HostingToolkitProvisioner {
	if opts.HomeRoot == "" {
		opts.HomeRoot = "/home"
	}
	if opts.NginxLogRoot == "" {
		opts.NginxLogRoot = "/var/log/nginx"
	}
	if opts.FTPSConfigDir == "" {
		opts.FTPSConfigDir = "/etc/nakpanel/proftpd"
	}
	if opts.FTPSService == "" {
		opts.FTPSService = "nakpanel-proftpd.service"
	}
	if opts.SystemdUnitDir == "" {
		opts.SystemdUnitDir = "/etc/systemd/system"
	}
	if opts.ValkeyConfigRoot == "" {
		opts.ValkeyConfigRoot = "/etc/nakpanel/valkey"
	}
	if opts.ValkeyRuntimeRoot == "" {
		opts.ValkeyRuntimeRoot = "/run/nakpanel/valkey"
	}
	if opts.GitRoot == "" {
		opts.GitRoot = "/var/lib/nakpanel/git"
	}
	if opts.StagingRoot == "" {
		opts.StagingRoot = "/var/lib/nakpanel/staging"
	}
	if opts.NginxProtectedRoot == "" {
		opts.NginxProtectedRoot = "/etc/nginx/nakpanel/protected"
	}
	if opts.MariaDefaultsFile == "" {
		opts.MariaDefaultsFile = "/etc/nakpanel/mysql-agent.cnf"
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	return &HostingToolkitProvisioner{
		homeRoot: filepath.Clean(opts.HomeRoot), nginxLogRoot: filepath.Clean(opts.NginxLogRoot),
		ftpsConfigDir: filepath.Clean(opts.FTPSConfigDir), ftpsService: opts.FTPSService,
		systemdUnitDir: filepath.Clean(opts.SystemdUnitDir), valkeyConfigRoot: filepath.Clean(opts.ValkeyConfigRoot),
		valkeyRuntimeRoot: filepath.Clean(opts.ValkeyRuntimeRoot),
		gitRoot:           filepath.Clean(opts.GitRoot), stagingRoot: filepath.Clean(opts.StagingRoot),
		nginxProtectedRoot: filepath.Clean(opts.NginxProtectedRoot),
		mariaDefaultsFile:  filepath.Clean(opts.MariaDefaultsFile),
		valkeyImage:        strings.TrimSpace(opts.ValkeyImage), runner: opts.Runner,
		lookupUser:        user.Lookup,
		ftpsPublicAddress: strings.TrimSpace(opts.FTPSPublicAddress),
		ftpsTLSCertPath:   strings.TrimSpace(opts.FTPSTLSCertPath),
		ftpsTLSKeyPath:    strings.TrimSpace(opts.FTPSTLSKeyPath),
	}
}

func (p *HostingToolkitProvisioner) EnsureProtectedDirectories(ctx context.Context, req types.EnsureProtectedDirectoriesReq) (types.EnsureProtectedDirectoriesResult, error) {
	if req.SiteID <= 0 || site.ValidateUsername(req.Username) != nil || site.ValidateDomain(req.Domain) != nil {
		return types.EnsureProtectedDirectoriesResult{}, errors.New("valid protected-directory site identity is required")
	}
	seen := make(map[string]bool)
	for _, item := range req.Directories {
		clean := filepath.ToSlash(filepath.Clean(strings.TrimSpace(strings.TrimPrefix(item.Path, "/"))))
		if item.ID <= 0 || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.ContainsAny(clean+item.Realm+item.Username, "\x00\r\n") ||
			!protectedDirectoryUsernameRE.MatchString(item.Username) || !bcryptPasswordHashRE.MatchString(item.PasswordHash) ||
			strings.TrimSpace(item.Realm) == "" || len(item.Realm) > 128 || seen[clean] {
			return types.EnsureProtectedDirectoriesResult{}, errors.New("invalid protected-directory definition")
		}
		seen[clean] = true
	}

	siteConfigMutationMu.Lock()
	defer siteConfigMutationMu.Unlock()

	target := filepath.Join(p.nginxProtectedRoot, "site-"+strconv.FormatInt(req.SiteID, 10))
	if err := os.MkdirAll(p.nginxProtectedRoot, 0o710); err != nil {
		return types.EnsureProtectedDirectoriesResult{}, err
	}
	if err := os.Chmod(p.nginxProtectedRoot, 0o710); err != nil {
		return types.EnsureProtectedDirectoriesResult{}, err
	}
	if output, chownErr := p.runner.Run(ctx, "chown", "root:www-data", p.nginxProtectedRoot); chownErr != nil {
		return types.EnsureProtectedDirectoriesResult{}, fmt.Errorf("secure protected-directory root: %w: %s", chownErr, strings.TrimSpace(string(output)))
	}
	candidate, err := os.MkdirTemp(p.nginxProtectedRoot, ".site-candidate-*")
	if err != nil {
		return types.EnsureProtectedDirectoriesResult{}, err
	}
	defer os.RemoveAll(candidate)
	if err := os.Chmod(candidate, 0o710); err != nil {
		return types.EnsureProtectedDirectoriesResult{}, err
	}
	if output, chownErr := p.runner.Run(ctx, "chown", "root:www-data", candidate); chownErr != nil {
		return types.EnsureProtectedDirectoriesResult{}, fmt.Errorf("secure protected-directory candidate: %w: %s", chownErr, strings.TrimSpace(string(output)))
	}
	var locations strings.Builder
	locations.WriteString("# Managed by Nakpanel. Changes are replaced during reconciliation.\n")
	for _, item := range req.Directories {
		if !item.Enabled {
			continue
		}
		clean := filepath.ToSlash(filepath.Clean(strings.TrimSpace(strings.TrimPrefix(item.Path, "/"))))
		passwordPath := filepath.Join(candidate, "directory-"+strconv.FormatInt(item.ID, 10)+".htpasswd")
		if err := writeFileAtomic(passwordPath, []byte(item.Username+":"+item.PasswordHash+"\n"), 0o640); err != nil {
			return types.EnsureProtectedDirectoriesResult{}, err
		}
		if output, chownErr := p.runner.Run(ctx, "chown", "root:www-data", passwordPath); chownErr != nil {
			return types.EnsureProtectedDirectoriesResult{}, fmt.Errorf("secure password file: %w: %s", chownErr, strings.TrimSpace(string(output)))
		}
		configPasswordPath := filepath.Join(target, filepath.Base(passwordPath))
		fmt.Fprintf(&locations, `location %s {
    auth_basic %s;
    auth_basic_user_file %s;
    try_files $uri $uri/ /index.php?$query_string;
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/nakpanel-php/site-%d.sock;
    }
}
`, strconv.Quote("/"+clean+"/"), strconv.Quote(item.Realm), configPasswordPath, req.SiteID)
	}
	if err := writeFileAtomic(filepath.Join(candidate, "locations.conf"), []byte(locations.String()), 0o600); err != nil {
		return types.EnsureProtectedDirectoriesResult{}, err
	}

	backup := target + ".rollback"
	_ = os.RemoveAll(backup)
	hadTarget := false
	if _, statErr := os.Stat(target); statErr == nil {
		hadTarget = true
		if err := os.Rename(target, backup); err != nil {
			return types.EnsureProtectedDirectoriesResult{}, err
		}
	} else if !os.IsNotExist(statErr) {
		return types.EnsureProtectedDirectoriesResult{}, statErr
	}
	rollback := func(cause error) (types.EnsureProtectedDirectoriesResult, error) {
		_ = os.RemoveAll(target)
		if hadTarget {
			if restoreErr := os.Rename(backup, target); restoreErr != nil {
				return types.EnsureProtectedDirectoriesResult{}, errors.Join(cause, restoreErr)
			}
		} else {
			if restoreErr := os.MkdirAll(target, 0o710); restoreErr != nil {
				return types.EnsureProtectedDirectoriesResult{}, errors.Join(cause, restoreErr)
			}
			if restoreErr := writeFileAtomic(filepath.Join(target, "locations.conf"), []byte("# Managed by Nakpanel. No protected directories configured.\n"), 0o600); restoreErr != nil {
				return types.EnsureProtectedDirectoriesResult{}, errors.Join(cause, restoreErr)
			}
		}
		_, _ = p.runner.Run(context.Background(), "systemctl", "reload", "nginx")
		return types.EnsureProtectedDirectoriesResult{}, cause
	}
	if err := os.Rename(candidate, target); err != nil {
		return rollback(err)
	}
	if output, runErr := p.runner.Run(ctx, "nginx", "-t"); runErr != nil {
		return rollback(fmt.Errorf("validate nginx protected directories: %w: %s", runErr, strings.TrimSpace(string(output))))
	}
	if output, runErr := p.runner.Run(ctx, "systemctl", "reload", "nginx"); runErr != nil {
		return rollback(fmt.Errorf("reload nginx protected directories: %w: %s", runErr, strings.TrimSpace(string(output))))
	}
	_ = os.RemoveAll(backup)
	return types.EnsureProtectedDirectoriesResult{ConfigPath: filepath.Join(target, "locations.conf"), Changed: true}, nil
}

func (p *HostingToolkitProvisioner) EnsureGitRepository(ctx context.Context, req types.EnsureGitRepositoryReq) (types.EnsureGitRepositoryResult, error) {
	if err := validateGitRepositoryRequest(req); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	unlock := lockSiteContentMutations(req.SiteID)
	defer unlock()
	siteRoot := filepath.Join(p.homeRoot, req.Username, "domains", req.Domain, "public_html")
	target := filepath.Join(siteRoot, filepath.Clean(req.DeployTarget))
	if err := ensureNoSymlinkComponents(siteRoot, target); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	if err := ensureManagedDirectory(siteRoot, target, 0o750); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	if err := os.MkdirAll(p.gitRoot, 0o711); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	if err := os.Chmod(p.gitRoot, 0o711); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	repositoryRoot := filepath.Join(p.gitRoot, "site-"+strconv.FormatInt(req.SiteID, 10))
	deployedRevisionPath := filepath.Join(repositoryRoot, "deployed-revision")
	if err := os.MkdirAll(repositoryRoot, 0o700); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	if err := os.Chmod(repositoryRoot, 0o700); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	if req.State == "suspended" {
		return types.EnsureGitRepositoryResult{RepositoryPath: repositoryRoot}, nil
	}
	if req.Mode == "hosted" {
		bare := filepath.Join(repositoryRoot, "repository.git")
		if _, err := os.Stat(filepath.Join(bare, "HEAD")); errors.Is(err, os.ErrNotExist) {
			if output, runErr := p.runner.Run(ctx, "git", "init", "--bare", bare); runErr != nil {
				return types.EnsureGitRepositoryResult{}, fmt.Errorf("initialize hosted repository: %w: %s", runErr, strings.TrimSpace(string(output)))
			}
		}
		if output, runErr := p.runner.Run(ctx, "git", "--git-dir", bare, "symbolic-ref", "HEAD", "refs/heads/"+req.Branch); runErr != nil {
			return types.EnsureGitRepositoryResult{}, fmt.Errorf("set hosted repository default branch: %w: %s", runErr, strings.TrimSpace(string(output)))
		}
		if output, err := p.runner.Run(ctx, "chown", "-h", "-R", req.Username+":"+req.Username, repositoryRoot); err != nil {
			return types.EnsureGitRepositoryResult{}, fmt.Errorf("secure hosted repository: %w: %s", err, strings.TrimSpace(string(output)))
		}
		if !req.Deploy {
			return types.EnsureGitRepositoryResult{RepositoryPath: bare, Changed: true}, nil
		}
		revisionOutput, revisionErr := p.runner.Run(ctx, "runuser", "-u", req.Username, "--", "git", "--git-dir", bare, "rev-parse", "refs/heads/"+req.Branch)
		if revisionErr != nil {
			empty, inspectErr := p.gitRepositoryIsEmpty(ctx, req.Username, bare)
			if inspectErr != nil {
				return types.EnsureGitRepositoryResult{}, errors.Join(
					fmt.Errorf("resolve hosted Git branch: %w: %s", revisionErr, strings.TrimSpace(string(revisionOutput))),
					inspectErr,
				)
			}
			if empty {
				// An automatic hosted repository has nothing to deploy until
				// its first push. Initializing it is successful convergence.
				return types.EnsureGitRepositoryResult{RepositoryPath: bare, Changed: true}, nil
			}
			return types.EnsureGitRepositoryResult{}, fmt.Errorf("resolve hosted Git branch: %w: %s", revisionErr, strings.TrimSpace(string(revisionOutput)))
		}
		revision := strings.TrimSpace(string(revisionOutput))
		if !gitRevisionRE.MatchString(revision) {
			return types.EnsureGitRepositoryResult{}, errors.New("hosted Git repository returned an invalid revision")
		}
		previous := readDeployedRevision(deployedRevisionPath)
		if err := p.prepareGitDeployment(ctx, req.Username, bare, target, previous, revision); err != nil {
			return types.EnsureGitRepositoryResult{}, err
		}
		if output, runErr := p.runner.Run(ctx, "runuser", "-u", req.Username, "--", "git", "--git-dir", bare, "--work-tree", target, "checkout", "-f", revision, "--", "."); runErr != nil {
			deployErr := fmt.Errorf("deploy hosted Git revision: %w: %s", runErr, strings.TrimSpace(string(output)))
			return types.EnsureGitRepositoryResult{}, errors.Join(deployErr, p.rollbackGitDeployment(req.Username, bare, target, previous, revision))
		}
		if err := writeFileAtomic(deployedRevisionPath, []byte(revision+"\n"), 0o600); err != nil {
			return types.EnsureGitRepositoryResult{}, errors.Join(err, p.rollbackGitDeployment(req.Username, bare, target, previous, revision))
		}
		return types.EnsureGitRepositoryResult{RepositoryPath: bare, Revision: revision, Changed: revision != previous}, nil
	}

	knownHosts := filepath.Join(repositoryRoot, "known_hosts")
	if err := writeFileAtomic(knownHosts, []byte(strings.TrimSpace(req.KnownHostKey)+"\n"), 0o600); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	deployKey := filepath.Join(repositoryRoot, "deploy_key")
	if _, err := os.Stat(deployKey); errors.Is(err, os.ErrNotExist) {
		if output, runErr := p.runner.Run(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "nakpanel-site-"+strconv.FormatInt(req.SiteID, 10), "-f", deployKey); runErr != nil {
			return types.EnsureGitRepositoryResult{}, fmt.Errorf("generate Git deploy key: %w: %s", runErr, strings.TrimSpace(string(output)))
		}
	}
	if output, err := p.runner.Run(ctx, "chown", "-h", "-R", req.Username+":"+req.Username, repositoryRoot); err != nil {
		return types.EnsureGitRepositoryResult{}, fmt.Errorf("secure Git repository: %w: %s", err, strings.TrimSpace(string(output)))
	}
	mirror := filepath.Join(repositoryRoot, "remote.git")
	publicKey, err := os.ReadFile(deployKey + ".pub")
	if err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	if !req.Deploy {
		return types.EnsureGitRepositoryResult{
			RepositoryPath: mirror, DeployPublicKey: strings.TrimSpace(string(publicKey)), Changed: true,
		}, nil
	}
	sshCommand := fmt.Sprintf("ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s", deployKey, knownHosts)
	if _, err := os.Stat(filepath.Join(mirror, "HEAD")); errors.Is(err, os.ErrNotExist) {
		if output, runErr := p.runner.Run(ctx, "runuser", "-u", req.Username, "--", "env", "GIT_SSH_COMMAND="+sshCommand, "git", "clone", "--mirror", req.RemoteURL, mirror); runErr != nil {
			return types.EnsureGitRepositoryResult{}, fmt.Errorf("clone Git repository: %w: %s", runErr, strings.TrimSpace(string(output)))
		}
	} else {
		if output, runErr := p.runner.Run(ctx, "runuser", "-u", req.Username, "--", "git", "--git-dir", mirror, "remote", "set-url", "origin", req.RemoteURL); runErr != nil {
			return types.EnsureGitRepositoryResult{}, fmt.Errorf("update Git remote: %w: %s", runErr, strings.TrimSpace(string(output)))
		}
		if output, runErr := p.runner.Run(ctx, "runuser", "-u", req.Username, "--", "env", "GIT_SSH_COMMAND="+sshCommand, "git", "--git-dir", mirror, "fetch", "--prune", "origin"); runErr != nil {
			return types.EnsureGitRepositoryResult{}, fmt.Errorf("fetch Git repository: %w: %s", runErr, strings.TrimSpace(string(output)))
		}
	}
	revisionOutput, err := p.runner.Run(ctx, "runuser", "-u", req.Username, "--", "git", "--git-dir", mirror, "rev-parse", "refs/heads/"+req.Branch)
	if err != nil {
		empty, inspectErr := p.gitRepositoryIsEmpty(ctx, req.Username, mirror)
		if inspectErr != nil {
			return types.EnsureGitRepositoryResult{}, errors.Join(
				fmt.Errorf("resolve Git branch: %w: %s", err, strings.TrimSpace(string(revisionOutput))),
				inspectErr,
			)
		}
		if empty {
			return types.EnsureGitRepositoryResult{
				RepositoryPath: mirror, DeployPublicKey: strings.TrimSpace(string(publicKey)), Changed: true,
			}, nil
		}
		return types.EnsureGitRepositoryResult{}, fmt.Errorf("resolve Git branch: %w: %s", err, strings.TrimSpace(string(revisionOutput)))
	}
	revision := strings.TrimSpace(string(revisionOutput))
	if !gitRevisionRE.MatchString(revision) {
		return types.EnsureGitRepositoryResult{}, errors.New("Git returned an invalid revision")
	}
	previous := readDeployedRevision(deployedRevisionPath)
	if err := p.prepareGitDeployment(ctx, req.Username, mirror, target, previous, revision); err != nil {
		return types.EnsureGitRepositoryResult{}, err
	}
	if output, runErr := p.runner.Run(ctx, "runuser", "-u", req.Username, "--", "git", "--git-dir", mirror, "--work-tree", target, "checkout", "-f", revision, "--", "."); runErr != nil {
		deployErr := fmt.Errorf("deploy Git revision: %w: %s", runErr, strings.TrimSpace(string(output)))
		return types.EnsureGitRepositoryResult{}, errors.Join(deployErr, p.rollbackGitDeployment(req.Username, mirror, target, previous, revision))
	}
	if err := writeFileAtomic(deployedRevisionPath, []byte(revision+"\n"), 0o600); err != nil {
		return types.EnsureGitRepositoryResult{}, errors.Join(err, p.rollbackGitDeployment(req.Username, mirror, target, previous, revision))
	}
	return types.EnsureGitRepositoryResult{
		RepositoryPath: mirror, Revision: revision, DeployPublicKey: strings.TrimSpace(string(publicKey)), Changed: revision != previous,
	}, nil
}

func (p *HostingToolkitProvisioner) gitRepositoryIsEmpty(ctx context.Context, username, repository string) (bool, error) {
	output, err := p.runner.Run(ctx, "runuser", "-u", username, "--", "git", "--git-dir", repository,
		"for-each-ref", "--format=%(refname)", "refs/heads", "refs/tags")
	if err != nil {
		return false, fmt.Errorf("inspect Git repository refs: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)) == "", nil
}

var gitRevisionRE = regexp.MustCompile(`^[a-f0-9]{40,64}$`)

func readDeployedRevision(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	revision := strings.TrimSpace(string(raw))
	if !gitRevisionRE.MatchString(revision) {
		return ""
	}
	return revision
}

func (p *HostingToolkitProvisioner) removeDeletedGitPaths(ctx context.Context, username, repository, target, previous, revision string) error {
	if !gitRevisionRE.MatchString(previous) || previous == revision {
		return nil
	}
	output, err := p.runner.Run(ctx, "runuser", "-u", username, "--", "git", "--git-dir", repository,
		"diff", "--no-renames", "--name-only", "--diff-filter=D", "-z", previous, revision, "--")
	if err != nil {
		return fmt.Errorf("list files removed by Git revision: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for _, raw := range bytes.Split(output, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		relative := filepath.Clean(filepath.FromSlash(string(raw)))
		destination := filepath.Join(target, relative)
		if relative == "." || filepath.IsAbs(relative) || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) || !site.PathWithinDir(target, destination) {
			return errors.New("Git returned an unsafe deleted path")
		}
		removeOutput, removeErr := p.runner.Run(ctx, "runuser", "-u", username, "--", "rm", "-rf", "--", destination)
		if removeErr != nil {
			return fmt.Errorf("remove file deleted by Git revision: %w: %s", removeErr, strings.TrimSpace(string(removeOutput)))
		}
	}
	return nil
}

func (p *HostingToolkitProvisioner) prepareGitDeployment(ctx context.Context, username, repository, target, previous, revision string) error {
	if err := p.removeDeletedGitPaths(ctx, username, repository, target, previous, revision); err != nil {
		return errors.Join(err, p.restoreGitRevision(username, repository, target, previous))
	}
	return nil
}

func (p *HostingToolkitProvisioner) rollbackGitDeployment(username, repository, target, previous, revision string) error {
	ctx := context.Background()
	var rollbackErrors []error
	if err := p.removeGitPathsAddedByRevision(ctx, username, repository, target, previous, revision); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	if err := p.restoreGitRevision(username, repository, target, previous); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	return errors.Join(rollbackErrors...)
}

func (p *HostingToolkitProvisioner) restoreGitRevision(username, repository, target, revision string) error {
	if !gitRevisionRE.MatchString(revision) {
		return nil
	}
	output, err := p.runner.Run(context.Background(), "runuser", "-u", username, "--", "git", "--git-dir", repository,
		"--work-tree", target, "checkout", "-f", revision, "--", ".")
	if err != nil {
		return fmt.Errorf("restore prior Git revision: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (p *HostingToolkitProvisioner) removeGitPathsAddedByRevision(ctx context.Context, username, repository, target, previous, revision string) error {
	if !gitRevisionRE.MatchString(revision) || previous == revision {
		return nil
	}
	args := []string{"-u", username, "--", "git", "--git-dir", repository}
	if gitRevisionRE.MatchString(previous) {
		args = append(args, "diff", "--no-renames", "--name-only", "--diff-filter=A", "-z", previous, revision, "--")
	} else {
		args = append(args, "ls-tree", "-r", "--name-only", "-z", revision, "--")
	}
	output, err := p.runner.Run(ctx, "runuser", args...)
	if err != nil {
		return fmt.Errorf("list files added by Git revision: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for _, raw := range bytes.Split(output, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		relative := filepath.Clean(filepath.FromSlash(string(raw)))
		destination := filepath.Join(target, relative)
		if relative == "." || filepath.IsAbs(relative) || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) || !site.PathWithinDir(target, destination) {
			return errors.New("Git returned an unsafe added path")
		}
		removeOutput, removeErr := p.runner.Run(ctx, "runuser", "-u", username, "--", "rm", "-rf", "--", destination)
		if removeErr != nil {
			return fmt.Errorf("remove file added by failed Git revision: %w: %s", removeErr, strings.TrimSpace(string(removeOutput)))
		}
	}
	return nil
}

func validateGitRepositoryRequest(req types.EnsureGitRepositoryReq) error {
	if req.RepositoryID <= 0 || req.SiteID <= 0 || site.ValidateUsername(req.Username) != nil || site.ValidateDomain(req.Domain) != nil {
		return errors.New("validated Git site identity is required")
	}
	if req.Mode != "remote" && req.Mode != "hosted" {
		return errors.New("unsupported Git repository mode")
	}
	if req.State != "active" && req.State != "suspended" {
		return errors.New("invalid Git repository state")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`).MatchString(req.Branch) {
		return errors.New("invalid Git branch")
	}
	target := filepath.Clean(req.DeployTarget)
	if target == "" || filepath.IsAbs(target) || target == ".." || strings.HasPrefix(target, ".."+string(filepath.Separator)) {
		return errors.New("Git deployment target escapes the site")
	}
	if req.Mode == "remote" {
		parsed, err := url.Parse(req.RemoteURL)
		if err != nil || urlContainsSecret(parsed) ||
			(parsed != nil && parsed.Scheme == "https" && parsed.User != nil) ||
			(parsed.Scheme != "ssh" && parsed.Scheme != "https") || parsed.Hostname() == "" {
			return errors.New("Git remote must be a credential-free ssh or https URL")
		}
		if parsed.Scheme == "ssh" {
			parts := strings.Fields(req.KnownHostKey)
			if len(parts) < 3 || strings.ContainsAny(req.KnownHostKey, "\r\n") || parts[0] != parsed.Hostname() {
				return errors.New("the SSH remote requires a verified host key for its hostname")
			}
		}
	}
	return nil
}

func (p *HostingToolkitProvisioner) RunStagingOperation(ctx context.Context, req types.RunStagingOperationReq) (types.RunStagingOperationResult, error) {
	if req.OperationID <= 0 || req.SourceSiteID <= 0 || req.TargetSiteID <= 0 || req.SourceSiteID == req.TargetSiteID ||
		site.ValidateUsername(req.Username) != nil || site.ValidateDomain(req.SourceDomain) != nil || site.ValidateDomain(req.TargetDomain) != nil ||
		(req.Direction != "copy_to_staging" && req.Direction != "promote") {
		return types.RunStagingOperationResult{}, errors.New("validated staging operation is required")
	}
	unlock := lockSiteContentMutations(req.SourceSiteID, req.TargetSiteID)
	defer unlock()
	accountRoot, err := filepath.EvalSymlinks(filepath.Join(p.homeRoot, req.Username))
	if err != nil {
		return types.RunStagingOperationResult{}, errors.New("subscription account home is missing")
	}
	roots := make([]string, 0, 2)
	candidates := []string{
		filepath.Join(p.homeRoot, req.Username, "domains", req.SourceDomain, "public_html"),
		filepath.Join(p.homeRoot, req.Username, "domains", req.TargetDomain, "public_html"),
	}
	for _, root := range candidates {
		resolved, resolveErr := filepath.EvalSymlinks(root)
		if resolveErr != nil || !site.PathWithinDir(accountRoot, resolved) {
			return types.RunStagingOperationResult{}, fmt.Errorf("staging root %q is missing or unsafe", root)
		}
		roots = append(roots, resolved)
	}
	source, target := roots[0], roots[1]
	snapshotRoot := filepath.Clean(p.stagingRoot)
	if !filepath.IsAbs(snapshotRoot) || snapshotRoot == "/" {
		return types.RunStagingOperationResult{}, errors.New("invalid staging snapshot root")
	}
	if err := os.MkdirAll(snapshotRoot, 0o700); err != nil {
		return types.RunStagingOperationResult{}, err
	}
	if err := pruneStagingSnapshots(snapshotRoot, req.TargetSiteID, 3); err != nil {
		return types.RunStagingOperationResult{}, fmt.Errorf("prune staging rollback points: %w", err)
	}
	targetBytes, err := directoryBytes(ctx, target)
	if err != nil {
		return types.RunStagingOperationResult{}, err
	}
	var databaseRollbackBytes int64
	for _, database := range req.Databases {
		if !usageDatabaseRE.MatchString(database.SourceName) || !usageDatabaseRE.MatchString(database.TargetName) || database.SourceName == database.TargetName {
			return types.RunStagingOperationResult{}, errors.New("invalid staging database mapping")
		}
		size, sizeErr := p.databaseBytes(ctx, database.TargetName)
		if sizeErr != nil {
			return types.RunStagingOperationResult{}, fmt.Errorf("measure database rollback capacity for %s: %w", database.TargetName, sizeErr)
		}
		databaseRollbackBytes, err = addStagingCapacity(databaseRollbackBytes, size)
		if err != nil {
			return types.RunStagingOperationResult{}, err
		}
	}
	var filesystem syscall.Statfs_t
	if err := syscall.Statfs(snapshotRoot, &filesystem); err != nil {
		return types.RunStagingOperationResult{}, fmt.Errorf("inspect staging capacity: %w", err)
	}
	available, err := stagingAvailableCapacity(uint64(filesystem.Bavail), uint64(filesystem.Bsize))
	if err != nil {
		return types.RunStagingOperationResult{}, err
	}
	required, err := addStagingCapacity(targetBytes, databaseRollbackBytes, 64<<20)
	if err != nil {
		return types.RunStagingOperationResult{}, err
	}
	if available < required {
		return types.RunStagingOperationResult{}, fmt.Errorf("staging rollback requires %d bytes but only %d bytes are available", required, available)
	}
	prefix := fmt.Sprintf("site-%d-operation-%d-%d", req.TargetSiteID, req.OperationID, time.Now().UTC().UnixNano())
	snapshot := filepath.Join(snapshotRoot, prefix+".tar.gz")
	if err := createMigrationSnapshot(snapshot, []types.LegacySiteMigration{{SiteID: req.TargetSiteID, LegacyDocroot: target}}); err != nil {
		return types.RunStagingOperationResult{}, fmt.Errorf("create staging rollback point: %w", err)
	}
	before, err := directoryBytes(ctx, target)
	if err != nil {
		return types.RunStagingOperationResult{}, err
	}
	databaseSnapshots := make([]string, 0, len(req.Databases))
	for _, database := range req.Databases {
		databaseSnapshot := filepath.Join(snapshotRoot, fmt.Sprintf("%s-db-%s.sql", prefix, database.TargetName))
		if err := p.dumpDatabase(ctx, database.TargetName, databaseSnapshot); err != nil {
			return types.RunStagingOperationResult{}, fmt.Errorf("create database rollback point for %s: %w", database.TargetName, err)
		}
		databaseSnapshots = append(databaseSnapshots, databaseSnapshot)
	}
	rollback := func(cause error) (types.RunStagingOperationResult, error) {
		var rollbackErrors []error
		if restoreErr := restoreMigrationSnapshot(snapshot, target, req.TargetSiteID); restoreErr != nil {
			rollbackErrors = append(rollbackErrors, restoreErr)
		}
		for index, database := range req.Databases {
			if index < len(databaseSnapshots) {
				if restoreErr := p.restoreDatabase(context.Background(), databaseSnapshots[index], database.TargetName); restoreErr != nil {
					rollbackErrors = append(rollbackErrors, restoreErr)
				}
			}
		}
		return types.RunStagingOperationResult{}, errors.Join(append([]error{cause}, rollbackErrors...)...)
	}
	for _, database := range req.Databases {
		if err := p.pipeDatabase(ctx, database.SourceName, database.TargetName); err != nil {
			return rollback(fmt.Errorf("copy database %s to %s: %w", database.SourceName, database.TargetName, err))
		}
	}
	if err := copyMigrationTree(source, target); err != nil {
		return rollback(err)
	}
	if output, err := p.runner.Run(ctx, "chown", "-h", "-R", req.Username+":"+req.Username, target); err != nil {
		return rollback(fmt.Errorf("restore staging ownership: %w: %s", err, strings.TrimSpace(string(output))))
	}
	after, err := directoryBytes(ctx, target)
	if err != nil {
		return rollback(err)
	}
	return types.RunStagingOperationResult{SnapshotPath: snapshot, DatabaseSnapshots: databaseSnapshots, CopiedBytes: max(after-before, 0), Changed: true}, nil
}

func addStagingCapacity(parts ...int64) (int64, error) {
	var total int64
	for _, part := range parts {
		if part < 0 || part > math.MaxInt64-total {
			return 0, errors.New("staging rollback capacity is invalid or too large")
		}
		total += part
	}
	return total, nil
}

func stagingAvailableCapacity(blocks, blockSize uint64) (int64, error) {
	if blockSize == 0 || blocks > uint64(math.MaxInt64)/blockSize {
		return 0, errors.New("available staging capacity is invalid or too large")
	}
	return int64(blocks * blockSize), nil
}

func (p *HostingToolkitProvisioner) databaseBytes(ctx context.Context, database string) (int64, error) {
	if !usageDatabaseRE.MatchString(database) {
		return 0, errors.New("invalid database identifier")
	}
	statement := "SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema='" + database + "'"
	output, err := p.runner.Run(ctx, "mariadb", "--batch", "--skip-column-names", "--execute", statement)
	if err != nil {
		return 0, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	if err != nil || value < 0 {
		return 0, errors.New("MariaDB returned an invalid database size")
	}
	return value, nil
}

func pruneStagingSnapshots(root string, targetSiteID int64, retainRollbackPoints int) error {
	if targetSiteID <= 0 || retainRollbackPoints < 0 {
		return errors.New("invalid staging retention request")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	prefix := fmt.Sprintf("site-%d-operation-", targetSiteID)
	type rollbackPointFiles struct {
		modified time.Time
		paths    []string
	}
	groups := make(map[string]*rollbackPointFiles)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		rest := strings.TrimPrefix(entry.Name(), prefix)
		separator := strings.IndexByte(rest, '-')
		if separator <= 0 {
			continue
		}
		operationID := rest[:separator]
		if _, parseErr := strconv.ParseInt(operationID, 10, 64); parseErr != nil {
			continue
		}
		attempt := rest[separator+1:]
		if end := strings.IndexAny(attempt, "-."); end >= 0 {
			attempt = attempt[:end]
		}
		if _, parseErr := strconv.ParseInt(attempt, 10, 64); parseErr != nil {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		groupKey := operationID + "-" + attempt
		group := groups[groupKey]
		if group == nil {
			group = &rollbackPointFiles{}
			groups[groupKey] = group
		}
		if info.ModTime().After(group.modified) {
			group.modified = info.ModTime()
		}
		group.paths = append(group.paths, filepath.Join(root, entry.Name()))
	}
	rollbackPoints := make([]*rollbackPointFiles, 0, len(groups))
	for _, group := range groups {
		rollbackPoints = append(rollbackPoints, group)
	}
	sort.Slice(rollbackPoints, func(i, j int) bool { return rollbackPoints[i].modified.After(rollbackPoints[j].modified) })
	for _, group := range rollbackPoints[min(retainRollbackPoints, len(rollbackPoints)):] {
		for _, path := range group.paths {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func urlContainsSecret(parsed *url.URL) bool {
	if parsed == nil || parsed.User == nil {
		return false
	}
	_, hasPassword := parsed.User.Password()
	return hasPassword
}

func (p *HostingToolkitProvisioner) dumpDatabase(ctx context.Context, name, path string) error {
	if !filepath.IsAbs(p.mariaDefaultsFile) {
		return errors.New("MariaDB agent defaults path must be absolute")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "mariadb-dump", "--defaults-extra-file="+p.mariaDefaultsFile, "--single-transaction", "--routines", "--events", "--", name)
	command.Stdout = file
	var stderr bytes.Buffer
	command.Stderr = &limitedWriter{writer: &stderr, remaining: 64 << 10}
	runErr := command.Run()
	closeErr := file.Close()
	if runErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("%w: %s", runErr, sanitizeLogLine(stderr.String()))
	}
	return closeErr
}

func (p *HostingToolkitProvisioner) pipeDatabase(ctx context.Context, source, target string) error {
	dump := exec.CommandContext(ctx, "mariadb-dump", "--defaults-extra-file="+p.mariaDefaultsFile, "--single-transaction", "--routines", "--events", "--", source)
	restore := exec.CommandContext(ctx, "mariadb", "--defaults-extra-file="+p.mariaDefaultsFile, "--", target)
	reader, err := dump.StdoutPipe()
	if err != nil {
		return err
	}
	restore.Stdin = reader
	var stderr bytes.Buffer
	dump.Stderr = &limitedWriter{writer: &stderr, remaining: 32 << 10}
	restore.Stderr = &limitedWriter{writer: &stderr, remaining: 32 << 10}
	if err := restore.Start(); err != nil {
		return err
	}
	if err := dump.Start(); err != nil {
		_ = restore.Process.Kill()
		_ = restore.Wait()
		return err
	}
	dumpErr := dump.Wait()
	restoreErr := restore.Wait()
	if dumpErr != nil || restoreErr != nil {
		return fmt.Errorf("mariadb copy failed: %v / %v: %s", dumpErr, restoreErr, sanitizeLogLine(stderr.String()))
	}
	return nil
}

func (p *HostingToolkitProvisioner) restoreDatabase(ctx context.Context, snapshotPath, target string) error {
	file, err := os.Open(snapshotPath)
	if err != nil {
		return err
	}
	defer file.Close()
	command := exec.CommandContext(ctx, "mariadb", "--defaults-extra-file="+p.mariaDefaultsFile, "--", target)
	command.Stdin = file
	var stderr bytes.Buffer
	command.Stderr = &limitedWriter{writer: &stderr, remaining: 64 << 10}
	if err := command.Run(); err != nil {
		return fmt.Errorf("restore database rollback point: %w: %s", err, sanitizeLogLine(stderr.String()))
	}
	return nil
}

func (p *HostingToolkitProvisioner) EnsureFTPS(ctx context.Context, req types.EnsureFTPSReq) (types.EnsureFTPSResult, error) {
	if req.PublicAddress == "" {
		req.PublicAddress = p.ftpsPublicAddress
	}
	if req.TLSCertPath == "" {
		req.TLSCertPath = p.ftpsTLSCertPath
	}
	if req.TLSKeyPath == "" {
		req.TLSKeyPath = p.ftpsTLSKeyPath
	}
	if err := p.validateFTPS(req); err != nil {
		return types.EnsureFTPSResult{}, err
	}
	ftpsConfigMutationMu.Lock()
	defer ftpsConfigMutationMu.Unlock()
	revisionPath := filepath.Join(p.ftpsConfigDir, "revision")
	if raw, readErr := os.ReadFile(revisionPath); readErr == nil {
		current, parseErr := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if parseErr != nil {
			return types.EnsureFTPSResult{}, errors.New("stored FTPS revision is invalid")
		}
		if current > req.Revision {
			return types.EnsureFTPSResult{Changed: false}, nil
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return types.EnsureFTPSResult{}, readErr
	}
	authPath := filepath.Join(p.ftpsConfigDir, "AuthUserFile")
	configPath := filepath.Join(p.ftpsConfigDir, "proftpd.conf")
	unitPath := filepath.Join(p.systemdUnitDir, p.ftpsService)
	if activeFTPSAccounts(req.Accounts) == 0 {
		if err := os.MkdirAll(p.ftpsConfigDir, 0o700); err != nil {
			return types.EnsureFTPSResult{}, err
		}
		hadUnit := false
		if _, err := os.Stat(unitPath); err == nil {
			hadUnit = true
			output, stopErr := p.runner.Run(ctx, "systemctl", "stop", p.ftpsService)
			if stopErr != nil {
				return types.EnsureFTPSResult{}, fmt.Errorf("stop disabled FTPS service: %w: %s", stopErr, strings.TrimSpace(string(output)))
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return types.EnsureFTPSResult{}, err
		}
		for _, path := range []string{authPath, configPath, unitPath} {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return types.EnsureFTPSResult{}, err
			}
		}
		if err := writeFileAtomic(revisionPath, []byte(strconv.FormatInt(req.Revision, 10)+"\n"), 0o600); err != nil {
			return types.EnsureFTPSResult{}, err
		}
		if hadUnit {
			output, err := p.runner.Run(ctx, "systemctl", "daemon-reload")
			if err != nil {
				return types.EnsureFTPSResult{}, fmt.Errorf("reload units after disabling FTPS: %w: %s", err, strings.TrimSpace(string(output)))
			}
		}
		return types.EnsureFTPSResult{Changed: hadUnit}, nil
	}
	tlsDirectives, err := proFTPDKeyDirectives(req.TLSCertPath, req.TLSKeyPath)
	if err != nil {
		return types.EnsureFTPSResult{}, err
	}
	var auth strings.Builder
	for _, ftp := range req.Accounts {
		if !ftp.Enabled {
			continue
		}
		account, err := p.lookupUser(ftp.Username)
		if err != nil {
			return types.EnsureFTPSResult{}, fmt.Errorf("lookup subscription account %q: %w", ftp.Username, err)
		}
		uid, err := strconv.Atoi(account.Uid)
		if err != nil {
			return types.EnsureFTPSResult{}, err
		}
		gid, err := strconv.Atoi(account.Gid)
		if err != nil {
			return types.EnsureFTPSResult{}, err
		}
		home := filepath.Join(p.homeRoot, ftp.Username)
		if ftp.SiteID > 0 {
			home = filepath.Join(home, "domains", ftp.Domain, "public_html")
		}
		if err := ensureNoSymlinkComponents(filepath.Join(p.homeRoot, ftp.Username), home); err != nil {
			return types.EnsureFTPSResult{}, fmt.Errorf("FTPS home for %q is unsafe: %w", ftp.Name, err)
		}
		if info, statErr := os.Stat(home); statErr != nil || !info.IsDir() {
			return types.EnsureFTPSResult{}, fmt.Errorf("FTPS home for %q is not a directory", ftp.Name)
		}
		fmt.Fprintf(&auth, "%s:%s:%d:%d::%s:/usr/sbin/nologin\n", ftp.Name, ftp.PasswordHash, uid, gid, home)
	}
	if err := os.MkdirAll(p.ftpsConfigDir, 0o700); err != nil {
		return types.EnsureFTPSResult{}, err
	}
	snapshots, err := snapshotFiles([]string{authPath, configPath, unitPath, revisionPath})
	if err != nil {
		return types.EnsureFTPSResult{}, err
	}
	hadUnit := false
	for _, snapshot := range snapshots {
		if snapshot.path == unitPath {
			hadUnit = snapshot.exists
			break
		}
	}
	rollback := func(cause error) (types.EnsureFTPSResult, error) {
		var rollbackErrors []error
		if restoreErr := restoreSnapshots(snapshots); restoreErr != nil {
			rollbackErrors = append(rollbackErrors, restoreErr)
		}
		if _, reloadErr := p.runner.Run(context.Background(), "systemctl", "daemon-reload"); reloadErr != nil {
			rollbackErrors = append(rollbackErrors, reloadErr)
		}
		action := "stop"
		if hadUnit {
			action = "reload-or-restart"
		}
		if _, serviceErr := p.runner.Run(context.Background(), "systemctl", action, p.ftpsService); serviceErr != nil {
			rollbackErrors = append(rollbackErrors, serviceErr)
		}
		return types.EnsureFTPSResult{}, errors.Join(append([]error{cause}, rollbackErrors...)...)
	}
	if err := os.MkdirAll("/var/log/proftpd", 0o755); err != nil {
		return rollback(err)
	}
	if err := writeFileAtomic(authPath, []byte(auth.String()), 0o600); err != nil {
		return rollback(err)
	}
	config := renderProFTPD(req, authPath, tlsDirectives)
	if err := writeFileAtomic(configPath, []byte(config), 0o600); err != nil {
		return rollback(err)
	}
	if err := writeFileAtomic(unitPath, []byte(renderProFTPDUnit(configPath, p.homeRoot, req.Accounts)), 0o644); err != nil {
		return rollback(err)
	}
	if err := writeFileAtomic(revisionPath, []byte(strconv.FormatInt(req.Revision, 10)+"\n"), 0o600); err != nil {
		return rollback(err)
	}
	output, err := p.runner.Run(ctx, "proftpd", "-t", "-c", configPath)
	if err != nil {
		return rollback(fmt.Errorf("validate ProFTPD configuration: %w: %s", err, strings.TrimSpace(string(output))))
	}
	if output, err = p.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return rollback(fmt.Errorf("reload FTPS unit: %w: %s", err, strings.TrimSpace(string(output))))
	}
	if req.State == "suspended" || activeFTPSAccounts(req.Accounts) == 0 {
		output, err = p.runner.Run(ctx, "systemctl", "stop", p.ftpsService)
	} else {
		output, err = p.runner.Run(ctx, "systemctl", "reload-or-restart", p.ftpsService)
	}
	if err != nil {
		return rollback(fmt.Errorf("converge FTPS service: %w: %s", err, strings.TrimSpace(string(output))))
	}
	return types.EnsureFTPSResult{Changed: true}, nil
}

func activeFTPSAccounts(accounts []types.EnsureFTPSAccount) int {
	count := 0
	for _, account := range accounts {
		if account.Enabled {
			count++
		}
	}
	return count
}

func (p *HostingToolkitProvisioner) validateFTPS(req types.EnsureFTPSReq) error {
	if req.Revision <= 0 {
		return errors.New("FTPS revision is required")
	}
	if req.State != "active" && req.State != "suspended" {
		return errors.New("invalid FTPS state")
	}
	if req.State == "active" && (!filepath.IsAbs(req.TLSCertPath) || !filepath.IsAbs(req.TLSKeyPath) || req.TLSCertPath == req.TLSKeyPath) {
		return errors.New("absolute FTPS certificate and key paths are required")
	}
	if req.PublicAddress != "" && net.ParseIP(req.PublicAddress) == nil {
		return errors.New("FTPS public address must be an IP address")
	}
	for _, account := range req.Accounts {
		if account.ID <= 0 || site.ValidateUsername(account.Username) != nil || !ftpAccountNameRE.MatchString(account.Name) || !sha512CryptRE.MatchString(account.PasswordHash) {
			return fmt.Errorf("invalid FTPS account %q", account.Name)
		}
		if account.SiteID > 0 && site.ValidateDomain(account.Domain) != nil {
			return fmt.Errorf("FTPS account %q has an invalid domain", account.Name)
		}
		if account.SiteID == 0 && account.Domain != "" {
			return fmt.Errorf("primary FTPS account %q cannot have a domain", account.Name)
		}
	}
	return nil
}

func renderProFTPD(req types.EnsureFTPSReq, authPath, tlsDirectives string) string {
	masquerade := ""
	if req.PublicAddress != "" {
		masquerade = "MasqueradeAddress " + req.PublicAddress + "\n"
	}
	return fmt.Sprintf(`LoadModule mod_tls.c
LoadModule mod_ident.c
ServerName "Nakpanel FTPS"
ServerType standalone
DefaultServer on
Port 21
UseIPv6 on
UseReverseDNS off
IdentLookups off
RequireValidShell off
AuthPAM off
AuthOrder mod_auth_file.c
AuthUserFile %s
DefaultRoot ~
Umask 0027
AllowOverwrite on
MaxInstances 50
PassivePorts 49152 49252
%s
<Anonymous ~ftp>
  <Limit LOGIN>
    DenyAll
  </Limit>
</Anonymous>
TLSEngine on
TLSRequired on
TLSProtocol TLSv1.2 TLSv1.3
%s
TLSOptions NoSessionReuseRequired
TLSVerifyClient off
`, authPath, masquerade, tlsDirectives)
}

func proFTPDKeyDirectives(certPath, keyPath string) (string, error) {
	certificatePEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("read FTPS certificate: %w", err)
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("FTPS certificate is not valid PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse FTPS certificate: %w", err)
	}
	certificateDirective, keyDirective, err := proFTPDKeyDirectiveNames(certificate.PublicKey)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s %s\n%s %s", certificateDirective, certPath, keyDirective, keyPath), nil
}

func proFTPDKeyDirectiveNames(publicKey any) (string, string, error) {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		return "TLSRSACertificateFile", "TLSRSACertificateKeyFile", nil
	case *ecdsa.PublicKey:
		return "TLSECCertificateFile", "TLSECCertificateKeyFile", nil
	default:
		return "", "", errors.New("FTPS certificate uses an unsupported public key algorithm")
	}
}

func renderProFTPDUnit(configPath, homeRoot string, accounts []types.EnsureFTPSAccount) string {
	writable := map[string]bool{}
	for _, account := range accounts {
		if !account.Enabled {
			continue
		}
		path := filepath.Join(homeRoot, account.Username)
		if account.SiteID > 0 {
			path = filepath.Join(path, "domains", account.Domain, "public_html")
		}
		writable[path] = true
	}
	paths := make([]string, 0, len(writable)+2)
	paths = append(paths, "/run", "/var/log/proftpd")
	for path := range writable {
		paths = append(paths, path)
	}
	sort.Strings(paths[2:])
	return fmt.Sprintf(`[Unit]
Description=Nakpanel TLS-only FTPS service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/proftpd --nodaemon -c %s
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s

[Install]
WantedBy=multi-user.target
`, configPath, strings.Join(paths, " "))
}

func (p *HostingToolkitProvisioner) FTPSStatus(ctx context.Context) (types.FTPSStatus, error) {
	output, err := p.runner.Run(ctx, "systemctl", "is-active", p.ftpsService)
	status := types.FTPSStatus{Running: strings.TrimSpace(string(output)) == "active", TLSRequired: true, PassiveStart: 49152, PassiveEnd: 49252}
	if err != nil && !status.Running {
		status.LastError = strings.TrimSpace(string(output))
	}
	return status, nil
}

func (p *HostingToolkitProvisioner) ReadSiteLog(_ context.Context, req types.SiteLogRequest) (types.SiteLogResult, error) {
	path, err := p.siteLogPath(req)
	if err != nil {
		return types.SiteLogResult{}, err
	}
	if req.LineLimit == 0 {
		req.LineLimit = 200
	}
	if req.ByteLimit == 0 {
		req.ByteLimit = 256 << 10
	}
	if req.LineLimit < 1 || req.LineLimit > 1000 || req.ByteLimit < 1024 || req.ByteLimit > 1<<20 || req.Cursor < 0 {
		return types.SiteLogResult{}, errors.New("log bounds are invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return types.SiteLogResult{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return types.SiteLogResult{}, err
	}
	result := types.SiteLogResult{Source: req.Source}
	if req.Cursor > info.Size() {
		req.Cursor = 0
		result.Rotated = true
	}
	if _, err := file.Seek(req.Cursor, 0); err != nil {
		return result, err
	}
	limited := &io.LimitedReader{R: file, N: int64(req.ByteLimit)}
	reader := bufio.NewReaderSize(limited, min(64<<10, req.ByteLimit))
	for len(result.Lines) < req.LineLimit && limited.N > 0 {
		line, readErr := reader.ReadString('\n')
		if line != "" {
			line = sanitizeLogLine(strings.TrimRight(line, "\r\n"))
			if (req.Search == "" || strings.Contains(strings.ToLower(line), strings.ToLower(req.Search))) &&
				(req.Severity == "" || strings.Contains(strings.ToLower(line), strings.ToLower(req.Severity))) {
				result.Lines = append(result.Lines, line)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return result, readErr
		}
	}
	result.NextCursor = req.Cursor + int64(req.ByteLimit) - limited.N
	result.Truncated = result.NextCursor < info.Size()
	return result, nil
}

func (p *HostingToolkitProvisioner) siteLogPath(req types.SiteLogRequest) (string, error) {
	if req.SiteID <= 0 || site.ValidateUsername(req.Username) != nil || site.ValidateDomain(req.Domain) != nil {
		return "", errors.New("validated site identity is required")
	}
	slug := req.Username + "-" + strings.ReplaceAll(req.Domain, ".", "-")
	var path string
	switch req.Source {
	case types.SiteLogNginxAccess:
		path = filepath.Join(p.nginxLogRoot, slug+".access.log")
	case types.SiteLogNginxError:
		path = filepath.Join(p.nginxLogRoot, slug+".error.log")
	case types.SiteLogPHPFPM:
		path = filepath.Join("/var/log/php-fpm", slug+".error.log")
	case types.SiteLogApplication:
		path = filepath.Join("/var/log/nakpanel/applications", "site-"+strconv.FormatInt(req.SiteID, 10)+".log")
	case types.SiteLogTask:
		path = filepath.Join("/var/log/nakpanel/tasks", "site-"+strconv.FormatInt(req.SiteID, 10)+".log")
	default:
		return "", errors.New("unsupported site log source")
	}
	return path, nil
}

func sanitizeLogLine(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r >= 0x20 {
			return r
		}
		return '\uFFFD'
	}, value)
}

func (p *HostingToolkitProvisioner) RunScheduledTask(ctx context.Context, req types.RunScheduledTaskReq) (types.RunScheduledTaskResult, error) {
	if req.TaskID <= 0 || req.SubscriptionID <= 0 || req.SiteID <= 0 || site.ValidateUsername(req.Username) != nil || site.ValidateDomain(req.Domain) != nil {
		return types.RunScheduledTaskResult{}, errors.New("validated scheduled-task identity is required")
	}
	if req.TimeoutSeconds < 1 || req.TimeoutSeconds > 86400 || strings.ContainsRune(req.Command+req.URL+req.Script, '\x00') {
		return types.RunScheduledTaskResult{}, errors.New("invalid scheduled task")
	}
	root := filepath.Join(p.homeRoot, req.Username, "domains", req.Domain, "public_html")
	working := filepath.Clean(req.WorkingDirectory)
	if working == "" || working == "." {
		working = root
	} else {
		if filepath.IsAbs(working) || working == ".." || strings.HasPrefix(working, ".."+string(filepath.Separator)) {
			return types.RunScheduledTaskResult{}, errors.New("scheduled-task working directory escapes the site")
		}
		working = filepath.Join(root, working)
	}
	taskCtx, cancel := context.WithTimeout(ctx, time.Duration(req.TimeoutSeconds)*time.Second)
	defer cancel()
	var command *exec.Cmd
	switch req.Kind {
	case "command":
		command = exec.CommandContext(taskCtx, "runuser", "-u", req.Username, "--", "/bin/sh", "-lc", req.Command)
	case "url":
		if parsed, err := url.ParseRequestURI(req.URL); err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return types.RunScheduledTaskResult{}, errors.New("scheduled URL is invalid")
		}
		command = exec.CommandContext(taskCtx, "runuser", "-u", req.Username, "--", "curl", "--fail", "--silent", "--show-error", "--max-time", strconv.Itoa(req.TimeoutSeconds), req.URL)
	case "php":
		script := filepath.Clean(req.Script)
		if filepath.IsAbs(script) || script == ".." || strings.HasPrefix(script, ".."+string(filepath.Separator)) {
			return types.RunScheduledTaskResult{}, errors.New("PHP task script escapes the site")
		}
		binary, err := scheduledPHPBinary(req.PHPVersion)
		if err != nil {
			return types.RunScheduledTaskResult{}, err
		}
		if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() {
			return types.RunScheduledTaskResult{}, fmt.Errorf("scheduled PHP runtime %s is unavailable", req.PHPVersion)
		}
		command = exec.CommandContext(taskCtx, "runuser", "-u", req.Username, "--", binary, filepath.Join(root, script))
	default:
		return types.RunScheduledTaskResult{}, errors.New("unsupported scheduled task kind")
	}
	command.Dir = working
	command.Env = []string{
		"HOME=" + filepath.Join(p.homeRoot, req.Username),
		"USER=" + req.Username,
		"LOGNAME=" + req.Username,
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"LANG=C.UTF-8",
	}
	var output bytes.Buffer
	command.Stdout = &limitedWriter{writer: &output, remaining: 64 << 10}
	command.Stderr = &limitedWriter{writer: &output, remaining: 64 << 10}
	err := command.Run()
	result := types.RunScheduledTaskResult{Status: "succeeded", Output: sanitizeLogLine(output.String())}
	if taskCtx.Err() != nil {
		result.Status = "timed_out"
		result.ExitCode = -1
		return result, nil
	}
	if err != nil {
		result.Status = "failed"
		result.ExitCode = exitCode(err)
	}
	return result, nil
}

func scheduledPHPBinary(version string) (string, error) {
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version) {
		return "", errors.New("scheduled PHP runtime is invalid")
	}
	return filepath.Join("/usr/bin", "php"+version), nil
}

type limitedWriter struct {
	writer    *bytes.Buffer
	remaining int
}

func (w *limitedWriter) Write(value []byte) (int, error) {
	original := len(value)
	if w.remaining <= 0 {
		return original, nil
	}
	if len(value) > w.remaining {
		value = value[:w.remaining]
	}
	_, _ = w.writer.Write(value)
	w.remaining -= len(value)
	return original, nil
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func (p *HostingToolkitProvisioner) EnsureValkey(ctx context.Context, req types.EnsureValkeyReq) (types.EnsureValkeyResult, error) {
	if req.SubscriptionID <= 0 || site.ValidateUsername(req.Username) != nil || !sha256HexRE.MatchString(req.ACLHash) {
		return types.EnsureValkeyResult{}, errors.New("valid Valkey subscription identity and ACL hash are required")
	}
	if !pinnedImageRE.MatchString(p.valkeyImage) {
		return types.EnsureValkeyResult{}, errors.New("NAKPANEL_VALKEY_IMAGE must be pinned by sha256 digest")
	}
	if req.State != "enabled" && req.State != "disabled" && req.State != "suspended" {
		return types.EnsureValkeyResult{}, errors.New("invalid Valkey state")
	}
	if req.MemoryMB < 16 || req.MaxClients < 1 || req.IdleTimeout < 0 || req.CPUPercent < 1 || req.ProcessLimit < 8 {
		return types.EnsureValkeyResult{}, errors.New("invalid Valkey resource limits")
	}
	account, err := p.lookupUser(req.Username)
	if err != nil {
		return types.EnsureValkeyResult{}, err
	}
	valkeyMutationMu.Lock()
	defer valkeyMutationMu.Unlock()
	base := filepath.Join(p.valkeyConfigRoot, fmt.Sprintf("sub-%d", req.SubscriptionID))
	runtimeDir := filepath.Join(p.valkeyRuntimeRoot, fmt.Sprintf("sub-%d", req.SubscriptionID))
	if err := os.MkdirAll(p.valkeyRuntimeRoot, 0o711); err != nil {
		return types.EnsureValkeyResult{}, err
	}
	if err := os.Chmod(p.valkeyRuntimeRoot, 0o711); err != nil {
		return types.EnsureValkeyResult{}, err
	}
	if err := os.MkdirAll(base, 0o750); err != nil {
		return types.EnsureValkeyResult{}, err
	}
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return types.EnsureValkeyResult{}, err
	}
	if os.Geteuid() == 0 {
		if err := os.MkdirAll("/run/crun", 0o755); err != nil {
			return types.EnsureValkeyResult{}, err
		}
		output, aclErr := p.runner.Run(ctx, "setfacl", "-m", "u:"+req.Username+":--x", filepath.Dir(p.valkeyRuntimeRoot))
		if aclErr != nil {
			return types.EnsureValkeyResult{}, fmt.Errorf("grant subscription cache traversal: %w: %s", aclErr, strings.TrimSpace(string(output)))
		}
		uid, _ := strconv.Atoi(account.Uid)
		gid, _ := strconv.Atoi(account.Gid)
		if err := os.Chown(base, 0, gid); err != nil {
			return types.EnsureValkeyResult{}, err
		}
		if err := os.Chmod(base, 0o750); err != nil {
			return types.EnsureValkeyResult{}, err
		}
		if err := os.Chown(runtimeDir, uid, gid); err != nil {
			return types.EnsureValkeyResult{}, err
		}
	}
	aclPath := filepath.Join(base, "users.acl")
	configPath := filepath.Join(base, "valkey.conf")
	unitName := fmt.Sprintf("nakpanel-valkey@%d.service", req.SubscriptionID)
	unitPath := filepath.Join(p.systemdUnitDir, unitName)
	acl := renderValkeyACL(req.ACLHash)
	config := fmt.Sprintf(`port 0
protected-mode yes
unixsocket /run/valkey/valkey.sock
unixsocketperm 0600
save ""
appendonly no
maxmemory %dmb
maxmemory-policy allkeys-lru
maxclients %d
timeout %d
aclfile /etc/valkey/users.acl
`, req.MemoryMB, req.MaxClients, req.IdleTimeout)
	unit := renderValkeyUnit(req, account.Uid, account.Gid, base, runtimeDir, p.valkeyImage)
	snapshots, err := snapshotFiles([]string{aclPath, configPath, unitPath})
	if err != nil {
		return types.EnsureValkeyResult{}, err
	}
	configChanged := snapshotsDiffer(snapshots, map[string][]byte{
		aclPath: []byte(acl), configPath: []byte(config), unitPath: []byte(unit),
	})
	hadUnit := false
	for _, snapshot := range snapshots {
		if snapshot.path == unitPath {
			hadUnit = snapshot.exists
			break
		}
	}
	wasEnabled := false
	wasActive := false
	if hadUnit {
		wasEnabled, wasActive, err = p.valkeyUnitState(ctx, unitName)
		if err != nil {
			return types.EnsureValkeyResult{}, err
		}
	}
	rollback := func(cause error) (types.EnsureValkeyResult, error) {
		var rollbackErrors []error
		if restoreErr := restoreSnapshots(snapshots); restoreErr != nil {
			rollbackErrors = append(rollbackErrors, restoreErr)
		}
		if _, reloadErr := p.runner.Run(context.Background(), "systemctl", "daemon-reload"); reloadErr != nil {
			rollbackErrors = append(rollbackErrors, reloadErr)
		}
		if hadUnit {
			enableAction := "disable"
			if wasEnabled {
				enableAction = "enable"
			}
			if _, serviceErr := p.runner.Run(context.Background(), "systemctl", enableAction, unitName); serviceErr != nil {
				rollbackErrors = append(rollbackErrors, serviceErr)
			}
		}
		action := "stop"
		if wasActive {
			action = "restart"
		}
		if _, serviceErr := p.runner.Run(context.Background(), "systemctl", action, unitName); serviceErr != nil {
			rollbackErrors = append(rollbackErrors, serviceErr)
		}
		return types.EnsureValkeyResult{}, errors.Join(append([]error{cause}, rollbackErrors...)...)
	}
	if err := writeFileAtomic(aclPath, []byte(acl), 0o640); err != nil {
		return rollback(err)
	}
	if err := writeFileAtomic(configPath, []byte(config), 0o640); err != nil {
		return rollback(err)
	}
	if os.Geteuid() == 0 {
		gid, gidErr := strconv.Atoi(account.Gid)
		if gidErr != nil {
			return rollback(gidErr)
		}
		if err := os.Chown(aclPath, 0, gid); err != nil {
			return rollback(err)
		}
		if err := os.Chown(configPath, 0, gid); err != nil {
			return rollback(err)
		}
	}
	if err := writeFileAtomic(unitPath, []byte(unit), 0o644); err != nil {
		return rollback(err)
	}
	if configChanged {
		if output, err := p.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return rollback(fmt.Errorf("reload Valkey unit: %w: %s", err, strings.TrimSpace(string(output))))
		}
	}
	running := true
	restarted := false
	if req.State != "enabled" {
		running = false
		if output, err := p.runner.Run(ctx, "systemctl", "disable", "--now", unitName); err != nil {
			return rollback(fmt.Errorf("stop Valkey service: %w: %s", err, strings.TrimSpace(string(output))))
		}
	} else {
		enabledOutput, enabledErr := p.runner.Run(ctx, "systemctl", "is-enabled", unitName)
		if enabledErr != nil || strings.TrimSpace(string(enabledOutput)) != "enabled" {
			if output, err := p.runner.Run(ctx, "systemctl", "enable", unitName); err != nil {
				return rollback(fmt.Errorf("enable Valkey service: %w: %s", err, strings.TrimSpace(string(output))))
			}
		}
		activeOutput, activeErr := p.runner.Run(ctx, "systemctl", "is-active", unitName)
		socketPath := filepath.Join(runtimeDir, "valkey.sock")
		socketInfo, socketErr := os.Stat(socketPath)
		ready := activeErr == nil && strings.TrimSpace(string(activeOutput)) == "active" &&
			socketErr == nil && socketInfo.Mode()&os.ModeSocket != 0
		if req.Flush || configChanged || !ready {
			if output, err := p.runner.Run(ctx, "systemctl", "restart", unitName); err != nil {
				return rollback(fmt.Errorf("restart Valkey service: %w: %s", err, strings.TrimSpace(string(output))))
			}
			restarted = true
			if err := p.waitForValkeyReady(ctx, unitName, socketPath); err != nil {
				return rollback(err)
			}
		}
	}
	return types.EnsureValkeyResult{
		SocketPath: filepath.Join(runtimeDir, "valkey.sock"),
		Changed:    configChanged || restarted,
		Running:    running,
		Flushed:    restarted,
	}, nil
}

func snapshotsDiffer(snapshots []fileSnapshot, desired map[string][]byte) bool {
	for _, snapshot := range snapshots {
		want, ok := desired[snapshot.path]
		if !ok || !snapshot.exists || snapshot.isSymlink || !bytes.Equal(snapshot.data, want) {
			return true
		}
	}
	return len(snapshots) != len(desired)
}

func (p *HostingToolkitProvisioner) valkeyUnitState(ctx context.Context, unitName string) (bool, bool, error) {
	enabledOutput, enabledErr := p.runner.Run(ctx, "systemctl", "is-enabled", unitName)
	enabledState := strings.TrimSpace(string(enabledOutput))
	if enabledState != "enabled" && enabledState != "disabled" {
		return false, false, fmt.Errorf("inspect Valkey enabled state: %w: %s", enabledErr, enabledState)
	}
	activeOutput, activeErr := p.runner.Run(ctx, "systemctl", "is-active", unitName)
	activeState := strings.TrimSpace(string(activeOutput))
	// systemctl reports a failed unit with exit status 3. That is observed
	// service state, not an inspection failure: reconciliation must be able to
	// rewrite its configuration and restart it. Unknown/malformed responses
	// still fail closed.
	if activeState != "active" && activeState != "inactive" && activeState != "failed" {
		return false, false, fmt.Errorf("inspect Valkey active state: %w: %s", activeErr, activeState)
	}
	return enabledState == "enabled", activeState == "active", nil
}

func renderValkeyUnit(req types.EnsureValkeyReq, uid, gid, base, runtimeDir, image string) string {
	return fmt.Sprintf(`[Unit]
Description=Nakpanel cache for subscription %d
After=podman.service

[Service]
Type=notify
NotifyAccess=all
Group=%s
RuntimeDirectory=nakpanel/valkey/sub-%d
RuntimeDirectoryMode=0770
ExecStart=/usr/bin/podman run --pull=never --rm --replace --sdnotify=conmon --name nakpanel-valkey-sub-%d --network=none --user %s:%s --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m -v %s:/etc/valkey:ro,Z -v %s:/run/valkey:rw,Z %s valkey-server /etc/valkey/valkey.conf
ExecStop=/usr/bin/podman stop -t 10 nakpanel-valkey-sub-%d
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/containers -/run/containers -/run/libpod -/run/lock -/run/crun %s
MemoryMax=%dM
CPUQuota=%d%%
TasksMax=%d

[Install]
WantedBy=multi-user.target
`, req.SubscriptionID, gid, req.SubscriptionID, req.SubscriptionID, uid, gid, base, runtimeDir, image, req.SubscriptionID, runtimeDir, max(req.MemoryMB+32, req.MemoryMB*5/4), req.CPUPercent, req.ProcessLimit)
}

func renderValkeyACL(hash string) string {
	return fmt.Sprintf("user default off\nuser app on #%s ~* &* +@read +@write +ping -flushall -flushdb -config -acl -module -debug -monitor -shutdown -save -bgsave -replicaof -slaveof\n", hash)
}

func (p *HostingToolkitProvisioner) waitForValkeyReady(ctx context.Context, unitName, socketPath string) error {
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var lastStatus string
	for {
		output, activeErr := p.runner.Run(ctx, "systemctl", "is-active", unitName)
		lastStatus = strings.TrimSpace(string(output))
		info, socketErr := os.Stat(socketPath)
		if activeErr == nil && lastStatus == "active" && socketErr == nil && info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		if lastStatus == "failed" {
			return fmt.Errorf("Valkey service failed before its Unix socket became ready")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("Valkey service did not become ready (status %q)", lastStatus)
		case <-ticker.C:
		}
	}
}

func (p *HostingToolkitProvisioner) ValkeyStatus(ctx context.Context, subscriptionID int64) (types.ValkeyStatus, error) {
	if subscriptionID <= 0 {
		return types.ValkeyStatus{}, errors.New("subscription id is required")
	}
	socket := filepath.Join(p.valkeyRuntimeRoot, fmt.Sprintf("sub-%d", subscriptionID), "valkey.sock")
	output, err := p.runner.Run(ctx, "systemctl", "is-active", fmt.Sprintf("nakpanel-valkey@%d.service", subscriptionID))
	status := types.ValkeyStatus{Running: strings.TrimSpace(string(output)) == "active", SocketPath: socket}
	if err != nil && !status.Running {
		status.LastError = strings.TrimSpace(string(output))
	}
	return status, nil
}
