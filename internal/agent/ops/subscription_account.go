package ops

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	accountUsernameRE = regexp.MustCompile(`^[a-z][a-z0-9]{2,31}$`)
	sshPublicKeyRE    = regexp.MustCompile(`^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+={0,3}( .*)?$`)
)

type SubscriptionAccountProvisionerOptions struct {
	HomeRoot        string
	SystemdUnitDir  string
	TaskStateDir    string
	UserManager     SystemUserManager
	Ownership       OwnershipManager
	DiskQuota       DiskQuotaManager
	Runner          CommandRunner
	SiteProvisioner *SiteProvisioner
}

type SubscriptionAccountProvisioner struct {
	homeRoot       string
	systemdUnitDir string
	taskStateDir   string
	users          SystemUserManager
	ownership      OwnershipManager
	diskQuota      DiskQuotaManager
	runner         CommandRunner
	sites          *SiteProvisioner
}

func NewSubscriptionAccountProvisioner(opts SubscriptionAccountProvisionerOptions) *SubscriptionAccountProvisioner {
	homeRoot := opts.HomeRoot
	if homeRoot == "" {
		homeRoot = "/home"
	}
	unitDir := opts.SystemdUnitDir
	if unitDir == "" {
		unitDir = "/etc/systemd/system"
	}
	taskStateDir := opts.TaskStateDir
	if taskStateDir == "" {
		taskStateDir = "/var/lib/nakpanel/tasks"
	}
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	return &SubscriptionAccountProvisioner{
		homeRoot: homeRoot, systemdUnitDir: unitDir, taskStateDir: taskStateDir, users: opts.UserManager,
		ownership: opts.Ownership, diskQuota: opts.DiskQuota, runner: runner,
		sites: opts.SiteProvisioner,
	}
}

func (p *SubscriptionAccountProvisioner) MigrateSubscriptionAccount(ctx context.Context, req types.MigrateSubscriptionAccountReq) (types.MigrateSubscriptionAccountResult, error) {
	if err := ValidateMigrationRequest(req, p.homeRoot); err != nil {
		return types.MigrateSubscriptionAccountResult{}, err
	}
	if p.sites == nil {
		return types.MigrateSubscriptionAccountResult{}, errors.New("site provisioner is not configured for account migration")
	}
	if _, err := p.EnsureSubscriptionAccount(ctx, types.EnsureSubscriptionAccountReq{
		SubscriptionID: req.SubscriptionID, Username: req.Username, HomePath: req.HomePath,
		State: "suspended", Policy: req.Policy,
	}); err != nil {
		return types.MigrateSubscriptionAccountResult{}, err
	}
	snapshotRoot := req.SnapshotRoot
	if snapshotRoot == "" {
		snapshotRoot = "/var/lib/nakpanel/migrations"
	}
	if !filepath.IsAbs(snapshotRoot) || filepath.Clean(snapshotRoot) == "/" {
		return types.MigrateSubscriptionAccountResult{}, errors.New("migration snapshot root must be absolute")
	}
	if err := os.MkdirAll(snapshotRoot, 0o700); err != nil {
		return types.MigrateSubscriptionAccountResult{}, err
	}
	snapshotPath := filepath.Join(snapshotRoot, fmt.Sprintf("subscription-%d-%d.tar.gz", req.SubscriptionID, time.Now().UTC().Unix()))
	if err := createMigrationSnapshot(snapshotPath, req.Sites); err != nil {
		return types.MigrateSubscriptionAccountResult{}, fmt.Errorf("create migration snapshot: %w", err)
	}
	var created []string
	var cutover []types.LegacySiteMigration
	var suspended []types.LegacySiteMigration
	rollback := func() {
		for i := len(cutover) - 1; i >= 0; i-- {
			item := cutover[i]
			_ = p.sites.CreateSite(ctx, types.CreateSiteReq{
				SubscriptionID: req.SubscriptionID, Username: item.LegacyUsername, Domain: item.Domain,
				PHPVersion: item.PHPVersion, Limits: siteLimitsFromPolicy(req.Policy),
			})
		}
		for _, path := range created {
			_ = os.RemoveAll(path)
		}
		for _, item := range suspended {
			_ = p.sites.SetHostingState(ctx, types.SetHostingStateReq{Username: item.LegacyUsername, Domain: item.Domain, PHPVersion: item.PHPVersion, State: "active"})
		}
	}
	for _, item := range req.Sites {
		if err := p.sites.SetHostingState(ctx, types.SetHostingStateReq{Username: item.LegacyUsername, Domain: item.Domain, PHPVersion: item.PHPVersion, State: "suspended"}); err != nil {
			rollback()
			return types.MigrateSubscriptionAccountResult{}, fmt.Errorf("suspend %s for final sync: %w", item.Domain, err)
		}
		suspended = append(suspended, item)
	}
	for _, item := range req.Sites {
		if err := ensureNoSymlinkComponents(p.homeRoot, item.TargetDocroot); err != nil {
			rollback()
			return types.MigrateSubscriptionAccountResult{}, fmt.Errorf("inspect target path %s: %w", item.Domain, err)
		}
		_, statErr := os.Lstat(item.TargetDocroot)
		targetExisted := statErr == nil
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			rollback()
			return types.MigrateSubscriptionAccountResult{}, fmt.Errorf("inspect target %s: %w", item.Domain, statErr)
		}
		if err := copyMigrationTree(item.LegacyDocroot, item.TargetDocroot); err != nil {
			rollback()
			return types.MigrateSubscriptionAccountResult{}, fmt.Errorf("copy %s: %w", item.Domain, err)
		}
		if !targetExisted {
			created = append(created, item.TargetDocroot)
		}
		if err := p.sites.CreateSite(ctx, types.CreateSiteReq{
			SubscriptionID: req.SubscriptionID, Username: req.Username, Domain: item.Domain,
			PHPVersion: item.PHPVersion, SharedAccount: true,
			Limits: siteLimitsFromPolicy(req.Policy),
		}); err != nil {
			rollback()
			return types.MigrateSubscriptionAccountResult{}, fmt.Errorf("cut over %s: %w", item.Domain, err)
		}
		cutover = append(cutover, item)
	}
	if p.ownership != nil {
		if err := p.ownership.ChownRecursive(ctx, req.HomePath, req.Username); err != nil {
			rollback()
			return types.MigrateSubscriptionAccountResult{}, err
		}
	}
	legacyHomes := make([]string, 0, len(req.Sites))
	seen := make(map[string]bool)
	for _, item := range req.Sites {
		if !seen[item.LegacyHome] && item.LegacyHome != req.HomePath {
			seen[item.LegacyHome] = true
			legacyHomes = append(legacyHomes, item.LegacyHome)
			_ = os.Chmod(item.LegacyHome, 0o550)
		}
	}
	return types.MigrateSubscriptionAccountResult{SubscriptionID: req.SubscriptionID, Username: req.Username, HomePath: req.HomePath, SnapshotPath: snapshotPath, LegacyHomes: legacyHomes}, nil
}

func (p *SubscriptionAccountProvisioner) CleanupLegacyHomes(_ context.Context, req types.CleanupLegacyHomesReq) (types.CleanupLegacyHomesResult, error) {
	activeHome := filepath.Clean(req.ActiveHome)
	if req.SubscriptionID <= 0 || activeHome == filepath.Clean(p.homeRoot) || filepath.Dir(activeHome) != filepath.Clean(p.homeRoot) {
		return types.CleanupLegacyHomesResult{}, errors.New("invalid legacy cleanup request")
	}
	var result types.CleanupLegacyHomesResult
	for _, rawPath := range req.LegacyHomes {
		path := filepath.Clean(rawPath)
		if filepath.Dir(path) != filepath.Clean(p.homeRoot) || path == activeHome || path == filepath.Clean(p.homeRoot) {
			return result, fmt.Errorf("unsafe legacy home %q", rawPath)
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			result.Deleted = append(result.Deleted, path)
			continue
		}
		if err != nil {
			return result, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return result, fmt.Errorf("legacy home %q is not a real directory", path)
		}
		if err := os.RemoveAll(path); err != nil {
			return result, fmt.Errorf("delete legacy home %q: %w", path, err)
		}
		result.Deleted = append(result.Deleted, path)
	}
	return result, nil
}

func ValidateMigrationRequest(req types.MigrateSubscriptionAccountReq, homeRoot string) error {
	if req.SubscriptionID <= 0 || !accountUsernameRE.MatchString(req.Username) || filepath.Clean(req.HomePath) != filepath.Join(homeRoot, req.Username) {
		return errors.New("invalid migration account")
	}
	if len(req.Sites) == 0 {
		return errors.New("migration requires at least one site")
	}
	if err := policy.Validate(req.Policy); err != nil {
		return err
	}
	for _, item := range req.Sites {
		if item.SiteID <= 0 || site.ValidateDomain(item.Domain) != nil || !accountUsernameRE.MatchString(item.LegacyUsername) {
			return errors.New("invalid legacy site")
		}
		if filepath.Clean(item.LegacyHome) != filepath.Join(homeRoot, item.LegacyUsername) || filepath.Clean(item.LegacyDocroot) != filepath.Join(item.LegacyHome, "public_html") {
			return errors.New("legacy paths are not derived from the legacy account")
		}
		want := filepath.Join(req.HomePath, "domains", item.Domain, "public_html")
		if filepath.Clean(item.TargetDocroot) != want {
			return errors.New("target document root is not derived from the subscription account")
		}
	}
	return nil
}

func createMigrationSnapshot(path string, sites []types.LegacySiteMigration) (err error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}()
	gz := gzip.NewWriter(file)
	defer func() {
		if closeErr := gz.Close(); err == nil {
			err = closeErr
		}
	}()
	tw := tar.NewWriter(gz)
	defer func() {
		if closeErr := tw.Close(); err == nil {
			err = closeErr
		}
	}()
	for _, item := range sites {
		root := filepath.Clean(item.LegacyDocroot)
		resolved, resolveErr := filepath.EvalSymlinks(root)
		if resolveErr != nil || resolved != root {
			return errors.New("legacy document root is missing or is a symlink")
		}
		err = filepath.Walk(root, func(current string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, relErr := filepath.Rel(root, current)
			if relErr != nil {
				return relErr
			}
			name := filepath.ToSlash(filepath.Join("sites", strconv.FormatInt(item.SiteID, 10), rel))
			link := ""
			if info.Mode()&os.ModeSymlink != 0 {
				link, relErr = os.Readlink(current)
				if relErr != nil {
					return relErr
				}
				if filepath.IsAbs(link) || strings.HasPrefix(filepath.Clean(link), "..") {
					return errors.New("archive contains escaping symlink")
				}
			}
			header, headerErr := tar.FileInfoHeader(info, link)
			if headerErr != nil {
				return headerErr
			}
			header.Name = name
			if headerErr = tw.WriteHeader(header); headerErr != nil {
				return headerErr
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			source, openErr := os.Open(current)
			if openErr != nil {
				return openErr
			}
			_, copyErr := io.Copy(tw, source)
			closeErr := source.Close()
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func copyMigrationTree(source, target string) error {
	resolvedSource, err := filepath.EvalSymlinks(source)
	if err != nil || filepath.Clean(resolvedSource) != filepath.Clean(source) {
		return errors.New("migration source is missing or is a symlink")
	}
	if info, statErr := os.Lstat(target); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("migration target cannot be a symlink")
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	return filepath.Walk(source, func(current string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, rel)
		if destination != target && !strings.HasPrefix(destination, target+string(filepath.Separator)) {
			return errors.New("migration destination escapes target")
		}
		if err := ensureNoSymlinkComponents(target, filepath.Dir(destination)); err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(current)
			if err != nil {
				return err
			}
			if filepath.IsAbs(link) || strings.HasPrefix(filepath.Clean(link), "..") {
				return errors.New("migration source contains escaping symlink")
			}
			_ = os.Remove(destination)
			return os.Symlink(link, destination)
		}
		if info.IsDir() {
			if targetInfo, statErr := os.Lstat(destination); statErr == nil {
				if targetInfo.Mode()&os.ModeSymlink != 0 || !targetInfo.IsDir() {
					return fmt.Errorf("migration destination directory %q is unsafe", destination)
				}
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return statErr
			}
			return os.MkdirAll(destination, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported migration file %q", current)
		}
		input, err := os.Open(current)
		if err != nil {
			return err
		}
		if targetInfo, statErr := os.Lstat(destination); statErr == nil && targetInfo.Mode()&os.ModeSymlink != 0 {
			_ = input.Close()
			return fmt.Errorf("migration destination file %q is a symlink", destination)
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			_ = input.Close()
			return statErr
		}
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			_ = input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		inputCloseErr := input.Close()
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if inputCloseErr != nil {
			return inputCloseErr
		}
		return closeErr
	})
}

func ensureNoSymlinkComponents(root, path string) error {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("migration path escapes its root")
	}
	current := root
	components := []string{}
	if rel != "." {
		components = strings.Split(rel, string(filepath.Separator))
	}
	for index := -1; index < len(components); index++ {
		if index >= 0 {
			current = filepath.Join(current, components[index])
		}
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("migration path component %q is a symlink", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("migration path component %q is not a directory", current)
		}
	}
	return nil
}

func (p *SubscriptionAccountProvisioner) EnsureSubscriptionAccount(ctx context.Context, req types.EnsureSubscriptionAccountReq) (types.EnsureSubscriptionAccountResult, error) {
	if err := ValidateSubscriptionAccountRequest(req, p.homeRoot); err != nil {
		return types.EnsureSubscriptionAccountResult{}, err
	}
	if p.users == nil {
		return types.EnsureSubscriptionAccountResult{}, errors.New("system user manager is not configured")
	}
	if err := p.users.EnsureUser(ctx, req.Username); err != nil {
		return types.EnsureSubscriptionAccountResult{}, fmt.Errorf("ensure subscription user: %w", err)
	}
	for _, dir := range []string{req.HomePath, filepath.Join(req.HomePath, "domains"), filepath.Join(req.HomePath, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return types.EnsureSubscriptionAccountResult{}, fmt.Errorf("create account directory %q: %w", dir, err)
		}
	}
	for _, domain := range req.Domains {
		if err := os.MkdirAll(domain.DocumentRoot, 0o750); err != nil {
			return types.EnsureSubscriptionAccountResult{}, fmt.Errorf("create document root %q: %w", domain.DocumentRoot, err)
		}
	}
	if err := p.renderSFTPKeys(req); err != nil {
		return types.EnsureSubscriptionAccountResult{}, err
	}
	if p.ownership != nil {
		if err := p.ownership.ChownRecursive(ctx, req.HomePath, req.Username); err != nil {
			return types.EnsureSubscriptionAccountResult{}, fmt.Errorf("set account ownership: %w", err)
		}
	}
	if req.Policy.Resources.DiskMB > 0 {
		if p.diskQuota == nil {
			return types.EnsureSubscriptionAccountResult{}, errors.New("disk quota manager is not configured")
		}
		if err := p.diskQuota.ApplyUserQuota(ctx, req.Username, req.HomePath, req.Policy.Resources.DiskMB); err != nil {
			return types.EnsureSubscriptionAccountResult{}, err
		}
	}
	if p.sites != nil {
		for _, domain := range req.Domains {
			phpVersion := domain.Policy.PHP.DefaultVersion
			if phpVersion == "" {
				phpVersion = "8.3"
			}
			if err := p.sites.CreateSite(ctx, types.CreateSiteReq{
				SubscriptionID: req.SubscriptionID, Username: req.Username, Domain: domain.Domain,
				PHPVersion: phpVersion, SharedAccount: true, Limits: siteLimitsFromPolicy(domain.Policy),
			}); err != nil {
				return types.EnsureSubscriptionAccountResult{}, fmt.Errorf("converge domain %q: %w", domain.Domain, err)
			}
			if req.State == "suspended" || domain.State == "suspended" {
				if err := p.sites.SetHostingState(ctx, types.SetHostingStateReq{Username: req.Username, Domain: domain.Domain, PHPVersion: phpVersion, State: "suspended"}); err != nil {
					return types.EnsureSubscriptionAccountResult{}, fmt.Errorf("suspend domain %q: %w", domain.Domain, err)
				}
			}
		}
	}
	uid, err := p.lookupUID(ctx, req.Username)
	if err != nil {
		return types.EnsureSubscriptionAccountResult{}, err
	}
	if err := p.renderUserSlice(uid, req.Policy.Resources); err != nil {
		return types.EnsureSubscriptionAccountResult{}, err
	}
	if _, err := p.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return types.EnsureSubscriptionAccountResult{}, fmt.Errorf("reload systemd units: %w", err)
	}
	return types.EnsureSubscriptionAccountResult{Username: req.Username, HomePath: req.HomePath, LinuxUID: uid, Changed: true}, nil
}

func siteLimitsFromPolicy(p types.HostingPolicy) types.SiteResourceLimits {
	return types.SiteResourceLimits{
		DiskQuotaMB: p.Resources.DiskMB, PHPFPMMaxChildren: p.PHP.FPMMaxChildren,
		PHPMemoryMB: p.PHP.MemoryLimitMB, PHPFPMMaxRequests: p.PHP.FPMMaxRequests,
		PHPMaxExecutionSeconds: p.PHP.MaxExecutionSeconds, PHPMaxInputSeconds: p.PHP.MaxInputSeconds,
		PHPPostMaxMB: p.PHP.PostMaxMB, PHPUploadMaxMB: p.PHP.UploadMaxMB,
		PHPDisplayErrors: p.PHP.DisplayErrors, PHPLogErrors: p.PHP.LogErrors,
		PHPAllowURLFOpen: p.PHP.AllowURLFOpen, PHPExecEnabled: p.PHP.ExecEnabled,
		RequestRatePerSecond: p.Web.RequestRatePerSecond, RequestBurst: p.Web.RequestBurst,
		MaxConnections: p.Web.MaxConnections, StaticCache: p.Web.StaticCache,
	}
}

func ValidateSubscriptionAccountRequest(req types.EnsureSubscriptionAccountReq, homeRoot string) error {
	if req.SubscriptionID <= 0 {
		return errors.New("subscription id is required")
	}
	if !accountUsernameRE.MatchString(req.Username) {
		return fmt.Errorf("unsafe subscription username %q", req.Username)
	}
	wantHome := filepath.Join(homeRoot, req.Username)
	if filepath.Clean(req.HomePath) != wantHome {
		return fmt.Errorf("home path must be %q", wantHome)
	}
	if req.State != "active" && req.State != "suspended" {
		return fmt.Errorf("unsupported account state %q", req.State)
	}
	if err := policy.Validate(req.Policy); err != nil {
		return fmt.Errorf("hosting policy: %w", err)
	}
	for _, domain := range req.Domains {
		if site.ValidateDomain(domain.Domain) != nil {
			return fmt.Errorf("unsafe domain %q", domain.Domain)
		}
		wantRoot := filepath.Join(wantHome, "domains", domain.Domain, "public_html")
		if filepath.Clean(domain.DocumentRoot) != wantRoot {
			return fmt.Errorf("document root for %q must be %q", domain.Domain, wantRoot)
		}
	}
	for _, identity := range req.SFTPIdentities {
		if err := validateSFTPIdentity(identity); err != nil {
			return err
		}
	}
	return nil
}

func validateSFTPIdentity(identity types.SFTPAccessIdentity) error {
	if strings.TrimSpace(identity.Name) == "" || strings.ContainsAny(identity.Name, "\r\n") {
		return errors.New("SFTP identity name is required")
	}
	if !sshPublicKeyRE.MatchString(strings.TrimSpace(identity.PublicKey)) || strings.ContainsAny(identity.PublicKey, "\r\n") {
		return fmt.Errorf("invalid SSH public key for %q", identity.Name)
	}
	root := filepath.Clean(strings.TrimSpace(identity.RelativeRoot))
	if root == "" || root == "." {
		return nil
	}
	if filepath.IsAbs(root) || root == ".." || strings.HasPrefix(root, ".."+string(filepath.Separator)) {
		return fmt.Errorf("SFTP root for %q escapes the subscription home", identity.Name)
	}
	return nil
}

func (p *SubscriptionAccountProvisioner) renderSFTPKeys(req types.EnsureSubscriptionAccountReq) error {
	lines := make([]string, 0, len(req.SFTPIdentities))
	for _, identity := range req.SFTPIdentities {
		if !identity.Enabled {
			continue
		}
		root := filepath.Clean(identity.RelativeRoot)
		if root == "." || root == "" {
			root = req.HomePath
		} else {
			root = filepath.Join(req.HomePath, root)
		}
		line := fmt.Sprintf(`restrict,command="internal-sftp -d %s" %s`, root, strings.TrimSpace(identity.PublicKey))
		lines = append(lines, line)
	}
	path := filepath.Join(req.HomePath, ".ssh", "authorized_keys")
	return writeFileAtomic(path, []byte(strings.Join(lines, "\n")+conditionalNewline(len(lines))), 0o600)
}

func conditionalNewline(count int) string {
	if count > 0 {
		return "\n"
	}
	return ""
}

func (p *SubscriptionAccountProvisioner) lookupUID(ctx context.Context, username string) (int, error) {
	output, err := p.runner.Run(ctx, "id", "-u", username)
	if err != nil {
		return 0, fmt.Errorf("lookup uid for %q: %w", username, err)
	}
	uid, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil || uid <= 0 {
		return 0, fmt.Errorf("invalid uid for %q", username)
	}
	return uid, nil
}

func (p *SubscriptionAccountProvisioner) renderUserSlice(uid int, limits types.HostingResourcePolicy) error {
	dir := filepath.Join(p.systemdUnitDir, fmt.Sprintf("user-%d.slice.d", uid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create user slice directory: %w", err)
	}
	var directives []string
	if limits.CPUPercent > 0 {
		directives = append(directives, fmt.Sprintf("CPUQuota=%d%%", limits.CPUPercent))
	}
	if limits.MemoryMB > 0 {
		directives = append(directives, fmt.Sprintf("MemoryHigh=%dM", limits.MemoryMB*9/10), fmt.Sprintf("MemoryMax=%dM", limits.MemoryMB))
	}
	if limits.MaxTasks > 0 {
		directives = append(directives, fmt.Sprintf("TasksMax=%d", limits.MaxTasks))
	}
	if limits.IOReadMBPS > 0 {
		directives = append(directives, fmt.Sprintf("IOReadBandwidthMax=/ %dM", limits.IOReadMBPS))
	}
	if limits.IOWriteMBPS > 0 {
		directives = append(directives, fmt.Sprintf("IOWriteBandwidthMax=/ %dM", limits.IOWriteMBPS))
	}
	contents := "[Slice]\n" + strings.Join(directives, "\n")
	if len(directives) > 0 {
		contents += "\n"
	}
	return writeFileAtomic(filepath.Join(dir, "50-nakpanel.conf"), []byte(contents), 0o644)
}

func (p *SubscriptionAccountProvisioner) ApplyScheduledTasks(ctx context.Context, req types.ApplyScheduledTasksReq) error {
	if req.SubscriptionID <= 0 || !accountUsernameRE.MatchString(req.Username) || filepath.Clean(req.HomePath) != filepath.Join(p.homeRoot, req.Username) {
		return errors.New("invalid scheduled task account")
	}
	statePath := filepath.Join(p.taskStateDir, fmt.Sprintf("subscription-%d.json", req.SubscriptionID))
	previous, err := readTaskState(statePath)
	if err != nil {
		return err
	}
	desired := make(map[int64]bool, len(req.Tasks))
	for _, task := range req.Tasks {
		if err := validateScheduledTask(task, req.HomePath); err != nil {
			return fmt.Errorf("task %q: %w", task.Name, err)
		}
		desired[task.ID] = true
		base := fmt.Sprintf("nakpanel-task-%d", task.ID)
		service := renderTaskService(base, req.Username, req.HomePath, task)
		timer := renderTaskTimer(base, task)
		if err := writeFileAtomic(filepath.Join(p.systemdUnitDir, base+".service"), []byte(service), 0o644); err != nil {
			return err
		}
		if err := writeFileAtomic(filepath.Join(p.systemdUnitDir, base+".timer"), []byte(timer), 0o644); err != nil {
			return err
		}
	}
	for _, id := range previous {
		if desired[id] {
			continue
		}
		unit := fmt.Sprintf("nakpanel-task-%d.timer", id)
		if _, err := p.runner.Run(ctx, "systemctl", "disable", "--now", unit); err != nil {
			servicePath := filepath.Join(p.systemdUnitDir, fmt.Sprintf("nakpanel-task-%d.service", id))
			timerPath := filepath.Join(p.systemdUnitDir, fmt.Sprintf("nakpanel-task-%d.timer", id))
			if fileExists(servicePath) || fileExists(timerPath) {
				return fmt.Errorf("disable removed task %s: %w", unit, err)
			}
		}
		for _, suffix := range []string{".service", ".timer"} {
			if err := os.Remove(filepath.Join(p.systemdUnitDir, fmt.Sprintf("nakpanel-task-%d%s", id, suffix))); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove task unit %d: %w", id, err)
			}
		}
	}
	if _, err := p.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("reload scheduled task units: %w", err)
	}
	for _, task := range req.Tasks {
		unit := fmt.Sprintf("nakpanel-task-%d.timer", task.ID)
		action := "disable"
		if task.Enabled {
			action = "enable"
		}
		if _, err := p.runner.Run(ctx, "systemctl", action, "--now", unit); err != nil {
			return fmt.Errorf("%s %s: %w", action, unit, err)
		}
	}
	ids := make([]int64, 0, len(desired))
	for id := range desired {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	state, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath, append(state, '\n'), 0o600)
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func readTaskState(path string) ([]int64, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read scheduled task state: %w", err)
	}
	var ids []int64
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, fmt.Errorf("decode scheduled task state: %w", err)
	}
	for _, id := range ids {
		if id <= 0 {
			return nil, errors.New("scheduled task state contains an invalid id")
		}
	}
	return ids, nil
}

func validateScheduledTask(task types.ScheduledTask, home string) error {
	if task.ID <= 0 || strings.TrimSpace(task.Name) == "" {
		return errors.New("id and name are required")
	}
	if strings.ContainsAny(task.Name+task.Command+task.Schedule+task.WorkingDirectory, "\x00\r\n") {
		return errors.New("task fields cannot contain control characters")
	}
	if strings.TrimSpace(task.Command) == "" {
		return errors.New("command is required")
	}
	if task.TimeoutSeconds < 1 || task.TimeoutSeconds > 86400 {
		return errors.New("timeout must be between 1 and 86400 seconds")
	}
	work := filepath.Clean(task.WorkingDirectory)
	if work == "." || work == "" {
		work = home
	} else if !filepath.IsAbs(work) {
		work = filepath.Join(home, work)
	}
	if work != home && !strings.HasPrefix(work, home+string(filepath.Separator)) {
		return errors.New("working directory escapes subscription home")
	}
	if _, err := cronToCalendar(task.Schedule); err != nil {
		return err
	}
	return nil
}

func cronToCalendar(schedule string) (string, error) {
	parts := strings.Fields(schedule)
	if len(parts) != 5 {
		return "", errors.New("schedule must be a five-field cron expression")
	}
	for _, part := range parts {
		if !regexp.MustCompile(`^[A-Za-z0-9*,\-]+$`).MatchString(part) {
			return "", errors.New("schedule contains unsupported characters")
		}
	}
	if parts[2] != "*" && parts[4] != "*" {
		return "", errors.New("day-of-month and weekday cannot both be restricted")
	}
	weekday, err := systemdWeekday(parts[4])
	if err != nil {
		return "", err
	}
	calendar := "*-" + parts[3] + "-" + parts[2] + " " + parts[1] + ":" + parts[0] + ":00"
	if weekday != "" {
		calendar = weekday + " " + calendar
	}
	return calendar, nil
}

func systemdWeekday(value string) (string, error) {
	if value == "*" {
		return "", nil
	}
	names := map[string]string{"0": "Sun", "7": "Sun", "1": "Mon", "2": "Tue", "3": "Wed", "4": "Thu", "5": "Fri", "6": "Sat", "SUN": "Sun", "MON": "Mon", "TUE": "Tue", "WED": "Wed", "THU": "Thu", "FRI": "Fri", "SAT": "Sat"}
	items := strings.Split(value, ",")
	for i, item := range items {
		rangeParts := strings.Split(item, "-")
		if len(rangeParts) > 2 {
			return "", errors.New("invalid weekday range")
		}
		for j, part := range rangeParts {
			mapped, ok := names[strings.ToUpper(part)]
			if !ok {
				return "", fmt.Errorf("unsupported weekday %q", part)
			}
			rangeParts[j] = mapped
		}
		items[i] = strings.Join(rangeParts, "..")
	}
	return strings.Join(items, ","), nil
}

func renderTaskService(base, username, home string, task types.ScheduledTask) string {
	work := filepath.Clean(task.WorkingDirectory)
	if work == "." || work == "" {
		work = home
	} else if !filepath.IsAbs(work) {
		work = filepath.Join(home, work)
	}
	return fmt.Sprintf("[Unit]\nDescription=Nakpanel scheduled task %s\n\n[Service]\nType=oneshot\nUser=%s\nWorkingDirectory=%s\nTimeoutStartSec=%d\nExecStart=/bin/sh -lc %s\n", systemdEscape(task.Name), username, work, task.TimeoutSeconds, systemdQuote(task.Command))
}

func renderTaskTimer(base string, task types.ScheduledTask) string {
	calendar, _ := cronToCalendar(task.Schedule)
	return fmt.Sprintf("[Unit]\nDescription=Nakpanel timer %s\n\n[Timer]\nOnCalendar=%s\nPersistent=true\nUnit=%s.service\n\n[Install]\nWantedBy=timers.target\n", systemdEscape(task.Name), calendar, base)
}

func systemdEscape(value string) string { return strings.ReplaceAll(value, "%", "%%") }

func systemdQuote(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "%", "%%")
	return `"` + value + `"`
}
