package ops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

type SystemUserManager interface {
	EnsureUser(ctx context.Context, username string) error
}

type OwnershipManager interface {
	ChownRecursive(ctx context.Context, path, username string) error
}

type SiteServiceReloader interface {
	ReloadService(ctx context.Context, name string) error
}

type DiskQuotaManager interface {
	ApplyUserQuota(ctx context.Context, username, path string, limitMB int) error
}

type SitePathConfig struct {
	HomeRoot          string
	NginxAvailableDir string
	NginxEnabledDir   string
	NginxLogDir       string
	PHPFPMPoolDir     string
	PHPFPMLogDir      string
	PHPRunDir         string
	NginxSnippet      string
	WWWGroup          string
	PHPTmpDir         string
	DefaultFileMode   os.FileMode
}

type SitePlan struct {
	Username       string
	Domain         string
	PHPVersion     string
	SiteSlug       string
	SiteHome       string
	Docroot        string
	NginxConfig    string
	NginxEnabled   string
	NginxAccessLog string
	NginxErrorLog  string
	NginxSnippet   string
	PHPFPMConfig   string
	PHPFPMPool     string
	PHPFPMSocket   string
	PHPFPMErrorLog string
	WWWGroup       string
	PHPTmpDir      string
	FileMode       os.FileMode
	Limits         types.SiteResourceLimits
}

type SiteProvisionerOptions struct {
	Paths            SitePathConfig
	UserManager      SystemUserManager
	OwnershipManager OwnershipManager
	DiskQuotaManager DiskQuotaManager
	Reloader         SiteServiceReloader
}

type SiteProvisioner struct {
	paths      SitePathConfig
	users      SystemUserManager
	ownership  OwnershipManager
	diskQuotas DiskQuotaManager
	reloader   SiteServiceReloader
}

func DefaultSitePathConfig() SitePathConfig {
	return SitePathConfig{
		HomeRoot:          "/home",
		NginxAvailableDir: "/etc/nginx/sites-available",
		NginxEnabledDir:   "/etc/nginx/sites-enabled",
		NginxLogDir:       "/var/log/nginx",
		PHPFPMLogDir:      "/var/log/php-fpm",
		PHPRunDir:         "/run/php",
		NginxSnippet:      "snippets/fastcgi-php.conf",
		WWWGroup:          "www-data",
		PHPTmpDir:         "/tmp",
		DefaultFileMode:   0o644,
	}
}

func NewSiteProvisioner(opts SiteProvisionerOptions) *SiteProvisioner {
	return &SiteProvisioner{
		paths:      opts.Paths,
		users:      opts.UserManager,
		ownership:  opts.OwnershipManager,
		diskQuotas: opts.DiskQuotaManager,
		reloader:   opts.Reloader,
	}
}

func ValidateCreateSiteRequest(req types.CreateSiteReq) error {
	return site.ValidateCreateSiteRequest(site.NormalizeCreateSiteRequest(req))
}

func NewSitePlan(req types.CreateSiteReq, paths SitePathConfig) (SitePlan, error) {
	normalized := site.NormalizeCreateSiteRequest(req)
	if err := ValidateCreateSiteRequest(normalized); err != nil {
		return SitePlan{}, err
	}

	customPHPFPMPoolDir := paths.PHPFPMPoolDir
	paths = fillSitePathDefaults(paths)
	if customPHPFPMPoolDir == "" {
		paths.PHPFPMPoolDir = filepath.Join("/etc/php", normalized.PHPVersion, "fpm", "pool.d")
	}
	siteHome := filepath.Join(paths.HomeRoot, normalized.Username)
	docroot := filepath.Join(siteHome, "public_html")
	slug := normalized.Username + "-" + strings.ReplaceAll(normalized.Domain, ".", "-")
	nginxName := normalized.Domain + ".conf"
	fpmName := "nakpanel-" + slug

	return SitePlan{
		Username:       normalized.Username,
		Domain:         normalized.Domain,
		PHPVersion:     normalized.PHPVersion,
		SiteSlug:       slug,
		SiteHome:       siteHome,
		Docroot:        docroot,
		NginxConfig:    filepath.Join(paths.NginxAvailableDir, nginxName),
		NginxEnabled:   filepath.Join(paths.NginxEnabledDir, nginxName),
		NginxAccessLog: filepath.Join(paths.NginxLogDir, slug+".access.log"),
		NginxErrorLog:  filepath.Join(paths.NginxLogDir, slug+".error.log"),
		NginxSnippet:   paths.NginxSnippet,
		PHPFPMConfig:   filepath.Join(paths.PHPFPMPoolDir, fpmName+".conf"),
		PHPFPMPool:     fpmName,
		PHPFPMSocket:   filepath.Join(paths.PHPRunDir, fpmName+".sock"),
		PHPFPMErrorLog: filepath.Join(paths.PHPFPMLogDir, slug+".error.log"),
		WWWGroup:       paths.WWWGroup,
		PHPTmpDir:      paths.PHPTmpDir,
		FileMode:       paths.DefaultFileMode,
		Limits:         normalized.Limits,
	}, nil
}

func RenderNginxVHost(plan SitePlan) string {
	return fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %[1]s;
    root %[2]s;
    index index.php index.html;

    access_log %[3]s;
    error_log %[4]s;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include %[5]s;
        fastcgi_pass unix:%[6]s;
    }

    location ~ /\. {
        deny all;
    }
}
`, plan.Domain, plan.Docroot, plan.NginxAccessLog, plan.NginxErrorLog, plan.NginxSnippet, plan.PHPFPMSocket)
}

func RenderSuspendedNginxVHost(plan SitePlan) string {
	return fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;
    location / {
        add_header Retry-After "3600" always;
        return 503;
	    }
}
`, plan.Domain)
}

func RenderNginxRuntimeVHost(plan SitePlan, certPath, keyPath string, redirectHTTPS bool) string {
	if certPath == "" || keyPath == "" {
		return RenderNginxVHost(plan)
	}
	if !redirectHTTPS {
		return RenderNginxTLSVHost(plan, certPath, keyPath)
	}
	return fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %[1]s;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name %[1]s;
    root %[2]s;
    index index.php index.html;

    ssl_certificate %[7]s;
    ssl_certificate_key %[8]s;
    ssl_protocols TLSv1.2 TLSv1.3;

    access_log %[3]s;
    error_log %[4]s;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        include %[5]s;
        fastcgi_pass unix:%[6]s;
    }
    location ~ /\. { deny all; }
}
`, plan.Domain, plan.Docroot, plan.NginxAccessLog, plan.NginxErrorLog, plan.NginxSnippet, plan.PHPFPMSocket, certPath, keyPath)
}

func (p *SiteProvisioner) ApplySiteRuntime(ctx context.Context, req types.ApplySiteRuntimeReq) (err error) {
	state := strings.ToLower(strings.TrimSpace(req.State))
	if state != "active" && state != "suspended" {
		return errors.New("site runtime state must be active or suspended")
	}
	if (req.TLSCertPath == "") != (req.TLSKeyPath == "") {
		return errors.New("certificate and key must be provided together")
	}
	if req.HTTPSRedirect && req.TLSCertPath == "" {
		return errors.New("https redirect requires an active certificate")
	}
	if p.reloader == nil {
		return errors.New("service reloader is not configured")
	}
	currentVersion := strings.TrimSpace(req.CurrentPHPVersion)
	if currentVersion == "" {
		currentVersion = req.DesiredPHPVersion
	}
	current, err := NewSitePlan(types.CreateSiteReq{Username: req.Username, Domain: req.Domain, PHPVersion: currentVersion, Limits: req.Limits}, p.paths)
	if err != nil {
		return err
	}
	desired, err := NewSitePlan(types.CreateSiteReq{Username: req.Username, Domain: req.Domain, PHPVersion: req.DesiredPHPVersion, Limits: req.Limits}, p.paths)
	if err != nil {
		return err
	}

	paths := []string{current.NginxConfig, desired.NginxEnabled, current.PHPFPMConfig, current.PHPFPMConfig + ".suspended", desired.PHPFPMConfig, desired.PHPFPMConfig + ".suspended"}
	snapshots, err := snapshotFiles(paths)
	if err != nil {
		return err
	}
	defer func() {
		if err == nil {
			return
		}
		_ = restoreSnapshots(snapshots)
		_ = p.reloader.ReloadService(context.Background(), "php"+current.PHPVersion+"-fpm")
		if current.PHPVersion != desired.PHPVersion {
			_ = p.reloader.ReloadService(context.Background(), "php"+desired.PHPVersion+"-fpm")
		}
		_ = p.reloader.ReloadService(context.Background(), "nginx")
	}()

	if state == "suspended" {
		if err = writeFileAtomic(desired.NginxConfig, []byte(RenderSuspendedNginxVHost(desired)), desired.FileMode); err != nil {
			return err
		}
		if err = p.reloader.ReloadService(ctx, "nginx"); err != nil {
			return err
		}
		if err = writeFileAtomic(desired.PHPFPMConfig+".suspended", []byte(RenderPHPFPMPool(desired)), desired.FileMode); err != nil {
			return err
		}
		_ = os.Remove(desired.PHPFPMConfig)
		if current.PHPVersion != desired.PHPVersion {
			_ = os.Remove(current.PHPFPMConfig)
			_ = os.Remove(current.PHPFPMConfig + ".suspended")
		}
	} else {
		if err = writeFileAtomic(desired.PHPFPMConfig, []byte(RenderPHPFPMPool(desired)), desired.FileMode); err != nil {
			return err
		}
		_ = os.Remove(desired.PHPFPMConfig + ".suspended")
		if err = writeFileAtomic(desired.NginxConfig, []byte(RenderNginxRuntimeVHost(desired, req.TLSCertPath, req.TLSKeyPath, req.HTTPSRedirect)), desired.FileMode); err != nil {
			return err
		}
		if err = ensureSymlink(desired.NginxConfig, desired.NginxEnabled); err != nil {
			return err
		}
		if current.PHPVersion != desired.PHPVersion {
			_ = os.Remove(current.PHPFPMConfig)
			_ = os.Remove(current.PHPFPMConfig + ".suspended")
		}
	}
	if err = p.reloader.ReloadService(ctx, "php"+desired.PHPVersion+"-fpm"); err != nil {
		return err
	}
	if current.PHPVersion != desired.PHPVersion {
		if err = p.reloader.ReloadService(ctx, "php"+current.PHPVersion+"-fpm"); err != nil {
			return err
		}
	}
	return p.reloader.ReloadService(ctx, "nginx")
}

func (p *SiteProvisioner) SiteRuntimeDrift(_ context.Context, req types.ApplySiteRuntimeReq) (bool, error) {
	state := strings.ToLower(strings.TrimSpace(req.State))
	if state != "active" && state != "suspended" {
		return false, errors.New("site runtime state must be active or suspended")
	}
	desired, err := NewSitePlan(types.CreateSiteReq{Username: req.Username, Domain: req.Domain, PHPVersion: req.DesiredPHPVersion, Limits: req.Limits}, p.paths)
	if err != nil {
		return false, err
	}
	nginx := []byte(RenderNginxRuntimeVHost(desired, req.TLSCertPath, req.TLSKeyPath, req.HTTPSRedirect))
	phpPath := desired.PHPFPMConfig
	absentPath := desired.PHPFPMConfig + ".suspended"
	if state == "suspended" {
		nginx = []byte(RenderSuspendedNginxVHost(desired))
		phpPath, absentPath = absentPath, phpPath
	}
	nginxCurrent, err := os.ReadFile(desired.NginxConfig)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	phpCurrent, err := os.ReadFile(phpPath)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if _, err = os.Lstat(absentPath); err == nil {
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if !bytes.Equal(nginxCurrent, nginx) || !bytes.Equal(phpCurrent, []byte(RenderPHPFPMPool(desired))) {
		return true, nil
	}
	if state == "active" {
		target, err := os.Readlink(desired.NginxEnabled)
		if err != nil || target != desired.NginxConfig {
			return true, nil
		}
	}
	return false, nil
}

type fileSnapshot struct {
	path          string
	data          []byte
	mode          os.FileMode
	exists        bool
	isSymlink     bool
	symlinkTarget string
}

func snapshotFiles(paths []string) ([]fileSnapshot, error) {
	seen := map[string]bool{}
	result := make([]fileSnapshot, 0, len(paths))
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			result = append(result, fileSnapshot{path: path})
			continue
		}
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, readErr := os.Readlink(path)
			if readErr != nil {
				return nil, readErr
			}
			result = append(result, fileSnapshot{path: path, mode: info.Mode(), exists: true, isSymlink: true, symlinkTarget: target})
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		result = append(result, fileSnapshot{path: path, data: data, mode: info.Mode(), exists: true})
	}
	return result, nil
}

func restoreSnapshots(items []fileSnapshot) error {
	for _, item := range items {
		if !item.exists {
			if err := os.Remove(item.path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if item.isSymlink {
			if err := os.Remove(item.path); err != nil && !os.IsNotExist(err) {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(item.path), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(item.symlinkTarget, item.path); err != nil {
				return err
			}
			continue
		}
		if err := writeFileAtomic(item.path, item.data, item.mode); err != nil {
			return err
		}
	}
	return nil
}

func (p *SiteProvisioner) SetHostingState(ctx context.Context, req types.SetHostingStateReq) error {
	state := strings.ToLower(strings.TrimSpace(req.State))
	if state != "active" && state != "suspended" {
		return fmt.Errorf("hosting state must be active or suspended")
	}
	paths := fillSitePathDefaults(p.paths)
	plan, err := NewSitePlan(types.CreateSiteReq{Username: req.Username, Domain: req.Domain, PHPVersion: req.PHPVersion}, paths)
	if err != nil {
		return err
	}
	if p.reloader == nil {
		return errors.New("service reloader is not configured")
	}
	suspendedPool := plan.PHPFPMConfig + ".suspended"
	if state == "suspended" {
		if err := writeFileAtomic(plan.NginxConfig, []byte(RenderSuspendedNginxVHost(plan)), plan.FileMode); err != nil {
			return fmt.Errorf("write suspended nginx config: %w", err)
		}
		webmailEnabled := filepath.Join(paths.NginxEnabledDir, "webmail."+plan.Domain+".conf")
		if _, err := os.Stat(webmailEnabled); err == nil {
			if err := os.Rename(webmailEnabled, webmailEnabled+".suspended"); err != nil {
				return fmt.Errorf("disable webmail: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		// Publish the deterministic maintenance response before taking PHP down.
		// The second reload leaves both the current and retiring nginx workers on
		// the suspended configuration after PHP-FPM has converged.
		if err := p.reloader.ReloadService(ctx, "nginx"); err != nil {
			return err
		}
		if _, err := os.Stat(plan.PHPFPMConfig); err == nil {
			if err := os.Rename(plan.PHPFPMConfig, suspendedPool); err != nil {
				return fmt.Errorf("disable php-fpm pool: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := p.reloader.ReloadService(ctx, "php"+plan.PHPVersion+"-fpm"); err != nil {
			return err
		}
		return p.reloader.ReloadService(ctx, "nginx")
	} else {
		if _, err := os.Stat(suspendedPool); err == nil {
			if err := os.Rename(suspendedPool, plan.PHPFPMConfig); err != nil {
				return fmt.Errorf("enable php-fpm pool: %w", err)
			}
		} else if os.IsNotExist(err) {
			if _, activeErr := os.Stat(plan.PHPFPMConfig); activeErr != nil {
				return errors.New("php-fpm pool is missing; reconcile the site before activation")
			}
		} else {
			return err
		}
		if err := writeFileAtomic(plan.NginxConfig, []byte(RenderNginxVHost(plan)), plan.FileMode); err != nil {
			return fmt.Errorf("restore nginx config: %w", err)
		}
		webmailEnabled := filepath.Join(paths.NginxEnabledDir, "webmail."+plan.Domain+".conf")
		if _, err := os.Stat(webmailEnabled + ".suspended"); err == nil {
			if err := os.Rename(webmailEnabled+".suspended", webmailEnabled); err != nil {
				return fmt.Errorf("enable webmail: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := p.reloader.ReloadService(ctx, "php"+plan.PHPVersion+"-fpm"); err != nil {
		return err
	}
	return p.reloader.ReloadService(ctx, "nginx")
}

func RenderPHPFPMPool(plan SitePlan) string {
	maxChildren := plan.Limits.PHPFPMMaxChildren
	if maxChildren <= 0 {
		maxChildren = 8
	}
	memoryLimit := ""
	if plan.Limits.PHPMemoryMB > 0 {
		memoryLimit = fmt.Sprintf("php_admin_value[memory_limit] = %dM\n", plan.Limits.PHPMemoryMB)
	}
	return fmt.Sprintf(`[%[1]s]
user = %[2]s
group = %[2]s
listen = %[3]s
listen.owner = %[4]s
listen.group = %[4]s
listen.mode = 0660

pm = ondemand
pm.max_children = %[8]d
pm.process_idle_timeout = 10s
pm.max_requests = 500

chdir = /
catch_workers_output = yes
php_admin_value[error_log] = %[5]s
php_admin_flag[log_errors] = on
%[9]sphp_admin_value[open_basedir] = %[6]s:%[7]s
`, plan.PHPFPMPool, plan.Username, plan.PHPFPMSocket, plan.WWWGroup, plan.PHPFPMErrorLog, plan.Docroot, plan.PHPTmpDir, maxChildren, memoryLimit)
}

func (p *SiteProvisioner) CreateSite(ctx context.Context, req types.CreateSiteReq) error {
	plan, err := NewSitePlan(req, p.paths)
	if err != nil {
		return err
	}
	if p.users == nil {
		return errors.New("system user manager is not configured")
	}
	if p.reloader == nil {
		return errors.New("service reloader is not configured")
	}

	if err := p.users.EnsureUser(ctx, plan.Username); err != nil {
		return fmt.Errorf("ensure site user: %w", err)
	}
	for _, dir := range []string{
		plan.SiteHome,
		plan.Docroot,
		filepath.Dir(plan.NginxConfig),
		filepath.Dir(plan.NginxEnabled),
		filepath.Dir(plan.PHPFPMConfig),
		filepath.Dir(plan.PHPFPMSocket),
		filepath.Dir(plan.NginxAccessLog),
		filepath.Dir(plan.PHPFPMErrorLog),
		plan.PHPTmpDir,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %q: %w", dir, err)
		}
	}
	for path, mode := range map[string]os.FileMode{
		plan.SiteHome: 0o755,
		plan.Docroot:  0o755,
	} {
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("chmod directory %q: %w", path, err)
		}
	}

	if err := writeFileAtomic(filepath.Join(plan.Docroot, "index.php"), []byte(renderPlaceholderIndex(plan)), plan.FileMode); err != nil {
		return fmt.Errorf("write placeholder index: %w", err)
	}
	if err := writeFileAtomic(plan.NginxConfig, []byte(RenderNginxVHost(plan)), plan.FileMode); err != nil {
		return fmt.Errorf("write nginx site config: %w", err)
	}
	if err := ensureSymlink(plan.NginxConfig, plan.NginxEnabled); err != nil {
		return fmt.Errorf("enable nginx site: %w", err)
	}
	if err := writeFileAtomic(plan.PHPFPMConfig, []byte(RenderPHPFPMPool(plan)), plan.FileMode); err != nil {
		return fmt.Errorf("write php-fpm pool config: %w", err)
	}
	if p.ownership != nil {
		if err := p.ownership.ChownRecursive(ctx, plan.SiteHome, plan.Username); err != nil {
			return fmt.Errorf("chown site home: %w", err)
		}
	}
	if plan.Limits.DiskQuotaMB > 0 {
		if p.diskQuotas == nil {
			return errors.New("disk quota manager is not configured")
		}
		if err := p.diskQuotas.ApplyUserQuota(ctx, plan.Username, plan.SiteHome, plan.Limits.DiskQuotaMB); err != nil {
			return fmt.Errorf("apply site disk quota: %w", err)
		}
	}

	if err := p.reloader.ReloadService(ctx, "php"+plan.PHPVersion+"-fpm"); err != nil {
		return err
	}
	if err := p.reloader.ReloadService(ctx, "nginx"); err != nil {
		return err
	}
	return nil
}

type LinuxDiskQuotaManager struct {
	runner CommandRunner
}

var quotaUsernameRE = regexp.MustCompile(`^[a-z][a-z0-9]{2,31}$`)

func NewLinuxDiskQuotaManager(runner CommandRunner) *LinuxDiskQuotaManager {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &LinuxDiskQuotaManager{runner: runner}
}

func (m *LinuxDiskQuotaManager) ApplyUserQuota(ctx context.Context, username, path string, limitMB int) error {
	if !quotaUsernameRE.MatchString(username) {
		return fmt.Errorf("unsafe quota username %q", username)
	}
	if limitMB <= 0 {
		return errors.New("disk quota limit must be greater than 0 MB")
	}
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "." || !filepath.IsAbs(cleanPath) {
		return fmt.Errorf("quota path must be absolute: %q", path)
	}
	output, err := m.runner.Run(ctx, "findmnt", "-n", "-o", "TARGET", "--target", cleanPath)
	if err != nil {
		return fmt.Errorf("find quota filesystem for %q: %w: %s", cleanPath, err, strings.TrimSpace(string(output)))
	}
	mountpoint := strings.TrimSpace(string(output))
	if mountpoint == "" || !filepath.IsAbs(mountpoint) {
		return fmt.Errorf("find quota filesystem for %q: empty mount target", cleanPath)
	}
	hardKiB := strconv.Itoa(limitMB * 1024)
	output, err = m.runner.Run(ctx, "setquota", "-u", username, "0", hardKiB, "0", "0", mountpoint)
	if err != nil {
		return fmt.Errorf("setquota user %q on %q: %w: %s", username, mountpoint, err, strings.TrimSpace(string(output)))
	}
	return nil
}

type LinuxUserManagerOptions struct {
	HomeRoot string
	Runner   CommandRunner
}

type LinuxUserManager struct {
	homeRoot string
	runner   CommandRunner
}

func NewLinuxUserManager(opts LinuxUserManagerOptions) *LinuxUserManager {
	homeRoot := opts.HomeRoot
	if homeRoot == "" {
		homeRoot = DefaultSitePathConfig().HomeRoot
	}
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	return &LinuxUserManager{homeRoot: homeRoot, runner: runner}
}

func (m *LinuxUserManager) EnsureUser(ctx context.Context, username string) error {
	if _, err := m.runner.Run(ctx, "id", "-u", username); err == nil {
		return nil
	}
	output, err := m.runner.Run(
		ctx,
		"useradd",
		"--system",
		"--user-group",
		"--home-dir", filepath.Join(m.homeRoot, username),
		"--create-home",
		"--shell", "/usr/sbin/nologin",
		username,
	)
	if err != nil {
		return fmt.Errorf("useradd %q: %w: %s", username, err, strings.TrimSpace(string(output)))
	}
	return nil
}

type LinuxOwnershipManager struct {
	runner CommandRunner
}

func NewLinuxOwnershipManager(runner CommandRunner) *LinuxOwnershipManager {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &LinuxOwnershipManager{runner: runner}
}

func (m *LinuxOwnershipManager) ChownRecursive(ctx context.Context, path, username string) error {
	output, err := m.runner.Run(ctx, "chown", "-R", username+":"+username, path)
	if err != nil {
		return fmt.Errorf("chown %q to %q: %w: %s", path, username, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func fillSitePathDefaults(paths SitePathConfig) SitePathConfig {
	defaults := DefaultSitePathConfig()
	if paths.HomeRoot == "" {
		paths.HomeRoot = defaults.HomeRoot
	}
	if paths.NginxAvailableDir == "" {
		paths.NginxAvailableDir = defaults.NginxAvailableDir
	}
	if paths.NginxEnabledDir == "" {
		paths.NginxEnabledDir = defaults.NginxEnabledDir
	}
	if paths.NginxLogDir == "" {
		paths.NginxLogDir = defaults.NginxLogDir
	}
	if paths.PHPFPMPoolDir == "" {
		paths.PHPFPMPoolDir = defaults.PHPFPMPoolDir
	}
	if paths.PHPFPMLogDir == "" {
		paths.PHPFPMLogDir = defaults.PHPFPMLogDir
	}
	if paths.PHPRunDir == "" {
		paths.PHPRunDir = defaults.PHPRunDir
	}
	if paths.NginxSnippet == "" {
		paths.NginxSnippet = defaults.NginxSnippet
	}
	if paths.WWWGroup == "" {
		paths.WWWGroup = defaults.WWWGroup
	}
	if paths.PHPTmpDir == "" {
		paths.PHPTmpDir = defaults.PHPTmpDir
	}
	if paths.DefaultFileMode == 0 {
		paths.DefaultFileMode = defaults.DefaultFileMode
	}
	return paths
}

func renderPlaceholderIndex(plan SitePlan) string {
	return fmt.Sprintf(`<?php
echo "nakpanel placeholder for %s\n";
`, plan.Domain)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".nakpanel-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func ensureSymlink(target, link string) error {
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return err
	}
	existing, err := os.Readlink(link)
	if err == nil {
		if existing == target {
			return nil
		}
		if err := os.Remove(link); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		if info, statErr := os.Lstat(link); statErr == nil && info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%q exists and is not a symlink", link)
		}
		return err
	}
	if err := os.Symlink(target, link); err != nil {
		return err
	}
	return syncDir(filepath.Dir(link))
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
