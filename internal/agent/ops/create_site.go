package ops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
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

type PHPConfigTester interface {
	TestPHPConfig(ctx context.Context, version, configPath string) error
}

type SitePathConfig struct {
	HomeRoot              string
	NginxAvailableDir     string
	NginxEnabledDir       string
	NginxLogDir           string
	NginxConfDir          string
	NginxCacheDir         string
	NginxProtectedDir     string
	PHPFPMPoolDir         string
	PHPFPMDedicatedDir    string
	PHPFPMDedicatedRunDir string
	PHPFPMLogDir          string
	PHPRunDir             string
	SystemdUnitDir        string
	NginxSnippet          string
	WWWGroup              string
	PHPTmpDir             string
	DefaultFileMode       os.FileMode
}

type SitePlan struct {
	SiteID                 int64
	Username               string
	Domain                 string
	PHPVersion             string
	SiteSlug               string
	SiteHome               string
	Docroot                string
	NginxConfig            string
	NginxEnabled           string
	NginxAccessLog         string
	NginxErrorLog          string
	NginxSnippet           string
	NginxPolicyConfig      string
	NginxRateZone          string
	NginxConnectionZone    string
	NginxCacheZone         string
	NginxCachePath         string
	NginxProtectedConfig   string
	NginxApplicationConfig string
	PHPFPMConfig           string
	PHPFPMPool             string
	PHPFPMSocket           string
	PHPFPMErrorLog         string
	PHPServiceName         string
	PHPServiceUnit         string
	WWWGroup               string
	PHPTmpDir              string
	FileMode               os.FileMode
	Limits                 types.SiteResourceLimits
}

const sitePrivateRuntimeFileMode os.FileMode = 0o600

type SiteProvisionerOptions struct {
	Paths            SitePathConfig
	UserManager      SystemUserManager
	OwnershipManager OwnershipManager
	DiskQuotaManager DiskQuotaManager
	Reloader         SiteServiceReloader
	NginxTester      NginxConfigTester
	PHPTester        PHPConfigTester
	Runner           CommandRunner
}

type SiteProvisioner struct {
	paths      SitePathConfig
	users      SystemUserManager
	ownership  OwnershipManager
	diskQuotas DiskQuotaManager
	reloader   SiteServiceReloader
	nginxTest  NginxConfigTester
	phpTest    PHPConfigTester
	runner     CommandRunner
}

// Site and certificate operations replace shared nginx and PHP-FPM files.
// The agent serves concurrent RPC connections, so these mutations must
// converge one at a time across provisioner types.
var (
	siteConfigMutationMu sync.Mutex
	systemUserMutationMu sync.Mutex
)

const defaultPHPFPMDedicatedRunDir = "/run/nakpanel-php"

func DefaultSitePathConfig() SitePathConfig {
	return SitePathConfig{
		HomeRoot:              "/home",
		NginxAvailableDir:     "/etc/nginx/sites-available",
		NginxEnabledDir:       "/etc/nginx/sites-enabled",
		NginxLogDir:           "/var/log/nginx",
		NginxConfDir:          "/etc/nginx/conf.d",
		NginxCacheDir:         "/var/cache/nginx/nakpanel",
		NginxProtectedDir:     "/etc/nginx/nakpanel/protected",
		PHPFPMDedicatedDir:    "/etc/nakpanel/php-fpm/sites",
		PHPFPMDedicatedRunDir: defaultPHPFPMDedicatedRunDir,
		PHPFPMLogDir:          "/var/log/php-fpm",
		PHPRunDir:             "/run/php",
		SystemdUnitDir:        "/etc/systemd/system",
		NginxSnippet:          "snippets/fastcgi-php.conf",
		WWWGroup:              "www-data",
		PHPTmpDir:             "/tmp",
		DefaultFileMode:       0o644,
	}
}

func NewSiteProvisioner(opts SiteProvisionerOptions) *SiteProvisioner {
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	return &SiteProvisioner{
		paths:      opts.Paths,
		users:      opts.UserManager,
		ownership:  opts.OwnershipManager,
		diskQuotas: opts.DiskQuotaManager,
		reloader:   opts.Reloader,
		nginxTest:  opts.NginxTester,
		phpTest:    opts.PHPTester,
		runner:     runner,
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
	customNginxAvailableDir := paths.NginxAvailableDir
	customNginxConfDir := paths.NginxConfDir
	customNginxCacheDir := paths.NginxCacheDir
	customNginxProtectedDir := paths.NginxProtectedDir
	customPHPFPMDedicatedDir := paths.PHPFPMDedicatedDir
	customPHPFPMDedicatedRunDir := paths.PHPFPMDedicatedRunDir
	customSystemdUnitDir := paths.SystemdUnitDir
	paths = fillSitePathDefaults(paths)
	if customPHPFPMPoolDir == "" {
		paths.PHPFPMPoolDir = filepath.Join("/etc/php", normalized.PHPVersion, "fpm", "pool.d")
	}
	if customNginxConfDir == "" && customNginxAvailableDir != "" {
		paths.NginxConfDir = filepath.Join(filepath.Dir(customNginxAvailableDir), "conf.d")
	}
	if customNginxCacheDir == "" && paths.HomeRoot != "/home" {
		paths.NginxCacheDir = filepath.Join(filepath.Dir(paths.HomeRoot), "var", "cache", "nginx", "nakpanel")
	}
	if customNginxProtectedDir == "" && paths.HomeRoot != "/home" {
		paths.NginxProtectedDir = filepath.Join(filepath.Dir(paths.HomeRoot), "etc", "nginx", "nakpanel", "protected")
	}
	if customPHPFPMDedicatedDir == "" && paths.HomeRoot != "/home" {
		paths.PHPFPMDedicatedDir = filepath.Join(filepath.Dir(paths.HomeRoot), "etc", "nakpanel", "php-fpm", "sites")
	}
	if customPHPFPMDedicatedRunDir == "" && paths.HomeRoot != "/home" {
		paths.PHPFPMDedicatedRunDir = filepath.Join(filepath.Dir(paths.HomeRoot), "run", "nakpanel", "php")
	}
	if customSystemdUnitDir == "" && paths.HomeRoot != "/home" {
		paths.SystemdUnitDir = filepath.Join(filepath.Dir(paths.HomeRoot), "etc", "systemd", "system")
	}
	siteHome := filepath.Join(paths.HomeRoot, normalized.Username)
	docroot := filepath.Join(siteHome, "public_html")
	if normalized.SharedAccount {
		docroot = filepath.Join(siteHome, "domains", normalized.Domain, "public_html")
	}
	slug := normalized.Username + "-" + strings.ReplaceAll(normalized.Domain, ".", "-")
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(normalized.Domain)))[:12]
	nginxName := normalized.Domain + ".conf"
	fpmName := "nakpanel-" + slug
	phpConfig := filepath.Join(paths.PHPFPMPoolDir, fpmName+".conf")
	phpSocket := filepath.Join(paths.PHPRunDir, fpmName+".sock")
	phpService := "php" + normalized.PHPVersion + "-fpm"
	phpUnit := ""
	if normalized.SiteID > 0 {
		phpConfig = filepath.Join(paths.PHPFPMDedicatedDir, strconv.FormatInt(normalized.SiteID, 10)+".conf")
		phpSocket = filepath.Join(paths.PHPFPMDedicatedRunDir, "site-"+strconv.FormatInt(normalized.SiteID, 10)+".sock")
		phpService = fmt.Sprintf("nakpanel-php-fpm@%d.service", normalized.SiteID)
		phpUnit = filepath.Join(paths.SystemdUnitDir, phpService)
		fpmName = "www"
	}

	return SitePlan{
		SiteID:                 normalized.SiteID,
		Username:               normalized.Username,
		Domain:                 normalized.Domain,
		PHPVersion:             normalized.PHPVersion,
		SiteSlug:               slug,
		SiteHome:               siteHome,
		Docroot:                docroot,
		NginxConfig:            filepath.Join(paths.NginxAvailableDir, nginxName),
		NginxEnabled:           filepath.Join(paths.NginxEnabledDir, nginxName),
		NginxAccessLog:         filepath.Join(paths.NginxLogDir, slug+".access.log"),
		NginxErrorLog:          filepath.Join(paths.NginxLogDir, slug+".error.log"),
		NginxSnippet:           paths.NginxSnippet,
		NginxPolicyConfig:      filepath.Join(paths.NginxConfDir, "00-nakpanel-"+digest+".conf"),
		NginxRateZone:          "npr_" + digest,
		NginxConnectionZone:    "npc_" + digest,
		NginxCacheZone:         "npm_" + digest,
		NginxCachePath:         filepath.Join(paths.NginxCacheDir, "npm_"+digest),
		NginxProtectedConfig:   filepath.Join(paths.NginxProtectedDir, "site-"+strconv.FormatInt(normalized.SiteID, 10), "locations.conf"),
		NginxApplicationConfig: filepath.Join(filepath.Dir(paths.NginxProtectedDir), "applications", "site-"+strconv.FormatInt(normalized.SiteID, 10)+".conf"),
		PHPFPMConfig:           phpConfig,
		PHPFPMPool:             fpmName,
		PHPFPMSocket:           phpSocket,
		PHPFPMErrorLog:         filepath.Join(paths.PHPFPMLogDir, slug+".error.log"),
		PHPServiceName:         phpService,
		PHPServiceUnit:         phpUnit,
		WWWGroup:               paths.WWWGroup,
		PHPTmpDir:              paths.PHPTmpDir,
		FileMode:               paths.DefaultFileMode,
		Limits:                 normalized.Limits,
	}, nil
}

func RenderNginxVHost(plan SitePlan) string {
	controls := renderNginxLocationControls(plan)
	return fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %[1]s;
    root %[2]s;
    index %[8]s;
%[9]s

    access_log %[3]s;
    error_log %[4]s;

	    location / {
	%[7]s
	        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include %[5]s;
%[10]s
        fastcgi_pass unix:%[6]s;
    }

    location ~ /\. {
        deny all;
    }
}
	`, nginxServerNames(plan), plan.Docroot, plan.NginxAccessLog, plan.NginxErrorLog, plan.NginxSnippet, plan.PHPFPMSocket, controls, nginxIndexFiles(plan), renderNginxServerControls(plan), renderNginxPHPControls(plan))
}

func renderNginxLocationControls(plan SitePlan) string {
	var lines []string
	if plan.SiteID > 0 {
		marker := filepath.Join(filepath.Dir(plan.NginxApplicationConfig), "site-"+strconv.FormatInt(plan.SiteID, 10)+".domain")
		lines = append(lines, fmt.Sprintf("        if (-f %s) { return 418; }", marker))
	}
	if plan.Limits.RequestRatePerSecond > 0 {
		burst := plan.Limits.RequestBurst
		if burst < 1 {
			burst = plan.Limits.RequestRatePerSecond
		}
		lines = append(lines, fmt.Sprintf("        limit_req zone=%s burst=%d nodelay;", plan.NginxRateZone, burst))
	}
	if plan.Limits.MaxConnections > 0 {
		lines = append(lines, fmt.Sprintf("        limit_conn %s %d;", plan.NginxConnectionZone, plan.Limits.MaxConnections))
	}
	if plan.Limits.StaticCache {
		ttl := plan.Limits.CacheTTLSeconds
		if ttl <= 0 {
			ttl = 300
		}
		lines = append(lines, fmt.Sprintf("        expires %ds;", ttl))
	}
	return strings.Join(lines, "\n")
}

func RenderNginxPolicyZones(plan SitePlan) string {
	var lines []string
	if plan.Limits.RequestRatePerSecond > 0 {
		lines = append(lines, fmt.Sprintf("limit_req_zone $binary_remote_addr zone=%s:10m rate=%dr/s;", plan.NginxRateZone, plan.Limits.RequestRatePerSecond))
	}
	if plan.Limits.MaxConnections > 0 {
		lines = append(lines, fmt.Sprintf("limit_conn_zone $binary_remote_addr zone=%s:10m;", plan.NginxConnectionZone))
	}
	if plan.Limits.FastCGIMicrocache {
		lines = append(lines, fmt.Sprintf("fastcgi_cache_path %s levels=1:2 keys_zone=%s:10m inactive=60m max_size=256m;", plan.NginxCachePath, plan.NginxCacheZone))
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func nginxIndexFiles(plan SitePlan) string {
	if value := strings.TrimSpace(plan.Limits.IndexFiles); value != "" {
		return value
	}
	return "index.php index.html"
}

func renderNginxServerControls(plan SitePlan) string {
	var lines []string
	if plan.SiteID > 0 {
		lines = append(lines, "    include "+plan.NginxProtectedConfig+";")
		lines = append(lines, "    include "+plan.NginxApplicationConfig+";")
	}
	preferred := strings.ToLower(strings.TrimSpace(plan.Limits.PreferredDomain))
	if preferred == "www" && !strings.HasPrefix(plan.Domain, "www.") {
		lines = append(lines, fmt.Sprintf("    if ($host = %s) { return 301 $scheme://www.%s$request_uri; }", plan.Domain, plan.Domain))
	}
	if (preferred == "root" || preferred == "non-www") && !strings.HasPrefix(plan.Domain, "www.") {
		lines = append(lines, fmt.Sprintf("    if ($host = www.%s) { return 301 $scheme://%s$request_uri; }", plan.Domain, plan.Domain))
	}
	if plan.Limits.RequestBodyLimitMB > 0 {
		lines = append(lines, fmt.Sprintf("    client_max_body_size %dm;", plan.Limits.RequestBodyLimitMB))
	}
	if plan.Limits.Compression {
		lines = append(lines, "    gzip on;", "    gzip_types text/plain text/css application/json application/javascript application/xml image/svg+xml;")
	}
	switch plan.Limits.SecurityHeaderPreset {
	case "strict":
		lines = append(lines, `    add_header X-Content-Type-Options "nosniff" always;`, `    add_header Referrer-Policy "strict-origin-when-cross-origin" always;`, `    add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'" always;`)
	case "balanced":
		lines = append(lines, `    add_header X-Content-Type-Options "nosniff" always;`, `    add_header Referrer-Policy "strict-origin-when-cross-origin" always;`)
	}
	cidrs := strings.FieldsFunc(plan.Limits.AllowedCIDRs, func(r rune) bool { return r == ',' || r == ' ' })
	for _, cidr := range cidrs {
		lines = append(lines, "    allow "+cidr+";")
	}
	if len(cidrs) > 0 {
		lines = append(lines, "    deny all;")
	}
	if plan.Limits.ErrorDocument404 != "" {
		lines = append(lines, "    error_page 404 "+plan.Limits.ErrorDocument404+";")
	}
	if plan.Limits.ErrorDocument50X != "" {
		lines = append(lines, "    error_page 500 502 503 504 "+plan.Limits.ErrorDocument50X+";")
	}
	return strings.Join(lines, "\n")
}

func nginxServerNames(plan SitePlan) string {
	if !strings.HasPrefix(plan.Domain, "www.") && plan.Limits.PreferredDomain != "" && plan.Limits.PreferredDomain != "none" {
		return plan.Domain + " www." + plan.Domain
	}
	return plan.Domain
}

func renderNginxPHPControls(plan SitePlan) string {
	var lines []string
	if plan.Limits.ConnectTimeoutSeconds > 0 {
		lines = append(lines, fmt.Sprintf("        fastcgi_connect_timeout %ds;", plan.Limits.ConnectTimeoutSeconds))
	}
	if plan.Limits.ReadTimeoutSeconds > 0 {
		lines = append(lines, fmt.Sprintf("        fastcgi_read_timeout %ds;", plan.Limits.ReadTimeoutSeconds))
	}
	if plan.Limits.FastCGIMicrocache {
		lines = append(lines,
			fmt.Sprintf("        fastcgi_cache %s;", plan.NginxCacheZone),
			`        fastcgi_cache_key "$scheme$request_method$host$request_uri";`,
			"        fastcgi_cache_methods GET HEAD;",
			"        fastcgi_cache_valid 200 1s;",
			"        fastcgi_cache_bypass $cookie_PHPSESSID $http_authorization;",
			"        fastcgi_no_cache $cookie_PHPSESSID $http_authorization;",
		)
	}
	return strings.Join(lines, "\n")
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
    index %[10]s;
%[11]s

    ssl_certificate %[7]s;
    ssl_certificate_key %[8]s;
    ssl_protocols TLSv1.2 TLSv1.3;

    access_log %[3]s;
    error_log %[4]s;
    location / {
%[9]s
        try_files $uri $uri/ /index.php?$query_string;
    }
    location ~ \.php$ {
        include %[5]s;
%[12]s
        fastcgi_pass unix:%[6]s;
    }
    location ~ /\. { deny all; }
}
`, nginxServerNames(plan), plan.Docroot, plan.NginxAccessLog, plan.NginxErrorLog, plan.NginxSnippet, plan.PHPFPMSocket, certPath, keyPath, renderNginxLocationControls(plan), nginxIndexFiles(plan), renderNginxServerControls(plan), renderNginxPHPControls(plan))
}

func (p *SiteProvisioner) ApplySiteRuntime(ctx context.Context, req types.ApplySiteRuntimeReq) (err error) {
	siteConfigMutationMu.Lock()
	defer siteConfigMutationMu.Unlock()

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
	current, err := NewSitePlan(types.CreateSiteReq{SiteID: req.SiteID, Username: req.Username, Domain: req.Domain, PHPVersion: currentVersion, SharedAccount: req.SharedAccount, Limits: req.Limits}, p.paths)
	if err != nil {
		return err
	}
	desired, err := NewSitePlan(types.CreateSiteReq{SiteID: req.SiteID, Username: req.Username, Domain: req.Domain, PHPVersion: req.DesiredPHPVersion, SharedAccount: req.SharedAccount, Limits: req.Limits}, p.paths)
	if err != nil {
		return err
	}
	if err := ensureSiteAuxiliaryIncludes(desired); err != nil {
		return err
	}
	if err := ensurePrivateSiteRuntimeArtifacts(current); err != nil {
		return err
	}
	if err := ensurePrivateSiteRuntimeArtifacts(desired); err != nil {
		return err
	}

	paths := []string{current.NginxConfig, desired.NginxEnabled, desired.NginxPolicyConfig, current.PHPFPMConfig, current.PHPFPMConfig + ".suspended", desired.PHPFPMConfig, desired.PHPFPMConfig + ".suspended"}
	if current.PHPServiceUnit != "" {
		paths = append(paths, current.PHPServiceUnit)
	}
	if desired.PHPServiceUnit != "" && desired.PHPServiceUnit != current.PHPServiceUnit {
		paths = append(paths, desired.PHPServiceUnit)
	}
	snapshots, err := snapshotFiles(paths)
	if err != nil {
		return err
	}
	defer func() {
		if err == nil {
			return
		}
		_ = restoreSnapshots(snapshots)
		_ = p.reloader.ReloadService(context.Background(), current.PHPServiceName)
		if current.PHPVersion != desired.PHPVersion {
			_ = p.reloader.ReloadService(context.Background(), desired.PHPServiceName)
		}
		_ = p.reloader.ReloadService(context.Background(), "nginx")
	}()
	if zones := RenderNginxPolicyZones(desired); zones != "" {
		if err = writeFileAtomic(desired.NginxPolicyConfig, []byte(zones), sitePrivateRuntimeFileMode); err != nil {
			return err
		}
	} else if err = os.Remove(desired.NginxPolicyConfig); err != nil && !os.IsNotExist(err) {
		return err
	}

	if state == "suspended" {
		if err = writeFileAtomic(desired.NginxConfig, []byte(RenderSuspendedNginxVHost(desired)), sitePrivateRuntimeFileMode); err != nil {
			return err
		}
		if err = p.reloader.ReloadService(ctx, "nginx"); err != nil {
			return err
		}
		if err = writeFileAtomic(desired.PHPFPMConfig+".suspended", []byte(RenderPHPFPMPool(desired)), sitePrivateRuntimeFileMode); err != nil {
			return err
		}
		_ = os.Remove(desired.PHPFPMConfig)
		if current.PHPVersion != desired.PHPVersion && current.PHPFPMConfig != desired.PHPFPMConfig {
			_ = os.Remove(current.PHPFPMConfig)
			_ = os.Remove(current.PHPFPMConfig + ".suspended")
		}
	} else {
		if err = writeFileAtomic(desired.PHPFPMConfig, []byte(RenderPHPFPMPool(desired)), sitePrivateRuntimeFileMode); err != nil {
			return err
		}
		if desired.PHPServiceUnit != "" {
			if err = writeFileAtomic(desired.PHPServiceUnit, []byte(RenderPHPFPMUnit(desired)), 0o644); err != nil {
				return err
			}
		}
		_ = os.Remove(desired.PHPFPMConfig + ".suspended")
		if err = writeFileAtomic(desired.NginxConfig, []byte(RenderNginxRuntimeVHost(desired, req.TLSCertPath, req.TLSKeyPath, req.HTTPSRedirect)), sitePrivateRuntimeFileMode); err != nil {
			return err
		}
		if err = ensureSymlink(desired.NginxConfig, desired.NginxEnabled); err != nil {
			return err
		}
		if current.PHPVersion != desired.PHPVersion && current.PHPFPMConfig != desired.PHPFPMConfig {
			_ = os.Remove(current.PHPFPMConfig)
			_ = os.Remove(current.PHPFPMConfig + ".suspended")
		}
	}
	if err = p.validateSiteConfig(ctx, desired, state == "active"); err != nil {
		return err
	}
	if state == "suspended" && desired.SiteID > 0 {
		controller, ok := p.reloader.(interface {
			StopService(context.Context, string) error
		})
		if !ok {
			return errors.New("dedicated PHP service controller is not configured")
		}
		if err = controller.StopService(ctx, desired.PHPServiceName); err != nil {
			return err
		}
	} else if err = p.reloader.ReloadService(ctx, desired.PHPServiceName); err != nil {
		return err
	}
	if current.PHPVersion != desired.PHPVersion && current.PHPServiceName != desired.PHPServiceName {
		if err = p.reloader.ReloadService(ctx, current.PHPServiceName); err != nil {
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
	desired, err := NewSitePlan(types.CreateSiteReq{SiteID: req.SiteID, Username: req.Username, Domain: req.Domain, PHPVersion: req.DesiredPHPVersion, SharedAccount: req.SharedAccount, Limits: req.Limits}, p.paths)
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
	desiredZones := []byte(RenderNginxPolicyZones(desired))
	currentZones, zoneErr := os.ReadFile(desired.NginxPolicyConfig)
	if os.IsNotExist(zoneErr) && len(desiredZones) > 0 {
		return true, nil
	}
	if len(desiredZones) == 0 && os.IsNotExist(zoneErr) {
		currentZones = nil
		zoneErr = nil
	}
	if zoneErr != nil {
		return false, zoneErr
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
	if !bytes.Equal(nginxCurrent, nginx) || !bytes.Equal(phpCurrent, []byte(RenderPHPFPMPool(desired))) || !bytes.Equal(currentZones, desiredZones) {
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
	siteConfigMutationMu.Lock()
	defer siteConfigMutationMu.Unlock()

	state := strings.ToLower(strings.TrimSpace(req.State))
	if state != "active" && state != "suspended" {
		return fmt.Errorf("hosting state must be active or suspended")
	}
	paths := fillSitePathDefaults(p.paths)
	plan, err := NewSitePlan(types.CreateSiteReq{SiteID: req.SiteID, Username: req.Username, Domain: req.Domain, PHPVersion: req.PHPVersion}, paths)
	if err != nil {
		return err
	}
	if p.reloader == nil {
		return errors.New("service reloader is not configured")
	}
	if err := ensurePrivateSiteRuntimeArtifacts(plan); err != nil {
		return err
	}
	suspendedPool := plan.PHPFPMConfig + ".suspended"
	if state == "suspended" {
		if err := writeFileAtomic(plan.NginxConfig, []byte(RenderSuspendedNginxVHost(plan)), sitePrivateRuntimeFileMode); err != nil {
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
		if p.nginxTest != nil {
			if err := p.nginxTest.TestNginxConfig(ctx); err != nil {
				return err
			}
		}
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
		if plan.SiteID > 0 {
			controller, ok := p.reloader.(interface {
				StopService(context.Context, string) error
			})
			if !ok {
				return errors.New("dedicated PHP service controller is not configured")
			}
			if err := controller.StopService(ctx, plan.PHPServiceName); err != nil {
				return err
			}
		} else if err := p.reloader.ReloadService(ctx, plan.PHPServiceName); err != nil {
			return err
		}
		if p.nginxTest != nil {
			if err := p.nginxTest.TestNginxConfig(ctx); err != nil {
				return err
			}
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
		if err := writeFileAtomic(plan.NginxConfig, []byte(RenderNginxVHost(plan)), sitePrivateRuntimeFileMode); err != nil {
			return fmt.Errorf("restore nginx config: %w", err)
		}
		if plan.PHPServiceUnit != "" {
			if err := writeFileAtomic(plan.PHPServiceUnit, []byte(RenderPHPFPMUnit(plan)), 0o644); err != nil {
				return err
			}
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
	if err := p.validateSiteConfig(ctx, plan, state == "active"); err != nil {
		return err
	}
	if err := p.reloader.ReloadService(ctx, plan.PHPServiceName); err != nil {
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
	maxRequests := plan.Limits.PHPFPMMaxRequests
	if maxRequests <= 0 {
		maxRequests = 500
	}
	var phpSettings []string
	advancedSettings := plan.Limits.PHPFPMMaxRequests != 0 || plan.Limits.PHPMaxExecutionSeconds != 0 || plan.Limits.PHPMaxInputSeconds != 0 || plan.Limits.PHPPostMaxMB != 0 || plan.Limits.PHPUploadMaxMB != 0 || plan.Limits.PHPDisplayErrors || plan.Limits.PHPLogErrors || plan.Limits.PHPAllowURLFOpen || plan.Limits.PHPExecEnabled
	for name, value := range map[string]int{"max_execution_time": plan.Limits.PHPMaxExecutionSeconds, "max_input_time": plan.Limits.PHPMaxInputSeconds, "post_max_size": plan.Limits.PHPPostMaxMB, "upload_max_filesize": plan.Limits.PHPUploadMaxMB} {
		if value > 0 {
			suffix := ""
			if strings.Contains(name, "size") {
				suffix = "M"
			}
			phpSettings = append(phpSettings, fmt.Sprintf("php_admin_value[%s] = %d%s", name, value, suffix))
		}
	}
	sort.Strings(phpSettings)
	if advancedSettings {
		phpSettings = append(phpSettings,
			fmt.Sprintf("php_admin_flag[display_errors] = %s", onOff(plan.Limits.PHPDisplayErrors)),
			fmt.Sprintf("php_admin_flag[log_errors] = %s", onOff(plan.Limits.PHPLogErrors)),
			fmt.Sprintf("php_admin_flag[allow_url_fopen] = %s", onOff(plan.Limits.PHPAllowURLFOpen)),
		)
		if !plan.Limits.PHPExecEnabled {
			phpSettings = append(phpSettings, "php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen")
		}
	}
	if plan.Limits.PHPOPcacheEnabled {
		memory := plan.Limits.PHPOPcacheMemoryMB
		if memory <= 0 {
			memory = 64
		}
		phpSettings = append(phpSettings,
			"php_admin_flag[opcache.enable] = on",
			fmt.Sprintf("php_admin_value[opcache.memory_consumption] = %d", memory),
		)
	}
	settingsBlock := strings.Join(phpSettings, "\n")
	if settingsBlock != "" {
		settingsBlock += "\n"
	}
	mode := plan.Limits.PHPFPMMode
	if mode == "" {
		mode = "ondemand"
	}
	idleTimeout := plan.Limits.PHPFPMIdleTimeoutSecs
	if idleTimeout <= 0 {
		idleTimeout = 10
	}
	modeSettings := fmt.Sprintf("pm.process_idle_timeout = %ds", idleTimeout)
	if mode == "dynamic" {
		start := min(2, maxChildren)
		minSpare := min(1, maxChildren)
		maxSpare := min(3, maxChildren)
		modeSettings = fmt.Sprintf("pm.start_servers = %d\npm.min_spare_servers = %d\npm.max_spare_servers = %d", start, minSpare, maxSpare)
	} else if mode == "static" {
		modeSettings = ""
	}
	requestTerminate := ""
	if plan.Limits.PHPRequestTerminateSecs > 0 {
		requestTerminate = fmt.Sprintf("request_terminate_timeout = %ds\n", plan.Limits.PHPRequestTerminateSecs)
	}
	pool := fmt.Sprintf(`[%[1]s]
user = %[2]s
group = %[2]s
listen = %[3]s
listen.owner = %[4]s
listen.group = %[4]s
listen.mode = 0660

pm = %[12]s
pm.max_children = %[8]d
%[13]s
pm.max_requests = %[10]d
%[14]s

chdir = /
catch_workers_output = yes
clear_env = yes
security.limit_extensions = .php
php_admin_value[error_log] = %[5]s
php_admin_flag[log_errors] = on
%[9]s%[11]sphp_admin_value[open_basedir] = %[6]s:%[7]s
`, plan.PHPFPMPool, plan.Username, plan.PHPFPMSocket, plan.WWWGroup, plan.PHPFPMErrorLog, plan.Docroot, plan.PHPTmpDir, maxChildren, memoryLimit, maxRequests, settingsBlock, mode, modeSettings, requestTerminate)
	if plan.SiteID <= 0 {
		return pool
	}
	pidPath := filepath.Join(filepath.Dir(plan.PHPFPMSocket), fmt.Sprintf("site-%d.pid", plan.SiteID))
	return fmt.Sprintf(`[global]
pid = %[1]s
error_log = %[2]s
daemonize = no

%[3]s`, pidPath, plan.PHPFPMErrorLog, pool)
}

const phpSessionDirectory = "/var/lib/php/sessions"

func RenderPHPFPMUnit(plan SitePlan) string {
	return fmt.Sprintf(`[Unit]
Description=Nakpanel PHP-FPM for site %d
After=network.target

[Service]
Type=simple
ExecStartPre=/usr/sbin/php-fpm%s -t -y %s
ExecStart=/usr/sbin/php-fpm%s --nodaemonize -y %s
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s %s %s %s
RuntimeDirectory=nakpanel-php
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
MemoryMax=%dM
TasksMax=128

[Install]
WantedBy=multi-user.target
	`, plan.SiteID, plan.PHPVersion, plan.PHPFPMConfig, plan.PHPVersion, plan.PHPFPMConfig, plan.Docroot, filepath.Dir(plan.PHPFPMErrorLog), filepath.Dir(plan.PHPFPMSocket), phpSessionDirectory, phpFPMUnitMemoryMaxMB(plan))
}

func phpFPMUnitMemoryMaxMB(plan SitePlan) int {
	memoryPerWorker := plan.Limits.PHPMemoryMB
	if memoryPerWorker <= 0 {
		memoryPerWorker = 128
	}
	children := plan.Limits.PHPFPMMaxChildren
	if children <= 0 {
		children = 8
	}
	opcache := 0
	if plan.Limits.PHPOPcacheEnabled {
		opcache = plan.Limits.PHPOPcacheMemoryMB
		if opcache <= 0 {
			opcache = 64
		}
	}
	// Reserve a small fixed allowance for the FPM master and shared runtime
	// structures in addition to the configured worker and OPcache ceilings.
	return children*memoryPerWorker + opcache + 64
}

func onOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

func (p *SiteProvisioner) CreateSite(ctx context.Context, req types.CreateSiteReq) (err error) {
	siteConfigMutationMu.Lock()
	defer siteConfigMutationMu.Unlock()

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
		filepath.Dir(plan.NginxPolicyConfig),
		filepath.Dir(plan.NginxProtectedConfig),
		filepath.Dir(plan.NginxApplicationConfig),
		filepath.Dir(plan.PHPFPMErrorLog),
		plan.PHPTmpDir,
		plan.NginxCachePath,
	} {
		homeRoot := fillSitePathDefaults(p.paths).HomeRoot
		rel, relErr := filepath.Rel(homeRoot, dir)
		var mkdirErr error
		if relErr == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			mkdirErr = ensureManagedDirectory(homeRoot, dir, 0o755)
		} else {
			mkdirErr = os.MkdirAll(dir, 0o755)
		}
		if mkdirErr != nil {
			return fmt.Errorf("create directory %q: %w", dir, mkdirErr)
		}
	}
	if err := ensureSiteAuxiliaryIncludes(plan); err != nil {
		return err
	}
	if err := ensurePrivateSiteRuntimeArtifacts(plan); err != nil {
		return err
	}
	siteModes := map[string]os.FileMode{plan.Docroot: 0o750}
	if !req.SharedAccount {
		siteModes[plan.SiteHome] = 0o700
	}
	for path, mode := range siteModes {
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("chmod directory %q: %w", path, err)
		}
	}
	if req.SharedAccount {
		for _, path := range []string{filepath.Join(plan.SiteHome, "domains"), filepath.Dir(plan.Docroot)} {
			if err := secureDirectoryAnchor(path, 0, 0, 0o711); err != nil {
				return fmt.Errorf("chmod shared account directory %q: %w", path, err)
			}
		}
	}
	if os.Geteuid() == 0 && fillSitePathDefaults(p.paths).HomeRoot == "/home" {
		traversalPaths := []string{plan.SiteHome}
		if req.SharedAccount {
			traversalPaths = []string{filepath.Join(plan.SiteHome, "domains"), filepath.Dir(plan.Docroot)}
		}
		for _, path := range traversalPaths {
			if _, err := p.runner.Run(ctx, "setfacl", "-m", "u:www-data:--x", path); err != nil {
				return fmt.Errorf("grant nginx traversal for %q: %w", path, err)
			}
		}
	}
	snapshotPaths := []string{plan.NginxConfig, plan.NginxEnabled, plan.NginxPolicyConfig, plan.PHPFPMConfig}
	if plan.PHPServiceUnit != "" {
		snapshotPaths = append(snapshotPaths, plan.PHPServiceUnit)
	}
	snapshots, err := snapshotFiles(snapshotPaths)
	if err != nil {
		return err
	}
	defer func() {
		if err == nil {
			return
		}
		_ = restoreSnapshots(snapshots)
		_ = p.reloader.ReloadService(context.Background(), plan.PHPServiceName)
		_ = p.reloader.ReloadService(context.Background(), "nginx")
	}()

	indexPath := filepath.Join(plan.Docroot, "index.php")
	if _, statErr := os.Stat(indexPath); os.IsNotExist(statErr) {
		if err := writeFileAtomic(indexPath, []byte(renderPlaceholderIndex(plan)), plan.FileMode); err != nil {
			return fmt.Errorf("write placeholder index: %w", err)
		}
	}
	if err := writeFileAtomic(plan.NginxConfig, []byte(RenderNginxVHost(plan)), sitePrivateRuntimeFileMode); err != nil {
		return fmt.Errorf("write nginx site config: %w", err)
	}
	if zones := RenderNginxPolicyZones(plan); zones != "" {
		if err := writeFileAtomic(plan.NginxPolicyConfig, []byte(zones), sitePrivateRuntimeFileMode); err != nil {
			return fmt.Errorf("write nginx policy zones: %w", err)
		}
	} else if err := os.Remove(plan.NginxPolicyConfig); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := ensureSymlink(plan.NginxConfig, plan.NginxEnabled); err != nil {
		return fmt.Errorf("enable nginx site: %w", err)
	}
	if err := writeFileAtomic(plan.PHPFPMConfig, []byte(RenderPHPFPMPool(plan)), sitePrivateRuntimeFileMode); err != nil {
		return fmt.Errorf("write php-fpm pool config: %w", err)
	}
	if plan.PHPServiceUnit != "" {
		if err := writeFileAtomic(plan.PHPServiceUnit, []byte(RenderPHPFPMUnit(plan)), 0o644); err != nil {
			return fmt.Errorf("write dedicated php-fpm unit: %w", err)
		}
	}
	if err := p.validateSiteConfig(ctx, plan, true); err != nil {
		return err
	}
	if p.ownership != nil {
		ownershipRoot := plan.SiteHome
		if req.SharedAccount {
			// The domain directory is a root-owned chroot anchor. Tenant
			// ownership starts at public_html so the account cannot rename or
			// replace the domain boundary.
			ownershipRoot = plan.Docroot
		}
		if err := p.ownership.ChownRecursive(ctx, ownershipRoot, plan.Username); err != nil {
			return fmt.Errorf("chown site content: %w", err)
		}
	}
	if err := secureHostedDocumentTree(plan.Docroot); err != nil {
		return fmt.Errorf("grant nginx document-root access: %w", err)
	}
	if plan.Limits.DiskQuotaMB > 0 {
		if p.diskQuotas == nil {
			return errors.New("disk quota manager is not configured")
		}
		if err := p.diskQuotas.ApplyUserQuota(ctx, plan.Username, plan.SiteHome, plan.Limits.DiskQuotaMB); err != nil {
			return fmt.Errorf("apply site disk quota: %w", err)
		}
	}

	if err := p.reloader.ReloadService(ctx, plan.PHPServiceName); err != nil {
		return err
	}
	if plan.SiteID > 0 && strings.HasPrefix(plan.PHPFPMSocket, "/run/") {
		if err := waitForUnixSocket(ctx, plan.PHPFPMSocket, 3*time.Second); err != nil {
			return fmt.Errorf("wait for dedicated PHP-FPM socket: %w", err)
		}
	}
	if err := p.reloader.ReloadService(ctx, "nginx"); err != nil {
		return err
	}
	return nil
}

func ensureSiteAuxiliaryIncludes(plan SitePlan) error {
	if plan.SiteID <= 0 {
		return nil
	}
	files := []struct {
		path    string
		content string
		label   string
	}{
		{
			path: plan.NginxProtectedConfig, label: "protected-directory",
			content: "# Managed by Nakpanel. No protected directories configured.\n",
		},
		{
			path: plan.NginxApplicationConfig, label: "application-route",
			content: "# Managed by Nakpanel. No application routes configured.\nerror_page 418 = @nakpanel_application;\nlocation @nakpanel_application { return 404; }\n",
		},
	}
	for _, file := range files {
		if err := os.MkdirAll(filepath.Dir(file.path), 0o755); err != nil {
			return fmt.Errorf("create %s include directory: %w", file.label, err)
		}
		if _, err := os.Stat(file.path); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect %s include: %w", file.label, err)
		}
		if err := writeFileAtomic(file.path, []byte(file.content), 0o600); err != nil {
			return fmt.Errorf("initialize %s include: %w", file.label, err)
		}
	}
	return nil
}

func ensurePrivateSiteRuntimeArtifacts(plan SitePlan) error {
	for _, path := range []string{plan.NginxAccessLog, plan.NginxErrorLog, plan.PHPFPMErrorLog} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("create private site log directory %q: %w", filepath.Dir(path), err)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, sitePrivateRuntimeFileMode)
		if err != nil {
			return fmt.Errorf("initialize private site log %q: %w", path, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close private site log %q: %w", path, err)
		}
		if err := os.Chmod(path, sitePrivateRuntimeFileMode); err != nil {
			return fmt.Errorf("secure site log %q: %w", path, err)
		}
	}
	for _, path := range []string{
		plan.NginxConfig,
		plan.NginxPolicyConfig,
		plan.PHPFPMConfig,
		plan.PHPFPMConfig + ".suspended",
	} {
		if err := os.Chmod(path, sitePrivateRuntimeFileMode); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("secure site runtime file %q: %w", path, err)
		}
	}
	return nil
}

func waitForUnixSocket(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		info, err := os.Stat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("socket %q did not become ready", path)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (p *SiteProvisioner) validateSiteConfig(ctx context.Context, plan SitePlan, withPHP bool) error {
	if withPHP && plan.SiteID > 0 && p.phpTest != nil {
		if err := p.phpTest.TestPHPConfig(ctx, plan.PHPVersion, plan.PHPFPMConfig); err != nil {
			return err
		}
	}
	if p.nginxTest != nil {
		if err := p.nginxTest.TestNginxConfig(ctx); err != nil {
			return err
		}
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
	HomeRoot     string
	MarkerDir    string
	Runner       CommandRunner
	ManageSubIDs bool
	SubUIDPath   string
	SubGIDPath   string
}

type LinuxUserManager struct {
	homeRoot     string
	markerDir    string
	runner       CommandRunner
	manageSubIDs bool
	subUIDPath   string
	subGIDPath   string
}

func NewLinuxUserManager(opts LinuxUserManagerOptions) *LinuxUserManager {
	homeRoot := opts.HomeRoot
	if homeRoot == "" {
		homeRoot = DefaultSitePathConfig().HomeRoot
	}
	markerDir := opts.MarkerDir
	if markerDir == "" {
		markerDir = "/var/lib/nakpanel/system-users"
	}
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	subUIDPath := opts.SubUIDPath
	if subUIDPath == "" {
		subUIDPath = "/etc/subuid"
	}
	subGIDPath := opts.SubGIDPath
	if subGIDPath == "" {
		subGIDPath = "/etc/subgid"
	}
	return &LinuxUserManager{
		homeRoot: homeRoot, markerDir: markerDir, runner: runner,
		manageSubIDs: opts.ManageSubIDs, subUIDPath: subUIDPath, subGIDPath: subGIDPath,
	}
}

func (m *LinuxUserManager) EnsureUser(ctx context.Context, username string) error {
	if err := site.ValidateUsername(username); err != nil {
		return err
	}
	systemUserMutationMu.Lock()
	defer systemUserMutationMu.Unlock()
	if out, err := m.runner.Run(ctx, "getent", "passwd", username); err == nil {
		uid, home, parseErr := managedPasswdEntry(username, out, m.homeRoot)
		if parseErr != nil {
			return parseErr
		}
		if err := m.verifyMarker(username, uid, home); err != nil {
			return fmt.Errorf("refusing to adopt existing account %q: %w", username, err)
		}
		return m.ensureSubordinateIDs(ctx, username, uid)
	}
	if err := m.removeStaleMarker(username); err != nil {
		return fmt.Errorf("clean stale account marker %q: %w", username, err)
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
	out, err := m.runner.Run(ctx, "getent", "passwd", username)
	if err != nil {
		_, _ = m.runner.Run(ctx, "userdel", "--remove", username)
		return fmt.Errorf("lookup newly-created account %q: %w", username, err)
	}
	uid, home, err := managedPasswdEntry(username, out, m.homeRoot)
	if err != nil {
		_, _ = m.runner.Run(ctx, "userdel", "--remove", username)
		return err
	}
	if err := m.writeMarker(username, uid, home, true); err != nil {
		_, _ = m.runner.Run(ctx, "userdel", "--remove", username)
		_ = os.Remove(m.markerPath(username))
		return fmt.Errorf("mark newly-created account %q: %w", username, err)
	}
	return m.ensureSubordinateIDs(ctx, username, uid)
}

func (m *LinuxUserManager) ensureSubordinateIDs(ctx context.Context, username string, uid int) error {
	if !m.manageSubIDs {
		return nil
	}
	if uid <= 0 {
		return errors.New("valid uid is required for subordinate id allocation")
	}
	const allocationSize = 65536
	start := 100000000 + uid*allocationSize
	end := start + allocationSize - 1
	for _, item := range []struct {
		path string
		flag string
		kind string
	}{
		{m.subUIDPath, "--add-subuids", "uid"},
		{m.subGIDPath, "--add-subgids", "gid"},
	} {
		present, err := subordinateIDRangeReady(item.path, username, allocationSize)
		if err != nil {
			return fmt.Errorf("read subordinate %s map: %w", item.kind, err)
		}
		if present {
			continue
		}
		if _, err := m.runner.Run(ctx, "usermod", item.flag, fmt.Sprintf("%d-%d", start, end), username); err != nil {
			return fmt.Errorf("allocate subordinate %s range for %q: %w", item.kind, username, err)
		}
		present, err = subordinateIDRangeReady(item.path, username, allocationSize)
		if err != nil || !present {
			return fmt.Errorf("subordinate %s range for %q was not persisted", item.kind, username)
		}
	}
	return nil
}

func subordinateIDEntryExists(path, username string) (bool, error) {
	return subordinateIDRangeReady(path, username, 1)
}

func subordinateIDRangeReady(path, username string, minimumCount int) (bool, error) {
	if minimumCount < 1 {
		return false, errors.New("minimum subordinate id count must be positive")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) != 3 || fields[0] != username {
			continue
		}
		start, startErr := strconv.ParseUint(fields[1], 10, 64)
		count, countErr := strconv.ParseUint(fields[2], 10, 64)
		if startErr != nil || countErr != nil || start == 0 || count < uint64(minimumCount) ||
			start > ^uint64(0)-count {
			continue
		}
		return true, nil
	}
	return false, nil
}

// AdoptLegacyUser is called only by the explicit subscription migration path.
// It records ownership of a pre-marker Nakpanel account after verifying that
// the account is confined to the expected managed home.
func (m *LinuxUserManager) AdoptLegacyUser(ctx context.Context, username string) error {
	if err := site.ValidateUsername(username); err != nil {
		return err
	}
	systemUserMutationMu.Lock()
	defer systemUserMutationMu.Unlock()
	out, err := m.runner.Run(ctx, "getent", "passwd", username)
	if err != nil {
		return nil
	}
	uid, home, err := managedPasswdEntry(username, out, m.homeRoot)
	if err != nil {
		return err
	}
	if err := m.verifyMarker(username, uid, home); err == nil {
		return nil
	}
	return m.writeMarker(username, uid, home, false)
}

func (m *LinuxUserManager) removeStaleMarker(username string) error {
	path := m.markerPath(username)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("stale Nakpanel ownership marker has unsafe type or permissions")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("stale Nakpanel ownership marker has an unexpected owner")
	}
	return os.Remove(path)
}

func managedPasswdEntry(username string, out []byte, homeRoot string) (int, string, error) {
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) < 6 {
		return 0, "", fmt.Errorf("unexpected passwd entry for %q", username)
	}
	uid, err := strconv.Atoi(fields[2])
	if err != nil || uid <= 0 {
		return 0, "", fmt.Errorf("invalid uid for account %q", username)
	}
	home := filepath.Clean(fields[5])
	wantHome := filepath.Join(homeRoot, username)
	if home != wantHome {
		return 0, "", fmt.Errorf("account %q has home %q, expected %q", username, home, wantHome)
	}
	return uid, home, nil
}

func (m *LinuxUserManager) markerPath(username string) string {
	return filepath.Join(m.markerDir, username)
}

func (m *LinuxUserManager) verifyMarker(username string, uid int, home string) error {
	path := m.markerPath(username)
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("Nakpanel ownership marker is missing")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("Nakpanel ownership marker has unsafe type or permissions")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("Nakpanel ownership marker has an unexpected owner")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(contents)) != fmt.Sprintf("%d:%s", uid, home) {
		return errors.New("Nakpanel ownership marker does not match the account")
	}
	return nil
}

func (m *LinuxUserManager) writeMarker(username string, uid int, home string, exclusive bool) error {
	if err := os.MkdirAll(m.markerDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(m.markerDir, 0o700); err != nil {
		return err
	}
	flag := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if exclusive {
		flag |= os.O_EXCL
	}
	file, err := os.OpenFile(m.markerPath(username), flag, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintf(file, "%d:%s\n", uid, home)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
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
	// -h/--no-dereference operates on symlinks themselves and -R with the
	// default -P never traverses a symlink, so a tenant symlink planted inside
	// the tree (e.g. public_html/evil -> /etc) is re-owned as a link, not
	// followed. "--" stops any path that looks like an option. This makes the
	// symlink-safety local to our code instead of relying on chown's default.
	output, err := m.runner.Run(ctx, "chown", "-h", "-R", "--", username+":"+username, path)
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
	if paths.NginxConfDir == "" {
		paths.NginxConfDir = defaults.NginxConfDir
	}
	if paths.NginxCacheDir == "" {
		paths.NginxCacheDir = defaults.NginxCacheDir
	}
	if paths.NginxProtectedDir == "" {
		paths.NginxProtectedDir = defaults.NginxProtectedDir
	}
	if paths.PHPFPMPoolDir == "" {
		paths.PHPFPMPoolDir = defaults.PHPFPMPoolDir
	}
	if paths.PHPFPMDedicatedDir == "" {
		paths.PHPFPMDedicatedDir = defaults.PHPFPMDedicatedDir
	}
	if paths.PHPFPMDedicatedRunDir == "" {
		paths.PHPFPMDedicatedRunDir = defaults.PHPFPMDedicatedRunDir
	}
	if paths.PHPFPMLogDir == "" {
		paths.PHPFPMLogDir = defaults.PHPFPMLogDir
	}
	if paths.PHPRunDir == "" {
		paths.PHPRunDir = defaults.PHPRunDir
	}
	if paths.SystemdUnitDir == "" {
		paths.SystemdUnitDir = defaults.SystemdUnitDir
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
