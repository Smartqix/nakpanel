package ops

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

// siteCleanupPlan contains only deterministic artifact identities. It cannot
// supply a PHP executable or stand in for a validated runtime descriptor.
type siteCleanupPlan struct {
	SiteSlug               string
	SiteHome               string
	Docroot                string
	ACMEWebroot            string
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
}

// siteFileLayout is shared by live planning (after strict runtime resolution)
// and cleanup (after destructive identity validation). No executable is selected.
func siteFileLayout(normalized types.CreateSiteReq, paths SitePathConfig, poolDir string) siteCleanupPlan {
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
		paths.PHPFPMPoolDir = poolDir
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

	return siteCleanupPlan{
		SiteSlug:               slug,
		SiteHome:               siteHome,
		Docroot:                docroot,
		ACMEWebroot:            filepath.Join(paths.ACMEChallengeRoot, normalized.Domain),
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
	}
}

func newSiteCleanupPlan(id types.SiteIdentity, version string, paths SitePathConfig, poolDir string) (siteCleanupPlan, error) {
	if err := site.ValidateUsername(id.Username); err != nil {
		return siteCleanupPlan{}, err
	}
	if err := site.ValidateDomain(id.Domain); err != nil {
		return siteCleanupPlan{}, err
	}
	if id.Domain != site.NormalizeDomain(id.Domain) || id.SiteID < 0 || id.SubscriptionID < 0 {
		return siteCleanupPlan{}, errors.New("invalid cleanup identity")
	}
	if version != "" && !phpVersionDirectoryRE.MatchString(version) || id.SiteID == 0 && version == "" {
		return siteCleanupPlan{}, errors.New("invalid historical PHP directory")
	}
	return siteFileLayout(types.CreateSiteReq{SiteID: id.SiteID, SubscriptionID: id.SubscriptionID, Username: id.Username, Domain: id.Domain, PHPVersion: version, SharedAccount: true}, paths, poolDir), nil
}

func legacySiteCleanupPlans(id types.SiteIdentity, version string, paths SitePathConfig) ([]siteCleanupPlan, error) {
	id.SiteID = 0
	if !phpVersionDirectoryRE.MatchString(version) {
		return nil, errors.New("invalid historical PHP directory")
	}
	pools := []string{paths.PHPFPMPoolDir}
	if pools[0] == "" {
		pools = []string{filepath.Join("/etc/php", version, "fpm/pool.d"), filepath.Join("/opt/nakpanel/php", version, "etc/fpm/pool.d")}
	}
	plans := make([]siteCleanupPlan, 0, len(pools))
	for _, pool := range pools {
		root := pool
		if paths.PHPFPMPoolDir == "" {
			root = "/etc/php"
			if strings.HasPrefix(pool, "/opt/nakpanel/php/") {
				root = "/opt"
			}
		}
		if err := validateHistoricalPHPPoolRoot(root, pool); err != nil {
			return nil, err
		}
		if !filepath.IsAbs(pool) || filepath.Clean(pool) == string(filepath.Separator) {
			return nil, errors.New("invalid historical PHP pool root")
		}
		plan, err := newSiteCleanupPlan(id, version, paths, pool)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

// Canonical provider inventories are bounded at /etc/php and /opt, so every
// provider/version child is checked. An explicit custom pool directory is
// trusted host configuration and establishes its own boundary; it still may
// not itself be a symlink or contain an unsafe leaf.
func validateHistoricalPHPPoolRoot(root, pool string) error {
	if !filepath.IsAbs(root) || !filepath.IsAbs(pool) || filepath.Clean(root) == string(filepath.Separator) {
		return errors.New("invalid historical PHP pool boundary")
	}
	return ensureNoSymlinkComponents(root, pool)
}

// A retired/absent pool needs only file cleanup. Executing or reloading a live
// shared service still requires the authoritative, validated provider mapping.
func activePHPRuntimeForCleanup(ctx context.Context, runner CommandRunner, resolver PHPRuntimeResolver, version string) (PHPRuntimeDescriptor, bool, error) {
	if !phpVersionDirectoryRE.MatchString(version) {
		return PHPRuntimeDescriptor{}, false, errors.New("invalid cleanup PHP service")
	}
	unit := "php" + version + "-fpm.service"
	output, err := runner.Run(ctx, "systemctl", "show", "--property=LoadState", "--property=ActiveState", "--no-pager", unit)
	if err != nil {
		return PHPRuntimeDescriptor{}, false, fmt.Errorf("inspect shared PHP service %s: %w", unit, err)
	}
	var load, active string
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && key == "LoadState" {
			load = value
		}
		if ok && key == "ActiveState" {
			active = value
		}
	}
	if load == "" || active == "" {
		return PHPRuntimeDescriptor{}, false, errors.New("shared PHP service returned incomplete state")
	}
	if active == "inactive" || active == "failed" {
		return PHPRuntimeDescriptor{}, false, nil
	}
	if load != "loaded" || active != "active" {
		return PHPRuntimeDescriptor{}, false, errors.New("shared PHP service is not in a stable active state")
	}
	runtime, err := resolvePHPRuntime(resolver, version)
	if err != nil {
		return PHPRuntimeDescriptor{}, false, fmt.Errorf("resolve active shared PHP service: %w", err)
	}
	return runtime, true, nil
}

func reloadActivePHPAfterCleanup(ctx context.Context, runner CommandRunner, resolver PHPRuntimeResolver, version string) error {
	runtime, active, err := activePHPRuntimeForCleanup(ctx, runner, resolver, version)
	if err != nil || !active {
		return err
	}
	unit := "php" + version + "-fpm.service"

	name, args := runtime.FPMCommand("-t")
	if _, err = runner.Run(ctx, name, args...); err != nil {
		return errors.New("active shared PHP configuration validation failed")
	}
	if _, err = runner.Run(ctx, "systemctl", "reload", unit); err != nil {
		return errors.New("active shared PHP service reload failed")
	}
	return nil
}

func historicalPHPVersions(homeRoot string) []string {
	versions := []string{"8.1", "8.2", "8.3", "8.4", "8.5"}
	if homeRoot == "/home" {
		for _, root := range []string{"/etc/php", "/opt/nakpanel/php"} {
			if entries, err := os.ReadDir(root); err == nil {
				for _, entry := range entries {
					if entry.IsDir() {
						versions = append(versions, entry.Name())
					}
				}
			}
		}
	}
	return normalizedPHPVersionDirectories(versions)
}

func validateSiteCleanupFiles(plan siteCleanupPlan, dedicated bool) error {
	artifacts := []removalArtifact{
		{root: filepath.Dir(plan.NginxConfig), path: plan.NginxConfig},
		{root: filepath.Dir(plan.NginxEnabled), path: plan.NginxEnabled, expectedLink: plan.NginxConfig},
		{root: filepath.Dir(plan.NginxPolicyConfig), path: plan.NginxPolicyConfig},
		{root: filepath.Dir(plan.PHPFPMConfig), path: plan.PHPFPMConfig},
		{root: filepath.Dir(plan.PHPFPMConfig), path: plan.PHPFPMConfig + ".suspended"},
	}
	if dedicated {
		artifacts = append(artifacts, removalArtifact{root: filepath.Dir(plan.PHPServiceUnit), path: plan.PHPServiceUnit}, removalArtifact{root: filepath.Dir(filepath.Dir(plan.NginxProtectedConfig)), path: filepath.Dir(plan.NginxProtectedConfig), directory: true})
	}
	for _, artifact := range artifacts {
		if err := validateRemovalArtifact(artifact); err != nil {
			return err
		}
	}
	return nil
}
