package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	databaseIdentifierRE  = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	phpVersionDirectoryRE = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
)

type SubscriptionTeardownOptions struct {
	HomeRoot                string
	Paths                   SitePathConfig
	SystemdUnitDir          string
	TaskStateDir            string
	SSHConfigDir            string
	AuthorizedKeysDir       string
	ValkeyConfigRoot        string
	ValkeyRuntimeRoot       string
	GitRoot                 string
	StagingRoot             string
	PHPApplicationStateRoot string
	PodmanBinary            string
	Runner                  CommandRunner
}
type SubscriptionTeardownProvisioner struct {
	homeRoot                string
	paths                   SitePathConfig
	systemdUnitDir          string
	taskStateDir            string
	sshConfigDir            string
	authorizedKeysDir       string
	valkeyConfigRoot        string
	valkeyRuntimeRoot       string
	gitRoot                 string
	stagingRoot             string
	phpApplicationStateRoot string
	podmanBinary            string
	runner                  CommandRunner
}

func NewSubscriptionTeardownProvisioner(opts SubscriptionTeardownOptions) *SubscriptionTeardownProvisioner {
	root := filepath.Clean(opts.HomeRoot)
	if opts.HomeRoot == "" {
		root = "/home"
	}
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	paths := opts.Paths
	paths.HomeRoot = root
	systemdUnitDir := strings.TrimSpace(opts.SystemdUnitDir)
	if systemdUnitDir == "" {
		systemdUnitDir = strings.TrimSpace(paths.SystemdUnitDir)
	}
	systemdUnitDir = defaultPath(systemdUnitDir, "/etc/systemd/system")
	paths.SystemdUnitDir = systemdUnitDir
	taskStateDir := defaultPath(opts.TaskStateDir, "/var/lib/nakpanel/tasks")
	sshConfigDir := opts.SSHConfigDir
	authorizedKeysDir := opts.AuthorizedKeysDir
	if sshConfigDir == "" {
		sshConfigDir = "/etc/ssh/sshd_config.d"
	}
	if authorizedKeysDir == "" {
		authorizedKeysDir = "/etc/nakpanel/ssh/authorized_keys"
	}
	if root != "/home" {
		if opts.SSHConfigDir == "" {
			sshConfigDir = filepath.Join(filepath.Dir(root), "ssh", "sshd_config.d")
		}
		if opts.AuthorizedKeysDir == "" {
			authorizedKeysDir = filepath.Join(filepath.Dir(root), "ssh", "authorized_keys")
		}
	}
	return &SubscriptionTeardownProvisioner{
		homeRoot: root, paths: paths, systemdUnitDir: systemdUnitDir,
		taskStateDir: taskStateDir,
		sshConfigDir: filepath.Clean(sshConfigDir), authorizedKeysDir: filepath.Clean(authorizedKeysDir),
		valkeyConfigRoot:        defaultPath(opts.ValkeyConfigRoot, "/etc/nakpanel/valkey"),
		valkeyRuntimeRoot:       defaultPath(opts.ValkeyRuntimeRoot, "/run/nakpanel/valkey"),
		gitRoot:                 defaultPath(opts.GitRoot, "/var/lib/nakpanel/git"),
		stagingRoot:             defaultPath(opts.StagingRoot, "/var/lib/nakpanel/staging"),
		phpApplicationStateRoot: defaultPath(opts.PHPApplicationStateRoot, "/var/lib/nakpanel/php-applications"),
		podmanBinary:            defaultPath(opts.PodmanBinary, "/usr/bin/podman"), runner: runner,
	}
}

func defaultPath(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		value = fallback
	}
	return filepath.Clean(value)
}

func (p *SubscriptionTeardownProvisioner) TeardownSubscription(ctx context.Context, req types.TeardownSubscriptionReq) (types.TeardownSubscriptionResult, error) {
	var result types.TeardownSubscriptionResult
	if req.SubscriptionID <= 0 || !accountUsernameRE.MatchString(req.Username) {
		return result, errors.New("invalid subscription account identity")
	}
	home := filepath.Clean(req.HomePath)
	if home != filepath.Join(p.homeRoot, req.Username) || filepath.Dir(home) != p.homeRoot {
		return result, errors.New("account home is not the direct validated home-root child")
	}
	if len(req.SiteIDs) != 0 && len(req.SiteIDs) != len(req.Domains) {
		return result, errors.New("site identities and domains must have matching lengths")
	}
	for index, domain := range req.Domains {
		if site.ValidateDomain(site.NormalizeDomain(domain)) != nil || domain != site.NormalizeDomain(domain) {
			return result, fmt.Errorf("invalid teardown domain %q", domain)
		}
		if len(req.SiteIDs) != 0 && req.SiteIDs[index] <= 0 {
			return result, fmt.Errorf("invalid teardown site identity %d", req.SiteIDs[index])
		}
	}
	for _, name := range req.DatabaseNames {
		if !databaseIdentifierRE.MatchString(name) {
			return result, fmt.Errorf("invalid database identifier %q", name)
		}
	}
	ids := append(append([]int64{}, req.TaskIDs...), req.StagingOperationIDs...)
	ids = append(ids, req.PHPApplicationIDs...)
	ids = append(ids, req.PHPWorkerIDs...)
	for _, id := range ids {
		if id <= 0 {
			return result, fmt.Errorf("invalid teardown object identity %d", id)
		}
	}
	siteIDs := make(map[int64]struct{}, len(req.SiteIDs))
	for _, siteID := range req.SiteIDs {
		siteIDs[siteID] = struct{}{}
	}
	for _, deployment := range req.PHPDeployments {
		if deployment.SiteID <= 0 || deployment.DeploymentID <= 0 {
			return result, errors.New("invalid PHP deployment teardown identity")
		}
		if _, exists := siteIDs[deployment.SiteID]; !exists {
			return result, errors.New("PHP deployment teardown site is outside the subscription snapshot")
		}
	}
	for _, application := range req.Applications {
		if application.ID <= 0 || !applicationNameRE.MatchString(application.Name) {
			return result, errors.New("invalid teardown application identity")
		}
	}
	info, err := os.Lstat(home)
	homeExists := err == nil
	if homeExists {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return result, errors.New("account home must be a real directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	needsDaemonReload := false
	_, userLookupErr := p.runner.Run(ctx, "id", "-u", req.Username)
	userExists := userLookupErr == nil
	for _, application := range req.Applications {
		if !userExists {
			continue
		}
		stableContainer := applicationContainerName(application.ID)
		for _, container := range []string{
			stableContainer,
			stableContainer + "-candidate",
			stableContainer + "-previous",
			fmt.Sprintf("nakpanel-%d-%s", application.ID, application.Name),
		} {
			output, runErr := p.runner.Run(ctx, "runuser", "-u", req.Username, "--", p.podmanBinary, "rm", "--force", "--ignore", container)
			if runErr != nil {
				return result, fmt.Errorf("remove application %s: %w: %s", application.Name, runErr, strings.TrimSpace(string(output)))
			}
		}
		result.Removed = append(result.Removed, "application:"+application.Name)
	}
	for _, deployment := range req.PHPDeployments {
		unit := fmt.Sprintf("nakpanel-php-fpm-candidate@%d-%d.service", deployment.SiteID, deployment.DeploymentID)
		output, inspectErr := p.runner.Run(ctx, "systemctl", "show", "--property=LoadState", "--value", "--no-pager", unit)
		if inspectErr != nil {
			return result, fmt.Errorf("inspect managed PHP candidate %s: %w: %s", unit, inspectErr, strings.TrimSpace(string(output)))
		}
		loadState := strings.TrimSpace(string(output))
		if loadState == "not-found" {
			continue
		}
		if loadState == "" {
			return result, fmt.Errorf("inspect managed PHP candidate %s: systemd returned no load state", unit)
		}
		if output, stopErr := p.runner.Run(ctx, "systemctl", "disable", "--now", unit); stopErr != nil {
			return result, fmt.Errorf("stop managed PHP candidate %s: %w: %s", unit, stopErr, strings.TrimSpace(string(output)))
		}
		needsDaemonReload = true
	}
	for index, domain := range req.Domains {
		for _, php := range p.teardownPHPVersions() {
			plan, planErr := NewSitePlan(types.CreateSiteReq{SubscriptionID: req.SubscriptionID, Username: req.Username, Domain: domain, PHPVersion: php, SharedAccount: true}, p.paths)
			if planErr != nil {
				return result, planErr
			}
			for _, path := range []string{plan.NginxEnabled, plan.NginxConfig, plan.NginxPolicyConfig, plan.PHPFPMConfig, plan.PHPFPMConfig + ".suspended"} {
				if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return result, fmt.Errorf("remove tracked configuration: %w", err)
				}
			}
		}
		if len(req.SiteIDs) != 0 {
			plan, planErr := NewSitePlan(types.CreateSiteReq{SiteID: req.SiteIDs[index], SubscriptionID: req.SubscriptionID, Username: req.Username, Domain: domain, PHPVersion: "8.3", SharedAccount: true}, p.paths)
			if planErr != nil {
				return result, planErr
			}
			if _, statErr := os.Stat(plan.PHPServiceUnit); statErr == nil {
				if _, stopErr := p.runner.Run(ctx, "systemctl", "disable", "--now", plan.PHPServiceName); stopErr != nil {
					return result, fmt.Errorf("stop dedicated PHP service %s: %w", plan.PHPServiceName, stopErr)
				}
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return result, statErr
			}
			for _, path := range []string{plan.PHPFPMConfig, plan.PHPFPMConfig + ".suspended", plan.PHPServiceUnit} {
				if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return result, fmt.Errorf("remove dedicated PHP configuration: %w", err)
				}
			}
			if err = os.RemoveAll(filepath.Dir(plan.NginxProtectedConfig)); err != nil {
				return result, fmt.Errorf("remove protected-directory configuration: %w", err)
			}
			if err = os.RemoveAll(filepath.Join(p.gitRoot, fmt.Sprintf("site-%d", req.SiteIDs[index]))); err != nil {
				return result, fmt.Errorf("remove site Git repository: %w", err)
			}
			needsDaemonReload = true
			candidatePattern := filepath.Join(p.systemdUnitDir, fmt.Sprintf("nakpanel-php-fpm-candidate@%d-*.service", req.SiteIDs[index]))
			candidateUnits, globErr := filepath.Glob(candidatePattern)
			if globErr != nil {
				return result, globErr
			}
			for _, unitPath := range candidateUnits {
				unitName := filepath.Base(unitPath)
				if _, stopErr := p.runner.Run(ctx, "systemctl", "disable", "--now", unitName); stopErr != nil {
					return result, fmt.Errorf("stop managed PHP candidate %s: %w", unitName, stopErr)
				}
				if err = os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					return result, err
				}
			}
			for _, pattern := range []string{
				filepath.Join(p.paths.NginxConfDir, fmt.Sprintf("90-nakpanel-php-candidate-%d-*.conf", req.SiteIDs[index])),
				filepath.Join(p.paths.PHPFPMDedicatedRunDir, fmt.Sprintf("candidate-%d-*.sock", req.SiteIDs[index])),
			} {
				artifacts, artifactErr := filepath.Glob(pattern)
				if artifactErr != nil {
					return result, artifactErr
				}
				for _, artifact := range artifacts {
					if err = os.Remove(artifact); err != nil && !errors.Is(err, os.ErrNotExist) {
						return result, err
					}
				}
			}
		}
		result.Removed = append(result.Removed, "domain:"+domain)
	}
	for _, workerID := range req.PHPWorkerIDs {
		patterns := []string{
			filepath.Join(p.systemdUnitDir, fmt.Sprintf("nakpanel-php-worker@%d.service", workerID)),
			filepath.Join(p.systemdUnitDir, fmt.Sprintf("nakpanel-php-worker@%d-*.service", workerID)),
		}
		for _, pattern := range patterns {
			units, globErr := filepath.Glob(pattern)
			if globErr != nil {
				return result, globErr
			}
			for _, unitPath := range units {
				unitName := filepath.Base(unitPath)
				if _, stopErr := p.runner.Run(ctx, "systemctl", "disable", "--now", unitName); stopErr != nil {
					return result, fmt.Errorf("stop managed PHP worker %s: %w", unitName, stopErr)
				}
				if err = os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					return result, err
				}
				needsDaemonReload = true
			}
		}
	}
	for _, applicationID := range req.PHPApplicationIDs {
		if err = os.Remove(filepath.Join(p.systemdUnitDir, fmt.Sprintf("nakpanel-php-app-%d.slice", applicationID))); err != nil && !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
		if err = os.RemoveAll(filepath.Join(p.phpApplicationStateRoot, "app-"+strconv.FormatInt(applicationID, 10))); err != nil {
			return result, err
		}
		needsDaemonReload = true
	}
	if needsDaemonReload {
		if output, reloadErr := p.runner.Run(ctx, "systemctl", "daemon-reload"); reloadErr != nil {
			return result, fmt.Errorf("reload systemd after site teardown: %w: %s", reloadErr, strings.TrimSpace(string(output)))
		}
	}
	for _, name := range req.DatabaseNames {
		statement := "DROP DATABASE IF EXISTS `" + name + "`"
		output, runErr := p.runner.Run(ctx, "mariadb", "--batch", "--skip-column-names", "--execute", statement)
		if runErr != nil {
			return result, fmt.Errorf("drop database %s: %w: %s", name, runErr, strings.TrimSpace(string(output)))
		}
		result.Removed = append(result.Removed, "database:"+name)
	}
	for _, taskID := range req.TaskIDs {
		unit := fmt.Sprintf("nakpanel-task-%d.timer", taskID)
		timerPath := filepath.Join(p.systemdUnitDir, unit)
		if _, statErr := os.Stat(timerPath); statErr == nil {
			if _, runErr := p.runner.Run(ctx, "systemctl", "disable", "--now", unit); runErr != nil {
				return result, fmt.Errorf("stop scheduled task %d: %w", taskID, runErr)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return result, statErr
		}
		for _, suffix := range []string{".service", ".timer"} {
			if err = os.Remove(filepath.Join(p.systemdUnitDir, fmt.Sprintf("nakpanel-task-%d%s", taskID, suffix))); err != nil && !errors.Is(err, os.ErrNotExist) {
				return result, fmt.Errorf("remove scheduled task unit: %w", err)
			}
		}
	}
	if err = os.Remove(filepath.Join(p.taskStateDir, fmt.Sprintf("subscription-%d.json", req.SubscriptionID))); err != nil && !errors.Is(err, os.ErrNotExist) {
		return result, fmt.Errorf("remove scheduled task state: %w", err)
	}
	if req.ValkeyPresent {
		valkeyUnit := fmt.Sprintf("nakpanel-valkey@%d.service", req.SubscriptionID)
		valkeyUnitPath := filepath.Join(p.systemdUnitDir, valkeyUnit)
		if _, statErr := os.Stat(valkeyUnitPath); statErr == nil {
			if output, runErr := p.runner.Run(ctx, "systemctl", "disable", "--now", valkeyUnit); runErr != nil {
				return result, fmt.Errorf("stop Valkey service: %w: %s", runErr, strings.TrimSpace(string(output)))
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return result, statErr
		}
		if output, runErr := p.runner.Run(ctx, p.podmanBinary, "rm", "--force", "--ignore", fmt.Sprintf("nakpanel-valkey-sub-%d", req.SubscriptionID)); runErr != nil {
			return result, fmt.Errorf("remove Valkey container: %w: %s", runErr, strings.TrimSpace(string(output)))
		}
		for _, path := range []string{
			filepath.Join(p.systemdUnitDir, valkeyUnit),
			filepath.Join(p.valkeyConfigRoot, fmt.Sprintf("sub-%d", req.SubscriptionID)),
			filepath.Join(p.valkeyRuntimeRoot, fmt.Sprintf("sub-%d", req.SubscriptionID)),
		} {
			if err = os.RemoveAll(path); err != nil {
				return result, fmt.Errorf("remove Valkey state: %w", err)
			}
		}
	}
	for _, operationID := range req.StagingOperationIDs {
		for _, pattern := range []string{
			filepath.Join(p.stagingRoot, fmt.Sprintf("operation-%d-*", operationID)),
			filepath.Join(p.stagingRoot, fmt.Sprintf("site-*-operation-%d-*", operationID)),
		} {
			matches, globErr := filepath.Glob(pattern)
			if globErr != nil {
				return result, globErr
			}
			for _, path := range matches {
				if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return result, fmt.Errorf("remove staging rollback point: %w", err)
				}
			}
		}
	}
	for _, path := range []string{
		filepath.Join(p.sshConfigDir, "90-nakpanel-"+req.Username+".conf"),
		filepath.Join(p.authorizedKeysDir, req.Username),
	} {
		if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return result, fmt.Errorf("remove SFTP access state: %w", err)
		}
	}
	needsDaemonReload = true
	if needsDaemonReload {
		if output, reloadErr := p.runner.Run(ctx, "systemctl", "daemon-reload"); reloadErr != nil {
			return result, fmt.Errorf("reload systemd after subscription cleanup: %w: %s", reloadErr, strings.TrimSpace(string(output)))
		}
		if output, reloadErr := p.runner.Run(ctx, "systemctl", "reload", "ssh"); reloadErr != nil {
			return result, fmt.Errorf("reload SSH after subscription cleanup: %w: %s", reloadErr, strings.TrimSpace(string(output)))
		}
	}
	if homeExists {
		if err = os.RemoveAll(home); err != nil {
			return result, fmt.Errorf("remove account home: %w", err)
		}
	}
	result.Removed = append(result.Removed, "home:"+home)
	if userExists {
		if req.ValkeyPresent {
			aclParent := filepath.Dir(p.valkeyRuntimeRoot)
			if output, aclErr := p.runner.Run(ctx, "setfacl", "-x", "u:"+req.Username, aclParent); aclErr != nil {
				acl, inspectErr := p.runner.Run(ctx, "getfacl", "-cp", aclParent)
				if inspectErr != nil || !aclConfirmsUserAbsent(acl, req.Username) {
					return result, fmt.Errorf("remove subscription cache traversal ACL: %w: %s", aclErr, strings.TrimSpace(string(output)))
				}
			}
		}
		output, userErr := p.runner.Run(ctx, "userdel", "--", req.Username)
		if userErr != nil {
			return result, fmt.Errorf("delete system account: %w: %s", userErr, strings.TrimSpace(string(output)))
		}
	}
	result.Removed = append(result.Removed, "user:"+req.Username)
	return result, nil
}

func (p *SubscriptionTeardownProvisioner) teardownPHPVersions() []string {
	versions := []string{"8.2", "8.3"}
	if p.homeRoot == "/home" {
		if entries, err := os.ReadDir("/etc/php"); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					versions = append(versions, entry.Name())
				}
			}
		}
	}
	return normalizedPHPVersionDirectories(versions)
}

func normalizedPHPVersionDirectories(versions []string) []string {
	unique := make(map[string]struct{}, len(versions))
	for _, version := range versions {
		version = strings.TrimSpace(version)
		if phpVersionDirectoryRE.MatchString(version) {
			unique[version] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for version := range unique {
		result = append(result, version)
	}
	sort.Strings(result)
	return result
}

func aclConfirmsUserAbsent(output []byte, username string) bool {
	prefix := "user:" + username + ":"
	hasOwnerEntry := false
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return false
		}
		if strings.HasPrefix(line, "user::") {
			hasOwnerEntry = true
		}
	}
	return hasOwnerEntry
}
