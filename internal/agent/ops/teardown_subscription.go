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
	"time"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	databaseIdentifierRE  = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	phpVersionDirectoryRE = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
	teardownOCIUnitRE     = regexp.MustCompile(`^(nakpanel-app-[1-9][0-9]*(-g[1-9][0-9]*|-candidate|-previous)?|nakpanel-[1-9][0-9]*-[a-z][a-z0-9-]{1,47})\.service$`)
)

type SubscriptionTeardownOptions struct {
	IdentityRegistry        *SiteIdentityRegistry
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
	ContainerStateRoot      string
	ContainerRuntimeRoot    string
	Runner                  CommandRunner
}
type SubscriptionTeardownProvisioner struct {
	identityRegistry        *SiteIdentityRegistry
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
	containerStateRoot      string
	containerRuntimeRoot    string
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
		if opts.ContainerStateRoot == "" {
			opts.ContainerStateRoot = filepath.Join(filepath.Dir(root), "containers")
		}
		if opts.ContainerRuntimeRoot == "" {
			opts.ContainerRuntimeRoot = filepath.Join(filepath.Dir(root), "container-run")
		}
	}
	return &SubscriptionTeardownProvisioner{
		identityRegistry: opts.IdentityRegistry,
		homeRoot:         root, paths: paths, systemdUnitDir: systemdUnitDir,
		taskStateDir: taskStateDir,
		sshConfigDir: filepath.Clean(sshConfigDir), authorizedKeysDir: filepath.Clean(authorizedKeysDir),
		valkeyConfigRoot:        defaultPath(opts.ValkeyConfigRoot, "/etc/nakpanel/valkey"),
		valkeyRuntimeRoot:       defaultPath(opts.ValkeyRuntimeRoot, "/run/nakpanel/valkey"),
		gitRoot:                 defaultPath(opts.GitRoot, "/var/lib/nakpanel/git"),
		stagingRoot:             defaultPath(opts.StagingRoot, "/var/lib/nakpanel/staging"),
		phpApplicationStateRoot: defaultPath(opts.PHPApplicationStateRoot, "/var/lib/nakpanel/php-applications"),
		podmanBinary:            defaultPath(opts.PodmanBinary, "/usr/bin/podman"), runner: runner,
		containerStateRoot:   defaultPath(opts.ContainerStateRoot, "/var/lib/nakpanel/containers"),
		containerRuntimeRoot: defaultPath(opts.ContainerRuntimeRoot, "/run/nakpanel-containers"),
	}
}

func defaultPath(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		value = fallback
	}
	return filepath.Clean(value)
}

func (p *SubscriptionTeardownProvisioner) TeardownSubscription(ctx context.Context, req types.TeardownSubscriptionReq) (types.TeardownSubscriptionResult, error) {
	if p.identityRegistry != nil {
		if err := p.validateAccountRemovalIntent(req); err != nil {
			return types.TeardownSubscriptionResult{}, err
		}
		if len(req.SiteIDs) != len(req.Domains) {
			return types.TeardownSubscriptionResult{}, errors.New("account removal requires current positive website identities")
		}
		ids := make([]types.SiteIdentity, 0, len(req.Domains))
		for index, domain := range req.Domains {
			ids = append(ids, types.SiteIdentity{SiteID: req.SiteIDs[index], SubscriptionID: req.SubscriptionID, Username: req.Username, Domain: domain})
		}
		var result types.TeardownSubscriptionResult
		err := p.identityRegistry.WithAccountRemoval(ctx, req.SubscriptionID, ids, func(ctx context.Context) error {
			var err error
			result, err = p.teardownSubscription(ctx, req)
			return err
		})
		return result, err
	}
	return p.teardownSubscription(ctx, req)
}

// Validate the complete destructive identity before writing durable fences.
// The legacy execution path also validates it before touching managed services.
func (p *SubscriptionTeardownProvisioner) validateAccountRemovalIntent(req types.TeardownSubscriptionReq) error {
	if req.SubscriptionID <= 0 || !accountUsernameRE.MatchString(req.Username) || filepath.Clean(req.HomePath) != filepath.Join(p.homeRoot, req.Username) {
		return errors.New("invalid subscription account removal identity")
	}
	if len(req.SiteIDs) != len(req.Domains) {
		return errors.New("account removal requires matching website identities")
	}
	sites := map[int64]bool{}
	for index, domain := range req.Domains {
		if req.SiteIDs[index] <= 0 || site.ValidateDomain(domain) != nil || domain != site.NormalizeDomain(domain) || sites[req.SiteIDs[index]] {
			return errors.New("invalid account website identity")
		}
		sites[req.SiteIDs[index]] = true
	}
	for _, name := range req.DatabaseNames {
		if !databaseIdentifierRE.MatchString(name) {
			return errors.New("invalid account database identity")
		}
	}
	for _, ids := range [][]int64{req.TaskIDs, req.StagingOperationIDs, req.PHPApplicationIDs, req.PHPWorkerIDs} {
		for _, id := range ids {
			if id <= 0 {
				return errors.New("invalid account object identity")
			}
		}
	}
	for _, deployment := range req.PHPDeployments {
		if deployment.DeploymentID <= 0 || !sites[deployment.SiteID] {
			return errors.New("invalid account PHP deployment identity")
		}
	}
	for _, app := range req.Applications {
		if app.ID <= 0 || !applicationNameRE.MatchString(app.Name) {
			return errors.New("invalid account application identity")
		}
	}
	for _, root := range []string{p.systemdUnitDir, p.containerStateRoot, p.containerRuntimeRoot} {
		if !filepath.IsAbs(root) || root == string(filepath.Separator) {
			return errors.New("invalid account removal state root")
		}
		if err := ensureNoSymlinkComponents(root, root); err != nil {
			return err
		}
	}
	return nil
}

func (p *SubscriptionTeardownProvisioner) teardownSubscription(ctx context.Context, req types.TeardownSubscriptionReq) (types.TeardownSubscriptionResult, error) {
	var result types.TeardownSubscriptionResult
	if req.SubscriptionID <= 0 || !accountUsernameRE.MatchString(req.Username) {
		return result, errors.New("invalid subscription account identity")
	}
	for _, root := range []string{p.systemdUnitDir, p.containerStateRoot, p.containerRuntimeRoot} {
		if !filepath.IsAbs(root) || root == string(filepath.Separator) {
			return result, errors.New("teardown state roots must be absolute non-root directories")
		}
		if err := ensureNoSymlinkComponents(root, root); err != nil {
			return result, err
		}
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
	uidOutput, userLookupErr := p.runner.Run(ctx, "id", "-u", req.Username)
	userExists := userLookupErr == nil
	var userUID uint64
	if userExists {
		userUID, err = strconv.ParseUint(strings.TrimSpace(string(uidOutput)), 10, 32)
		if err != nil || userUID == 0 || userUID == 1<<32-1 {
			return result, errors.New("subscription teardown requires a validated non-root UID")
		}
	} else {
		output, lookupErr := p.runner.Run(ctx, "getent", "passwd", req.Username)
		if !commandExitedWith(lookupErr, 2) || len(strings.TrimSpace(string(output))) != 0 {
			return result, fmt.Errorf("confirm missing subscription user: %w", userLookupErr)
		}
	}
	ociUnits, err := p.accountOCIUnits(ctx, req.Username)
	if err != nil {
		return result, err
	}
	for _, unit := range ociUnits {
		if output, stopErr := p.runner.Run(ctx, "systemctl", "disable", "--now", unit); stopErr != nil {
			return result, fmt.Errorf("stop subscription OCI unit %s: %w: %s", unit, stopErr, strings.TrimSpace(string(output)))
		}
		if err = os.Remove(filepath.Join(p.systemdUnitDir, unit)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return result, fmt.Errorf("remove subscription OCI unit %s: %w", unit, err)
		}
		result.Removed = append(result.Removed, "oci-unit:"+unit)
	}
	if len(ociUnits) > 0 {
		if _, err = p.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return result, fmt.Errorf("reload removed OCI units: %w", err)
		}
	}
	base := filepath.Join(p.containerStateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10))
	identity := applicationIdentity{
		stateHome: filepath.Join(base, "home"), dataHome: filepath.Join(base, "data"),
		configHome:  filepath.Join(base, "config"),
		runtimeHome: filepath.Join(p.containerRuntimeRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10)),
	}
	for _, path := range []string{identity.stateHome, identity.dataHome, identity.configHome} {
		if err = ensureNoSymlinkComponents(p.containerStateRoot, path); err != nil {
			return result, fmt.Errorf("validate rootless container state: %w", err)
		}
	}
	if err = ensureNoSymlinkComponents(p.containerRuntimeRoot, identity.runtimeHome); err != nil {
		return result, fmt.Errorf("validate rootless container runtime: %w", err)
	}
	podman := (&PodmanProvisioner{binary: p.podmanBinary, runner: p.runner}).rootlessRunner(req.Username, identity)
	rootlessStateExists := true
	for _, path := range []string{base, identity.runtimeHome} {
		if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
			rootlessStateExists = false
		} else if statErr != nil {
			return result, statErr
		}
	}
	for _, application := range req.Applications {
		if !userExists || !rootlessStateExists {
			continue
		}
		stableContainer := applicationContainerName(application.ID)
		output, inspectErr := podman(ctx, "ps", "-a", "--filter", "label=io.nakpanel.application-id="+strconv.FormatInt(application.ID, 10), "--format", "{{.Names}}")
		if inspectErr != nil {
			return result, fmt.Errorf("inspect application containers %s: %w: %s", application.Name, inspectErr, strings.TrimSpace(string(output)))
		}
		containers := []string{
			stableContainer,
			stableContainer + "-candidate",
			stableContainer + "-previous",
			fmt.Sprintf("nakpanel-%d-%s", application.ID, application.Name),
		}
		for _, container := range applicationContainerNames(output, application.ID) {
			if _, revisionErr := applicationContainerRevision(container, application.ID); revisionErr != nil {
				return result, revisionErr
			}
			containers = append(containers, container)
		}
		for _, container := range containers {
			output, runErr := podman(ctx, "rm", "--force", "--ignore", container)
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
			loaded, inspectErr := p.systemdUnitLoaded(ctx, plan.PHPServiceName)
			if inspectErr != nil {
				return result, fmt.Errorf("inspect dedicated PHP service %s: %w", plan.PHPServiceName, inspectErr)
			}
			if loaded {
				if output, stopErr := p.runner.Run(ctx, "systemctl", "disable", "--now", plan.PHPServiceName); stopErr != nil {
					return result, fmt.Errorf("stop dedicated PHP service %s: %w: %s", plan.PHPServiceName, stopErr, strings.TrimSpace(string(output)))
				}
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
		unitPaths := make(map[string]string)
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
				unitPaths[filepath.Base(unitPath)] = unitPath
			}
		}
		pattern := fmt.Sprintf("nakpanel-php-worker@%d*.service", workerID)
		output, listErr := p.runner.Run(ctx, "systemctl", "list-units", "--all", "--type=service", "--no-legend", "--plain", "--no-pager", pattern)
		if listErr != nil {
			return result, fmt.Errorf("list loaded PHP worker generations for %d: %w: %s", workerID, listErr, strings.TrimSpace(string(output)))
		}
		unitNames := make(map[string]struct{}, len(unitPaths))
		for unitName := range unitPaths {
			unitNames[unitName] = struct{}{}
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			match := phpWorkerUnitFileRE.FindStringSubmatch(fields[0])
			if len(match) == 0 || match[1] != strconv.FormatInt(workerID, 10) {
				continue
			}
			unitNames[fields[0]] = struct{}{}
		}
		sortedUnits := make([]string, 0, len(unitNames))
		for unitName := range unitNames {
			sortedUnits = append(sortedUnits, unitName)
		}
		sort.Strings(sortedUnits)
		for _, unitName := range sortedUnits {
			if output, stopErr := p.runner.Run(ctx, "systemctl", "disable", "--now", unitName); stopErr != nil {
				return result, fmt.Errorf("stop managed PHP worker %s: %w: %s", unitName, stopErr, strings.TrimSpace(string(output)))
			}
			if unitPath := unitPaths[unitName]; unitPath != "" {
				if err = os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					return result, err
				}
			}
			needsDaemonReload = true
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
	if userExists {
		if err = p.stopAccountProcesses(ctx, req.Username, userUID, 3*time.Second); err != nil {
			return result, err
		}
	}
	for _, root := range []string{p.containerStateRoot, p.containerRuntimeRoot} {
		path := filepath.Join(root, "sub-"+strconv.FormatInt(req.SubscriptionID, 10))
		if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
			continue
		} else if statErr != nil {
			return result, statErr
		}
		if err = ensureNoSymlinkComponents(root, path); err != nil {
			return result, fmt.Errorf("validate rootless account state: %w", err)
		}
		if err = os.RemoveAll(path); err != nil {
			return result, fmt.Errorf("remove rootless account state: %w", err)
		}
		result.Removed = append(result.Removed, "rootless-state:"+path)
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

// Inventory systemd as well as files: removed application records can leave loaded
// generation units behind, and their Restart policy must not survive UID shutdown.
func (p *SubscriptionTeardownProvisioner) accountOCIUnits(ctx context.Context, username string) ([]string, error) {
	names := map[string]struct{}{}
	for _, pattern := range []string{"nakpanel-app-*.service", "nakpanel-*.service"} {
		files, err := filepath.Glob(filepath.Join(p.systemdUnitDir, pattern))
		if err != nil {
			return nil, err
		}
		for _, path := range files {
			unit := filepath.Base(path)
			if teardownOCIUnitRE.MatchString(unit) {
				info, statErr := os.Lstat(path)
				if statErr != nil {
					return nil, statErr
				}
				if !info.Mode().IsRegular() {
					return nil, fmt.Errorf("OCI unit %s is not a regular file", unit)
				}
				names[unit] = struct{}{}
			}
		}
		output, err := p.runner.Run(ctx, "systemctl", "list-units", "--all", "--type=service", "--no-legend", "--plain", "--no-pager", pattern)
		if err != nil {
			return nil, fmt.Errorf("inventory subscription OCI units: %w: %s", err, strings.TrimSpace(string(output)))
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && teardownOCIUnitRE.MatchString(fields[0]) {
				names[fields[0]] = struct{}{}
			}
		}
	}
	var units []string
	for unit := range names {
		output, err := p.runner.Run(ctx, "systemctl", "show", "--property=User", "--value", "--no-pager", unit)
		if err != nil {
			return nil, fmt.Errorf("inspect OCI unit ownership %s: %w: %s", unit, err, strings.TrimSpace(string(output)))
		}
		if strings.TrimSpace(string(output)) == username {
			units = append(units, unit)
		}
	}
	sort.Strings(units)
	return units, nil
}

func commandExitedWith(err error, code int) bool {
	var exit interface{ ExitCode() int }
	return errors.As(err, &exit) && exit.ExitCode() == code
}

var errAccountProcessesRemain = errors.New("subscription account processes remain")

func (p *SubscriptionTeardownProvisioner) accountProcessesRemain(ctx context.Context, uid string) (bool, error) {
	output, err := p.runner.Run(ctx, "pgrep", "--uid", uid, "--")
	if commandExitedWith(err, 1) && len(strings.TrimSpace(string(output))) == 0 {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect subscription UID processes: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for _, pid := range strings.Fields(string(output)) {
		value, parseErr := strconv.ParseUint(pid, 10, 32)
		if parseErr != nil || value == 0 {
			return false, errors.New("unexpected subscription process inventory")
		}
	}
	return len(strings.Fields(string(output))) > 0, nil
}

func (p *SubscriptionTeardownProvisioner) waitAccountProcesses(ctx context.Context, uid string, grace time.Duration) error {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		remaining, err := p.accountProcessesRemain(ctx, uid)
		if err != nil {
			return err
		}
		if !remaining {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errAccountProcessesRemain
		case <-ticker.C:
		}
	}
}

func (p *SubscriptionTeardownProvisioner) stopAccountProcesses(ctx context.Context, username string, uid uint64, grace time.Duration) error {
	if uid == 0 || uid >= 1<<32-1 {
		return errors.New("invalid subscription process shutdown UID")
	}
	output, err := p.runner.Run(ctx, "id", "-u", username)
	current, parseErr := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 32)
	if err != nil || parseErr != nil || current != uid {
		return errors.New("subscription UID changed before process shutdown")
	}
	value := strconv.FormatUint(uid, 10)
	// A rootless pause may outlive its recorded containers and may not be
	// registered with logind. Session shutdown is followed by UID verification.
	_, _ = p.runner.Run(ctx, "loginctl", "disable-linger", value)
	_, _ = p.runner.Run(ctx, "loginctl", "terminate-user", value)
	_, _ = p.runner.Run(ctx, "systemctl", "stop", "user@"+value+".service")
	for _, signal := range []string{"TERM", "KILL"} {
		remaining, err := p.accountProcessesRemain(ctx, value)
		if err != nil {
			return err
		}
		if !remaining {
			return nil
		}
		output, err := p.runner.Run(ctx, "pkill", "--signal", signal, "--uid", value, "--")
		if err != nil && !commandExitedWith(err, 1) {
			return fmt.Errorf("terminate subscription UID processes: %w: %s", err, strings.TrimSpace(string(output)))
		}
		if err = p.waitAccountProcesses(ctx, value, grace); err == nil {
			return nil
		} else if !errors.Is(err, errAccountProcessesRemain) {
			return err
		}
	}
	return errAccountProcessesRemain
}

func (p *SubscriptionTeardownProvisioner) systemdUnitLoaded(ctx context.Context, unit string) (bool, error) {
	output, err := p.runner.Run(ctx, "systemctl", "show", "--property=LoadState", "--property=ActiveState", "--no-pager", unit)
	if err != nil {
		return false, fmt.Errorf("systemctl show: %w: %s", err, strings.TrimSpace(string(output)))
	}
	var loadState, activeState string
	for _, line := range strings.Split(string(output), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "LoadState":
			loadState = value
		case "ActiveState":
			activeState = value
		}
	}
	if loadState == "" || activeState == "" {
		return false, errors.New("systemd returned incomplete unit state")
	}
	if loadState == "not-found" && (activeState == "inactive" || activeState == "failed") {
		return false, nil
	}
	return true, nil
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
