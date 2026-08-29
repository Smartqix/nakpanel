package ops

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

type PodmanProvisionerOptions struct {
	Binary             string
	HomeRoot           string
	StateRoot          string
	RuntimeRoot        string
	SystemdUnitDir     string
	NginxConfigDir     string
	SubUIDPath         string
	SubGIDPath         string
	NetworkCommandPath string
	Runner             CommandRunner
}

type PodmanProvisioner struct {
	binary             string
	homeRoot           string
	stateRoot          string
	runtimeRoot        string
	systemdUnitDir     string
	nginxConfigDir     string
	subUIDPath         string
	subGIDPath         string
	networkCommandPath string
	runner             CommandRunner
}

var (
	applicationNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)
	environmentKeyRE  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	imageReferenceRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{1,511}$`)
)

func NewPodmanProvisioner(opts PodmanProvisionerOptions) *PodmanProvisioner {
	binary := opts.Binary
	if binary == "" {
		binary = "/usr/bin/podman"
	}
	homeRoot := filepath.Clean(opts.HomeRoot)
	if opts.HomeRoot == "" {
		homeRoot = "/home"
	}
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	stateRoot := opts.StateRoot
	if stateRoot == "" {
		stateRoot = "/var/lib/nakpanel/containers"
	}
	runtimeRoot := opts.RuntimeRoot
	if runtimeRoot == "" {
		runtimeRoot = "/run/nakpanel-containers"
	}
	unitDir := opts.SystemdUnitDir
	if unitDir == "" {
		unitDir = "/etc/systemd/system"
	}
	nginxDir := opts.NginxConfigDir
	if nginxDir == "" {
		nginxDir = "/etc/nginx/nakpanel/applications"
	}
	subUIDPath := opts.SubUIDPath
	if subUIDPath == "" {
		subUIDPath = "/etc/subuid"
	}
	subGIDPath := opts.SubGIDPath
	if subGIDPath == "" {
		subGIDPath = "/etc/subgid"
	}
	networkCommandPath := opts.NetworkCommandPath
	if networkCommandPath == "" {
		networkCommandPath = "/usr/lib/nakpanel/slirp4netns"
	}
	return &PodmanProvisioner{
		binary: binary, homeRoot: homeRoot, stateRoot: stateRoot, runtimeRoot: runtimeRoot,
		systemdUnitDir: unitDir, nginxConfigDir: nginxDir, subUIDPath: subUIDPath,
		subGIDPath: subGIDPath, networkCommandPath: networkCommandPath, runner: runner,
	}
}

func (p *PodmanProvisioner) EnsureApplication(ctx context.Context, req types.EnsureApplicationReq) error {
	if req.ApplicationID <= 0 || !accountUsernameRE.MatchString(req.Username) || !applicationNameRE.MatchString(req.Name) {
		return errors.New("valid application id, account, and name are required")
	}
	if req.Runtime != "php" && req.Runtime != "python" && req.Runtime != "node" && req.Runtime != "oci" {
		return fmt.Errorf("unsupported application runtime %q", req.Runtime)
	}
	if req.DesiredState != "running" && req.DesiredState != "stopped" {
		return fmt.Errorf("unsupported application state %q", req.DesiredState)
	}
	container := applicationContainerName(req.ApplicationID)
	legacyContainer := fmt.Sprintf("nakpanel-%d-%s", req.ApplicationID, req.Name)
	candidateContainer := container + "-candidate"
	previousContainer := container + "-previous"
	run := func(args ...string) ([]byte, error) {
		return p.runner.Run(ctx, "runuser", append([]string{"-u", req.Username, "--", p.binary}, args...)...)
	}
	cleanupReplacementContainers := func() error {
		for _, name := range []string{candidateContainer, previousContainer} {
			if _, err := run("rm", "--force", "--ignore", name); err != nil {
				return fmt.Errorf("remove stale application replacement %s: %w", name, err)
			}
		}
		return nil
	}
	if req.Remove {
		for _, name := range []string{container, candidateContainer, previousContainer, legacyContainer} {
			if _, err := run("rm", "--force", "--ignore", name); err != nil {
				return fmt.Errorf("remove application: %w", err)
			}
		}
		return nil
	}
	if req.DesiredState == "stopped" {
		for _, name := range []string{container, candidateContainer, previousContainer, legacyContainer} {
			if _, err := run("stop", "--ignore", name); err != nil {
				return fmt.Errorf("stop application %s: %w", name, err)
			}
		}
		return nil
	}
	if req.SiteID <= 0 || site.ValidateDomain(req.Domain) != nil {
		return errors.New("validated application domain identity is required")
	}
	siteRoot := filepath.Join(p.homeRoot, req.Username, "domains", req.Domain, "public_html")
	resolvedRoot, err := filepath.EvalSymlinks(siteRoot)
	resolvedHomeRoot, homeErr := filepath.EvalSymlinks(p.homeRoot)
	expectedRoot := filepath.Join(resolvedHomeRoot, req.Username, "domains", req.Domain, "public_html")
	if err != nil || homeErr != nil || filepath.Clean(resolvedRoot) != filepath.Clean(expectedRoot) {
		return errors.New("application document root is missing or unsafe")
	}
	siteRoot = resolvedRoot
	if !imageReferenceRE.MatchString(req.ImageRef) {
		return errors.New("application image reference is invalid")
	}
	if !imageAllowed(req.ImageRef, req.Policy) {
		return fmt.Errorf("application image %q is not allowed by the subscription policy", req.ImageRef)
	}
	for key, value := range req.Environment {
		if !environmentKeyRE.MatchString(key) || strings.ContainsRune(value, '\x00') || len(value) > 8192 {
			return fmt.Errorf("invalid application environment entry %q", key)
		}
	}
	specJSON, _ := json.Marshal(struct {
		ApplicationID int64               `json:"application_id"`
		SiteID        int64               `json:"site_id"`
		Username      string              `json:"username"`
		Domain        string              `json:"domain"`
		Name          string              `json:"name"`
		Runtime       string              `json:"runtime"`
		DocumentRoot  string              `json:"document_root"`
		Image         string              `json:"image"`
		Environment   map[string]string   `json:"environment"`
		Policy        types.HostingPolicy `json:"policy"`
	}{
		ApplicationID: req.ApplicationID,
		SiteID:        req.SiteID,
		Username:      req.Username,
		Domain:        req.Domain,
		Name:          req.Name,
		Runtime:       req.Runtime,
		DocumentRoot:  siteRoot,
		Image:         req.ImageRef,
		Environment:   req.Environment,
		Policy:        req.Policy,
	})
	specHash := fmt.Sprintf("%x", sha256.Sum256(specJSON))
	buildRunArgs := func(name string) []string {
		args := []string{"run", "--detach", "--name", name, "--label", "io.nakpanel.spec-sha256=" + specHash, "--userns=keep-id", "--pull=missing", "--restart=unless-stopped", "--volume", siteRoot + ":/workspace:rw,Z", "--workdir", "/workspace", "--env", "NAKPANEL_SITE_DOMAIN=" + req.Domain}
		if !req.Policy.Permissions.ApplicationEgress || !req.Policy.Applications.EgressEnabled {
			args = append(args, "--network=none")
		}
		if req.Policy.Resources.MemoryMB > 0 {
			args = append(args, "--memory", fmt.Sprintf("%dm", req.Policy.Resources.MemoryMB))
		}
		if req.Policy.Resources.CPUPercent > 0 {
			args = append(args, "--cpus", fmt.Sprintf("%.2f", float64(req.Policy.Resources.CPUPercent)/100))
		}
		if req.Policy.Resources.MaxTasks > 0 {
			args = append(args, "--pids-limit", fmt.Sprintf("%d", req.Policy.Resources.MaxTasks))
		}
		keys := make([]string, 0, len(req.Environment))
		for key := range req.Environment {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			args = append(args, "--env", key+"="+req.Environment[key])
		}
		return append(args, req.ImageRef)
	}
	currentHash, inspectErr := run("container", "inspect", "--format", `{{ index .Config.Labels "io.nakpanel.spec-sha256" }}`, container)
	if inspectErr == nil {
		if strings.TrimSpace(string(currentHash)) == specHash {
			if _, err := run("start", container); err != nil {
				return fmt.Errorf("start application: %w", err)
			}
			if err := cleanupReplacementContainers(); err != nil {
				return err
			}
			if _, err := run("rm", "--force", "--ignore", legacyContainer); err != nil {
				return fmt.Errorf("remove legacy application: %w", err)
			}
			return nil
		}
		if err := cleanupReplacementContainers(); err != nil {
			return err
		}
		if _, err := run(buildRunArgs(candidateContainer)...); err != nil {
			return fmt.Errorf("start replacement application without changing the current container: %w", err)
		}
		if _, err := run("rename", container, previousContainer); err != nil {
			_, cleanupErr := run("rm", "--force", "--ignore", candidateContainer)
			return errors.Join(fmt.Errorf("preserve current application before replacement: %w", err), cleanupErr)
		}
		if _, err := run("rename", candidateContainer, container); err != nil {
			_, restoreErr := run("rename", previousContainer, container)
			_, cleanupErr := run("rm", "--force", "--ignore", candidateContainer)
			return errors.Join(fmt.Errorf("activate replacement application: %w", err), restoreErr, cleanupErr)
		}
		if _, err := run("stop", "--ignore", previousContainer); err != nil {
			return fmt.Errorf("stop prior application after replacement: %w", err)
		}
		if _, err := run("rm", "--force", "--ignore", previousContainer); err != nil {
			return fmt.Errorf("remove prior application after replacement: %w", err)
		}
		if _, err := run("rm", "--force", "--ignore", legacyContainer); err != nil {
			return fmt.Errorf("remove legacy application: %w", err)
		}
		return nil
	}
	if _, err := run(buildRunArgs(container)...); err != nil {
		return fmt.Errorf("create application: %w", err)
	}
	if err := cleanupReplacementContainers(); err != nil {
		return err
	}
	if _, err := run("rm", "--force", "--ignore", legacyContainer); err != nil {
		return fmt.Errorf("remove legacy application: %w", err)
	}
	return nil
}

func applicationContainerName(applicationID int64) string {
	return fmt.Sprintf("nakpanel-app-%d", applicationID)
}

func imageAllowed(image string, policy types.HostingPolicy) bool {
	if !policy.Permissions.Applications || !policy.Applications.Rootless {
		return false
	}
	registry := strings.SplitN(image, "/", 2)[0]
	if !strings.Contains(registry, ".") && !strings.Contains(registry, ":") && registry != "localhost" {
		registry = "docker.io"
	}
	for _, allowed := range policy.Applications.AllowedRegistries {
		if strings.EqualFold(registry, allowed) {
			return true
		}
	}
	return false
}
