package ops

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

type PodmanProvisionerOptions struct {
	Binary string
	Runner CommandRunner
}

type PodmanProvisioner struct {
	binary string
	runner CommandRunner
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
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	return &PodmanProvisioner{binary: binary, runner: runner}
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
	container := fmt.Sprintf("nakpanel-%d-%s", req.ApplicationID, req.Name)
	run := func(args ...string) ([]byte, error) {
		return p.runner.Run(ctx, "runuser", append([]string{"-u", req.Username, "--", p.binary}, args...)...)
	}
	if req.Remove {
		if _, err := run("rm", "--force", "--ignore", container); err != nil {
			return fmt.Errorf("remove application: %w", err)
		}
		return nil
	}
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
		Image       string            `json:"image"`
		Environment map[string]string `json:"environment"`
	}{Image: req.ImageRef, Environment: req.Environment})
	specHash := fmt.Sprintf("%x", sha256.Sum256(specJSON))
	currentHash, inspectErr := run("container", "inspect", "--format", `{{ index .Config.Labels "io.nakpanel.spec-sha256" }}`, container)
	if req.DesiredState == "stopped" {
		if inspectErr == nil {
			if _, err := run("stop", "--ignore", container); err != nil {
				return fmt.Errorf("stop application: %w", err)
			}
		}
		return nil
	}
	if inspectErr == nil {
		if strings.TrimSpace(string(currentHash)) == specHash {
			if _, err := run("start", container); err != nil {
				return fmt.Errorf("start application: %w", err)
			}
			return nil
		}
		if _, err := run("rm", "--force", container); err != nil {
			return fmt.Errorf("replace changed application: %w", err)
		}
	}
	args := []string{"run", "--detach", "--name", container, "--label", "io.nakpanel.spec-sha256=" + specHash, "--userns=keep-id", "--pull=missing", "--restart=unless-stopped"}
	keys := make([]string, 0, len(req.Environment))
	for key := range req.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--env", key+"="+req.Environment[key])
	}
	args = append(args, req.ImageRef)
	if _, err := run(args...); err != nil {
		return fmt.Errorf("create application: %w", err)
	}
	return nil
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
