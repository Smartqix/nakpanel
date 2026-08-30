package phpapp

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	gitRefPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	environmentPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	workerNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
	healthPathPattern  = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@/-]*$`)
)

func validateApplicationConfiguration(input ConfigureApplicationInput, policy types.HostingPolicy, current types.PHPHostingMode) (ConfigureApplicationInput, error) {
	if input.HostingMode != types.PHPHostingModeClassic && input.HostingMode != types.PHPHostingModeManaged {
		return input, errors.New("PHP hosting mode must be classic or managed")
	}
	if current == types.PHPHostingModeManaged && input.HostingMode == types.PHPHostingModeClassic {
		return input, ErrManagedToClassic
	}
	if !policy.Permissions.Hosting {
		return input, fmt.Errorf("%w: hosting is disabled", controlquota.ErrExceeded)
	}
	if !contains(policy.PHP.AllowedVersions, input.PHPVersion) {
		return input, fmt.Errorf("%w: PHP %s is not allowed", controlquota.ErrExceeded, input.PHPVersion)
	}
	if input.HostingMode == types.PHPHostingModeClassic {
		input.RepositoryID = 0
		input.RepositoryRef = "main"
		input.FrameworkProfile = types.PHPFrameworkPlain
		input.PublicPath = ""
		input.HealthPath = "/"
		input.SharedPaths = nil
		input.ReleaseRetention = 5
		input.Composer = types.PHPComposerSpec{}
		return input, nil
	}
	if !policy.Permissions.ManagedPHPDeployments || !policy.Permissions.Git {
		return input, fmt.Errorf("%w: managed PHP deployments require Git permission", controlquota.ErrExceeded)
	}
	if input.RepositoryID <= 0 {
		return input, errors.New("a site Git repository is required")
	}
	input.RepositoryRef = strings.TrimSpace(input.RepositoryRef)
	if !gitRefPattern.MatchString(input.RepositoryRef) || strings.Contains(input.RepositoryRef, "..") || strings.HasPrefix(input.RepositoryRef, "-") {
		return input, errors.New("repository revision is invalid")
	}
	if input.Composer.Install && !policy.Permissions.Composer {
		return input, fmt.Errorf("%w: Composer is disabled", controlquota.ErrExceeded)
	}
	if (input.Composer.AllowScripts || input.Composer.AllowPlugins) && !policy.Permissions.ComposerCodeExecution {
		return input, fmt.Errorf("%w: Composer code execution is disabled", controlquota.ErrExceeded)
	}
	if input.ReleaseRetention < 1 || input.ReleaseRetention > 100 ||
		(policy.Resources.MaxPHPReleases >= 0 && input.ReleaseRetention > policy.Resources.MaxPHPReleases) {
		return input, fmt.Errorf("%w: PHP release retention exceeds the subscription limit", controlquota.ErrExceeded)
	}
	switch input.FrameworkProfile {
	case "", types.PHPFrameworkPlain:
		input.FrameworkProfile = types.PHPFrameworkPlain
		if input.HealthPath == "" {
			input.HealthPath = "/"
		}
	case types.PHPFrameworkLaravel:
		if input.PublicPath == "" {
			input.PublicPath = "public"
		}
		if len(input.SharedPaths) == 0 {
			input.SharedPaths = []string{"storage", "bootstrap/cache"}
		}
		if input.HealthPath == "" {
			input.HealthPath = "/up"
		}
	case types.PHPFrameworkSymfony:
		if input.PublicPath == "" {
			input.PublicPath = "public"
		}
		if len(input.SharedPaths) == 0 {
			input.SharedPaths = []string{"var"}
		}
		if input.HealthPath == "" {
			input.HealthPath = "/"
		}
	case types.PHPFrameworkCustom:
		if input.HealthPath == "" {
			input.HealthPath = "/"
		}
	default:
		return input, errors.New("framework profile is invalid")
	}
	if err := validateRelativePath(input.PublicPath, true); err != nil {
		return input, fmt.Errorf("public path: %w", err)
	}
	if !healthPathPattern.MatchString(input.HealthPath) || strings.Contains(input.HealthPath, "..") || strings.ContainsAny(input.HealthPath, "\x00\r\n") {
		return input, errors.New("health path is invalid")
	}
	if len(input.SharedPaths) > 16 {
		return input, errors.New("at most 16 shared paths are supported")
	}
	seen := make(map[string]struct{}, len(input.SharedPaths))
	for index, value := range input.SharedPaths {
		if err := validateRelativePath(value, false); err != nil {
			return input, fmt.Errorf("shared path %d: %w", index+1, err)
		}
		clean := path.Clean(value)
		for existing := range seen {
			if clean == existing || strings.HasPrefix(clean, existing+"/") || strings.HasPrefix(existing, clean+"/") {
				return input, errors.New("shared paths must be unique and non-overlapping")
			}
		}
		if clean == input.PublicPath || (input.PublicPath != "" && strings.HasPrefix(input.PublicPath, clean+"/")) {
			return input, errors.New("public path cannot be contained by writable shared storage")
		}
		seen[clean] = struct{}{}
		input.SharedPaths[index] = clean
	}
	if input.PublicPath != "" {
		input.PublicPath = path.Clean(input.PublicPath)
	}
	return input, nil
}

func validateRelativePath(value string, emptyAllowed bool) error {
	if value == "" && emptyAllowed {
		return nil
	}
	if value == "" || len(value) > 240 || strings.Contains(value, `\`) || strings.ContainsAny(value, "\x00\r\n") || path.IsAbs(value) {
		return errors.New("must be a safe relative path")
	}
	clean := path.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != value {
		return errors.New("must be canonical and cannot traverse")
	}
	return nil
}

func validateEnvironment(input EnvironmentInput) (EnvironmentInput, error) {
	input.Name = strings.ToUpper(strings.TrimSpace(input.Name))
	if !environmentPattern.MatchString(input.Name) {
		return input, errors.New("environment name is invalid")
	}
	if len(input.Value) > 65536 || strings.ContainsRune(input.Value, '\x00') {
		return input, errors.New("environment value is invalid")
	}
	if input.Secret && input.Value == "" {
		return input, errors.New("secret environment value is required")
	}
	return input, nil
}

func validateWorker(input WorkerInput, policy types.HostingPolicy, otherProcesses int) (WorkerInput, error) {
	input.Name = strings.ToLower(strings.TrimSpace(input.Name))
	if !policy.Permissions.PHPWorkers {
		return input, fmt.Errorf("%w: PHP workers are disabled", controlquota.ErrExceeded)
	}
	if !workerNamePattern.MatchString(input.Name) || validateRelativePath(input.Script, false) != nil {
		return input, errors.New("worker name or script is invalid")
	}
	if input.Processes < 1 || input.Processes > 64 {
		return input, errors.New("worker processes must be between 1 and 64")
	}
	if input.DesiredState == "" {
		input.DesiredState = "running"
	}
	if input.DesiredState != "running" && input.DesiredState != "stopped" {
		return input, errors.New("worker state must be running or stopped")
	}
	if len(input.Arguments) > 64 {
		return input, errors.New("at most 64 worker arguments are supported")
	}
	argumentBytes := 0
	for _, argument := range input.Arguments {
		if len(argument) > 4096 || strings.ContainsAny(argument, "\x00\r\n") {
			return input, errors.New("worker argument is invalid")
		}
		argumentBytes += len(argument)
	}
	if argumentBytes > 32<<10 {
		return input, errors.New("worker arguments exceed 32 KiB")
	}
	if policy.Resources.MaxPHPWorkers >= 0 && otherProcesses+input.Processes > policy.Resources.MaxPHPWorkers {
		return input, fmt.Errorf("%w: PHP worker processes %d / %d", controlquota.ErrExceeded, otherProcesses+input.Processes, policy.Resources.MaxPHPWorkers)
	}
	return input, nil
}

func readyPHPRuntime(capabilities types.RuntimeCapabilities, version string) (types.PHPRuntimeCapability, error) {
	for _, runtime := range capabilities.PHPRuntimes {
		if runtime.Version == version {
			if !runtime.Ready {
				return runtime, fmt.Errorf("%w: PHP %s failed capability checks", ErrRuntimeUnavailable, version)
			}
			return runtime, nil
		}
	}
	return types.PHPRuntimeCapability{}, fmt.Errorf("%w: PHP %s has no detailed capability record", ErrRuntimeUnavailable, version)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
