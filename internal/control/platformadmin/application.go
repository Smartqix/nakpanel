package platformadmin

import (
	"errors"
	"fmt"
	"strings"
)

type ApplicationRuntime string

const (
	ApplicationRuntimePHP    ApplicationRuntime = "php"
	ApplicationRuntimePython ApplicationRuntime = "python"
	ApplicationRuntimeNode   ApplicationRuntime = "node"
	ApplicationRuntimeOCI    ApplicationRuntime = "oci"
)

type ApplicationCatalogPolicy struct {
	AllowedRegistries     []string             `json:"allowed_registries"`
	AllowedRuntimes       []ApplicationRuntime `json:"allowed_runtimes"`
	MaxPorts              int                  `json:"max_ports"`
	MaxVolumes            int                  `json:"max_volumes"`
	MaxSecrets            int                  `json:"max_secrets"`
	AllowPublicHTTP       bool                 `json:"allow_public_http"`
	RequireReadOnlyRootFS bool                 `json:"require_read_only_rootfs"`
}

func (p ApplicationCatalogPolicy) Validate() error {
	for name, limit := range map[string]int{
		"max_ports": p.MaxPorts, "max_volumes": p.MaxVolumes, "max_secrets": p.MaxSecrets,
	} {
		if limit < -1 {
			return fmt.Errorf("%s cannot be less than -1", name)
		}
	}
	if len(p.AllowedRegistries) == 0 || len(p.AllowedRuntimes) == 0 {
		return errors.New("application policy requires an allowed registry and runtime")
	}
	seenRegistries := make(map[string]struct{}, len(p.AllowedRegistries))
	for _, registry := range p.AllowedRegistries {
		if registry != strings.ToLower(strings.TrimSpace(registry)) {
			return errors.New("allowed registries must be canonical lowercase values")
		}
		if err := validateRegistry(registry); err != nil {
			return fmt.Errorf("allowed registry %q: %w", registry, err)
		}
		if _, duplicate := seenRegistries[registry]; duplicate {
			return fmt.Errorf("allowed registry %q is duplicated", registry)
		}
		seenRegistries[registry] = struct{}{}
	}
	seenRuntimes := make(map[ApplicationRuntime]struct{}, len(p.AllowedRuntimes))
	for _, runtime := range p.AllowedRuntimes {
		if !validApplicationRuntime(runtime) {
			return fmt.Errorf("unsupported application runtime %q", runtime)
		}
		if _, duplicate := seenRuntimes[runtime]; duplicate {
			return fmt.Errorf("allowed runtime %q is duplicated", runtime)
		}
		seenRuntimes[runtime] = struct{}{}
	}
	return nil
}

type ApplicationPortProtocol string
type ApplicationPortExposure string

const (
	ApplicationPortTCP ApplicationPortProtocol = "tcp"
	ApplicationPortUDP ApplicationPortProtocol = "udp"

	ApplicationExposureInternal ApplicationPortExposure = "internal"
	ApplicationExposureHTTP     ApplicationPortExposure = "http"
	ApplicationExposureHTTPS    ApplicationPortExposure = "https"
)

type ApplicationPortPolicy struct {
	Name          string                  `json:"name"`
	ContainerPort int                     `json:"container_port"`
	Protocol      ApplicationPortProtocol `json:"protocol"`
	Exposure      ApplicationPortExposure `json:"exposure"`
}

type ApplicationVolumeTarget string

const (
	ApplicationVolumeData    ApplicationVolumeTarget = "data"
	ApplicationVolumeConfig  ApplicationVolumeTarget = "config"
	ApplicationVolumeUploads ApplicationVolumeTarget = "uploads"
	ApplicationVolumeCache   ApplicationVolumeTarget = "cache"
)

// ApplicationVolumePolicy uses a renderer-owned target rather than accepting
// a host or container filesystem path.
type ApplicationVolumePolicy struct {
	Name     string                  `json:"name"`
	Target   ApplicationVolumeTarget `json:"target"`
	SizeMB   int                     `json:"size_mb"`
	ReadOnly bool                    `json:"read_only"`
}

// ApplicationSecretPolicy declares a mounted secret slot. Deployments bind the
// slot to an encrypted secret ID; no plaintext value or mount path is accepted.
type ApplicationSecretPolicy struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
}

type ApplicationEnvironmentPolicy struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Default  string `json:"default,omitempty"`
}

type ApplicationHealthKind string

const (
	ApplicationHealthNone ApplicationHealthKind = ""
	ApplicationHealthTCP  ApplicationHealthKind = "tcp"
	ApplicationHealthHTTP ApplicationHealthKind = "http"
)

type ApplicationHealthPolicy struct {
	Kind             ApplicationHealthKind `json:"kind,omitempty"`
	Port             string                `json:"port,omitempty"`
	HTTPPath         string                `json:"http_path,omitempty"`
	IntervalSeconds  int                   `json:"interval_seconds,omitempty"`
	TimeoutSeconds   int                   `json:"timeout_seconds,omitempty"`
	FailureThreshold int                   `json:"failure_threshold,omitempty"`
}

type ApplicationCatalogManifest struct {
	SchemaVersion  int                            `json:"schema_version"`
	Slug           string                         `json:"slug"`
	Revision       string                         `json:"revision"`
	DisplayName    string                         `json:"display_name"`
	Runtime        ApplicationRuntime             `json:"runtime"`
	Image          string                         `json:"image"`
	ReadOnlyRootFS bool                           `json:"read_only_rootfs"`
	Ports          []ApplicationPortPolicy        `json:"ports,omitempty"`
	Volumes        []ApplicationVolumePolicy      `json:"volumes,omitempty"`
	Environment    []ApplicationEnvironmentPolicy `json:"environment,omitempty"`
	Secrets        []ApplicationSecretPolicy      `json:"secrets,omitempty"`
	Health         ApplicationHealthPolicy        `json:"health,omitempty"`
}

func ValidateApplicationManifest(m ApplicationCatalogManifest, policy ApplicationCatalogPolicy) error {
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("application catalog policy: %w", err)
	}
	if m.SchemaVersion != 1 {
		return fmt.Errorf("unsupported application manifest schema version %d", m.SchemaVersion)
	}
	if err := validateSlug("application slug", m.Slug); err != nil {
		return err
	}
	if !safeRefRE.MatchString(m.Revision) {
		return errors.New("application revision must be an immutable safe identifier")
	}
	if err := validateDisplayName("application display name", m.DisplayName, 100); err != nil {
		return err
	}
	if !validApplicationRuntime(m.Runtime) || !runtimeAllowed(m.Runtime, policy.AllowedRuntimes) {
		return fmt.Errorf("application runtime %q is not allowed", m.Runtime)
	}
	registry, err := validatePinnedImage(m.Image)
	if err != nil {
		return err
	}
	if !containsString(policy.AllowedRegistries, registry) {
		return fmt.Errorf("application registry %q is not allowed", registry)
	}
	if policy.RequireReadOnlyRootFS && !m.ReadOnlyRootFS {
		return errors.New("application policy requires a read-only root filesystem")
	}
	if err := validateManifestPorts(m.Ports, policy); err != nil {
		return err
	}
	if err := validateManifestVolumes(m.Volumes, policy.MaxVolumes); err != nil {
		return err
	}
	if err := validateManifestEnvironment(m.Environment); err != nil {
		return err
	}
	if err := validateManifestSecrets(m.Secrets, policy.MaxSecrets); err != nil {
		return err
	}
	if err := validateHealthPolicy(m.Health, m.Ports); err != nil {
		return err
	}
	return nil
}

func validateManifestPorts(ports []ApplicationPortPolicy, policy ApplicationCatalogPolicy) error {
	if exceedsLimit(len(ports), policy.MaxPorts) {
		return errors.New("application manifest exceeds the port limit")
	}
	names := make(map[string]struct{}, len(ports))
	endpoints := make(map[string]struct{}, len(ports))
	for _, port := range ports {
		if err := validateSlug("application port name", port.Name); err != nil {
			return err
		}
		if port.ContainerPort < 1 || port.ContainerPort > 65535 {
			return fmt.Errorf("application port %q is outside 1-65535", port.Name)
		}
		if port.Protocol != ApplicationPortTCP && port.Protocol != ApplicationPortUDP {
			return fmt.Errorf("application port %q has unsupported protocol %q", port.Name, port.Protocol)
		}
		switch port.Exposure {
		case ApplicationExposureInternal:
		case ApplicationExposureHTTP, ApplicationExposureHTTPS:
			if port.Protocol != ApplicationPortTCP {
				return fmt.Errorf("application port %q must use TCP for HTTP exposure", port.Name)
			}
			if !policy.AllowPublicHTTP {
				return fmt.Errorf("application port %q requests disabled public HTTP exposure", port.Name)
			}
		default:
			return fmt.Errorf("application port %q has unsupported exposure %q", port.Name, port.Exposure)
		}
		if _, duplicate := names[port.Name]; duplicate {
			return fmt.Errorf("application port name %q is duplicated", port.Name)
		}
		names[port.Name] = struct{}{}
		endpoint := fmt.Sprintf("%d/%s", port.ContainerPort, port.Protocol)
		if _, duplicate := endpoints[endpoint]; duplicate {
			return fmt.Errorf("application endpoint %s is duplicated", endpoint)
		}
		endpoints[endpoint] = struct{}{}
	}
	return nil
}

func validateManifestVolumes(volumes []ApplicationVolumePolicy, limit int) error {
	if exceedsLimit(len(volumes), limit) {
		return errors.New("application manifest exceeds the volume limit")
	}
	names := make(map[string]struct{}, len(volumes))
	targets := make(map[ApplicationVolumeTarget]struct{}, len(volumes))
	for _, volume := range volumes {
		if err := validateSlug("application volume name", volume.Name); err != nil {
			return err
		}
		switch volume.Target {
		case ApplicationVolumeData, ApplicationVolumeConfig, ApplicationVolumeUploads, ApplicationVolumeCache:
		default:
			return fmt.Errorf("application volume %q has unsupported target %q", volume.Name, volume.Target)
		}
		if volume.SizeMB < 1 || volume.SizeMB > 1024*1024 {
			return fmt.Errorf("application volume %q size must be between 1 MB and 1 TB", volume.Name)
		}
		if _, duplicate := names[volume.Name]; duplicate {
			return fmt.Errorf("application volume name %q is duplicated", volume.Name)
		}
		if _, duplicate := targets[volume.Target]; duplicate {
			return fmt.Errorf("application volume target %q is duplicated", volume.Target)
		}
		names[volume.Name] = struct{}{}
		targets[volume.Target] = struct{}{}
	}
	return nil
}

func validateManifestEnvironment(environment []ApplicationEnvironmentPolicy) error {
	if len(environment) > 128 {
		return errors.New("application manifest is limited to 128 environment variables")
	}
	names := make(map[string]struct{}, len(environment))
	for _, variable := range environment {
		if !envNameRE.MatchString(variable.Name) || len(variable.Default) > 8192 || strings.ContainsAny(variable.Default, "\x00\r\n") {
			return fmt.Errorf("application environment variable %q is invalid", variable.Name)
		}
		if variable.Required && variable.Default != "" {
			return fmt.Errorf("required environment variable %q cannot define a default", variable.Name)
		}
		if _, duplicate := names[variable.Name]; duplicate {
			return fmt.Errorf("application environment variable %q is duplicated", variable.Name)
		}
		names[variable.Name] = struct{}{}
	}
	return nil
}

func validateManifestSecrets(secrets []ApplicationSecretPolicy, limit int) error {
	if exceedsLimit(len(secrets), limit) {
		return errors.New("application manifest exceeds the secret limit")
	}
	names := make(map[string]struct{}, len(secrets))
	for _, secret := range secrets {
		if err := validateSlug("application secret name", secret.Name); err != nil {
			return err
		}
		if _, duplicate := names[secret.Name]; duplicate {
			return fmt.Errorf("application secret %q is duplicated", secret.Name)
		}
		names[secret.Name] = struct{}{}
	}
	return nil
}

func validateHealthPolicy(health ApplicationHealthPolicy, ports []ApplicationPortPolicy) error {
	if health.Kind == ApplicationHealthNone {
		if health.Port != "" || health.HTTPPath != "" || health.IntervalSeconds != 0 ||
			health.TimeoutSeconds != 0 || health.FailureThreshold != 0 {
			return errors.New("disabled application health check cannot define settings")
		}
		return nil
	}
	if health.Kind != ApplicationHealthTCP && health.Kind != ApplicationHealthHTTP {
		return fmt.Errorf("unsupported application health check %q", health.Kind)
	}
	var selected *ApplicationPortPolicy
	for index := range ports {
		if ports[index].Name == health.Port {
			selected = &ports[index]
			break
		}
	}
	if selected == nil || selected.Protocol != ApplicationPortTCP {
		return errors.New("application health check must reference a TCP port")
	}
	if health.Kind == ApplicationHealthHTTP {
		if !validHTTPHealthPath(health.HTTPPath) {
			return errors.New("application HTTP health path is invalid")
		}
	} else if health.HTTPPath != "" {
		return errors.New("TCP application health checks cannot define an HTTP path")
	}
	if health.IntervalSeconds < 5 || health.IntervalSeconds > 300 {
		return errors.New("application health interval must be between 5 and 300 seconds")
	}
	if health.TimeoutSeconds < 1 || health.TimeoutSeconds > 30 || health.TimeoutSeconds >= health.IntervalSeconds {
		return errors.New("application health timeout must be positive, below 30 seconds, and shorter than its interval")
	}
	if health.FailureThreshold < 1 || health.FailureThreshold > 10 {
		return errors.New("application health failure threshold must be between 1 and 10")
	}
	return nil
}

// ApplicationDeploymentRequest binds user-editable values to declarations in
// a validated catalog manifest. Secret values remain referenced by database ID.
type ApplicationDeploymentRequest struct {
	CatalogSlug string            `json:"catalog_slug"`
	Revision    string            `json:"revision"`
	Name        string            `json:"name"`
	Environment map[string]string `json:"environment,omitempty"`
	SecretIDs   map[string]int64  `json:"secret_ids,omitempty"`
}

func ValidateApplicationDeployment(r ApplicationDeploymentRequest, m ApplicationCatalogManifest) error {
	if r.CatalogSlug != m.Slug || r.Revision != m.Revision {
		return errors.New("application deployment does not match the selected catalog revision")
	}
	if err := validateSlug("application name", r.Name); err != nil {
		return err
	}
	env := make(map[string]ApplicationEnvironmentPolicy, len(m.Environment))
	for _, variable := range m.Environment {
		env[variable.Name] = variable
	}
	for name, value := range r.Environment {
		if _, ok := env[name]; !ok || len(value) > 8192 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("application environment value %q is invalid", name)
		}
	}
	for name, variable := range env {
		if variable.Required && r.Environment[name] == "" {
			return fmt.Errorf("application environment value %q is required", name)
		}
	}
	secrets := make(map[string]ApplicationSecretPolicy, len(m.Secrets))
	for _, secret := range m.Secrets {
		secrets[secret.Name] = secret
	}
	for name, id := range r.SecretIDs {
		if _, ok := secrets[name]; !ok || id <= 0 {
			return fmt.Errorf("application secret binding %q is invalid", name)
		}
	}
	for name, secret := range secrets {
		if secret.Required && r.SecretIDs[name] <= 0 {
			return fmt.Errorf("application secret binding %q is required", name)
		}
	}
	return nil
}

func validApplicationRuntime(runtime ApplicationRuntime) bool {
	switch runtime {
	case ApplicationRuntimePHP, ApplicationRuntimePython, ApplicationRuntimeNode, ApplicationRuntimeOCI:
		return true
	default:
		return false
	}
}

func runtimeAllowed(runtime ApplicationRuntime, allowed []ApplicationRuntime) bool {
	for _, candidate := range allowed {
		if runtime == candidate {
			return true
		}
	}
	return false
}

func exceedsLimit(count, limit int) bool {
	return limit >= 0 && count > limit
}

func validHTTPHealthPath(value string) bool {
	if value == "" || len(value) > 256 || !healthPathRE.MatchString(value) {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return false
		}
	}
	return true
}
