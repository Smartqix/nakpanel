package platformadmin

import (
	"strings"
	"testing"
)

func validApplicationPolicy() ApplicationCatalogPolicy {
	return ApplicationCatalogPolicy{
		AllowedRegistries: []string{"registry.example.test"},
		AllowedRuntimes:   []ApplicationRuntime{ApplicationRuntimeOCI, ApplicationRuntimeNode},
		MaxPorts:          4, MaxVolumes: 4, MaxSecrets: 4,
		AllowPublicHTTP: true, RequireReadOnlyRootFS: true,
	}
}

func validApplicationManifest() ApplicationCatalogManifest {
	return ApplicationCatalogManifest{
		SchemaVersion: 1, Slug: "notes", Revision: "release_1",
		DisplayName: "Notes", Runtime: ApplicationRuntimeOCI,
		Image:          "registry.example.test/team/notes@sha256:" + strings.Repeat("a", 64),
		ReadOnlyRootFS: true,
		Ports: []ApplicationPortPolicy{{
			Name: "web", ContainerPort: 8080, Protocol: ApplicationPortTCP,
			Exposure: ApplicationExposureHTTPS,
		}},
		Volumes: []ApplicationVolumePolicy{{
			Name: "content", Target: ApplicationVolumeData, SizeMB: 1024,
		}},
		Environment: []ApplicationEnvironmentPolicy{
			{Name: "SITE_TITLE", Default: "My notes"},
			{Name: "ADMIN_EMAIL", Required: true},
		},
		Secrets: []ApplicationSecretPolicy{{Name: "database", Required: true}},
		Health: ApplicationHealthPolicy{
			Kind: ApplicationHealthHTTP, Port: "web", HTTPPath: "/health",
			IntervalSeconds: 30, TimeoutSeconds: 5, FailureThreshold: 3,
		},
	}
}

func TestValidateApplicationManifest(t *testing.T) {
	if err := ValidateApplicationManifest(validApplicationManifest(), validApplicationPolicy()); err != nil {
		t.Fatalf("valid manifest: %v", err)
	}
}

func TestApplicationPolicyRejectsUnsafeRegistriesAndLimits(t *testing.T) {
	tests := []func(*ApplicationCatalogPolicy){
		func(policy *ApplicationCatalogPolicy) {
			policy.AllowedRegistries = []string{"https://registry.example.test"}
		},
		func(policy *ApplicationCatalogPolicy) {
			policy.AllowedRegistries = []string{"registry.example.test", "registry.example.test"}
		},
		func(policy *ApplicationCatalogPolicy) { policy.AllowedRuntimes = []ApplicationRuntime{"shell"} },
		func(policy *ApplicationCatalogPolicy) { policy.MaxPorts = -2 },
	}
	for _, mutate := range tests {
		policy := validApplicationPolicy()
		mutate(&policy)
		if err := policy.Validate(); err == nil {
			t.Fatalf("expected policy rejection for %#v", policy)
		}
	}
}

func TestApplicationManifestRequiresPinnedAllowedImage(t *testing.T) {
	tests := []string{
		"registry.example.test/team/notes:latest",
		"docker.io/team/notes@sha256:" + strings.Repeat("a", 64),
		"registry.example.test/team/notes@sha256:" + strings.Repeat("z", 64),
		"registry.example.test/Team/notes@sha256:" + strings.Repeat("a", 64),
		"registry.example.test/team/../notes@sha256:" + strings.Repeat("a", 64),
		"registry.example.test/team/notes@sha256:" + strings.Repeat("a", 63) + ";",
	}
	for _, image := range tests {
		manifest := validApplicationManifest()
		manifest.Image = image
		if err := ValidateApplicationManifest(manifest, validApplicationPolicy()); err == nil {
			t.Fatalf("expected image %q to be rejected", image)
		}
	}
}

func TestApplicationManifestPortPolicies(t *testing.T) {
	tests := []func(*ApplicationCatalogManifest, *ApplicationCatalogPolicy){
		func(manifest *ApplicationCatalogManifest, _ *ApplicationCatalogPolicy) {
			manifest.Ports[0].ContainerPort = 0
		},
		func(manifest *ApplicationCatalogManifest, _ *ApplicationCatalogPolicy) {
			manifest.Ports[0].Protocol = "tcp; command"
		},
		func(manifest *ApplicationCatalogManifest, _ *ApplicationCatalogPolicy) {
			manifest.Ports[0].Protocol = ApplicationPortUDP
		},
		func(manifest *ApplicationCatalogManifest, policy *ApplicationCatalogPolicy) {
			policy.AllowPublicHTTP = false
		},
		func(manifest *ApplicationCatalogManifest, _ *ApplicationCatalogPolicy) {
			manifest.Ports = append(manifest.Ports, manifest.Ports[0])
		},
	}
	for _, mutate := range tests {
		manifest, policy := validApplicationManifest(), validApplicationPolicy()
		mutate(&manifest, &policy)
		if err := ValidateApplicationManifest(manifest, policy); err == nil {
			t.Fatalf("expected port policy rejection for %#v", manifest.Ports)
		}
	}
}

func TestApplicationManifestVolumeAndSecretPolicies(t *testing.T) {
	tests := []func(*ApplicationCatalogManifest){
		func(manifest *ApplicationCatalogManifest) { manifest.Volumes[0].Target = "/etc" },
		func(manifest *ApplicationCatalogManifest) { manifest.Volumes[0].SizeMB = 0 },
		func(manifest *ApplicationCatalogManifest) {
			manifest.Volumes = append(manifest.Volumes, ApplicationVolumePolicy{
				Name: "other", Target: ApplicationVolumeData, SizeMB: 10,
			})
		},
		func(manifest *ApplicationCatalogManifest) {
			manifest.Secrets = append(manifest.Secrets, manifest.Secrets[0])
		},
		func(manifest *ApplicationCatalogManifest) {
			manifest.Secrets[0].Name = "../host-secret"
		},
	}
	for _, mutate := range tests {
		manifest := validApplicationManifest()
		mutate(&manifest)
		if err := ValidateApplicationManifest(manifest, validApplicationPolicy()); err == nil {
			t.Fatalf("expected volume/secret policy rejection: %#v %#v", manifest.Volumes, manifest.Secrets)
		}
	}
}

func TestApplicationManifestEnvironmentAndHealthPolicies(t *testing.T) {
	tests := []func(*ApplicationCatalogManifest){
		func(manifest *ApplicationCatalogManifest) { manifest.Environment[0].Name = "BAD-NAME" },
		func(manifest *ApplicationCatalogManifest) { manifest.Environment[0].Default = "bad\x00value" },
		func(manifest *ApplicationCatalogManifest) { manifest.Environment[0].Default = "bad\nvalue" },
		func(manifest *ApplicationCatalogManifest) {
			manifest.Environment = append(manifest.Environment, manifest.Environment[0])
		},
		func(manifest *ApplicationCatalogManifest) { manifest.Health.Port = "missing" },
		func(manifest *ApplicationCatalogManifest) { manifest.Health.HTTPPath = "/../../admin" },
		func(manifest *ApplicationCatalogManifest) { manifest.Health.HTTPPath = "/%2e%2e/admin" },
		func(manifest *ApplicationCatalogManifest) { manifest.Health.HTTPPath = "/health?verbose=1" },
		func(manifest *ApplicationCatalogManifest) { manifest.Health.TimeoutSeconds = 30 },
	}
	for _, mutate := range tests {
		manifest := validApplicationManifest()
		mutate(&manifest)
		if err := ValidateApplicationManifest(manifest, validApplicationPolicy()); err == nil {
			t.Fatalf("expected environment/health rejection for %#v", manifest)
		}
	}
}

func TestValidateApplicationDeployment(t *testing.T) {
	manifest := validApplicationManifest()
	valid := ApplicationDeploymentRequest{
		CatalogSlug: "notes", Revision: "release_1", Name: "customer-notes",
		Environment: map[string]string{"ADMIN_EMAIL": "admin@example.test"},
		SecretIDs:   map[string]int64{"database": 91},
	}
	if err := ValidateApplicationDeployment(valid, manifest); err != nil {
		t.Fatalf("valid deployment: %v", err)
	}

	tests := []func(*ApplicationDeploymentRequest){
		func(request *ApplicationDeploymentRequest) { request.Revision = "latest" },
		func(request *ApplicationDeploymentRequest) { request.Name = "../escape" },
		func(request *ApplicationDeploymentRequest) { request.Environment["UNDECLARED"] = "value" },
		func(request *ApplicationDeploymentRequest) { delete(request.Environment, "ADMIN_EMAIL") },
		func(request *ApplicationDeploymentRequest) { request.Environment["ADMIN_EMAIL"] = "bad\x00value" },
		func(request *ApplicationDeploymentRequest) { request.SecretIDs["unknown"] = 92 },
		func(request *ApplicationDeploymentRequest) { delete(request.SecretIDs, "database") },
	}
	for _, mutate := range tests {
		request := ApplicationDeploymentRequest{
			CatalogSlug: "notes", Revision: "release_1", Name: "customer-notes",
			Environment: map[string]string{"ADMIN_EMAIL": "admin@example.test"},
			SecretIDs:   map[string]int64{"database": 91},
		}
		mutate(&request)
		if err := ValidateApplicationDeployment(request, manifest); err == nil {
			t.Fatalf("expected deployment rejection for %#v", request)
		}
	}
}
