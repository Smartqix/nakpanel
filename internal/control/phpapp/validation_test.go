package phpapp

import (
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

func managedPolicy() types.HostingPolicy {
	return types.HostingPolicy{
		SchemaVersion: 3,
		Resources:     types.HostingResourcePolicy{MaxPHPWorkers: 4, MaxPHPReleases: 5},
		Permissions: types.HostingPermissionPolicy{
			Hosting: true, Git: true, Composer: true, ComposerCodeExecution: true,
			ManagedPHPDeployments: true, PHPWorkers: true,
		},
		PHP: types.HostingPHPPolicy{AllowedVersions: []string{"8.4", "8.5"}, DefaultVersion: "8.4"},
	}
}

func TestValidateManagedConfigurationRejectsUnsafeOrUnentitledInput(t *testing.T) {
	base := ConfigureApplicationInput{
		HostingMode: types.PHPHostingModeManaged, PHPVersion: "8.4", RepositoryID: 9,
		RepositoryRef: "main", FrameworkProfile: types.PHPFrameworkCustom,
		PublicPath: "public", HealthPath: "/health", SharedPaths: []string{"var"},
		ReleaseRetention: 3, Composer: types.PHPComposerSpec{Install: true},
	}
	tests := []struct {
		name   string
		mutate func(*ConfigureApplicationInput, *types.HostingPolicy)
	}{
		{"managed disabled", func(_ *ConfigureApplicationInput, p *types.HostingPolicy) {
			p.Permissions.ManagedPHPDeployments = false
		}},
		{"git disabled", func(_ *ConfigureApplicationInput, p *types.HostingPolicy) { p.Permissions.Git = false }},
		{"composer disabled", func(_ *ConfigureApplicationInput, p *types.HostingPolicy) { p.Permissions.Composer = false }},
		{"composer execution disabled", func(i *ConfigureApplicationInput, p *types.HostingPolicy) {
			i.Composer.AllowScripts = true
			p.Permissions.ComposerCodeExecution = false
		}},
		{"wrong PHP", func(i *ConfigureApplicationInput, _ *types.HostingPolicy) { i.PHPVersion = "8.3" }},
		{"absolute public path", func(i *ConfigureApplicationInput, _ *types.HostingPolicy) { i.PublicPath = "/srv/site" }},
		{"shared traversal", func(i *ConfigureApplicationInput, _ *types.HostingPolicy) { i.SharedPaths = []string{"../secret"} }},
		{"bad health path", func(i *ConfigureApplicationInput, _ *types.HostingPolicy) { i.HealthPath = "http://example.test" }},
		{"retention zero", func(i *ConfigureApplicationInput, _ *types.HostingPolicy) { i.ReleaseRetention = 0 }},
		{"retention ceiling", func(i *ConfigureApplicationInput, _ *types.HostingPolicy) { i.ReleaseRetention = 6 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, policy := base, managedPolicy()
			input.SharedPaths = append([]string(nil), base.SharedPaths...)
			test.mutate(&input, &policy)
			if _, err := validateApplicationConfiguration(input, policy, types.PHPHostingModeClassic); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateManagedConfigurationHonorsUnlimitedLimits(t *testing.T) {
	policy := managedPolicy()
	policy.Resources.MaxPHPReleases = -1
	input := ConfigureApplicationInput{
		HostingMode: types.PHPHostingModeManaged, PHPVersion: "8.4", RepositoryID: 9,
		RepositoryRef: "main", FrameworkProfile: types.PHPFrameworkLaravel,
		ReleaseRetention: 80, Composer: types.PHPComposerSpec{Install: true},
	}
	got, err := validateApplicationConfiguration(input, policy, types.PHPHostingModeClassic)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicPath != "public" || got.HealthPath != "/up" || len(got.SharedPaths) != 2 {
		t.Fatalf("Laravel defaults = %#v", got)
	}
}

func TestValidateClassicConfigurationUsesPersistableDefaults(t *testing.T) {
	input := ConfigureApplicationInput{
		HostingMode: types.PHPHostingModeClassic, PHPVersion: "8.4", RepositoryID: 99,
		RepositoryRef: "feature/managed", FrameworkProfile: types.PHPFrameworkLaravel,
		PublicPath: "public", HealthPath: "/up", SharedPaths: []string{"storage"},
		ReleaseRetention: 3, Composer: types.PHPComposerSpec{Install: true, AllowScripts: true},
	}
	got, err := validateApplicationConfiguration(input, managedPolicy(), types.PHPHostingModeClassic)
	if err != nil {
		t.Fatal(err)
	}
	if got.RepositoryID != 0 || got.RepositoryRef != "main" {
		t.Fatalf("classic repository fields = id %d ref %q; want schema-safe empty ownership and main ref", got.RepositoryID, got.RepositoryRef)
	}
	if got.FrameworkProfile != types.PHPFrameworkPlain || got.HealthPath != "/" || got.ReleaseRetention != 5 {
		t.Fatalf("classic persisted defaults = %#v", got)
	}
	if got.PublicPath != "" || len(got.SharedPaths) != 0 || got.Composer != (types.PHPComposerSpec{}) {
		t.Fatalf("classic managed-only fields were retained: %#v", got)
	}
}

func TestValidateWorkerUsesAggregateProcessLimit(t *testing.T) {
	policy := managedPolicy()
	input := WorkerInput{Name: "queue", Script: "artisan", Processes: 3, DesiredState: "running"}
	if _, err := validateWorker(input, policy, 2); !errors.Is(err, quota.ErrExceeded) {
		t.Fatalf("aggregate worker validation error = %v", err)
	}
	policy.Resources.MaxPHPWorkers = -1
	if _, err := validateWorker(input, policy, 100); err != nil {
		t.Fatalf("unlimited worker validation = %v", err)
	}
}

func TestReadyRuntimeRequiresExactReadyRecord(t *testing.T) {
	capabilities := types.RuntimeCapabilities{
		PHPVersions: []string{"8.4", "8.5"},
		PHPRuntimes: []types.PHPRuntimeCapability{
			{Version: "8.4", Ready: true},
			{Version: "8.5", Ready: false, ValidationErrors: []string{"FPM probe failed"}},
		},
	}
	if _, err := readyPHPRuntime(capabilities, "8.4"); err != nil {
		t.Fatal(err)
	}
	if _, err := readyPHPRuntime(capabilities, "8.5"); err == nil {
		t.Fatal("an unready detailed runtime was accepted through the compatibility projection")
	}
	if _, err := readyPHPRuntime(types.RuntimeCapabilities{PHPVersions: []string{"8.4"}}, "8.4"); err == nil {
		t.Fatal("missing detailed capability was accepted")
	}
}
