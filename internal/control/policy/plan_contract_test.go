package policy

import (
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestPlanContractClassifiesEveryHostingPolicyLeaf(t *testing.T) {
	fields := PlanContractFields()
	if len(fields) < 80 {
		t.Fatalf("PlanContractFields returned %d fields, want the complete policy surface", len(fields))
	}
	seen := make(map[string]types.PlanEnforcementKind, len(fields))
	for _, field := range fields {
		if field.Path == "" || field.Label == "" || field.Enforcement == "" {
			t.Fatalf("incomplete contract field: %+v", field)
		}
		if _, duplicate := seen[field.Path]; duplicate {
			t.Fatalf("duplicate contract field %q", field.Path)
		}
		seen[field.Path] = field.Enforcement
	}
	for path, want := range map[string]types.PlanEnforcementKind{
		"resources.disk_mb":                   types.PlanEnforcementMeasuredLimit,
		"resources.max_sites":                 types.PlanEnforcementHardLimit,
		"permissions.mail":                    types.PlanEnforcementServicePermission,
		"permissions.php_settings":            types.PlanEnforcementManagementPermission,
		"php.default_version":                 types.PlanEnforcementCreationDefault,
		"mail.autoresponders":                 types.PlanEnforcementStoredOnly,
		"dns.dnssec":                          types.PlanEnforcementStoredOnly,
		"applications.allowed_runtimes":       types.PlanEnforcementServicePermission,
		"applications.allowed_registries":     types.PlanEnforcementServicePermission,
		"permissions.managed_php_deployments": types.PlanEnforcementServicePermission,
		"resources.max_php_releases":          types.PlanEnforcementHardLimit,
	} {
		if got := seen[path]; got != want {
			t.Errorf("%s enforcement = %q, want %q", path, got, want)
		}
	}
}

func TestValidatePlanCapabilitiesReportsEveryBlockingRuntimeGap(t *testing.T) {
	policy := types.HostingPolicy{
		SchemaVersion: 3,
		Resources:     types.HostingResourcePolicy{DiskMB: 1024},
		Permissions: types.HostingPermissionPolicy{
			Hosting: true, Composer: true, ManagedPHPDeployments: true,
			Applications: true, CustomOCIImages: true, Valkey: true,
		},
		PHP:    types.HostingPHPPolicy{DefaultVersion: "8.5", AllowedVersions: []string{"8.4", "8.5"}},
		Valkey: types.HostingValkeyPolicy{Enabled: true, MemoryMB: 64},
	}
	issues := ValidatePlanCapabilities(policy, types.RuntimeCapabilities{
		PHPVersions: []string{"8.4"},
	})
	got := make(map[string]bool)
	for _, issue := range issues {
		got[issue.Code] = issue.Blocking
	}
	for _, code := range []string{
		"php_default_unavailable", "php_version_unavailable", "disk_quota_unavailable",
		"composer_unavailable", "podman_unavailable", "rootless_podman_unavailable",
		"subordinate_ids_unavailable", "valkey_runtime_unavailable",
	} {
		if !got[code] {
			t.Errorf("missing blocking capability issue %q in %+v", code, issues)
		}
	}
}

func TestValidatePlanCapabilitiesAcceptsReadyProductionPHPPlan(t *testing.T) {
	policy := types.HostingPolicy{
		SchemaVersion: 3,
		Resources:     types.HostingResourcePolicy{DiskMB: 2048},
		Permissions: types.HostingPermissionPolicy{
			Hosting: true, Composer: true, ManagedPHPDeployments: true,
		},
		PHP: types.HostingPHPPolicy{DefaultVersion: "8.4", AllowedVersions: []string{"8.4", "8.5"}},
	}
	issues := ValidatePlanCapabilities(policy, types.RuntimeCapabilities{
		PHPVersions:       []string{"8.4", "8.5"},
		ComposerAvailable: true,
		DiskQuota:         true,
	})
	for _, issue := range issues {
		if issue.Blocking {
			t.Fatalf("ready plan produced blocking issue: %+v", issue)
		}
	}
}

func TestValidatePlanCapabilitiesRequiresWordPressRuntime(t *testing.T) {
	policy := types.HostingPolicy{SchemaVersion: 4,
		Resources:   types.HostingResourcePolicy{MaxWordPressSites: 1},
		Permissions: types.HostingPermissionPolicy{WordPressToolkit: true},
	}
	issues := ValidatePlanCapabilities(policy, types.RuntimeCapabilities{})
	codes := map[string]bool{}
	for _, issue := range issues {
		codes[issue.Code] = issue.Blocking
	}
	if !codes["wp_cli_unavailable"] || !codes["wordpress_php_unavailable"] {
		t.Fatalf("WordPress readiness issues = %+v", issues)
	}
	if got := ValidatePlanCapabilities(policy, types.RuntimeCapabilities{WPCLIAvailable: true, PHPVersions: []string{"8.4"}}); len(got) != 0 {
		t.Fatalf("ready WordPress plan issues = %+v", got)
	}
}
