package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func testPolicy() types.HostingPolicy {
	return types.HostingPolicy{
		SchemaVersion: 1,
		Resources:     types.HostingResourcePolicy{DiskMB: 1024, CPUPercent: 100, MaxSites: 3},
		Permissions:   types.HostingPermissionPolicy{Hosting: true, DNS: true},
		PHP:           types.HostingPHPPolicy{DefaultVersion: "8.3", AllowedVersions: []string{"8.3", "8.2"}, MemoryLimitMB: 256},
		DNS:           types.HostingDNSPolicy{Enabled: true, Mode: "authoritative", DefaultTTL: 3600},
		Access:        types.HostingAccessPolicy{ShellMode: "disabled", SFTPOnly: true},
		Mail:          types.HostingMailPolicy{DMARCPolicy: "none"},
	}
}

func TestUpgradeV1AndV2ToV4PreservesLegacyValuesWithNewFeaturesDisabled(t *testing.T) {
	for _, version := range []int{1, 2} {
		legacy := testPolicy()
		legacy.SchemaVersion = version
		legacy.Permissions.Git = true
		legacy.Resources.MaxSites = 7

		got := Upgrade(legacy)
		if got.SchemaVersion != 5 || !got.Permissions.Git || got.Resources.MaxSites != 7 {
			t.Fatalf("Upgrade(v%d) did not preserve legacy policy: %#v", version, got)
		}
		if got.Permissions.Composer || got.Permissions.ComposerCodeExecution ||
			got.Permissions.ManagedPHPDeployments || got.Permissions.PHPWorkers ||
			got.Resources.MaxPHPWorkers != 0 || got.Resources.MaxPHPReleases != 0 {
			t.Fatalf("Upgrade(v%d) granted Phase 30 capability: %#v", version, got)
		}
	}
}

func TestHostingPolicyV3RoundTripsPHPHostingFields(t *testing.T) {
	want := testPolicy()
	want.SchemaVersion = 3
	want.Resources.MaxPHPWorkers = 4
	want.Resources.MaxPHPReleases = 8
	want.Permissions.Composer = true
	want.Permissions.ComposerCodeExecution = true
	want.Permissions.ManagedPHPDeployments = true
	want.Permissions.PHPWorkers = true

	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got types.HostingPolicy
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got.Resources.MaxPHPWorkers != 4 || got.Resources.MaxPHPReleases != 8 ||
		!got.Permissions.Composer || !got.Permissions.ComposerCodeExecution ||
		!got.Permissions.ManagedPHPDeployments || !got.Permissions.PHPWorkers {
		t.Fatalf("round-tripped Phase 30 policy = %#v", got)
	}
}

func TestValidateV3RejectsInvalidPHPHostingLimits(t *testing.T) {
	for name, mutate := range map[string]func(*types.HostingPolicy){
		"workers":  func(p *types.HostingPolicy) { p.Resources.MaxPHPWorkers = -2 },
		"releases": func(p *types.HostingPolicy) { p.Resources.MaxPHPReleases = -2 },
	} {
		policy := Upgrade(testPolicy())
		mutate(&policy)
		if err := Validate(policy); err == nil {
			t.Fatalf("negative max PHP %s was accepted", name)
		}
	}
}

func TestValidateWithinIncludesPHPHostingCeilings(t *testing.T) {
	ceiling := Upgrade(testPolicy())
	ceiling.Resources.MaxPHPWorkers = 2
	ceiling.Resources.MaxPHPReleases = 5
	ceiling.Permissions.Composer = true
	ceiling.Permissions.ManagedPHPDeployments = true
	child := ceiling
	if err := ValidateWithin(child, ceiling); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*types.HostingPolicy){
		"worker limit":       func(p *types.HostingPolicy) { p.Resources.MaxPHPWorkers = 3 },
		"release limit":      func(p *types.HostingPolicy) { p.Resources.MaxPHPReleases = 6 },
		"composer execution": func(p *types.HostingPolicy) { p.Permissions.ComposerCodeExecution = true },
		"PHP workers":        func(p *types.HostingPolicy) { p.Permissions.PHPWorkers = true },
	} {
		candidate := child
		mutate(&candidate)
		if err := ValidateWithin(candidate, ceiling); err == nil {
			t.Fatalf("%s exceeded provider ceiling", name)
		}
	}
}

func TestDefaultPolicyUsesV4WithoutGrantingNewHostingFeatures(t *testing.T) {
	got := DefaultFromEntitlements(types.SubscriptionEntitlements{HostingEnabled: true})
	if got.SchemaVersion != 5 {
		t.Fatalf("schema version = %d, want 5", got.SchemaVersion)
	}
	if got.Permissions.Composer || got.Permissions.ComposerCodeExecution ||
		got.Permissions.ManagedPHPDeployments || got.Permissions.PHPWorkers ||
		got.Resources.MaxPHPWorkers != 0 || got.Resources.MaxPHPReleases != 0 {
		t.Fatalf("legacy entitlements granted Phase 30 capability: %#v", got)
	}
}

func TestUpgradeLegacyPolicyToV4DoesNotGrantWordPressToolkit(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		legacy := testPolicy()
		legacy.SchemaVersion = version
		legacy.Resources.MaxSites = 4

		got := Upgrade(legacy)
		if got.SchemaVersion != 5 || got.Resources.MaxSites != 4 {
			t.Fatalf("Upgrade(v%d) = %#v", version, got)
		}
		if got.Permissions.WordPressToolkit || got.Resources.MaxWordPressSites != 0 {
			t.Fatalf("Upgrade(v%d) granted WordPress Toolkit: %#v", version, got)
		}
	}
}

func TestValidateWithinEnforcesWordPressToolkitCeiling(t *testing.T) {
	ceiling := Upgrade(testPolicy())
	ceiling.Permissions.WordPressToolkit = true
	ceiling.Resources.MaxWordPressSites = 2
	child := ceiling
	if err := ValidateWithin(child, ceiling); err != nil {
		t.Fatal(err)
	}

	child.Resources.MaxWordPressSites = 3
	if err := ValidateWithin(child, ceiling); err == nil {
		t.Fatal("WordPress site count exceeded provider ceiling")
	}
	child = ceiling
	child.Permissions.WordPressToolkit = true
	ceiling.Permissions.WordPressToolkit = false
	if err := ValidateWithin(child, ceiling); err == nil {
		t.Fatal("WordPress Toolkit permission exceeded provider ceiling")
	}
}

func TestResolveAppliesThreeLevelInheritance(t *testing.T) {
	got, err := Resolve(testPolicy(), []byte(`{"resources":{"disk_mb":2048},"php":{"memory_limit_mb":512}}`), []byte(`{"php":{"memory_limit_mb":128},"dns":{"default_ttl":600}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Resources.DiskMB != 2048 || got.PHP.MemoryLimitMB != 128 || got.DNS.DefaultTTL != 600 || got.Resources.MaxSites != 3 {
		t.Fatalf("resolved policy = %#v", got)
	}
}

func TestResolveNullMeansInherit(t *testing.T) {
	got, err := Resolve(testPolicy(), []byte(`{"resources":{"disk_mb":null}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Resources.DiskMB != 1024 {
		t.Fatalf("disk = %d, want inherited 1024", got.Resources.DiskMB)
	}
}

func TestResolveRejectsAccountFieldsAtSiteScope(t *testing.T) {
	_, err := Resolve(testPolicy(), nil, []byte(`{"resources":{"disk_mb":1}}`))
	if err == nil {
		t.Fatal("site resource override was accepted")
	}
}

func TestResolveRestrictsSitePermissionOverrides(t *testing.T) {
	if _, err := Resolve(testPolicy(), nil, []byte(`{"permissions":{"ssh":true}}`)); err == nil {
		t.Fatal("site SSH override was accepted")
	}
	if _, err := Resolve(testPolicy(), nil, []byte(`{"permissions":{"cgi":true}}`)); err != nil {
		t.Fatalf("site CGI override rejected: %v", err)
	}
}

func TestResolveRejectsUnknownAndInvalidValues(t *testing.T) {
	for _, patch := range []string{
		`{"unknown":true}`,
		`{"resources":{"disk_mb":-2}}`,
		`{"php":{"default_version":"9.0"}}`,
	} {
		if _, err := Resolve(testPolicy(), []byte(patch), nil); err == nil {
			t.Fatalf("patch %s was accepted", patch)
		}
	}
}

func TestValidateWithinProviderCeiling(t *testing.T) {
	ceiling := testPolicy()
	ceiling.Resources.DiskMB = 2048
	child := testPolicy()
	child.Resources.DiskMB = 1024
	if err := ValidateWithin(child, ceiling); err != nil {
		t.Fatal(err)
	}
	child.Resources.DiskMB = -1
	if err := ValidateWithin(child, ceiling); err == nil {
		t.Fatal("unlimited child accepted under finite ceiling")
	}
	child = testPolicy()
	child.Permissions.SSH = true
	if err := ValidateWithin(child, ceiling); err == nil {
		t.Fatal("undelegated SSH permission accepted")
	}
	child = testPolicy()
	ceiling.Permissions.Applications = true
	child.Permissions.Applications = true
	child.Permissions.ApplicationEgress = true
	if err := ValidateWithin(child, ceiling); err == nil {
		t.Fatal("undelegated application egress accepted")
	}
	child = testPolicy()
	ceiling.PHP.AllowedVersions = []string{"8.3"}
	if err := ValidateWithin(child, ceiling); err == nil {
		t.Fatal("undelegated PHP version accepted")
	}
	child.PHP.AllowedVersions = []string{"8.3"}
	child.PHP.DefaultVersion = "8.3"
	ceiling.Web.RequestBodyLimitMB = 64
	child.Web.RequestBodyLimitMB = 128
	if err := ValidateWithin(child, ceiling); err == nil {
		t.Fatal("oversized request body accepted")
	}
}

func TestValidateSiteWithinRuntimeCeilings(t *testing.T) {
	parent := testPolicy()
	parent.Web.MaxConnections = 50
	parent.Web.RequestBodyLimitMB = 64
	parent.Web.SecurityHeaderPreset = "strict"
	parent.Web.AllowedCIDRs = []string{"203.0.113.0/24"}
	parent.PHP.ExecEnabled = false
	parent.PHP.MaxExecutionSeconds = 60
	parent.PHP.AllowURLFOpen = false
	child := parent
	child.Web.MaxConnections = 25
	if err := ValidateSiteWithin(child, parent); err != nil {
		t.Fatal(err)
	}
	child.Web.MaxConnections = 75
	if err := ValidateSiteWithin(child, parent); err == nil {
		t.Fatal("domain connection limit exceeded subscription")
	}
	child = parent
	child.PHP.ExecEnabled = true
	if err := ValidateSiteWithin(child, parent); err == nil {
		t.Fatal("domain enabled PHP execution denied by subscription")
	}
	for name, mutate := range map[string]func(*types.HostingPolicy){
		"unbounded PHP execution": func(policy *types.HostingPolicy) { policy.PHP.MaxExecutionSeconds = 0 },
		"oversized request body":  func(policy *types.HostingPolicy) { policy.Web.RequestBodyLimitMB = 128 },
		"weaker security headers": func(policy *types.HostingPolicy) { policy.Web.SecurityHeaderPreset = "off" },
		"removed access restriction": func(policy *types.HostingPolicy) {
			policy.Web.AllowedCIDRs = nil
		},
		"URL fopen": func(policy *types.HostingPolicy) { policy.PHP.AllowURLFOpen = true },
	} {
		child = parent
		mutate(&child)
		if err := ValidateSiteWithin(child, parent); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestValidateSiteWithinNamesSubscriptionCeiling(t *testing.T) {
	parent := testPolicy()
	parent.PHP.MemoryLimitMB = 128
	child := parent
	child.PHP.MemoryLimitMB = 256

	err := ValidateSiteWithin(child, parent)
	if err == nil {
		t.Fatal("oversized site PHP memory was accepted")
	}
	if !strings.Contains(err.Error(), "subscription ceiling") || strings.Contains(err.Error(), "provider ceiling") {
		t.Fatalf("site ceiling error = %q, want subscription-specific language", err)
	}
}
