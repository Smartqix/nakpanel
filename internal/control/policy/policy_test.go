package policy

import (
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
}

func TestValidateSiteWithinRuntimeCeilings(t *testing.T) {
	parent := testPolicy()
	parent.Web.MaxConnections = 50
	parent.PHP.ExecEnabled = false
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
}
