package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase15VerifierCoversAccountProvisioning(t *testing.T) {
	const path = "phase15-verify.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable", path)
	}
	for _, want := range []string{
		"phase14-verify.sh", "Phase 15 schema is incomplete", "phase15acct", "account convergence",
		"shared domain provisioning", "subscription_policy_overrides", "Domain policy", "queue='heavy'",
		"subscription account and provisioning verification passed",
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("%s is missing %q", path, want)
		}
	}
}
