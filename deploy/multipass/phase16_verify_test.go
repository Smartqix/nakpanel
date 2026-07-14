package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase16VerifierCoversOperatorRecoveryCLI(t *testing.T) {
	data, err := os.ReadFile("phase16-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"phase15-verify.sh", "panelctl", "create-admin", "nakpanel_cli_bootstrap", "session revoke-user", "backup entitlement gate", "agent ping", "Phase 16 operator CLI verification passed"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("phase16-verify.sh is missing %q", want)
		}
	}
}
