package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase17VerifierCoversTrustedCustomTLS(t *testing.T) {
	data, err := os.ReadFile("phase17-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"phase16-verify.sh", "update-ca-certificates", "ssl set-custom", "custom:active:false", "does not match certificate", "certificate_expiring", "PRIVATE KEY", "Upload custom certificate", "Phase 17 custom TLS verification passed"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("phase17-verify.sh is missing %q", want)
		}
	}
}
