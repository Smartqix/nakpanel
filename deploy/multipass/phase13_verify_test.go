package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase13VerifierCoversSubscriptionAndDomainWorkspace(t *testing.T) {
	const path = "phase13-verify.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable", path)
	}
	for _, want := range []string{
		"phase12-verify.sh", "Phase 13 schema is incomplete", "Change Subscriber",
		"bulk plan change", "transactional subscriber transfer", "Websites &amp; Domains",
		"PHP switching", "HTTPS redirect convergence", "DNS record rendering", "DNS record deletion",
		"domain database assignment", "domain backup creation", "domain backup restore",
		"hierarchical desired status restore", "client exposed provider subscription actions", "CSRF check",
		"Phase 13 subscription and domain workspace verification passed",
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("%s is missing %q", path, want)
		}
	}
}
