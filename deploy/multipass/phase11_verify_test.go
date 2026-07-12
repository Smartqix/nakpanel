package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase11VerifierCoversRoutedSelfServiceAndIsolation(t *testing.T) {
	const path = "phase11-verify.sh"
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
	script := string(data)
	for _, want := range []string{
		"phase10-verify.sh",
		"np-routed-layout",
		"subscriptions/new",
		"Phase11 Client Workspace",
		"phase11-client.test",
		"cross-customer site lookup",
		"/support/customers/",
		"/search?q=phase11-client",
		"browser-like POST without CSRF",
		"audit_events",
		"Phase 11 routed workspace verification passed",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s is missing %q", path, want)
		}
	}
}
