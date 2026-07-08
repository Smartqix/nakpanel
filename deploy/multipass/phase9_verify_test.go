package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase9VerifierCoversPlansSubscriptionsAndPeerCredentials(t *testing.T) {
	const path = "phase9-verify.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) returned error: %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) returned error: %v", path, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable", path)
	}
	script := string(data)
	for _, want := range []string{
		"phase8-verify.sh",
		"Plans & subscriptions",
		"/assets/app.js",
		"np-layout",
		"data-np-view=\"subscriptions\"",
		"create-site-modal",
		"no active subscription",
		"action=\"/plans\"",
		"action=\"/subscriptions\"",
		"action=\"/settings/oversell\"",
		"Phase9 Tiny",
		"quota exceeded",
		"oversell cap exceeded",
		"nppeer9",
		"/run/nakpanel/agent.sock",
		"except OSError",
		"phase9 verification passed",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("phase9 verifier is missing %q", want)
		}
	}
}

func TestPhase9InstallerChainsQuotaTooling(t *testing.T) {
	const path = "../install/phase9-install.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) returned error: %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) returned error: %v", path, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable", path)
	}
	script := string(data)
	for _, want := range []string{
		"phase8-install.sh",
		"systemctl restart nakpanel-agent.service nakpanel.service",
		"Phase 9 plans/subscriptions",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("phase9 installer is missing %q", want)
		}
	}
}
