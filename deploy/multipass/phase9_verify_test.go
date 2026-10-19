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
		"Select an active subscription.",
		"legacy_unsubscribed_status",
		"no active subscription",
		"nakpanel_form_error",
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

func TestLegacyQuotaVerifiersRequestJSONFailures(t *testing.T) {
	for _, path := range []string{"phase9-verify.sh", "phase10-verify.sh", "phase12-verify.sh"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		script := string(data)
		start := strings.Index(script, "post_expect_400() {")
		if start < 0 {
			t.Fatalf("%s: rejection helper missing", path)
		}
		end := strings.Index(script[start:], "\n}\n")
		if end < 0 {
			t.Fatalf("%s: rejection helper incomplete", path)
		}
		helper := script[start : start+end]
		for _, want := range []string{"X-Nakpanel-SPA: true", "Accept: application/json", `"400"`, "assert_contains"} {
			if !strings.Contains(helper, want) {
				t.Errorf("%s: rejection helper missing %q", path, want)
			}
		}
		if path == "phase9-verify.sh" && strings.Count(script, `-d "subscription_id=${quota_subscription_id}"`) != 3 {
			t.Error("phase9: each resource quota rejection must select the fixture subscription")
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
