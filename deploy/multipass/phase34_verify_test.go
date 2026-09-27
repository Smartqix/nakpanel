package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase34VerifierExercisesProtectedReports(t *testing.T) {
	script := readExecutableScript(t, "phase34-verify.sh")
	requireScriptContracts(t, script, map[string][]string{
		"deployment": {"common.sh", "phase33-verify.sh", "sync_repo", "NAKPANEL_SKIP_PRIOR_PHASES", "goaccess --version"},
		"product":    {"logs_statistics_engine=goaccess", "statistics/refresh", "statistics/report", "site_web_statistics", "tools-settings/web-statistics"},
		"isolation":  {"Content-Security-Policy", "sandbox", "404", "client.cookies", "privacy-fixture", "referrer-fixture"},
		"bounded":    {"--max-time", "seq 1 120", "trap cleanup EXIT", "require_nakpanel_vm_name"},
	})
	for _, forbidden := range []string{"INSERT INTO site_web_statistics", "UPDATE site_web_statistics", "destroy_vm"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("verifier bypasses product behavior with %q", forbidden)
		}
	}
	chain, err := os.ReadFile("deployment-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(string(chain), "phase34-verify.sh") <= strings.Index(string(chain), "phase33-verify.sh") {
		t.Fatal("Phase 34 must follow Phase 33")
	}
}

func TestPhase34PackageIsInstalledDuringUpgrades(t *testing.T) {
	data, err := os.ReadFile("../install/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "run_component_installers() {")
	if start < 0 {
		t.Fatal("component installer hook is missing")
	}
	end := strings.Index(script[start:], "\n}")
	if end < 0 || !strings.Contains(script[start:start+end], "apt-get install -y goaccess") {
		t.Fatal("GoAccess must be installed in the fresh/upgrade component path")
	}
}
