package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase8VerifierCoversQuotasAndDiskIsolation(t *testing.T) {
	const path = "phase8-verify.sh"
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
		"phase7-verify.sh",
		"action=\"/quotas\"",
		"quotaon",
		"setquota",
		"pm.max_children = 2",
		"php_admin_value[memory_limit] = 64M",
		"quota exceeded",
		"phase8 verification passed",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("phase8 verifier is missing %q", want)
		}
	}
}

func TestPhase8InstallerInstallsQuotaTooling(t *testing.T) {
	const path = "../install/phase8-install.sh"
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
		"phase7-install.sh",
		"quota",
		"quotacheck",
		"quotaon",
		"systemctl restart nakpanel-agent.service nakpanel.service",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("phase8 installer is missing %q", want)
		}
	}
}
