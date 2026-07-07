package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase7VerifierCoversRestoreAndHardening(t *testing.T) {
	const path = "phase7-verify.sh"
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
		"phase6-verify.sh",
		"action=\"/restores\"",
		"restore_runs",
		"restored",
		"named-checkzone",
		"named-checkconf",
		"Origin: https://attacker.test",
		"phase7 verification passed",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("phase7 verifier is missing %q", want)
		}
	}
}

func TestPhase7InstallerInstallsProductionPackages(t *testing.T) {
	const path = "../install/phase7-install.sh"
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
		"adminer",
		"roundcube",
		"bind9",
		"ufw allow 7443/tcp",
		"systemctl enable --now nakpanel-agent.service nakpanel.service",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("phase7 installer is missing %q", want)
		}
	}
}
