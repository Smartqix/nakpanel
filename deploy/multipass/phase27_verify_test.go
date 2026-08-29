package multipass

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPhase27VerifierCoversSharedDomainWorkspace(t *testing.T) {
	const path = "phase27-verify.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, marker := range []string{
		"common.sh", `VM_NAME="${NAKPANEL_MULTIPASS_VM}"`, `IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"`,
		"phase26-verify.sh", "np-domain-primary-nav", "Domain tools", "/web-server",
		"Performance &amp; cache", "Traffic controls", "Security &amp; access",
		"/php-settings", "Process Manager", "Resource limits", "Error handling &amp; security",
		"data-np-dns-workspace", "Connection security", "Database allocation summary",
		"Recovery points", "/files", ".np-settings-fields",
		"Phase 27 Plesk-like domain workspace verification passed",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("%s is missing %q", path, marker)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable", path)
	}
}

func TestPhase27VerifierHasValidShellSyntax(t *testing.T) {
	cmd := exec.Command("bash", "-n", "phase27-verify.sh")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n phase27-verify.sh: %v\n%s", err, output)
	}
}
