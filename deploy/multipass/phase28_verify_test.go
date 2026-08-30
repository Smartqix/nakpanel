package multipass

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPhase28VerifierCoversOperationalContainerRuntime(t *testing.T) {
	const path = "phase28-verify.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, marker := range []string{
		"common.sh", `VM_NAME="${NAKPANEL_MULTIPASS_VM}"`, `IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"`,
		"phase27-verify.sh", "uidmap", "/etc/subuid", "/etc/subgid",
		"docker.io/library/nginx@", "route_prefix=/phase28/", "in_sync:healthy",
		"127.0.0.1:", "definitely-unhealthy", "active_generation", "multipass restart",
		"desired_status=suspended", "PHP Application", "Classic Hosting", "Managed Deployment",
		"retired application containers remain", "data-np-container-logs", "/logs?lines=20&bytes=4096",
		"/tools-settings/application-catalog", "Phase 28 operational application runtime verification passed",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("%s is missing %q", path, marker)
		}
	}
	if strings.Contains(script, "Managed runtimes are not installed yet") {
		t.Fatal("phase28 verifier still requires the retired application placeholder")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable", path)
	}
}

func TestPhase28VerifierHasValidShellSyntax(t *testing.T) {
	cmd := exec.Command("bash", "-n", "phase28-verify.sh")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n phase28-verify.sh: %v\n%s", err, output)
	}
}
