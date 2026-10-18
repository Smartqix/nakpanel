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
	if strings.Contains(script, "'WordPress Toolkit'; do") {
		t.Fatal("the current WordPress Toolkit navigation is implemented; reject unsupported runtime choices, not working tool links")
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

func TestPhase28PrivateLeafAllowsParentTraversalButDeniesOtherUIDAccess(t *testing.T) {
	data, err := os.ReadFile("phase28-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, string(data), "assert_private_application_paths", true)
	for _, mode := range []string{"private", "parent readable", "leaf traversable", "secret readable"} {
		t.Run(mode, func(t *testing.T) {
			script := `set -euo pipefail
base=/fixture;application_id=1;revision=2
runuser(){
 case "$*" in
 *'test -x /fixture/apps') return 0;;
 *'test -r /fixture/apps') [[ "$MODE" == 'parent readable' ]];;
 *'test -x /fixture/apps/1/generations/2/secrets') [[ "$MODE" == 'leaf traversable' ]];;
 *'test -r /fixture/apps/1/generations/2/secrets/TEST_PASSWORD') [[ "$MODE" == 'secret readable' ]];;
 *) echo "unexpected permission probe: $*" >&2;return 70;;
 esac
}
` + function + `assert_private_application_paths`
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(), "MODE="+mode)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "private") {
				t.Fatalf("permission mode %s: %s %v", mode, out, err)
			}
		})
	}
}
