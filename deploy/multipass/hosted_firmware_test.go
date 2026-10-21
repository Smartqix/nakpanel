package multipass

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostedFirmwareExclusionRequiresExplicitOwnedDisposableGuest(t *testing.T) {
	data, err := os.ReadFile("common.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, string(data), "configure_hosted_guest_firmware", true)
	for _, mode := range []string{"disabled", "developer-host", "unowned", "owned"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "transport")
			body := `set -euo pipefail
NAKPANEL_MULTIPASS_VM=nakpanel-fixture
NAKPANEL_RUN_TOKEN=fixture; NAKPANEL_MULTIPASS_IMAGE=26.04
NAKPANEL_HOSTED_GUEST_FIRMWARE_POLICY=1
GITHUB_ACTIONS=true; RUNNER_ENVIRONMENT=github-hosted
[[ "$MODE" != disabled ]] || NAKPANEL_HOSTED_GUEST_FIRMWARE_POLICY=0
[[ "$MODE" != developer-host ]] || RUNNER_ENVIRONMENT=local
assert_current_vm_identity(){ [[ "$MODE" != unowned ]]; }
multipass_exec_short(){
 echo "$*" >"$CALLS"
 cat >>"$CALLS"
 printf '{"status":"EXCLUDED_HOST_FIRMWARE","physical_firmware_validated":false}\n'
}
` + function + `configure_hosted_guest_firmware`
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(), "MODE="+mode, "CALLS="+log, "NAKPANEL_OWNERSHIP_DIR="+dir)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "disabled" || mode == "owned") {
				t.Fatalf("%s: %s %v", mode, out, err)
			}
			calls, _ := os.ReadFile(log)
			if mode != "owned" && len(calls) > 0 {
				t.Fatalf("%s mutated guest: %s", mode, calls)
			}
			if mode == "owned" {
				if !strings.Contains(string(calls), `[[ "$(systemd-detect-virt --vm)" == kvm ]]`) || !strings.Contains(string(calls), "ExecCondition=") || strings.Contains(string(calls), "reset-failed") || strings.Contains(string(calls), "mask ") {
					t.Fatalf("missing KVM guard or silently cleared error: %s", calls)
				}
				proof, err := os.ReadFile(filepath.Join(dir, "fixture/firmware/nakpanel-fixture.json"))
				var result map[string]any
				if err != nil || json.Unmarshal(proof, &result) != nil || result["status"] != "EXCLUDED_HOST_FIRMWARE" || result["physical_firmware_validated"] != false {
					t.Fatalf("explicit exclusion receipt missing: %s %v", proof, err)
				}
			}
		})
	}
}
