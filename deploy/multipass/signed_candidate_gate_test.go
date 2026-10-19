package multipass

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExpectedSignedBundleRequiresGuestArtifacts(t *testing.T) {
	data, err := os.ReadFile("common.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, string(data), "assert_qualification_bundle_staged", false)
	for _, state := range []string{"legacy", "missing", "complete", "missing key", "missing panel", "symlink manifest"} {
		t.Run(state, func(t *testing.T) {
			dir := t.TempDir()
			bundle := filepath.Join(dir, "bundle")
			if state != "missing" && state != "legacy" {
				if err := os.MkdirAll(filepath.Join(bundle, "bin"), 0700); err != nil {
					t.Fatal(err)
				}
				for _, artifact := range []string{"manifest.json", "manifest.sig", "bin/panel", "bin/agent", "bin/panelctl"} {
					if state == "missing panel" && artifact == "bin/panel" {
						continue
					}
					if err := os.WriteFile(filepath.Join(bundle, artifact), []byte("fixture"), 0700); err != nil {
						t.Fatal(err)
					}
				}
				if state != "missing key" {
					if err := os.WriteFile(bundle+"-public.pem", []byte("fixture"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if state == "symlink manifest" {
					if err := os.Remove(filepath.Join(bundle, "manifest.json")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(bundle+"-public.pem", filepath.Join(bundle, "manifest.json")); err != nil {
						t.Fatal(err)
					}
				}
			}
			body := `set -euo pipefail
multipass_exec_short(){
 while [[ "$1" != -c ]]; do shift; done
 shift
 local code="$1"; shift
 code="${code//\/tmp\/nakpanel-release/$FIXTURE_BUNDLE}"
 bash -c "$code" "$@"
}
` + function + `assert_qualification_bundle_staged`
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(), "FIXTURE_BUNDLE="+bundle, "NAKPANEL_MULTIPASS_VM=nakpanel-fixture", "NAKPANEL_RELEASE_BUNDLE=")
			if state != "legacy" {
				cmd.Env = append(cmd.Env, "NAKPANEL_RELEASE_BUNDLE=/expected/bundle")
			}
			out, err := cmd.CombinedOutput()
			wantSuccess := state == "legacy" || state == "complete"
			if (err == nil) != wantSuccess {
				t.Fatalf("%s: %s %v", state, out, err)
			}
		})
	}
}

func TestModernGatesRejectMissingExpectedBundleBeforeInstall(t *testing.T) {
	for _, script := range []string{"phase28-verify.sh", "security-verify.sh", "phase29-verify.sh", "valkey-platform-verify.sh", "phase30-verify.sh", "phase31-verify.sh", "phase32-verify.sh", "internal-tools-verify.sh", "mail-workspace-verify.sh", "phase33-verify.sh", "phase34-verify.sh", "domain-removal-verify.sh"} {
		t.Run(script, func(t *testing.T) {
			dir := t.TempDir()
			data, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, script), data, 0700); err != nil {
				t.Fatal(err)
			}
			// Keep the gate's real control flow; replace the VM transport and
			// source sync only. A missing guard reaches the forbidden install.
			common := `NAKPANEL_MULTIPASS_VM=nakpanel-fixture
NAKPANEL_MULTIPASS_IMAGE=26.04
sync_repo(){ :; }
require_nakpanel_vm_name(){ :; }
assert_current_vm_identity(){ :; }
assert_distinct_vm_names(){ :; }
vm_ip(){ echo 127.0.0.1; }
assert_qualification_bundle_staged(){ echo 'expected signed bundle missing' >&2;return 75; }
multipass(){ echo 'FORBIDDEN_INSTALL' >&2;return 97; }
multipass_exec_short(){ :; }
`
			if err := os.WriteFile(filepath.Join(dir, "common.sh"), []byte(common), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", filepath.Join(dir, script))
			cmd.WaitDelay = time.Second
			cmd.Env = append(os.Environ(), "NAKPANEL_SKIP_PRIOR_PHASES=1", "NAKPANEL_RELEASE_BUNDLE=/expected/signed/bundle")
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "expected signed bundle missing") || strings.Contains(string(out), "FORBIDDEN_INSTALL") {
				t.Fatalf("gate reached mutation without expected artifact: %s %v", out, err)
			}
		})
	}
}
