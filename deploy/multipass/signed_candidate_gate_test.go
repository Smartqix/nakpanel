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

func TestSignedGuestPathsAreTokenBound(t *testing.T) {
	for _, tc := range []struct {
		name, token, override, want string
		valid                       bool
	}{
		{"private signed source", "test-run123", "", "/var/lib/nakpanel-qualification/test-run123/source:/var/lib/nakpanel-qualification/test-run123/release:/var/lib/nakpanel-qualification/test-run123/public.pem", true},
		{"source override", "test-run123", "/tmp/nakpanel-src", "", false},
		{"unsafe token", "../escape", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", `set -euo pipefail; source ./common.sh; printf '%s:%s:%s' "$NAKPANEL_REMOTE_SRC" "$NAKPANEL_GUEST_RELEASE_DIR" "$NAKPANEL_GUEST_RELEASE_PUBLIC_KEY"`)
			cmd.Env = append(os.Environ(), "NAKPANEL_RELEASE_BUNDLE=/host/selected", "NAKPANEL_RUN_TOKEN="+tc.token, "NAKPANEL_REMOTE_SRC="+tc.override)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.valid || (tc.valid && string(out) != tc.want) {
				t.Fatalf("paths: %s %v", out, err)
			}
		})
	}
}

func TestSignedSourceConfigurationCanPrecedeRunTokenCreation(t *testing.T) {
	cmd := exec.Command("bash", "-c", `set -euo pipefail
source ./common.sh
export NAKPANEL_RUN_TOKEN=review-run123
init_qualification_run
printf '%s' "$NAKPANEL_REMOTE_SRC"
`)
	cmd.Env = append(os.Environ(), "NAKPANEL_RELEASE_BUNDLE=/host/selected", "NAKPANEL_RUN_TOKEN=", "NAKPANEL_REMOTE_SRC=", "NAKPANEL_MULTIPASS_VM=nakpanel-lab")
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "/var/lib/nakpanel-qualification/review-run123/source" {
		t.Fatalf("source-before-token configuration: %s %v", out, err)
	}
}

func TestExplicitRawSourceDoesNotReuseSignedGuestArtifacts(t *testing.T) {
	cmd := exec.Command("bash", "-c", `set -euo pipefail
source ./common.sh
unset NAKPANEL_RELEASE_BUNDLE
NAKPANEL_REMOTE_SRC=/tmp/nakpanel-explicit-raw
configure_qualification_guest_paths
test "$NAKPANEL_REMOTE_SRC" = /tmp/nakpanel-explicit-raw
test -z "${NAKPANEL_GUEST_RELEASE_DIR:-}"
test -z "${NAKPANEL_GUEST_RELEASE_PUBLIC_KEY:-}"
`)
	cmd.Env = append(os.Environ(), "NAKPANEL_RELEASE_BUNDLE=/host/selected", "NAKPANEL_RUN_TOKEN=review-run123", "NAKPANEL_REMOTE_SRC=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("raw mode reused signed artifacts: %s %v", out, err)
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
			if script == "internal-tools-verify.sh" {
				// Local fixture validation deliberately precedes guest/artifact calls.
				cmd.Env = append(cmd.Env, "NAKPANEL_INTERNAL_TOOLS_SITE_ID=1", "NAKPANEL_INTERNAL_TOOLS_MAILBOX=phase29@example.test")
			}
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "expected signed bundle missing") || strings.Contains(string(out), "FORBIDDEN_INSTALL") {
				t.Fatalf("gate reached mutation without expected artifact: %s %v", out, err)
			}
		})
	}
}
