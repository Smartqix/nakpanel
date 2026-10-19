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

// The fake is an executable transport boundary: failures must occur before
// transfer, install, launch, deletion or a guest-side mutation is requested.
func TestPlatformIdentityRejectsUnsafeTargets(t *testing.T) {
	for _, tc := range []struct {
		name, body, version, arch, token string
		manifest                         bool
	}{
		{"wrong version", `assert_vm_identity "$NAKPANEL_MULTIPASS_VM" 26.04 arm64 run123`, "24.04", "arm64", "run123", true},
		{"wrong architecture", `assert_vm_identity "$NAKPANEL_MULTIPASS_VM" 26.04 arm64 run123`, "26.04", "amd64", "run123", true},
		{"missing guest token", `assert_vm_identity "$NAKPANEL_MULTIPASS_VM" 26.04 arm64 run123`, "26.04", "arm64", "", true},
		{"wrong guest token", `assert_vm_identity "$NAKPANEL_MULTIPASS_VM" 26.04 arm64 run123`, "26.04", "arm64", "other", true},
		{"protected lab", `NAKPANEL_MULTIPASS_VM=nakpanel-lab; destroy_owned_vm nakpanel-lab run123`, "26.04", "arm64", "run123", false},
		{"equal source and DR", `export NAKPANEL_MULTIPASS_DR_VM="$NAKPANEL_MULTIPASS_VM"; bash ./phase29-verify.sh`, "26.04", "arm64", "run123", true},
		{"existing unowned", `ensure_vm`, "26.04", "arm64", "run123", false},
		{"delete unowned", `destroy_vm "$NAKPANEL_MULTIPASS_VM"`, "26.04", "arm64", "run123", false},
		{"sync unowned", `sync_repo ../..`, "26.04", "arm64", "run123", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			manifest := filepath.Join(dir, "run123")
			if err := os.Mkdir(manifest, 0700); err != nil {
				t.Fatal(err)
			}
			if tc.manifest {
				if err := os.WriteFile(filepath.Join(manifest, "nakpanel-26-04-arm64-run123"), []byte("26.04\tarm64\trun123\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			fake := `#!/bin/bash
printf '%s\n' "$*" >> "$FAKE_LOG"
case "$1" in
info) exit 0;;
exec) case "$*" in
 *nakpanel-identity-probe*) printf '%s\n%s\n%s\n' "$FAKE_VERSION" "$FAKE_ARCH" "$FAKE_TOKEN";;
 *) echo 'UNSAFE guest mutation' >> "$FAKE_LOG";;
esac;;
*) echo 'UNSAFE transport mutation' >> "$FAKE_LOG";;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "multipass"), []byte(fake), 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", "set -euo pipefail; source ./common.sh; "+tc.body)
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "FAKE_LOG="+log, "FAKE_VERSION="+tc.version, "FAKE_ARCH="+tc.arch, "FAKE_TOKEN="+tc.token, "NAKPANEL_RUN_TOKEN=run123", "NAKPANEL_MULTIPASS_ARCH=arm64", "NAKPANEL_MULTIPASS_IMAGE=26.04", "NAKPANEL_MULTIPASS_VM=nakpanel-26-04-arm64-run123", "NAKPANEL_OWNERSHIP_DIR="+dir, "NAKPANEL_SKIP_PRIOR_PHASES=1")
			cmd.WaitDelay = time.Second
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("unsafe operation accepted: %s", out)
			}
			calls, _ := os.ReadFile(log)
			if strings.Contains(string(calls), "UNSAFE") {
				t.Fatalf("mutation before rejection:\n%s\n%s", calls, out)
			}
		})
	}
}

func TestPlatformIdentityOwnedGuestCanBeReusedAndDestroyed(t *testing.T) {
	dir := t.TempDir()
	name := "nakpanel-26-04-arm64-run123"
	manifest := filepath.Join(dir, "run123")
	if err := os.Mkdir(manifest, 0700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(manifest, name)
	if err := os.WriteFile(record, []byte("26.04\tarm64\trun123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fake := `#!/bin/bash
case "$1" in
info) exit 0;;
exec) printf '26.04\narm64\nrun123\n';;
delete) test "$2" = --purge && test "$3" = nakpanel-26-04-arm64-run123; printf deleted > "$FAKE_LOG";;
*) exit 99;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "multipass"), []byte(fake), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `set -euo pipefail; source ./common.sh; assert_current_vm_identity; destroy_owned_vm "$NAKPANEL_MULTIPASS_VM" run123`)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "FAKE_LOG="+filepath.Join(dir, "deleted"), "NAKPANEL_RUN_TOKEN=run123", "NAKPANEL_MULTIPASS_VM="+name, "NAKPANEL_MULTIPASS_IMAGE=26.04", "NAKPANEL_MULTIPASS_ARCH=arm64", "NAKPANEL_OWNERSHIP_DIR="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("owned VM rejected: %s %v", out, err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "deleted")); string(data) != "deleted" {
		t.Fatal("delete not invoked")
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatal("deleted VM host ownership record retained")
	}
}

func TestIdentityProbeRetriesTransientTransportButRejectsMismatches(t *testing.T) {
	for _, mode := range []string{"reset", "empty", "wrong token"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			record := filepath.Join(dir, "testtoken", "nakpanel-test-native")
			if err := os.MkdirAll(filepath.Dir(record), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(record, []byte("26.04\tarm64\ttesttoken\n"), 0600); err != nil {
				t.Fatal(err)
			}
			script := `set -euo pipefail
source ./common.sh
sleep(){ return 0; }
probe_vm_identity(){
 if [[ ! -e "$NAKPANEL_OWNERSHIP_DIR/probed" ]]; then touch "$NAKPANEL_OWNERSHIP_DIR/probed"; if [[ "$MODE" == reset ]]; then return 255; fi; if [[ "$MODE" == empty ]]; then return 0; fi; printf '26.04\narm64\nwrong\n';return;fi
 printf '26.04\narm64\ntesttoken\n'
}
assert_vm_identity nakpanel-test-native 26.04 arm64 testtoken
`
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(), "MODE="+mode, "NAKPANEL_OWNERSHIP_DIR="+dir, "NAKPANEL_MULTIPASS_IMAGE=26.04", "NAKPANEL_MULTIPASS_ARCH=arm64")
			out, err := cmd.CombinedOutput()
			if (err == nil) != (mode != "wrong token") {
				t.Fatalf("mode %s: %s %v", mode, out, err)
			}
		})
	}
}

func TestGuestIdentityProbeRequiresUbuntuBeforeReturningVersion(t *testing.T) {
	for _, id := range []string{"ubuntu", "debian"} {
		t.Run(id, func(t *testing.T) {
			dir := t.TempDir()
			release := filepath.Join(dir, "os-release")
			if err := os.WriteFile(release, []byte("ID="+id+"\nVERSION_ID=26.04\n"), 0600); err != nil {
				t.Fatal(err)
			}
			script := `source ./common.sh
dpkg(){ echo arm64; };export -f dpkg
multipass_exec_short(){
 while [[ "$1" != -c ]]; do shift; done
 shift; code="$1";code="${code//\/etc\/os-release/$TEST_RELEASE}";bash -c "$code"
}
probe_vm_identity nakpanel-test-native
`
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(), "TEST_RELEASE="+release)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (id == "ubuntu") {
				t.Fatalf("identity ID%s: %s %v", id, out, err)
			}
		})
	}
}
