package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallOnlyChecksHealthWithoutCreatingProductFixtures(t *testing.T) {
	dir := t.TempDir()
	script, err := os.ReadFile("current-install-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "current-install-verify.sh"), script, 0700)
	common := `NAKPANEL_MULTIPASS_VM=nakpanel-fixture
NAKPANEL_MULTIPASS_IMAGE=24.04
NAKPANEL_QUALIFICATION_PHP_PROVIDER=native
NAKPANEL_REMOTE_SRC=/private/source
NAKPANEL_GUEST_RELEASE_DIR=/private/release
NAKPANEL_GUEST_RELEASE_PUBLIC_KEY=/private/public.pem
require_nakpanel_vm_name(){ :; };ensure_vm(){ :; };sync_repo(){ :; };assert_current_vm_identity(){ :; }
stage_qualification_release(){ :; };assert_qualification_bundle_staged(){ :; };assert_qualification_installed_release(){ :; };multipass(){ :; }
vm_ip(){ echo 127.0.0.1; }
curl(){ printf '%s\n' "$*" >>"$CALL_LOG"; [[ "$*" == *'/healthz'* ]]; }
`
	os.WriteFile(filepath.Join(dir, "common.sh"), []byte(common), 0600)
	log := filepath.Join(dir, "calls")
	cmd := exec.Command("bash", filepath.Join(dir, "current-install-verify.sh"))
	cmd.Env = append(os.Environ(), "NAKPANEL_RELEASE_BUNDLE=/selected", "NAKPANEL_INSTALL_ONLY=1", "CALL_LOG="+log)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install-only: %s %v", out, err)
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "/healthz") || strings.Contains(string(calls), "/login") {
		t.Fatalf("fixtures created or health omitted: %s", calls)
	}
}

func TestInstallOnlyRejectsRawOrHistoricalModeBeforeVMWork(t *testing.T) {
	for _, mode := range []string{"raw", "historical"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			script, err := os.ReadFile("current-install-verify.sh")
			if err != nil {
				t.Fatal(err)
			}
			os.WriteFile(filepath.Join(dir, "current-install-verify.sh"), script, 0700)
			os.WriteFile(filepath.Join(dir, "common.sh"), []byte(`NAKPANEL_MULTIPASS_VM=nakpanel-fixture
NAKPANEL_MULTIPASS_IMAGE=24.04
require_nakpanel_vm_name(){ echo VM_MUTATION >&2;return 99; }
`), 0600)
			cmd := exec.Command("bash", filepath.Join(dir, "current-install-verify.sh"))
			cmd.Env = append(os.Environ(), "NAKPANEL_INSTALL_ONLY=1", "NAKPANEL_RELEASE_BUNDLE=")
			if mode == "historical" {
				cmd.Env = append(cmd.Env, "NAKPANEL_RELEASE_BUNDLE=/selected", "NAKPANEL_RELEASE_LEGACY_INSTALLER=1")
			}
			out, err := cmd.CombinedOutput()
			if err == nil || strings.Contains(string(out), "VM_MUTATION") {
				t.Fatalf("unsafe install-only reached guest work: %s %v", out, err)
			}
		})
	}
}
