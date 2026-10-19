package multipass_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestForwardMigrationVerifierRejectsMissingFixturesWithoutVMWork(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "multipass.log")
	if err := os.WriteFile(filepath.Join(tmp, "multipass"), []byte("#!/bin/sh\necho called >> \"$VM_CALL_LOG\"\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "ubuntu-forward-migration-verify.sh")
	cmd.Env = append(os.Environ(), "PATH="+tmp+":"+os.Getenv("PATH"), "VM_CALL_LOG="+log, "NAKPANEL_RUN_TOKEN=migrationtest", "NAKPANEL_MULTIPASS_ARCH=arm64", "NAKPANEL_FORWARD_ARCHIVE=", "NAKPANEL_FORWARD_KEY=", "NAKPANEL_FORWARD_FIXTURE_DRIVER=", "NAKPANEL_FORWARD_TARGET_BUNDLE=")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "NAKPANEL_FORWARD_ARCHIVE") {
		t.Fatalf("err=%v output=%s", err, out)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("called Multipass before validating fixtures")
	}
}
func TestForwardMigrationVerifierHasCompleteGates(t *testing.T) {
	data, err := os.ReadFile("ubuntu-forward-migration-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{"assert_vm_identity", "destroy_owned_vm", "--check-only", "--mode forward-migration", "--experimental-forward-migration", "install-native-target", "assert-source-readonly", "assert-migration-data", "assert-trusted-tls", "assert-no-source-writes", "assert-reboot", "pg_restore --version", "SHOW server_version", "SELECT VERSION()", "nginx -t", "named-checkconf", "sshd -t", "proftpd -t", "quotaon -p", "multipass restart"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(s, "destroy_legacy_phase_vms") || strings.Contains(s, "do-release-upgrade") {
		t.Fatal("uses unrelated cleanup or OS upgrade")
	}
}

func TestBundledForwardFixtureBehavior(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	cmd := exec.Command(python, "ubuntu_forward_migration_fixture_test.py")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture behavior: %v\n%s", err, out)
	}
}

func signedForwardBundle(t *testing.T, root string) (string, string) {
	t.Helper()
	bundle := filepath.Join(root, "bundle")
	key := filepath.Join(root, "private.pem")
	public := filepath.Join(root, "public.pem")
	for _, args := range [][]string{{"genrsa", "-out", key, "2048"}, {"pkey", "-in", key, "-pubout", "-out", public}} {
		if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
			t.Fatalf("key fixture: %s %v", out, err)
		}
	}
	elf := make([]byte, 120)
	copy(elf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(elf[16:], 2)
	binary.LittleEndian.PutUint16(elf[18:], 183)
	binary.LittleEndian.PutUint32(elf[20:], 1)
	binary.LittleEndian.PutUint64(elf[32:], 64)
	binary.LittleEndian.PutUint16(elf[52:], 64)
	binary.LittleEndian.PutUint16(elf[54:], 56)
	binary.LittleEndian.PutUint16(elf[56:], 1)
	binary.LittleEndian.PutUint32(elf[64:], 1)
	binary.LittleEndian.PutUint64(elf[96:], 120)
	files := map[string][]byte{"VERSION": []byte("29.0.0\n"), "Makefile": []byte("build:\n"), "go.mod": []byte("module example\n"), "go.sum": []byte("checksums\n"), "deploy/install/install.sh": []byte("#!/bin/sh\n"), "migrations/00001.sql": []byte("-- fixture\n")}
	for _, name := range []string{"panel", "agent", "panelctl"} {
		files["bin/"+name] = elf
	}
	hashes := map[string]string{}
	for name, data := range files {
		path := filepath.Join(bundle, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	manifest, _ := json.Marshal(map[string]any{"schema_version": 1, "version": "29.0.0", "commit": strings.Repeat("a", 40), "go_toolchain": "go1.26.9", "cgo_enabled": false, "os": "linux", "architecture": "arm64", "cpu_baseline": "v8.0", "files": hashes})
	os.WriteFile(filepath.Join(bundle, "manifest.json"), manifest, 0600)
	if out, err := exec.Command("openssl", "dgst", "-sha256", "-sign", key, "-out", filepath.Join(bundle, "manifest.sig"), filepath.Join(bundle, "manifest.json")).CombinedOutput(); err != nil {
		t.Fatalf("sign fixture: %s %v", out, err)
	}
	return bundle, public
}

func TestForwardVerifierRejectsUnsignedTargetBeforeAnyVMWork(t *testing.T) {
	tmp := t.TempDir()
	bundle, public := signedForwardBundle(t, tmp)
	os.WriteFile(filepath.Join(bundle, "bin/panel"), []byte("tampered"), 0600)
	log := filepath.Join(tmp, "multipass.log")
	os.WriteFile(filepath.Join(tmp, "multipass"), []byte("#!/bin/sh\necho called >> \"$VM_CALL_LOG\"\nexit 1\n"), 0700)
	archive, key := filepath.Join(tmp, "source.nkbk"), filepath.Join(tmp, "key")
	os.WriteFile(archive, []byte("archive"), 0600)
	os.WriteFile(key, []byte("key"), 0600)
	driver := filepath.Join(tmp, "driver")
	os.WriteFile(driver, []byte("#!/bin/sh\nprintf '%s\\n' fixture-v1 install-native-target assert-source-readonly assert-baseline assert-migration-data assert-services assert-trusted-tls assert-reboot assert-no-source-writes\n"), 0700)
	cmd := exec.Command("bash", "ubuntu-forward-migration-verify.sh")
	cmd.Env = append(os.Environ(), "PATH="+tmp+":"+os.Getenv("PATH"), "VM_CALL_LOG="+log, "NAKPANEL_RUN_TOKEN=migrationtest", "NAKPANEL_MULTIPASS_ARCH=arm64", "NAKPANEL_MULTIPASS_SOURCE_VM=nakpanel-source-test", "NAKPANEL_FORWARD_ARCHIVE="+archive, "NAKPANEL_FORWARD_KEY="+key, "NAKPANEL_FORWARD_TARGET_BUNDLE="+bundle, "NAKPANEL_FORWARD_TARGET_PUBLIC_KEY="+public, "NAKPANEL_FORWARD_TARGET_VERSION=29.0.0", "NAKPANEL_FORWARD_ALLOW_DEVELOPMENT=0", "NAKPANEL_FORWARD_FIXTURE_DRIVER="+driver)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "bundle verification") {
		t.Fatalf("err=%v out=%s", err, out)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("called Multipass before signature validation")
	}
}

func TestForwardVerifierDoesNotReuseNobleCloudImageForResoluteTarget(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "alias", true: "explicit"}[explicit], func(t *testing.T) {
			tmp := t.TempDir()
			scriptdir := filepath.Join(tmp, "deploy/multipass")
			os.MkdirAll(scriptdir, 0700)
			for source, destination := range map[string]string{"ubuntu-forward-migration-verify.sh": "deploy/multipass/verify.sh", "ubuntu-forward-migration-fixture.py": "deploy/multipass/ubuntu-forward-migration-fixture.py", "../release/verify.py": "deploy/release/verify.py", "../install/stage_bundle.py": "deploy/install/stage_bundle.py"} {
				data, err := os.ReadFile(source)
				if err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(tmp, destination)
				os.MkdirAll(filepath.Dir(target), 0700)
				os.WriteFile(target, data, 0700)
			}
			os.WriteFile(filepath.Join(scriptdir, "common.sh"), []byte(`assert_distinct_vm_names(){ :; }
validate_run_identity(){ :; }
assert_disposable_name(){ :; }
require_multipass(){ printf '%s|%s|%s' "$NAKPANEL_MULTIPASS_IMAGE" "${NAKPANEL_MULTIPASS_IMAGE_SOURCE:-}" "${NAKPANEL_MULTIPASS_IMAGE_SHA256:-}" > "$FORWARD_OBSERVED"; return 1; }
`), 0600)
			driver := filepath.Join(tmp, "driver")
			os.WriteFile(driver, []byte("#!/bin/sh\nprintf '%s\\n' fixture-v1 install-native-target assert-source-readonly assert-baseline assert-migration-data assert-services assert-trusted-tls assert-reboot assert-no-source-writes\n"), 0700)
			bundle, public := signedForwardBundle(t, tmp)
			archive, key := filepath.Join(tmp, "archive"), filepath.Join(tmp, "key")
			os.WriteFile(archive, []byte("archive"), 0600)
			os.WriteFile(key, []byte("key"), 0600)
			observed := filepath.Join(tmp, "observed")
			cmd := exec.Command("bash", filepath.Join(scriptdir, "verify.sh"))
			cmd.Env = append(os.Environ(), "NAKPANEL_FORWARD_ARCHIVE="+archive, "NAKPANEL_FORWARD_KEY="+key, "NAKPANEL_FORWARD_TARGET_BUNDLE="+bundle, "NAKPANEL_FORWARD_TARGET_PUBLIC_KEY="+public, "NAKPANEL_FORWARD_TARGET_VERSION=29.0.0", "NAKPANEL_FORWARD_ALLOW_DEVELOPMENT=0", "NAKPANEL_FORWARD_FIXTURE_DRIVER="+driver, "NAKPANEL_MULTIPASS_SOURCE_VM=nakpanel-source-test", "NAKPANEL_RUN_TOKEN=migrationtest", "NAKPANEL_MULTIPASS_ARCH=arm64", "NAKPANEL_MULTIPASS_IMAGE=24.04", "NAKPANEL_MULTIPASS_IMAGE_SOURCE=/offline/noble.img", "NAKPANEL_MULTIPASS_IMAGE_SHA256=noble-digest", "FORWARD_OBSERVED="+observed, "NAKPANEL_FORWARD_TARGET_IMAGE_SOURCE=", "NAKPANEL_FORWARD_TARGET_IMAGE_SHA256=")
			want := "26.04||"
			if explicit {
				cmd.Env = append(cmd.Env, "NAKPANEL_FORWARD_TARGET_IMAGE_SOURCE=/offline/resolute.img", "NAKPANEL_FORWARD_TARGET_IMAGE_SHA256=resolute-digest")
				want = "26.04|/offline/resolute.img|resolute-digest"
			}
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("stub must stop before VM access: %s", out)
			}
			got, err := os.ReadFile(observed)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Fatalf("target image=%q want %q", got, want)
			}
		})
	}
}
