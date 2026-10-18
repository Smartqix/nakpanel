package multipass_test

import (
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
	cmd.Env = append(os.Environ(), "PATH="+tmp+":"+os.Getenv("PATH"), "VM_CALL_LOG="+log, "NAKPANEL_RUN_TOKEN=migrationtest", "NAKPANEL_MULTIPASS_ARCH=arm64", "NAKPANEL_FORWARD_ARCHIVE=", "NAKPANEL_FORWARD_KEY=", "NAKPANEL_FORWARD_FIXTURE_DRIVER=", "NAKPANEL_FORWARD_TARGET_ARTIFACTS=")
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

func TestBundledForwardFixtureRejectsUnpreparedInputBeforeVMWork(t *testing.T) {
	tmp := t.TempDir()
	for _, name := range []string{"panel", "agent", "panelctl", "VERSION"} {
		os.WriteFile(filepath.Join(tmp, name), []byte("artifact"), 0600)
	}
	log := filepath.Join(tmp, "multipass.log")
	if err := os.WriteFile(filepath.Join(tmp, "multipass"), []byte("#!/bin/sh\necho called >> \"$VM_CALL_LOG\"\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(tmp, "source.nkbk")
	key := filepath.Join(tmp, "key")
	os.WriteFile(archive, []byte("archive"), 0600)
	os.WriteFile(key, []byte("key"), 0600)
	cmd := exec.Command("bash", "ubuntu-forward-migration-verify.sh")
	cmd.Env = append(os.Environ(), "PATH="+tmp+":"+os.Getenv("PATH"), "VM_CALL_LOG="+log, "NAKPANEL_RUN_TOKEN=migrationtest", "NAKPANEL_MULTIPASS_ARCH=arm64", "NAKPANEL_MULTIPASS_SOURCE_VM=nakpanel-source-test", "NAKPANEL_FORWARD_ARCHIVE="+archive, "NAKPANEL_FORWARD_KEY="+key, "NAKPANEL_FORWARD_TARGET_ARTIFACTS="+tmp, "NAKPANEL_FORWARD_FIXTURE_DRIVER=", "NAKPANEL_FORWARD_FIXTURE_JSON=")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "NAKPANEL_FORWARD_FIXTURE_JSON") {
		t.Fatalf("err=%v output=%s", err, out)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("called Multipass with missing prepared fixture")
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

func TestForwardVerifierRejectsMissingNativeBinaryBeforeVMWork(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "multipass.log")
	os.WriteFile(filepath.Join(tmp, "multipass"), []byte("#!/bin/sh\necho called >> \"$VM_CALL_LOG\"\nexit 1\n"), 0700)
	archive := filepath.Join(tmp, "source.nkbk")
	key := filepath.Join(tmp, "key")
	os.WriteFile(archive, []byte("archive"), 0600)
	os.WriteFile(key, []byte("key"), 0600)
	cmd := exec.Command("bash", "ubuntu-forward-migration-verify.sh")
	cmd.Env = append(os.Environ(), "PATH="+tmp+":"+os.Getenv("PATH"), "VM_CALL_LOG="+log, "NAKPANEL_RUN_TOKEN=migrationtest", "NAKPANEL_MULTIPASS_ARCH=arm64", "NAKPANEL_MULTIPASS_SOURCE_VM=nakpanel-source-test", "NAKPANEL_FORWARD_ARCHIVE="+archive, "NAKPANEL_FORWARD_KEY="+key, "NAKPANEL_FORWARD_TARGET_ARTIFACTS="+tmp, "NAKPANEL_FORWARD_FIXTURE_DRIVER=", "NAKPANEL_FORWARD_FIXTURE_JSON=")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "native artifact missing: panel") {
		t.Fatalf("err=%v output=%s", err, out)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("called Multipass before validating native binary inputs")
	}
}
