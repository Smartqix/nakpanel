package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestHostingToolkitVerifierChain(t *testing.T) {
	expected := map[string][]string{
		"phase21-verify.sh": {"phase20-verify.sh", "phase21-25-install.sh", "TLSRequired on", `restrict,command=\"internal-sftp -d /domains/`, "root:root:711"},
		"phase22-verify.sh": {"phase21-verify.sh", "nakpanel-php-fpm@", "fastcgi_cache", "nginx -t"},
		"phase23-verify.sh": {"phase22-verify.sh", "scheduled_task_runs", "/logs/data", "/statistics"},
		"phase24-verify.sh": {"phase23-verify.sh", "/git/deploy", "protected-directories", "/staging", "retained a file deleted"},
		"phase25-verify.sh": {"phase24-verify.sh", "redis-cli", "NetworkMode", "valkey.sock", "getfacl", "idempotent Valkey convergence"},
	}
	for path, markers := range expected {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&0o111 == 0 {
				t.Fatalf("%s is not executable", path)
			}
			script := string(data)
			for _, marker := range append([]string{"common.sh", `VM_NAME="${NAKPANEL_MULTIPASS_VM}"`, `IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"`}, markers...) {
				if !strings.Contains(script, marker) {
					t.Fatalf("%s is missing %q", path, marker)
				}
			}
		})
	}
}

func TestSecurityVerifierChainsFinalFunctionalPhase(t *testing.T) {
	data, err := os.ReadFile("security-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "phase26-verify.sh") {
		t.Fatal("security verifier does not chain Phase 26")
	}
}

func TestHostingToolkitInstallerRecreatesVolatilePodmanState(t *testing.T) {
	data, err := os.ReadFile("../install/phase21-25-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, marker := range []string{
		"d /run/nakpanel-containers 0711 root root -",
		"d /run/libpod 0751 root root -",
		"d /run/crun 0755 root root -",
		"systemd-tmpfiles --create /etc/tmpfiles.d/nakpanel-containers.conf",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("phase21-25-install.sh is missing volatile runtime policy %q", marker)
		}
	}
}
