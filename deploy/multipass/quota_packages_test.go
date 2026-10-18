package multipass

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestQuotaInstallerRequiresAnInstallablePackageCandidate(t *testing.T) {
	data, err := os.ReadFile("../install/phase8-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "apt_package_has_candidate() {")
	if start < 0 {
		t.Fatal("quota installer does not check the APT candidate")
	}
	end := strings.Index(script[start:], "\n}\n")
	if end < 0 {
		t.Fatal("candidate helper missing its end")
	}
	function := script[start : start+end+3]
	for _, candidate := range []string{"(none)", "", "6.8.0-147.147"} {
		t.Run(candidate, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", `apt-cache() { printf '  Installed: (none)\n  Candidate: %s\n' "$CANDIDATE"; }; `+function+"\napt_package_has_candidate package")
			cmd.Env = append(os.Environ(), "CANDIDATE="+candidate)
			err := cmd.Run()
			if (err == nil) != (candidate != "" && candidate != "(none)") {
				t.Fatalf("candidate %q: %v", candidate, err)
			}
		})
	}
	if strings.Contains(script, `apt-cache show "linux-modules-extra-$(uname -r)"`) {
		t.Fatal("obsolete metadata is not evidence of an installable kernel module")
	}
}

func TestQuotaInstallerRequiresRebootBeforeChangingQuotaMount(t *testing.T) {
	data, err := os.ReadFile("../install/phase8-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "if ! modprobe quota_v2;")
	end := strings.Index(script, "ensure_quota_fstab()")
	if start < 0 || end < start {
		t.Fatal("missing module readiness gate")
	}
	for _, available := range []bool{false, true} {
		code := "1"
		if available {
			code = "0"
		}
		cmd := exec.Command("bash", "-c", "modprobe() { return "+code+"; };\n"+script[start:end]+"\nprintf ready")
		output, err := cmd.CombinedOutput()
		if available {
			if err != nil || string(output) != "ready" {
				t.Fatalf("usable module: %s: %v", output, err)
			}
		} else {
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 75 || !strings.Contains(string(output), "Reboot") || strings.Contains(string(output), "ready") {
				t.Fatalf("missing module must require reboot: %s: %v", output, err)
			}
		}
	}
}
