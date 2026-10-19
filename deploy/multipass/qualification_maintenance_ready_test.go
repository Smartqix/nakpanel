package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestQualificationMaintenanceReadinessBehavior(t *testing.T) {
	for _, path := range []string{"qualification_maintenance_ready.py", "qualification_maintenance_ready_test.py", "current-install-verify.sh"} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	for _, flags := range [][]string{{"-I", "-B"}, {"-I", "-B", "-O"}} {
		args := append(append([]string{}, flags...), "qualification_maintenance_ready_test.py", "-v")
		if out, err := exec.Command("python3", args...).CombinedOutput(); err != nil {
			t.Fatalf("read-only maintenance readiness %v: %v\n%s", flags, err, out)
		}
	}
}

func TestQualificationMaintenanceReadinessBeforeCoreChecksAndFixtures(t *testing.T) {
	data, err := os.ReadFile("current-install-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	start, end := strings.Index(source, "install_args=(--yes)"), strings.Index(source, "/usr/local/bin/panelctl version")
	if start < 0 || end <= start {
		t.Fatal("post-installer qualification boundary missing")
	}
	for _, mode := range []string{"modern", "legacy", "installer-failed", "readiness-failed"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			body := `set -euo pipefail
set -- /frozen/controller 26.04 1 1 0 native /staged/release /staged/public.pem
[[ "$MODE" != legacy ]] || set -- /frozen/controller 24.04 1 1 1 native /staged/release /staged/public.pem
mktemp(){ command mktemp "$TEST_DIRECTORY/password.XXXXXXXX"; }
timeout(){ echo installer >> "$CALL_LOG"; [[ "$MODE" != installer-failed ]]; }
python3(){
 [[ "$*" == '-I -B deploy/multipass/qualification_maintenance_ready.py' ]] || return 92
 echo readiness >> "$CALL_LOG"; [[ "$MODE" != readiness-failed ]]
}
systemctl(){ echo core-check >> "$CALL_LOG"; }
` + source[start:end]
			command := exec.Command("bash", "-c", body)
			log := filepath.Join(directory, "calls")
			command.Env = append(os.Environ(), "MODE="+mode, "TEST_DIRECTORY="+directory, "CALL_LOG="+log)
			output, err := command.CombinedOutput()
			if (err == nil) != (mode == "modern" || mode == "legacy") {
				t.Fatalf("%s: %v\n%s", mode, err, output)
			}
			calls, _ := os.ReadFile(log)
			want := "installer\nreadiness\ncore-check\n"
			if mode == "installer-failed" {
				want = "installer\n"
			} else if mode == "readiness-failed" {
				want = "installer\nreadiness\n"
			}
			if string(calls) != want {
				t.Fatalf("readiness ordering = %q, want %q", calls, want)
			}
		})
	}
}
