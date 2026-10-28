package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase29IMAPReadinessAndSingleAppendBehavior(t *testing.T) {
	if out, err := exec.Command("python3", "phase29_imap_canary_test.py", "-v").CombinedOutput(); err != nil {
		t.Fatalf("Phase29 IMAP readiness behavior failed: %v\n%s", err, out)
	}
}

func TestPhase29IMAPCallerChecksOwnedTargetBeforeOneTransport(t *testing.T) {
	data, err := os.ReadFile("phase29-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, string(data), "imap_canary", false)
	for _, mode := range []string{"success", "identity failure", "helper failure"} {
		t.Run(mode, func(t *testing.T) {
			log := filepath.Join(t.TempDir(), "calls")
			body := `set -euo pipefail
SCRIPT_DIR=/frozen/controller;IMAGE=26.04;NAKPANEL_MULTIPASS_ARCH=arm64;NAKPANEL_RUN_TOKEN=owned-run123
mailbox_address=phase29@example.test
assert_vm_identity(){
 [[ "$*" == 'nakpanel-owned-dr 26.04 arm64 owned-run123' ]] || return 92
 echo identity >>"$CALL_LOG"
 [[ "$MODE" != 'identity failure' ]]
}
python3(){
 [[ "$*" == '/frozen/controller/phase29-imap-canary.py remote nakpanel-owned-dr assert phase29@example.test Phase29Mail!2026' ]] || return 93
 echo one-transport >>"$CALL_LOG"
 [[ "$MODE" != 'helper failure' ]]
}
multipass_exec_short(){
 [[ "$1" == nakpanel-owned-dr ]] || return 95
 case "$*" in
   *' systemctl show '*|*' ss -ltn '*|*' psql -X '*) ;;
   *) return 96;;
 esac
 echo diagnostic >>"$CALL_LOG"
}
` + function + `imap_canary nakpanel-owned-dr assert`
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(), "CALL_LOG="+log, "MODE="+mode)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "success") {
				t.Fatalf("%s: %v\n%s", mode, err, out)
			}
			calls, _ := os.ReadFile(log)
			want := "identity\n"
			if mode != "identity failure" {
				want += "one-transport\n"
			}
			if mode == "helper failure" {
				want += "diagnostic\ndiagnostic\ndiagnostic\n"
			}
			if string(calls) != want {
				t.Fatalf("ownership/transport sequence: %q, want %q", calls, want)
			}
		})
	}
	if strings.Count(string(data), `imap_canary "${VM_NAME}" seed`) != 1 ||
		strings.Count(string(data), `imap_canary "${DR_VM_NAME}" assert`) != 2 {
		t.Fatal("canary must seed once and verify restored content after restore and its second boot")
	}
}
