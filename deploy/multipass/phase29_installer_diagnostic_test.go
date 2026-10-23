package multipass

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase29InstallerRetainsBoundedFailureEvidenceAndExitStatus(t *testing.T) {
	source, err := os.ReadFile("phase29-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, strings.Replace(string(source), "run_installer(){", "run_installer() {", 1), "run_installer", true)
	for _, code := range []string{"0", "73"} {
		t.Run(code, func(t *testing.T) {
			dir := t.TempDir()
			body := `set -euo pipefail
VM_NAME=nakpanel-fixture;REMOTE_SRC=/fixture/source;tmpdir="$FIXTURE_DIR"
export NAKPANEL_CELL_REPORT_DIR="$FIXTURE_DIR/evidence"
multipass(){ python3 -c 'print("x"*70000);print("installer diagnostic: synthetic root cause");print("password=NakpanelAdmin!2026")';return "$INSTALL_EXIT"; }
` + function + `
result=0
run_installer NAKPANEL_INSTALL_FAULT=before-migrate || result=$?
[[ "$result" == "$INSTALL_EXIT" ]] || exit 91
run_installer NAKPANEL_INSTALL_FAULT=unhealthy-panel || result=$?
[[ "$result" == "$INSTALL_EXIT" ]] || exit 91
`
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(), "FIXTURE_DIR="+dir, "INSTALL_EXIT="+code)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("installer status changed: %s %v", out, err)
			}
			receipts, err := filepath.Glob(filepath.Join(dir, "evidence", "installer-attempts", "*.json"))
			if err != nil || len(receipts) != 2 {
				t.Fatalf("installer receipts missing: %v %v", receipts, err)
			}
			for _, path := range receipts {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var receipt struct {
					ExitCode int    `json:"exit_code"`
					Log      string `json:"log"`
				}
				if err = json.Unmarshal(raw, &receipt); err != nil {
					t.Fatal(err)
				}
				want := 0
				if code == "73" {
					want = 73
				}
				if receipt.ExitCode != want || !strings.Contains(receipt.Log, "synthetic root cause") || strings.Contains(receipt.Log, "NakpanelAdmin!2026") || len(receipt.Log) > 65536 {
					t.Fatalf("unsafe or incomplete installer receipt: code=%d bytes=%d", receipt.ExitCode, len(receipt.Log))
				}
			}
		})
	}
}
