package multipass

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVMIPWaitsForTransientRebootConnection(t *testing.T) {
	common, err := filepath.Abs("common.sh")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "attempt")
	cmd := exec.Command("bash", "-se", "--", common, marker)
	cmd.Stdin = strings.NewReader(`source "$1"
marker="$2"
sleep(){ return 0; }
multipass(){
 if [[ ! -f "${marker}" ]]; then touch "${marker}"; echo 'SSH connection reset after reboot' >&2; return 1; fi
 printf 'IPv4: 192.168.252.79\n'
}
vm_ip
`)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "192.168.252.79" {
		t.Fatalf("ip=%s error=%v", out, err)
	}
}
