package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatabaseManagerUsesSelectedAuthenticatedAssets(t *testing.T) {
	data, err := os.ReadFile("internal-tools-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, `if [[ "${NAKPANEL_VERIFY_DATABASE_MANAGER:-0}" == 1 ]]`)
	if start < 0 {
		t.Fatal("database manager branch absent")
	}
	block := script[start:]
	for _, mode := range []string{"signed", "raw"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "source")
			bundle := filepath.Join(dir, "selected-bundle")
			for label, root := range map[string]string{"source": source, "signed": bundle} {
				target := filepath.Join(root, "deploy/install/database-manager-install.sh")
				os.MkdirAll(filepath.Dir(target), 0700)
				os.WriteFile(target, []byte("#!/bin/bash\nprintf '%s' "+label+" >\"$CALL_LOG\"\n"), 0700)
			}
			for name, body := range map[string]string{"timeout": "#!/bin/bash\nshift;exec \"$@\"\n", "systemctl": "#!/bin/bash\nexit 0\n", "python3": "#!/bin/bash\nexit 0\n", "node": "#!/bin/bash\nexit 0\n"} {
				os.WriteFile(filepath.Join(dir, name), []byte(body), 0700)
			}
			body := `set -euo pipefail
NAKPANEL_VERIFY_DATABASE_MANAGER=1;VM_NAME=nakpanel-fixture;base=https://fixture;site_id=1;tmpdir="$FIXTURE_DIR";SCRIPT_DIR="$FIXTURE_DIR"
assert_current_vm_identity(){ :; }
multipass(){ while [[ "$1" != bash ]];do shift;done;shift;bash "$@"; }
` + block
			cmd := exec.Command("bash", "-c", body)
			log := filepath.Join(dir, "calls")
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "CALL_LOG="+log, "FIXTURE_DIR="+dir, "NAKPANEL_REMOTE_SRC="+source, "NAKPANEL_GUEST_RELEASE_DIR=")
			want := "source"
			if mode == "signed" {
				want = "signed"
				cmd.Env = append(cmd.Env, "NAKPANEL_GUEST_RELEASE_DIR="+bundle)
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("installer asset boundary: %s %v", out, err)
			}
			got, _ := os.ReadFile(log)
			if string(got) != want {
				t.Fatalf("%s used %q installer, want %q", mode, got, want)
			}
		})
	}
}
