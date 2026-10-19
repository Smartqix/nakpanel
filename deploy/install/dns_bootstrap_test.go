package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The managed include may exist yet be unreadable to named when install -d
// created its intermediate parent under the administrator setup's umask 077.
func TestDNSBootstrapParentIsTraversableBeforeFirstNamedReload(t *testing.T) {
	for _, state := range []string{"missing-parent", "restricted-parent", "existing-zones"} {
		t.Run(state, func(t *testing.T) {
			root := t.TempDir()
			bind := filepath.Join(root, "bind")
			parent := filepath.Join(bind, "nakpanel")
			if err := os.MkdirAll(bind, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bind, "named.conf.local"), []byte("// local BIND settings\n"), 0644); err != nil {
				t.Fatal(err)
			}
			const zones = "// preserve live zones\nzone \"customer.example\" { type primary; file \"/existing/zone\"; };\n"
			if state != "missing-parent" {
				if err := os.MkdirAll(parent, 0700); err != nil {
					t.Fatal(err)
				}
				if state == "existing-zones" {
					if err := os.WriteFile(filepath.Join(parent, "named.conf"), []byte(zones), 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			data, err := os.ReadFile("phase18-install.sh")
			if err != nil {
				t.Fatal(err)
			}
			source := string(data)
			start := strings.Index(source, "# The panel's BIND zones")
			if start < 0 {
				t.Fatal("DNS bootstrap boundary missing")
			}
			end := strings.Index(source[start:], "\nif command -v ufw")
			if start < 0 || end < 0 {
				t.Fatal("DNS bootstrap boundary missing")
			}
			block := strings.ReplaceAll(source[start:start+end], "/etc/bind", bind)
			command := exec.Command("bash", "-c", `set -euo pipefail
umask 077
# Ownership needs root in production; retain actual mkdir/chmod behavior in the
# private fixture and replace only the root/group ownership boundary.
install(){
 local arguments=()
 while [[ $# -gt 0 ]];do
  case "$1" in -o|-g) shift 2;;*) arguments+=("$1");shift;;esac
 done
 command install "${arguments[@]}"
}
chgrp(){ :; }
systemctl(){
 python3 - "$DNS_FIXTURE" <<'PY'
import pathlib,stat,sys
root=pathlib.Path(sys.argv[1]);parent=root/'nakpanel';target=parent/'named.conf'
if parent.stat().st_mode&0o050!=0o050:raise SystemExit('named cannot traverse its managed include parent')
if target.stat().st_mode&0o040!=0o040:raise SystemExit('named cannot read its managed include')
(root/'reloaded').write_text('validated before reload')
PY
}
`+block)
			command.Env = append(os.Environ(), "DNS_FIXTURE="+bind)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("named bootstrap under umask 077: %v: %s", err, output)
			}
			if _, err := os.Stat(filepath.Join(bind, "reloaded")); err != nil {
				t.Fatalf("first reload was not exercised: %v", err)
			}
			if state == "existing-zones" {
				after, err := os.ReadFile(filepath.Join(parent, "named.conf"))
				if err != nil || string(after) != zones {
					t.Fatalf("existing aggregate changed: %q, %v", after, err)
				}
			}
		})
	}
}
