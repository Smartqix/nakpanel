package multipass

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestUbuntu26QualificationDefaultsKeepAllPHPVersions(t *testing.T) {
	cmd := exec.Command("bash", "-c", `set -eu; source ./common.sh; printf '%s|%s|%s|%s' "$NAKPANEL_MULTIPASS_IMAGE" "$NAKPANEL_QUALIFICATION_PHP_PROVIDER" "$NAKPANEL_QUALIFICATION_PROFILE" "$NAKPANEL_PHP_VERSIONS"`)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "NAKPANEL_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "26.04|sury|ubuntu-26.04-sury|8.5,8.4,8.3" {
		t.Fatalf("defaults=%q err=%v", out, err)
	}
}
