package multipass_test

import (
	"os"
	"strings"
	"testing"
)

func TestPhase5UIVerifierCoversEmbeddedAndRoleScopedUI(t *testing.T) {
	const path = "phase5-ui-verify.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable; mode is %v", path, info.Mode())
	}

	script := string(data)
	for _, want := range []string{
		"common.sh",
		"VM_NAME=\"${NAKPANEL_MULTIPASS_VM}\"",
		"sudo rm -rf \"${REMOTE_SRC}\"",
		"test ! -e \"${REMOTE_SRC}\"",
		"/assets/app.css",
		"--np-bg",
		"content:attr(data-label)",
		"data-label=\"Domain\"",
		"data-label=\"Name\"",
		"data-label=\"Created\"",
		"action=\"/sites\"",
		"name=\"username\"",
		"name=\"domain\"",
		"action=\"/databases\"",
		"name=\"db_name\"",
		"name=\"db_user\"",
		"phase5-ui.test",
		"np_phase5",
		"Client dashboard",
		"Account overview",
		"Hosting account",
		"action=\"/certificates\"",
		"client dashboard exposed admin form",
		"Phase 5 UI verification passed",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s missing required verifier coverage %q", path, want)
		}
	}
}
