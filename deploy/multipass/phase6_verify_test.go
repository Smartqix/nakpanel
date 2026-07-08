package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase6VerifierCoversOperationsEndToEnd(t *testing.T) {
	const path = "phase6-verify.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) returned error: %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) returned error: %v", path, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable", path)
	}
	script := string(data)
	for _, want := range []string{
		"common.sh",
		"VM_NAME=\"${NAKPANEL_MULTIPASS_VM}\"",
		"phase5-ui-verify.sh",
		"bind9",
		"named.service",
		"Adminer SSO",
		"action=\"/backups\"",
		"action=\"/webmail\"",
		"action=\"/dns\"",
		"action=\"/reconcile\"",
		"webmail.phase5-ui.test",
		"db.phase5-ui.test",
		"sudo tar -tzf",
		"databases/np_phase5.sql",
		"systemctl stop nginx",
		"http://${VM_IP}:7443/login",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("phase6 verifier is missing %q", want)
		}
	}
}
