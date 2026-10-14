package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestDomainRemovalSingleVMProductGate(t *testing.T) {
	data, err := os.ReadFile("domain-removal-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, want := range []string{"common.sh", `VM_NAME="${NAKPANEL_MULTIPASS_VM}"`, `IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"`, "require_nakpanel_vm_name", "phase34-verify.sh", "run_id=", "/removal/preview", "acknowledge_permanent", "/status", "completed", "redirect", "backups/", "/download", "primary_site_id", "site_id IS NULL", "403", "404", "stale", "retry"} {
		if !strings.Contains(script, want) {
			t.Errorf("product gate missing %q", want)
		}
	}
	for _, forbidden := range []string{"2.29.45.217", "nakpanel.com", "DELETE FROM sites", "TRUNCATE", "DROP DATABASE nakpanel", "rm -rf /home"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("unsafe verifier command %q", forbidden)
		}
	}
	final, err := os.ReadFile("deployment-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	if strings.LastIndex(string(final), "domain-removal-verify.sh") < strings.LastIndex(string(final), "phase34-verify.sh") {
		t.Fatal("removal must be the final product gate")
	}
}
