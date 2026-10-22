package multipass

import (
	"gopkg.in/yaml.v3"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestSubdomainMailHostedGuards(t *testing.T) {
	out, err := exec.Command("python3", "-m", "unittest", "discover", "-s", ".", "-p", "subdomain_mail_test.py").CombinedOutput()
	if err != nil {
		t.Fatalf("hosted guards: %s %v", out, err)
	}
}
func TestSubdomainMailSelectionExcludesUnrelatedHostedGates(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/ubuntu-hosted-qualification.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow qualificationWorkflow
	if err = yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	job, ok := workflow.Jobs["subdomain-mail"]
	if !ok {
		t.Fatal("focused subdomain mail job missing")
	}
	if !strings.Contains(job.If, "inputs.subdomain_mail_only") {
		t.Fatal("focused job lacks explicit selection")
	}
	for _, name := range []string{"qualify-amd64", "scheduled-backups", "diagnose-fwupd", "diagnose-php-maintenance", "hosted-evidence-summary"} {
		if !strings.Contains(workflow.Jobs[name].If, "!inputs.subdomain_mail_only") {
			t.Errorf("%s would run outside mail-only scope", name)
		}
	}
	upload, cleanup := false, false
	for _, step := range job.Steps {
		if strings.Contains(step.Uses, "upload-artifact") {
			upload = step.If == "always()"
			path, _ := step.With["path"].(string)
			if strings.Contains(path, "private") {
				t.Fatal("credentials must not be published")
			}
		}
		if strings.Contains(step.Run, "destroy_owned_vm") {
			cleanup = step.If == "always()"
		}
	}
	if !upload || !cleanup {
		t.Fatal("failure evidence and owned cleanup must always execute")
	}
}
