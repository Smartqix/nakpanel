package multipass

import (
	"gopkg.in/yaml.v3"
	"os"
	"strings"
	"testing"
)

func TestOperationsSelectionRunsOnlyFocusedHostedAcceptance(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/ubuntu-hosted-qualification.yml")
	if err != nil {
		t.Fatal(err)
	}
	var w qualificationWorkflow
	if err = yaml.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	job, ok := w.Jobs["operations"]
	if !ok || !strings.Contains(job.If, "inputs.operations_only") {
		t.Fatal("focused operations selection missing")
	}
	for _, name := range []string{"diagnose-fwupd", "diagnose-php-maintenance", "scheduled-backups", "subdomain-mail", "qualify-amd64", "hosted-evidence-summary"} {
		if !strings.Contains(w.Jobs[name].If, "!inputs.operations_only") {
			t.Errorf("%s can run outside focused operations scope", name)
		}
	}
	cleanup, evidence := false, false
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "destroy_owned_vm") {
			cleanup = step.If == "always()"
		}
		if strings.Contains(step.Uses, "upload-artifact") {
			evidence = step.If == "always()"
			path, _ := step.With["path"].(string)
			if strings.Contains(path, "private") {
				t.Fatal("private credentials would be uploaded")
			}
		}
	}
	if !cleanup || !evidence {
		t.Fatal("owned cleanup and evidence must always run")
	}
}
