package multipass

import (
	"gopkg.in/yaml.v3"
	"os"
	"strings"
	"testing"
)

func TestPleskR0R1SelectionExcludesOtherHostedRehearsals(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/ubuntu-hosted-qualification.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow qualificationWorkflow
	if err = yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	job, ok := workflow.Jobs["plesk-r0-r1"]
	if !ok || !strings.Contains(job.If, "inputs.plesk_r0_r1_only") {
		t.Fatal("focused R0/R1 job missing")
	}
	for _, name := range []string{"diagnose-fwupd", "diagnose-php-maintenance", "scheduled-backups", "subdomain-mail", "operations", "qualify-amd64", "hosted-evidence-summary"} {
		if !strings.Contains(workflow.Jobs[name].If, "!inputs.plesk_r0_r1_only") {
			t.Errorf("%s can run outside R0/R1 scope", name)
		}
	}
	cleanup, evidence := false, false
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "plesk-rehearsal-verify.py cleanup") {
			cleanup = step.If == "always()"
		}
		if strings.Contains(step.Uses, "upload-artifact") {
			evidence = step.If == "always()"
			path, _ := step.With["path"].(string)
			if strings.Contains(path, "private") {
				t.Fatal("private fixture data would be uploaded")
			}
		}
	}
	if !cleanup || !evidence {
		t.Fatal("owned cleanup and safe evidence must always run")
	}
}
