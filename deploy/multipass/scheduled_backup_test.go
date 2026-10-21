package multipass

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestHostedScheduledBackupAcceptance(t *testing.T) {
	for _, name := range []string{"scheduled-backup-verify.py", "scheduled-backup-verify.sh", "scheduled_backup_test.py"} {
		if _, err := os.ReadFile(name); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "python3", "scheduled_backup_test.py", "-v").CombinedOutput()
	if err != nil {
		t.Fatalf("focused scheduled-backup acceptance: %v\n%s", err, out)
	}
}

func TestScheduledBackupDispatchDoesNotRepeatProductGates(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ubuntu-hosted-qualification.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow qualificationWorkflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"signed-bundles", "qualify-amd64", "hosted-evidence-summary", "diagnose-fwupd", "diagnose-php-maintenance"} {
		if !strings.Contains(workflow.Jobs[name].If, "!inputs.scheduled_backups_only") {
			t.Fatalf("%s would repeat or mix unrelated qualification", name)
		}
	}
	job := workflow.Jobs["scheduled-backups"]
	preflight, run, cleanup, uploaded := false, false, false, false
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "hosted-runner-preflight.py") {
			preflight = true
		}
		if strings.Contains(step.Run, "scheduled-backup-verify.sh run") {
			if !preflight {
				t.Fatal("VM work precedes actual KVM/capacity preflight")
			}
			run = true
		}
		cleanup = cleanup || step.If == "always()" && strings.Contains(step.Run, "destroy_owned_vm")
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") {
			uploaded = step.If == "always()" && step.With["path"] == "${{ runner.temp }}/scheduled-backup-evidence/"
		}
	}
	if !run || !cleanup || !uploaded {
		t.Fatal("focused run, owned cleanup, or safe bounded evidence is missing")
	}
}
