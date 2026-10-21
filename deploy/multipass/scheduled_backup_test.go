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

func TestScheduledBackupCanReadPinnedPriorRunArtifactAtExpectedPath(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ubuntu-hosted-qualification.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Permissions map[string]string
			Steps       []struct {
				Uses string
				With map[string]any
			}
		}
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	job := workflow.Jobs["scheduled-backups"]
	if job.Permissions["actions"] != "read" || job.Permissions["contents"] != "read" {
		t.Error("prior-run artifact and status API need explicit read permissions")
	}
	found := false
	for _, step := range job.Steps {
		if strings.HasPrefix(step.Uses, "actions/download-artifact@") && step.With["path"] == "${{ runner.temp }}/phase3-backup-baseline" {
			found = true
			if step.With["artifact-ids"] != "12370348308" || step.With["run-id"] != "39652821843" || step.With["merge-multiple"] != true {
				t.Error("pinned ID download must unpack at the verifier's expected root")
			}
		}
	}
	if !found {
		t.Fatal("accepted artifact download missing")
	}
}

func TestScheduledBackupRepairBuildIsExplicitAndUsesTheCanonicalSignedBuilder(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ubuntu-hosted-qualification.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			If    string
			Needs any
			Steps []struct {
				If   string
				Uses string
				Run  string
				With map[string]any
			}
		}
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	job := workflow.Jobs["scheduled-backups"]
	if job.Needs != "signed-bundles" || !strings.Contains(job.If, "needs.signed-bundles.result") || !strings.Contains(job.If, "always()") {
		t.Fatal("focused job must wait for exactly the requested builder result, including skipped baseline reuse")
	}
	if !strings.Contains(workflow.Jobs["signed-bundles"].If, "inputs.scheduled_backups_build_current") {
		t.Fatal("runtime repair must explicitly select the existing signed builder")
	}
	downloaded, authenticated := false, false
	for _, step := range job.Steps {
		if strings.HasPrefix(step.Uses, "actions/download-artifact@") && step.With["path"] == "${{ runner.temp }}/current-backup-candidate" {
			downloaded = step.If == "inputs.scheduled_backups_build_current" && step.With["name"] == "hosted-development-bundles-${{ github.run_id }}-${{ github.run_attempt }}" && step.With["run-id"] == nil
		}
		if strings.Contains(step.Run, `scheduled-backup-verify.sh prepare "${RUNNER_TEMP}/phase3-backup-baseline" "${RUNNER_TEMP}/current-backup-candidate"`) {
			authenticated = step.If == "inputs.scheduled_backups_build_current"
		}
	}
	if !downloaded || !authenticated {
		t.Fatal("new signed bytes must come from this run and be authenticated before VM work")
	}
}
