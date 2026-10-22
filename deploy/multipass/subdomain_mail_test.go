package multipass

import (
	"gopkg.in/yaml.v3"
	"os"
	"os/exec"
	"path/filepath"
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

func TestSubdomainMailLaunchTimeoutIsBoundedAndExplicit(t *testing.T) {
	for _, budget := range []string{"", "600", "0", "601", "unbounded"} {
		t.Run(budget, func(t *testing.T) {
			dir := t.TempDir()
			calls := filepath.Join(dir, "calls")
			fake := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$FAKE_LOG\"\ncase \"$1\" in info) exit 1;; launch) exit 88;; *) exit 99;; esac\n"
			if err := os.WriteFile(filepath.Join(dir, "multipass"), []byte(fake), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", "set -euo pipefail; source ./common.sh; ensure_vm 2 5G 32G")
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "FAKE_LOG="+calls,
				"NAKPANEL_MULTIPASS_IMAGE=26.04", "NAKPANEL_MULTIPASS_ARCH=amd64", "NAKPANEL_QUALIFICATION_PHP_PROVIDER=sury",
				"NAKPANEL_MULTIPASS_VM=nakpanel-submail-budget", "NAKPANEL_RUN_TOKEN=submail-budget", "NAKPANEL_OWNERSHIP_DIR="+dir,
				"NAKPANEL_MULTIPASS_IMAGE_SOURCE=", "NAKPANEL_MULTIPASS_IMAGE_SHA256=", "NAKPANEL_QUALIFICATION_LAUNCH_TIMEOUT="+budget)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("fake failed launch was accepted: %s", out)
			}
			raw, _ := os.ReadFile(calls)
			log := string(raw)
			if budget == "" {
				if !strings.Contains(log, "launch 26.04") || strings.Contains(log, "--timeout") {
					t.Fatalf("default changed: %s %s", log, out)
				}
			} else if budget == "600" {
				if !strings.Contains(log, "--timeout 600") {
					t.Fatalf("explicit bounded timeout missing: %s %s", log, out)
				}
			} else if strings.Contains(log, "launch") {
				t.Fatalf("unsafe timeout launched a guest: %s %s", log, out)
			}
			if _, err := os.Stat(filepath.Join(dir, "submail-budget", "nakpanel-submail-budget")); !os.IsNotExist(err) {
				t.Fatal("failed launch claimed ownership")
			}
		})
	}
}
