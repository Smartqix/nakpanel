package multipass

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type qualificationWorkflow struct {
	On   map[string]any `yaml:"on"`
	Jobs map[string]struct {
		If       string `yaml:"if"`
		RunsOn   any    `yaml:"runs-on"`
		Strategy struct {
			MaxParallel int `yaml:"max-parallel"`
			Matrix      struct {
				Include []struct{ Release, Architecture string }
			} `yaml:"matrix"`
		} `yaml:"strategy"`
		Steps []struct {
			Name, Run, Uses, If string
			Env                 map[string]string
			With                map[string]any
		}
	} `yaml:"jobs"`
}

func TestCIQualificationUsesOwnedVMsAndExplicitNativeCells(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow qualificationWorkflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"unit", "security-suite", "release-build", "native-qualification"} {
		if _, ok := workflow.Jobs[name]; !ok {
			t.Errorf("required job missing: %s", name)
		}
	}
	security := workflow.Jobs["security-suite"]
	setup, cleanup := false, false
	for _, step := range security.Steps {
		if strings.Contains(step.Run, "init_qualification_run") && strings.Contains(step.Run, "GITHUB_ENV") {
			setup = true
		}
		if step.If == "always()" && strings.Contains(step.Run, "destroy_owned_vm") {
			cleanup = true
		}
		if step.Env["NAKPANEL_MULTIPASS_VM"] != "" || step.Env["NAKPANEL_MULTIPASS_DR_VM"] != "" {
			t.Error("fixed VM override breaks inherited run ownership")
		}
		if strings.Contains(step.Run, "multipass delete") {
			t.Error("cleanup bypasses ownership helper")
		}
	}
	if !setup || !cleanup {
		t.Errorf("security ownership lifecycle missing: setup=%v cleanup=%v", setup, cleanup)
	}
	native := workflow.Jobs["native-qualification"]
	cells := map[string]bool{}
	for _, cell := range native.Strategy.Matrix.Include {
		cells[cell.Release+"/"+cell.Architecture] = true
	}
	for _, cell := range []string{"26.04/amd64", "26.04/arm64"} {
		if !cells[cell] {
			t.Errorf("missing native cell %s", cell)
		}
	}
	if len(cells) != 2 || native.Strategy.MaxParallel < 1 || native.Strategy.MaxParallel > 2 {
		t.Error("native qualification must have two cells and bounded parallelism")
	}
	if !strings.Contains(fmt.Sprint(native.RunsOn), "matrix.architecture") {
		t.Error("runner must match cell architecture")
	}
	gate, report := false, false
	for _, step := range native.Steps {
		if strings.Contains(step.Run, "ubuntu-platform-verify.sh") {
			gate = true
			if strings.Contains(step.Run, "|| true") {
				t.Error("native gate masks failure")
			}
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && step.If == "always()" {
			report = true
		}
	}
	if !gate || !report {
		t.Errorf("native gate/evidence missing: gate=%v report=%v", gate, report)
	}
}

func TestCIQualificationMissingArtifactsFailsWithEvidence(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow qualificationWorkflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	body := ""
	for _, step := range workflow.Jobs["native-qualification"].Steps {
		if strings.Contains(step.Run, "PYCONFIG") {
			body = step.Run
			break
		}
	}
	parts := strings.SplitN(body, "python3 - <<'PYCONFIG'\n", 2)
	if len(parts) != 2 {
		t.Fatal("configuration preflight missing")
	}
	script := strings.TrimSuffix(strings.TrimSpace(parts[1]), "PYCONFIG")
	dir := t.TempDir()
	cmd := exec.Command("python3", "-")
	cmd.Dir = "../.."
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(), "RUNNER_TEMP="+dir, "GITHUB_ENV="+filepath.Join(dir, "environment"), "QUALIFICATION_ARTIFACTS_JSON=", "NAKPANEL_MULTIPASS_ARCH=amd64", "NAKPANEL_MULTIPASS_IMAGE=26.04", "NAKPANEL_RELEASE_ALLOW_DEVELOPMENT=0")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("missing artifacts accepted: %s", out)
	}
	evidence, err := os.ReadFile(filepath.Join(dir, "native-preflight-26.04-amd64.json"))
	if err != nil {
		t.Fatalf("failure evidence missing: %s %v", out, err)
	}
	var result map[string]any
	if err := json.Unmarshal(evidence, &result); err != nil {
		t.Fatal(err)
	}
	if result["status"] != "FAIL" || result["promotion_eligible"] != false || !strings.Contains(string(out), "NAKPANEL_QUALIFICATION_ARTIFACTS") {
		t.Fatalf("unclear/false passing preflight: %s %s", out, evidence)
	}
}

func TestCIQualificationSummaryRejectsMissingOrDifferentEvidence(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow qualificationWorkflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	body := ""
	for _, step := range workflow.Jobs["native-qualification-summary"].Steps {
		if strings.Contains(step.Run, "PYSUMMARY") {
			body = step.Run
			break
		}
	}
	parts := strings.SplitN(body, "python3 - <<'PYSUMMARY'\n", 2)
	if len(parts) != 2 {
		t.Fatal("summary missing")
	}
	script := strings.TrimSuffix(strings.TrimSpace(parts[1]), "PYSUMMARY")
	for _, mode := range []string{"missing cell", "missing manifest", "incomplete PHP", "development"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			for _, release := range []string{"26.04"} {
				for _, arch := range []string{"amd64", "arm64"} {
					if mode == "missing cell" && release == "26.04" && arch == "arm64" {
						continue
					}
					target := filepath.Join(dir, "native-results", release+"-"+arch)
					if err := os.MkdirAll(target, 0700); err != nil {
						t.Fatal(err)
					}
					report, _ := json.Marshal(map[string]any{"release": release, "architecture": arch, "qualification_passed": true, "promotion_eligible": mode != "development", "profile": "ubuntu-26.04-sury", "qualification_scope": "CURRENT_VERSION_ONLY", "full_php_parity": mode != "incomplete PHP", "php_contract": []string{"8.3", "8.4", "8.5"}})
					if err := os.WriteFile(filepath.Join(target, "report.json"), report, 0600); err != nil {
						t.Fatal(err)
					}
					manifest := arch
					if mode == "missing manifest" && arch == "amd64" {
						continue
					}
					if err := os.WriteFile(filepath.Join(target, "release-manifest.json"), []byte(manifest), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			cmd := exec.Command("python3", "-")
			cmd.Dir = dir
			cmd.Stdin = strings.NewReader(script)
			cmd.Env = append(os.Environ(), `BASELINE_RESULTS={"unit":{"result":"success"},"security-suite":{"result":"success"},"release-build":{"result":"success"},"native-qualification":{"result":"success"}}`)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "development") {
				t.Fatalf("summary %s: %v %s", mode, err, out)
			}
			resultJSON, err := os.ReadFile(filepath.Join(dir, "native-summary.json"))
			if err != nil {
				t.Fatal(err)
			}
			var result map[string]any
			if err := json.Unmarshal(resultJSON, &result); err != nil {
				t.Fatal(err)
			}
			if result["promotion_eligible"] != false {
				t.Fatalf("invalid/development evidence promoted: %s", resultJSON)
			}
		})
	}
}
