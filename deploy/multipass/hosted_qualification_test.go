package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestHostedQualificationRequiresActualNativeGatesAndPinnedBaseline(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ubuntu-hosted-qualification.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow qualificationWorkflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	if _, ok := workflow.On["workflow_dispatch"]; !ok {
		t.Fatal("hosted qualification must be manually dispatched")
	}
	if _, ok := workflow.On["pull_request"]; ok {
		t.Fatal("hosted qualification must not run implicitly for pull requests")
	}
	push, ok := workflow.On["push"].(map[string]any)
	if !ok {
		t.Fatal("dedicated review branch push trigger missing")
	}
	branches, ok := push["branches"].([]any)
	if !ok || len(branches) != 1 || branches[0] != "codex/ubuntu-26-support" {
		t.Fatal("push trigger must be limited to isolated review branch")
	}
	if !strings.Contains(string(data), "ef8b5a7ebc0462cb90a1ae5b8fa98e4a3af46466") {
		t.Fatal("actual historical application baseline is not pinned")
	}
	job, ok := workflow.Jobs["qualify-amd64"]
	if !ok {
		t.Fatal("native AMD64 qualification job missing")
	}
	if job.RunsOn != "ubuntu-24.04" {
		t.Fatal("hosted native AMD64 runner must be explicit")
	}
	releases := map[string]bool{}
	for _, cell := range job.Strategy.Matrix.Include {
		releases[cell.Release] = true
	}
	if len(releases) != 2 || !releases["24.04"] || !releases["26.04"] {
		t.Fatal("both release cells required")
	}
	gate, preflight, cleanup, evidence := false, false, false, false
	for _, step := range job.Steps {
		gate = gate || strings.Contains(step.Run, "ubuntu-platform-verify.sh")
		preflight = preflight || strings.Contains(step.Run, "hosted-runner-preflight.py")
		cleanup = cleanup || (step.If == "always()" && strings.Contains(step.Run, "destroy_owned_vm"))
		evidence = evidence || (step.If == "always()" && strings.HasPrefix(step.Uses, "actions/upload-artifact@"))
		if strings.Contains(step.Run, "multipass delete") {
			t.Fatal("owned deletion helper bypassed")
		}
	}
	if !gate || !preflight || !cleanup || !evidence {
		t.Fatalf("missing strict hosted lifecycle: gates%v preflight%v cleanup%v evidence%v", gate, preflight, cleanup, evidence)
	}
}

func TestHostedCapacityPreflightRejectsMissingKVMAndInsufficientDisk(t *testing.T) {
	helper, err := filepath.Abs("hosted-runner-preflight.py")
	if err != nil {
		t.Fatal(err)
	}
	script := `import importlib.util,sys
spec=importlib.util.spec_from_file_location('preflight',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
good=dict(architecture='x86_64',cpu_count=4,total_memory=16*2**30,available_memory=12*2**30,free_disk=56*2**30,kvm_api=12)
assert m.capacity_errors(**good)==[]
for key,value,needle in [('kvm_api',None,'KVM'),('free_disk',14*2**30,'disk'),('available_memory',8*2**30,'memory'),('architecture','aarch64','AMD64')]:
 case=dict(good);case[key]=value;assert any(needle in e for e in m.capacity_errors(**case)),(key,m.capacity_errors(**case))
`
	out, err := exec.Command("python3", "-c", script, helper).CombinedOutput()
	if err != nil {
		t.Fatalf("hosted preflight: %s %v", out, err)
	}
}
