package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestSecurityVerifierCoversEveryPart keeps the adversarial suite honest: it
// must attack every boundary (Parts A–H), fail closed, and clean up. If a part
// is removed the gate silently weakens, so this guard fails instead.
func TestSecurityVerifierCoversEveryPart(t *testing.T) {
	data, err := os.ReadFile("security-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, want := range []string{
		"common.sh",
		"Part A — Filesystem boundary",
		"Part B — Config template injection",
		"Part C — Cross-tenant isolation",
		"Part D — Entitlement / quota bypass",
		"Part E — Provisioning API auth",
		"Part F — Agent socket boundary",
		"Part G — Destructive-op safety",
		"Part H — Secret handling",
		"agentprobe",         // real agent-socket client, not a mock
		"provision_tenant A", // two real tenants
		"provision_tenant B",
		"SO_PEERCRED",             // socket peer-uid attack
		"plan_downgrade_conflict", // quota bypass
		"external_ref",            // concurrent idempotency
		"SECURITY-FAIL",           // fails closed
		"exit 1",
		"trap cleanup EXIT",     // self-cleaning
		"api-key revoke",        // no live verifier credentials remain
		"outbox.status<>'sent'", // teardown events drain before sink shutdown
		"NAKPANEL_PUBLIC_URL",   // production-like panel environment restored
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("security-verify.sh is missing %q", want)
		}
	}
}

func TestSecurityDatabaseDenialsUseValidEnhancedFormsAndNoIntentProof(t *testing.T) {
	data, err := os.ReadFile("security-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`-H 'X-Nakpanel-SPA: true'`, `db_user=dbususp${STAMP}`, `db_user=dbunosub${STAMP}`, `db_name='over${STAMP}'`, `db_name='susp${STAMP}'`, `db_name='nosub${STAMP}'`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing valid denial assertion %q", want)
		}
	}
}

func TestSecurityCIKeepsHostGoCachesPrivate(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Env   map[string]string `yaml:"env"`
			Steps []struct {
				Name  string         `yaml:"name"`
				Run   string         `yaml:"run"`
				Shell string         `yaml:"shell"`
				Uses  string         `yaml:"uses"`
				With  map[string]any `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	job, ok := workflow.Jobs["security-suite"]
	if !ok {
		t.Fatal("security-suite job is missing")
	}
	for name, value := range job.Env {
		if strings.Contains(value, "runner.") {
			t.Errorf("job-level %s uses the unavailable runner context", name)
		}
	}
	setupIndex, isolateIndex := -1, -1
	for i, step := range job.Steps {
		if step.Name == "Isolate host Go state" {
			isolateIndex = i
		}
		if step.Uses == "actions/setup-go@v5" {
			setupIndex = i
			if step.With["cache"] != false {
				t.Error("the Multipass gate must not publish the self-hosted machine's Go caches")
			}
		}
	}
	if setupIndex < 0 {
		t.Fatal("security-suite Go setup step is missing")
	}
	if isolateIndex < 0 || isolateIndex >= setupIndex {
		t.Fatal("host Go state must be isolated in a step before setup-go")
	}
	step := job.Steps[isolateIndex]
	if step.Shell != "bash" {
		t.Fatal("host Go isolation must explicitly use bash")
	}
	temp := t.TempDir()
	envFile := filepath.Join(temp, "github-env")
	cmd := exec.Command("bash", "-e", "-c", step.Run)
	cmd.Env = []string{"RUNNER_TEMP=" + temp, "GITHUB_ENV=" + envFile}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("host Go isolation failed: %v: %s", err, output)
	}
	values, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"GOPATH":     filepath.Join(temp, "nakpanel-go"),
		"GOCACHE":    filepath.Join(temp, "nakpanel-go-build"),
		"GOMODCACHE": filepath.Join(temp, "nakpanel-go", "pkg", "mod"),
	}
	for _, line := range strings.Split(strings.TrimSpace(string(values)), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok || want[name] != value {
			t.Errorf("unexpected isolation environment entry %q", line)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("host Go isolation did not set %s", name)
	}
	for _, step := range workflow.Jobs["unit"].Steps {
		if step.Uses == "actions/setup-go@v5" && step.With["cache"] != true {
			t.Error("disposable GitHub-hosted unit job caching must remain enabled")
		}
	}
}
