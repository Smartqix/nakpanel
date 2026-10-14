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

func TestDomainRemovalPrerequisiteQuotaBeforePhase5Provisioning(t *testing.T) {
	data, err := os.ReadFile("phase5-ui-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "ensure_lab_quota")
	provision := strings.Index(script, "-d 'domain=phase5-ui.test'")
	if start < 0 || (provision >= 0 && start > provision) {
		t.Fatal("current Phase 5 provisioning needs quota tooling and an enabled filesystem first")
	}
}

func TestLabQuotaChecksUserStateIndependentlyOfOffGroup(t *testing.T) {
	data, err := os.ReadFile("common.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(data), "ensure_lab_quota()")
	if start < 0 || strings.Count(string(data)[start:], `state="$(quotaon -p "${target}" 2>/dev/null || true)"`) < 2 {
		t.Fatal("quotaon -p returns nonzero for disabled group/project quotas; inspect user state from captured output")
	}
}

func TestLegacyDatabaseChecksRespectEscapedSchemaGrants(t *testing.T) {
	for _, phase := range []string{"4", "5"} {
		name := "phase" + phase + "-verify.sh"
		if phase == "5" {
			name = "phase5-ui-verify.sh"
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "mariadb -NrBe") || !strings.Contains(string(data), "ON `np\\_phase"+phase+"`.*") {
			t.Errorf("%s must check literal, escaped database grants", name)
		}
	}
}

func TestFreshDomainRemovalBootstrapUsesProductionInstaller(t *testing.T) {
	data, err := os.ReadFile("deployment-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "current-install-verify.sh") || !strings.Contains(string(data), `NAKPANEL_SKIP_PRIOR_PHASES=1 "${ROOT_DIR}/deploy/multipass/phase28-verify.sh"`) {
		t.Fatal("fresh bootstrap must use the current production installer before modern native gates")
	}
	data, err = os.ReadFile("current-install-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"common.sh", "require_nakpanel_vm_name", "sync_repo", "deploy/install/install.sh --yes", "/healthz", "panelctl version", "current-bootstrap.test", "np_current_bootstrap", "post sites", "post databases", "post dns", "dig +short", "php_version=8.3", "csrf_token", "wait_for"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("current installer gate missing %q", want)
		}
	}
}

func TestRemovalDatabaseFixturesUseCompleteValidCredentials(t *testing.T) {
	for _, name := range []string{"current-install-verify.sh", "domain-removal-verify.sh"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		script := string(data)
		if !strings.Contains(script, "db_user=") || strings.Contains(script, "password=NakpanelBootstrap!2026") || strings.Contains(script, "password=NakpanelRemoval!2026") {
			t.Errorf("%s must submit an explicit database principal and URL-safe password", name)
		}
		if !strings.Contains(script, `-H 'X-Nakpanel-SPA: true'`) {
			t.Errorf("%s must receive enhanced validation errors rather than error-cookie redirects", name)
		}
	}
}
