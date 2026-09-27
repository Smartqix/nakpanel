package multipass

import (
	"strings"
	"testing"
)

func TestPhase31VerifierCoversProductionServicePlanAcceptance(t *testing.T) {
	script := readExecutableScript(t, "phase31-verify.sh")
	requireScriptContracts(t, script, map[string][]string{
		"single_vm_and_current_build": {
			"common.sh", `VM_NAME="${NAKPANEL_MULTIPASS_VM}"`, `IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"`,
			"phase30-verify.sh", "NAKPANEL_SKIP_PRIOR_PHASES", "sync_repo", "vm_ip",
			"deploy/install/install.sh --yes --allow-downgrade --force", "/usr/local/bin/nakpanel-panel",
		},
		"schema_and_lifecycle": {
			"plan_revisions", "lifecycle_status", "last_validated_at", "readiness_error",
			"compliance_status", "Future runtime draft", "cannot activate plan", "draft plan is assignable",
		},
		"editor_contract": {
			"Plan contract", "Customer Permissions", "Defaults", "Advanced", "data-np-enforcement",
			"Runtime readiness", "Plan preview failed", "Revision history",
		},
		"preview_and_compliance": {
			"plans/preview", "resources.max_sites", "hard_limit", "subscription_impacts",
			"no resources will be deleted", "in_sync:over_limit", "sites 1/0", "in_sync:compliant:true",
			"background measurement refreshes compliance", "phase31-measured.bin", "measured compliance recovery",
		},
		"revision_integrity": {
			"definition_hash", "UPDATE plan_revisions", "immutable plan revision accepted an update",
			"COUNT(DISTINCT definition_hash)", "Immutable plan contract records",
		},
	})

	for _, forbidden := range []string{
		"INSERT INTO subscription_entitlements",
		"UPDATE subscription_entitlements",
		"DELETE FROM sites",
		"UPDATE subscriptions SET compliance_status",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("verifier contains forbidden state bypass %q", forbidden)
		}
	}
}

func TestPhase31VerifierIsBoundedAndFailClosed(t *testing.T) {
	script := readExecutableScript(t, "phase31-verify.sh")
	for _, want := range []string{
		"for _ in $(seq 1 120)",
		"mktemp -d",
		"trap cleanup_phase31 EXIT",
		`PHASE31_COMPLETE=0`,
		`PHASE31_COMPLETE=1`,
		"require_nakpanel_vm_name",
		"systemctl restart nakpanel",
		"is_complete",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("verifier is missing safety contract %q", want)
		}
	}
}
