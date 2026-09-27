package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase33VerifierCoversSafeWordPressUninstall(t *testing.T) {
	script := readExecutableScript(t, "phase33-verify.sh")
	requireScriptContracts(t, script, map[string][]string{
		"chain": {
			"common.sh", `VM_NAME="${NAKPANEL_MULTIPASS_VM}"`, `IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"`,
			"phase32-verify.sh", "NAKPANEL_SKIP_PRIOR_PHASES", "sync_repo", "vm_ip",
		},
		"backup_gate": {
			"wordpress/uninstall", "create_backup=on", "delete_database=on", "waiting_backup",
			"checksum_sha256", "database_names",
		},
		"removal": {
			"observed_state", "removed", "wp core is-installed", "information_schema", "mysql.user",
		},
		"preservation": {
			"curl", "Nakpanel", "tls_status", "dns_zones", "subscription_id",
		},
		"reinstall": {
			"wordpress/install", "wp core verify-checksums", "desired_revision",
		},
		"external_database": {
			"action=discover", "database_managed", "database preserved",
		},
		"rollback": {
			"database-removal failure", "original site remains available",
		},
		"secrecy": {
			"river_job", "audit_events", "journalctl", "quarantine", "archive", "/home/",
		},
	})

	for _, forbidden := range []string{
		"INSERT INTO wordpress_instances",
		"INSERT INTO wordpress_operations",
		"UPDATE wordpress_instances SET",
		"UPDATE wordpress_operations SET",
		"DROP DATABASE phase33_",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("verifier bypasses the safe WordPress uninstall workflow with %q", forbidden)
		}
	}
}

func TestPhase33DocumentationExplainsSafeRemoval(t *testing.T) {
	checks := map[string][]string{
		"../../README.md": {
			"Detach", "Uninstall", "Toolkit-managed database", "Phase 33 is the uninstall gate",
		},
		"../../docs/RECOVERY.md": {
			"Safe WordPress Uninstall Recovery (Phase 33)", "waiting_backup", "removing", "removed", "failed",
			"database_names", "external database is always preserved", "Do not delete, rename, chown, or edit",
		},
		"../../IMPLEMENTATION_PLAN.md": {
			"Phase 33", "Safe WordPress Uninstall", "phase33-verify.sh",
		},
	}
	for path, wants := range checks {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", path, err)
		}
		for _, want := range wants {
			if !strings.Contains(string(data), want) {
				t.Errorf("%s is missing %q", path, want)
			}
		}
	}
}

func TestPhase33VerifierIsBoundedAndFailClosed(t *testing.T) {
	script := readExecutableScript(t, "phase33-verify.sh")
	for _, want := range []string{
		"for _ in $(seq 1 180)",
		"mktemp -d",
		"trap cleanup_phase33 EXIT",
		`PHASE33_COMPLETE=0`,
		`PHASE33_COMPLETE=1`,
		"require_nakpanel_vm_name",
		"systemctl is-active --quiet nakpanel.service",
		"systemctl is-active --quiet nakpanel-agent.service",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("verifier is missing safety contract %q", want)
		}
	}
}
