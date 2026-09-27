package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase32VerifierCoversWordPressToolkitAcceptance(t *testing.T) {
	script := readExecutableScript(t, "phase32-verify.sh")
	requireScriptContracts(t, script, map[string][]string{
		"single_vm_and_current_build": {
			"common.sh", `VM_NAME="${NAKPANEL_MULTIPASS_VM}"`, `IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"`,
			"phase31-verify.sh", "NAKPANEL_SKIP_PRIOR_PHASES", "sync_repo", "vm_ip",
			"deploy/install/install.sh --yes --allow-downgrade --force",
		},
		"schema_and_entitlement": {
			"wordpress_instances", "wordpress_operations", "maintenance_enabled",
			"allow_wordpress_toolkit=true", "max_wordpress_sites=1", "WordPress Toolkit",
		},
		"install_and_inventory": {
			"wordpress/install", "site_title=Phase 32 WordPress", "admin_password=",
			"wp core verify-checksums", "installed_version", "convergence_status", "wp-config.php",
		},
		"password_and_tenant_isolation": {
			"action=password_reset", "user_pass", "client.cookies", "customer_id<>", "404",
		},
		"backup_update_and_maintenance": {
			"target_type=all", "confirm=update", "waiting_backup", "backup_id",
			"action=maintenance", "maintenance=true", "maintenance=false", "maintenance_mode",
		},
		"security_and_isolation": {
			"river_job", "database_password", "admin_password", "service_secrets",
			"stat -c '%a'", "sudo -u nobody", "wordpress_operation_failed", "audit_events", "journalctl",
		},
		"safe_detach": {
			"wordpress/detach", "confirm=detach", "files and database", "wordpress_instances", "wordpress_operations",
		},
		"complete_rediscovery": {
			"phase32-empty-discovery", "failed discovery placeholder", "phase32-rediscover", "action=discover", "site_title||':'||admin_user||':'||admin_email", "discovery did not restore WordPress identity",
		},
	})

	for _, forbidden := range []string{
		"INSERT INTO wordpress_instances",
		"INSERT INTO wordpress_operations",
		"UPDATE wordpress_instances SET",
		"UPDATE wordpress_operations SET",
		"wp core install",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("verifier bypasses the WordPress product workflow with %q", forbidden)
		}
	}
}

func TestPhase32VerifierIsBoundedAndFailClosed(t *testing.T) {
	script := readExecutableScript(t, "phase32-verify.sh")
	for _, want := range []string{
		"for _ in $(seq 1 180)",
		"mktemp -d",
		"trap cleanup_phase32 EXIT",
		`PHASE32_COMPLETE=0`,
		`PHASE32_COMPLETE=1`,
		"require_nakpanel_vm_name",
		"systemctl is-active --quiet nakpanel.service",
		"systemctl is-active --quiet nakpanel-agent.service",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("verifier is missing safety contract %q", want)
		}
	}
}

func TestPhase32DocumentationMatchesToolkitBoundary(t *testing.T) {
	checks := map[string][]string{
		"../../README.md": {
			"domain-scoped WordPress Toolkit", "guided installation", "backup-gated", "Phase 32 remains directly",
			"stops short of cloning, staging", "update policies, multisite orchestration",
		},
		"../../docs/RECOVERY.md": {
			"WordPress Toolkit Recovery (Phase 32)", "failed discovery placeholder", "phase32-verify.sh",
		},
		"../../IMPLEMENTATION_PLAN.md": {
			"Phase 32", "WordPress Toolkit", "phase32-verify.sh", "implemented and live-verified",
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
