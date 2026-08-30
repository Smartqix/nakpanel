package multipass

import (
	"os"
	"strings"
	"testing"
)

func requireScriptContracts(t *testing.T, script string, contracts map[string][]string) {
	t.Helper()
	for group, wants := range contracts {
		t.Run(group, func(t *testing.T) {
			for _, want := range wants {
				if !strings.Contains(script, want) {
					t.Errorf("verifier is missing %q", want)
				}
			}
		})
	}
}

func TestPhase30VerifierCoversProductionPHPAcceptance(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	requireScriptContracts(t, script, map[string][]string{
		"single_vm_and_current_build": {
			"common.sh", `VM_NAME="${NAKPANEL_MULTIPASS_VM}"`, `IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"`,
			"phase29-verify.sh", "NAKPANEL_SKIP_PRIOR_PHASES", "sync_repo", "vm_ip",
			"deploy/install/install.sh --yes", "--allow-downgrade --force", "/usr/local/bin/nakpanel-panel", "/usr/local/bin/nakpanel-agent",
		},
		"runtime_inventory": {
			"8.3", "8.4", "8.5", `"php${version}-fpm"`,
			"PHPVersions", "validation_errors", "required_extensions", "opcache",
			"Composer version 2.8.11", "composer self-update", "WP-CLI 2.12.0", "freshclam", "clamscan",
		},
		"classic_wordpress": {
			"phase30-classic.test", "service-plans", "customers", "subscriptions", "databases",
			"subscription_system_accounts", "panelctl --actor phase30", "ssl set-custom",
			"/usr/local/share/ca-certificates/nakpanel-phase30-root.crt", "curl --cacert",
			"wp core download --version=7.1", "wp core verify-checksums", "wp core install",
			"wp rewrite structure", "wp plugin activate", "wp media import", "wp cron event schedule",
			"session_start", "opcache_get_status", "backup create", "panelctl --actor phase30 restore",
			"desired_php_version=8.5", `"php${version}-fpm"`, "quota -u", "repquota -u /", "Phase30 Isolated",
		},
		"managed_php": {
			"phase30-managed.test", `git -C "${work}" init -q`, "composer.json", "/php-application",
			"/php-application/environment", "secret_value", "/php-application/deployments",
			"/php-application/workers", "php_deployments", "active_deployment_id",
			"unhealthy", "php_workers", "systemctl", "desired_status=suspended",
			"desired_status=active", "reboot", "/php-application/reconcile",
		},
		"secret_hygiene": {
			"phase30-db-secret", "phase30-app-secret", "chmod 0600", "unset DB_PASSWORD APP_SECRET",
			"river_job", "audit_events", "deployment output", "journalctl", "systemctl show",
			"grep -Fq -f", "assert_secret_absent", "Accept: application/json",
			"database-rotation.json", "application-secret.json", "phase30-wp-admin-secret",
			"system_database_mutation",
		},
		"ui_contract": {
			"PHP Application", "Classic", "Managed", "/tools-settings/php", "/tools-settings/applications", "Runtime inventory",
			"Managed PHP deployments", "PHP workers", "Node.js", "Python", "WordPress Toolkit",
		},
	})

	for _, forbidden := range []string{
		"INSERT INTO subscription_entitlements",
		"curl -k --cacert",
		"curl -sk --cacert",
		"wp core download --force",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("verifier contains forbidden bypass %q", forbidden)
		}
	}
}

func TestPhase30VerifierUsesBoundedWaitsAndSafeSecretFiles(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	for _, want := range []string{
		"for _ in $(seq 1 120)",
		"mktemp -d",
		`trap cleanup_phase30 EXIT`,
		"rm -f \"${DB_SECRET_FILE}\" \"${APP_SECRET_FILE}\"",
		"rm -f /usr/local/lib/nakpanel/phase30-agentprobe",
		"rm -rf /tmp/nakpanel-phase30-certs",
		"require_nakpanel_vm_name",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("verifier is missing safety contract %q", want)
		}
	}
}

func TestPhase30DocumentationMatchesProvenProductBoundary(t *testing.T) {
	checks := map[string][]string{
		"../../README.md": {
			"PHP 8.3, 8.4, and 8.5", "Classic PHP", "Managed PHP", "WordPress 7.1 compatibility",
			"not a WordPress Toolkit", "does not offer Node.js or Python applications", "phase30-verify.sh",
		},
		"../../docs/RECOVERY.md": {
			"Phase 30", "PHP application", "active release", "desired-active worker", "phase30-verify.sh",
		},
		"../../.superpowers/sdd/phase30-production-php/progress.md": {
			"Task 8", "Phase 30 verifier", "controller", "Multipass",
		},
		"../../IMPLEMENTATION_PLAN.md": {
			"Phase 30", "Production PHP hosting", "phase30-verify.sh", "compatibility only",
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
