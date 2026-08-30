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
			"/usr/local/share/ca-certificates/nakpanel-phase30-root.crt", "--cacert",
			"wp core download --version=7.1", "wp core verify-checksums", "wp core install",
			"wp rewrite structure", "wp plugin activate", "wp media import", "wp cron event schedule",
			"session_start", "opcache_get_status", "backup create", "panelctl --actor phase30 restore",
			"desired_php_version=8.5", `"php${version}-fpm"`, "quota -u", "repquota -up /", "Phase30 Isolated",
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

func TestPhase30VerifierReviewRoundOneContracts(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	requireScriptContracts(t, script, map[string][]string{
		"authoritative_isolation_artifacts": {
			"classic_document_root", "require_first_subscription_artifact", "assert_cross_subscription_open_denied",
			`test -e "${path}"`, `test -s "${path}"`, `head -c 1 "${path}"`, "Permission denied",
		},
		"desired_stopped_worker": {
			"phase30-stopped-worker", "stopped_worker_id", "desired_state=stopped",
			"desired-stopped worker before suspension", "desired-stopped worker during suspension",
			"desired-stopped worker after reactivation", "desired-stopped worker after explicit reconciliation",
			"post-reboot desired-stopped worker", "assert_worker_inactive",
		},
		"complete_secret_log_window": {
			"journal_cursor", "--show-cursor", "--after-cursor", `nakpanel-php-worker@${worker_id}.service`,
			`nakpanel-php-worker@${stopped_worker_id}.service`, "failed to capture PHP unit metadata",
		},
		"effective_disk_quota": {
			"expected_hard_kib=$((512 * 1024))", "repquota -up /", "hard_kib", "effective hard block quota",
		},
		"composer_policy": {
			"composer_wrapper_hash_before", "composer_phar_hash_before", "composer_version_before",
			"composer self-update is disabled; use the nakpanel installer", "composer_self_update_status",
			"composer_wrapper_hash_after", "composer_phar_hash_after", "composer_version_after",
		},
	})

	existsAt := strings.Index(script, "require_first_subscription_artifact")
	openAt := strings.LastIndex(script, "assert_cross_subscription_open_denied")
	if existsAt < 0 || openAt < 0 || existsAt >= openAt {
		t.Fatalf("first-subscription artifacts must be required before cross-subscription open probes")
	}

	for _, forbidden := range []string{
		"journalctl -u nakpanel.service -u nakpanel-agent.service --no-pager -n 2000",
		`systemctl show "nakpanel-php-fpm@${site_id}.service" "nakpanel-php-worker@*.service"`,
		`systemctl.out" 2>/dev/null || true`,
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("verifier retains review-round bypass %q", forbidden)
		}
	}
}

func TestPhase30VerifierBoundsEveryCurlAndExternalInstaller(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	logical := strings.ReplaceAll(script, "\\\n", " ")
	for lineNumber, line := range strings.Split(logical, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "curl ") || strings.HasPrefix(trimmed, "for tool in ") || strings.Contains(trimmed, "trusted_curl ") {
			continue
		}
		if !strings.Contains(trimmed, "--connect-timeout") || !strings.Contains(trimmed, "--max-time") {
			t.Errorf("logical line %d contains an unbounded curl command: %s", lineNumber+1, trimmed)
		}
	}
	for _, want := range []string{
		"timeout 45m deploy/install/install.sh --yes --allow-downgrade --force",
		`timeout 10m sudo -u "${username}" wp core download --version=7.1`,
		`timeout 5m sudo -u "${username}" wp eval`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("verifier is missing outer command bound %q", want)
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
