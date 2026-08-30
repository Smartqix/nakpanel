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
			"Composer version 2.8.11", "composer self-update", "wp --version --allow-root", "WP-CLI 2.12.0", "freshclam", "clamscan",
		},
		"classic_wordpress": {
			"phase30-classic.test", "service-plans", "customers", "subscriptions", "databases",
			"subscription_system_accounts", "panelctl --actor phase30", "ssl set-custom",
			"/usr/local/share/ca-certificates/nakpanel-phase30-root.crt", "--cacert",
			"wp core download https://wordpress.org/wordpress-7.1.zip", "wp core verify-checksums", "wp core install",
			"wp rewrite structure", "wp plugin activate", "wp media import", "wp cron event schedule",
			"session_start", "opcache_get_status", "backup create", "panelctl --actor phase30 restore",
			"desired_php_version=8.5", `"php${version}-fpm"`, "quota -u", "repquota -up /", "Phase30 Isolated",
		},
		"managed_php": {
			"phase30-managed.test", `git -C "${work}" init -q`, "composer.json", "composer.lock",
			`composer --working-dir="${work}" update --no-install --no-interaction --no-ansi --no-progress --no-scripts --no-plugins`, "/php-application",
			"/php-application/environment", "secret_value", "/php-application/deployments",
			"/php-application/workers", "php_deployments", "active_deployment_id",
			"unhealthy", "php_workers", "systemctl", "desired_status=suspended",
			"desired_status=active", "reboot", "/php-application/reconcile",
		},
		"secret_hygiene": {
			"DB_PASSWORD", "APP_SECRET", "WP_ADMIN_PASSWORD", "unset DB_PASSWORD APP_SECRET WP_ADMIN_PASSWORD",
			"river_job", "audit_events", "deployment data", "journalctl", "systemctl show",
			"assert_secret_absent_in_memory", "X-Nakpanel-SPA: true", "password@-", "secret_value@-",
			"DATABASE_ROTATION_RESPONSE", "APPLICATION_SECRET_RESPONSE", "PRE_REBOOT_JOURNAL", "FINAL_JOURNAL",
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
		"wp core download --version=7.1",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("verifier contains forbidden bypass %q", forbidden)
		}
	}
}

func TestPhase30VerifierUsesBoundedWaitsAndMemoryOnlySecrets(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	for _, want := range []string{
		"for _ in $(seq 1 120)",
		"mktemp -d",
		`trap cleanup_phase30 EXIT`,
		"unset DB_PASSWORD APP_SECRET WP_ADMIN_PASSWORD",
		"rm -f /usr/local/lib/nakpanel/phase30-agentprobe",
		"rm -rf /tmp/nakpanel-phase30-certs",
		"require_nakpanel_vm_name",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("verifier is missing safety contract %q", want)
		}
	}
}

func TestPhase30VerifierAcceptsWPCLIInfoWhitespace(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	for _, want := range []string{
		`wp_info="$(timeout 1m wp --info)"`,
		`grep -Eq 'WP-CLI version:[[:space:]]+2\.12\.0' <<<"${wp_info}"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("verifier is missing whitespace-safe WP-CLI assertion %q", want)
		}
	}
	if strings.Contains(script, `grep -Fq 'WP-CLI version: 2.12.0'`) {
		t.Fatal("verifier must not assume WP-CLI uses a literal space before its version")
	}
}

func TestPhase30VerifierUsesAcceptedDatabaseRotationPassword(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	if !strings.Contains(script, `DB_PASSWORD="Aa9_$(openssl rand -hex 18)"`) {
		t.Fatal("verifier database rotation password must use the URL-safe credential policy")
	}
	if strings.Contains(script, `DB_PASSWORD="Aa9!`) {
		t.Fatal("verifier database rotation password must not use a rejected punctuation character")
	}
}

func TestPhase30VerifierMakesCustomCertificateInputOperatorReadable(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	if !strings.Contains(script, `install -d -m 0750 -o root -g nakpanel "${certs}"`) {
		t.Fatal("custom certificate fixture must be traversable only by root and the nakpanel operator")
	}
	if strings.Contains(script, `install -d -m 0700 "${certs}"`) {
		t.Fatal("root-only custom certificate fixture cannot be consumed by panelctl as nakpanel")
	}
}

func TestPhase30VerifierRuntimeGateAvoidsEarlyExitPipelines(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	for _, want := range []string{
		`php_modules="$("php${version}" -m)"`,
		`wp_version="$(timeout 1m wp --version --allow-root)"`,
		`clamav_signature="$(find /var/lib/clamav`,
		`clamav_version="$(timeout 1m clamscan --version)"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("runtime gate is missing captured-output contract %q", want)
		}
	}
	for _, forbidden := range []string{
		`"php${version}" -m | grep`,
		`wp --version --allow-root | grep`,
		`| grep -q .`,
		`clamscan --version | grep`,
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("runtime gate retains pipefail-sensitive assertion %q", forbidden)
		}
	}
}

func TestPhase30VerifierUsesNeutralGuestWorkingDirectory(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	if strings.Contains(script, `multipass exec "${VM_NAME}" -- sudo`) {
		t.Fatal("guest commands must not inherit /home/ubuntu when testing isolated subscription users")
	}
	if got := strings.Count(script, `multipass exec "${VM_NAME}" --working-directory / -- sudo`); got < 14 {
		t.Fatalf("neutral guest working-directory uses = %d, want at least 14", got)
	}
}

func TestPhase30VerifierAvoidsSplitArgumentsAndEarlyExitChecks(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	if !strings.Contains(script, `--title=Phase30WordPress`) {
		t.Fatal("direct Multipass WP-CLI arguments must not contain an embedded display-title space")
	}
	for _, forbidden := range []string{
		`--title='Phase 30 WordPress'`,
		`| grep -Fq`,
		`| grep -Fxq`,
		`| grep -q`,
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("verifier retains split or pipefail-sensitive contract %q", forbidden)
		}
	}
}

func TestPhase30VerifierAssertsHostedDocumentOwnershipModel(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	if !strings.Contains(script, `test "$(stat -c '%U:%G' "${docroot}")" = "${username}:www-data"`) {
		t.Fatal("Classic document root must remain account-owned with nginx group access")
	}
	if strings.Contains(script, `test "$(stat -c '%U:%G' "${docroot}")" = "${username}:${username}"`) {
		t.Fatal("verifier must not reject the deliberate www-data group on hosted document roots")
	}
}

func TestPhase30VerifierSchedulesWordPressCronIdempotently(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	for _, fragment := range []string{
		`cron_hooks="$(timeout 5m sudo -u "${username}" wp cron event list --fields=hook --path="${docroot}")"`,
		`if ! grep -Fxq 'phase30_event' <<<"${cron_hooks}"; then`,
		`wp cron event schedule phase30_event '+1 hour' --repeat=hourly`,
	} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("verifier must make WordPress cron scheduling repeatable; missing %q", fragment)
		}
	}
}

func TestPhase30VerifierValidatesQuotaStatusOutputDespiteQuotaonExitCode(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	if !strings.Contains(script, `quota_status="$(quotaon -p / || true)"`) {
		t.Fatal("quotaon status output must be inspected even when inactive quota classes make it exit nonzero")
	}
	if !strings.Contains(script, `grep -q 'user quota .* is on' <<<"${quota_status}"`) {
		t.Fatal("verifier must still require active user quotas")
	}
}

func TestPhase30VerifierRequestsEnhancedJSONForSecretMutation(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	secretRequest := script[strings.Index(script, `application_secret_result=`):strings.Index(script, `application_secret_status=`)]
	if !strings.Contains(secretRequest, `-H 'X-Nakpanel-SPA: true'`) {
		t.Fatal("secret mutation must use the panel's enhanced-request header before asserting HTTP 200")
	}
}

func TestPhase30VerifierUpsertsReusableWorkerFixtures(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	for _, want := range []string{
		`existing_worker_id="$(db "SELECT id FROM php_workers WHERE application_id=${managed_application_id} AND name='queue'")"`,
		`existing_stopped_worker_id="$(db "SELECT id FROM php_workers WHERE application_id=${managed_application_id} AND name='maintenance'")"`,
		`worker_id_form=(-d "worker_id=${existing_worker_id}")`,
		`stopped_worker_id_form=(-d "worker_id=${existing_stopped_worker_id}")`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("repeatable worker fixture is missing %q", want)
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
			"expected_hard_kib=$((2048 * 1024))", "repquota -up /", "hard_kib", "effective hard block quota",
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
		`timeout 10m sudo -u "${username}" wp core download https://wordpress.org/wordpress-7.1.zip`,
		`timeout 5m sudo -u "${username}" wp eval`,
		"timeout 1m openssl s_client",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("verifier is missing outer command bound %q", want)
		}
	}
	for lineNumber, line := range strings.Split(logical, "\n") {
		if strings.Contains(line, "openssl s_client") && !strings.Contains(line, "timeout ") {
			t.Errorf("logical line %d contains an unbounded openssl network command: %s", lineNumber+1, strings.TrimSpace(line))
		}
	}
}

func TestPhase30VerifierRunsFinalSecretSweepAfterRebootReconciliation(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	for _, want := range []string{
		"PRE_REBOOT_JOURNAL", "systemctl stop nakpanel.service nakpanel-agent.service",
		"POST_REBOOT_JOURNAL", "FINAL_JOURNAL", "FINAL_DATABASE_SURFACES",
		"FINAL_SYSTEMD_METADATA", "FINAL_TENANT_CONFIG", "final_secret_non_disclosure_sweep",
		`nakpanel-php-worker@${worker_id}.service`, `nakpanel-php-worker@${stopped_worker_id}.service`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("verifier is missing final disclosure contract %q", want)
		}
	}
	postReboot := strings.Index(script, "post-reboot desired-stopped worker")
	finalSweep := strings.LastIndex(script, "final_secret_non_disclosure_sweep")
	if postReboot < 0 || finalSweep < 0 || finalSweep <= postReboot {
		t.Fatalf("final secret sweep must run after post-reboot reconciliation assertions")
	}
}

func TestPhase30VerifierKeepsSecretNeedlesOnlyInHostMemory(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	for _, want := range []string{
		"DB_PASSWORD=", "APP_SECRET=", "WP_ADMIN_PASSWORD=", "assert_secret_absent_in_memory",
		`--data-urlencode "password@-"`, `--data-urlencode "secret_value@-"`,
		`printf '%s' "${DB_PASSWORD}" |`, `printf '%s' "${APP_SECRET}" |`,
		`printf '%s' "${WP_ADMIN_PASSWORD}" |`, "unset DB_PASSWORD APP_SECRET WP_ADMIN_PASSWORD",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("verifier is missing in-memory secret contract %q", want)
		}
	}
	for _, forbidden := range []string{
		"DB_SECRET_FILE", "APP_SECRET_FILE", "WP_ADMIN_SECRET_FILE",
		"/var/lib/nakpanel/phase30-verifier", "/tmp/phase30-db-secret",
		"/tmp/phase30-app-secret", "/tmp/phase30-wp-admin-secret", "multipass transfer",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("verifier persists or names a secret file via %q", forbidden)
		}
	}
	secretMarkers := []string{"DB_PASSWORD", "APP_SECRET", "WP_ADMIN_PASSWORD"}
	for lineNumber, line := range strings.Split(script, "\n") {
		containsSecret := false
		for _, marker := range secretMarkers {
			containsSecret = containsSecret || strings.Contains(line, marker)
		}
		if !containsSecret {
			continue
		}
		for _, persistentRoot := range []string{
			"/var/lib", "/tmp", "/etc", "/home", "${ROOT_DIR}", "${REMOTE_SRC}",
			"docs/", ".superpowers/", "README.md", "IMPLEMENTATION_PLAN.md",
		} {
			if strings.Contains(line, persistentRoot) {
				t.Errorf("line %d places verifier secret material under persistent/repo path %q: %s", lineNumber+1, persistentRoot, strings.TrimSpace(line))
			}
		}
		if strings.Contains(line, ">") {
			t.Errorf("line %d redirects verifier secret material to a file: %s", lineNumber+1, strings.TrimSpace(line))
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
