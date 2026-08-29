package multipass

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPhase26VerifierCoversSettingsCatalogAndRoleIsolation(t *testing.T) {
	const path = "phase26-verify.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable", path)
	}

	script := string(data)
	for _, want := range []string{
		"common.sh",
		`VM_NAME="${NAKPANEL_MULTIPASS_VM}"`,
		`IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"`,
		"ensure_vm 2 3G 16G",
		"bootstrap_secret_key",
		"useradd --system",
		"phase25-verify.sh",
		"phase20-verify.sh",
		"/healthz",
		"/tools-settings",
		"/tools-settings/server",
		"/tools-settings/php",
		"/tools-settings/security",
		"/tools-settings/services",
		"/tools-settings/logs",
		"/tools-settings/updates",
		"/tools-settings/inventory",
		"/tools-settings/status",
		"panelctl secret-key init",
		"panelctl secret-key migrate",
		"secret-keys.json",
		`sudo stat -c '%U:%G:%a' /etc/nakpanel`,
		`sudo stat -c '%U:%G:%a' /etc/nakpanel/secret-keys.json`,
		"nakpanel_phase26_migration_test",
		"nakpanel_toolkit_semantic_rollback",
		"phase23_legacy_site_backfill",
		"phase25_entitlement_snapshot_backup",
		"make goose-down",
		"20260723000028",
		"/tools-settings/reauthenticate",
		"/tools-settings/services/action",
		"service_id=web",
		"action=reload",
		"server_operations",
		"server.reauthenticated",
		"server.service_reload",
		"/tools-settings/journal?source=panel&source=agent&hours=1&limit=25",
		"/tools-settings/updates/inventory",
		"/tools-settings/updates/dry-run",
		"/tools-settings/operations/updates",
		"/tools-settings/security/status",
		"/tools-settings/mail/queue?limit=25",
		"/tools-settings/mail/logs?since_minutes=60&limit=25",
		"/tools-settings/databases/status",
		"/tools-settings/operations/application-catalog",
		"/mail/status",
		"/tools-utilities",
		"Tools &amp; Utilities",
		"data-np-settings-search",
		"data-np-settings-tool",
		"data-np-settings-empty",
		"data-np-settings-health",
		"General Settings",
		"Web &amp; PHP",
		"Security",
		"Tools &amp; Resources",
		"Server Management",
		"Mail",
		"Applications &amp; Databases",
		"Monitoring &amp; Logs",
		"Panel Administration",
		"data-np-role=\"admin\"",
		"data-np-role=\"reseller\"",
		"data-np-(raw-config|root-terminal)",
		"name=\"viewport\"",
		"@media (max-width:",
		"Privileged agent op pending",
		`"firewall_mutation":true`,
		`"ssh_mutation":false`,
		`"dry_run":true`,
		"not-a-message",
		"limit=501",
		"Phase 26 implemented Tools & Settings surface verification passed",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s is missing %q", path, want)
		}
	}
}

func TestPhase26VerifierNeverInvokesPowerOrPackageInstall(t *testing.T) {
	data, err := os.ReadFile("phase26-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, forbidden := range []string{
		`-X POST "${BASE_URL}/tools-settings/operations/power"`,
		`"dry_run":false`,
		`confirmation=INSTALL UPDATES`,
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("phase26-verify.sh contains disruptive operation %q", forbidden)
		}
	}
}

func TestPhase26VerifierBootstrapsBeforePriorVerifierAndUsesDisposableMigrationDB(t *testing.T) {
	data, err := os.ReadFile("phase26-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)

	ensureAt := strings.Index(script, "ensure_vm 2 3G 16G")
	bootstrapAt := strings.Index(script, "bootstrap_secret_key\n\nif [[")
	priorAt := strings.Index(script, "run_prior_verifier\nfi")
	if ensureAt < 0 || bootstrapAt < 0 || priorAt < 0 ||
		!(ensureAt < bootstrapAt && bootstrapAt < priorAt) {
		t.Fatalf("fresh VM and key bootstrap must run before the prior verifier")
	}
	if !strings.Contains(script, "if ! id nakpanel") ||
		!strings.Contains(script, "if ! sudo test -s /etc/nakpanel/secret-keys.json") {
		t.Fatal("secret bootstrap must tolerate both a missing user and an existing key")
	}
	if !strings.Contains(script, "trap cleanup_migration_test_db EXIT") ||
		!strings.Contains(script, "dropdb --if-exists --force") {
		t.Fatal("migration round trip must use and clean a disposable database")
	}
}

func TestPhase26VerifierHasValidShellSyntax(t *testing.T) {
	cmd := exec.Command("bash", "-n", "phase26-verify.sh")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n phase26-verify.sh: %v\n%s", err, output)
	}
}

func TestPhase26InstallerKeepsKeyParentAndBackupWritesSafe(t *testing.T) {
	data, err := os.ReadFile("../install/phase26-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		`KEY_DIR="$(dirname "${KEY_FILE}")"`,
		`"${KEY_DIR}" != "/etc/nakpanel"`,
		`pg_dump --format=custom "${DB_DSN}" >"${backup_dir}/nakpanel-before-phase26.dump"`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("phase26 installer is missing %q", required)
		}
	}
	if strings.Contains(script, `install -d -o root -g nakpanel -m 0750 "$(dirname "${KEY_FILE}")"`) {
		t.Fatal("phase26 installer still mutates an unvalidated key parent")
	}
}
