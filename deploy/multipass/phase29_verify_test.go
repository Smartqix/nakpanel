package multipass

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func readExecutableScript(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) returned error: %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) returned error: %v", path, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable", path)
	}
	if bash, lookErr := exec.LookPath("bash"); lookErr == nil {
		if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
			t.Fatalf("bash -n %s failed: %v\n%s", path, err, out)
		}
	}
	return string(data)
}

func TestPhase29VerifierCoversTheReliabilityGate(t *testing.T) {
	script := readExecutableScript(t, "phase29-verify.sh")
	for _, want := range []string{
		"common.sh",
		`VM_NAME="${NAKPANEL_MULTIPASS_VM}"`,
		`IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"`,
		"phase28-verify.sh",
		// Upgrade leg with both rollback drills.
		"deploy/install/install.sh --yes",
		"NAKPANEL_INSTALL_FAULT=before-migrate",
		"NAKPANEL_INSTALL_FAULT=unhealthy-panel",
		"upgrade-backups",
		"previous_version=",
		"refusing downgrade",
		"phase29_drill_canary",
		// The DR mailbox canary must be selected from a subscription that
		// actually permits mail; earlier phase fixtures intentionally do not.
		"JOIN subscription_entitlements entitlement",
		"entitlement.max_mailboxes <> 0",
		"entitlement.hosting_policy#>>'{permissions,mail}'",
		"entitlement.hosting_policy#>>'{mail,enabled}'",
		// A mail-entitled fixture may already be at its mailbox limit after
		// the Phase 18/19 acceptance tests. Reuse an owned mailbox instead of
		// weakening the production quota gate or assuming spare capacity.
		"mailbox_local=",
		"mailbox_address=\"${mailbox_local}@${domain}\"",
		`"${mailbox_address}" 'Phase29Mail!2026'`,
		// Enabling domain mail queues convergence work that may briefly repair
		// subscription path permissions. The baseline must wait for the real
		// tenant endpoint rather than racing those durable jobs.
		"canary_reachable=false",
		"canary_reachable=true",
		`[[ "${canary_reachable}" == "true" ]]`,
		// Security leg.
		"user unlock admin@nakpanel.test",
		// Exercise the durable application throttle over loopback so the
		// separately tested five-attempt Fail2ban jail cannot cut off the
		// verifier host before the ten-attempt panel threshold is reached.
		"https://127.0.0.1:7443/login",
		// Phase 11+ uses the routed Service Provider workspace. Authentication
		// assertions must use stable role/session markers, not the retired
		// Phase 1 "Admin dashboard" heading.
		"assert_admin_workspace",
		`data-np-role="admin"`,
		`action="/logout"`,
		"fail2ban-client status nakpanel-login",
		"tools-settings/security/bans/unban",
		"tools-settings/security/firewall/revert",
		"/account/2fa/activate",
		"wait_for_next_totp_window",
		"nakpanel-csrf-2fa-v1",
		"disable-2fa admin@nakpanel.test",
		// Reboot leg.
		"multipass restart",
		"wait_for_cloud_init",
		"reconcile --system",
		"assert_no_failed_units",
		// Disaster recovery leg.
		"backup-server key init",
		"backup-server run --destination phase29-local",
		`require_nakpanel_vm_name "${DR_VM_NAME}"`,
		"restore-server",
		"--backup-key-file",
		"named-checkconf",
		"imaplib.IMAP4_SSL",
		`destroy_vm "${DR_VM_NAME}"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("phase29-verify.sh is missing %q", want)
		}
	}

	// The legs must run in order: populate/upgrade, security, reboot, DR.
	ordered := []string{
		"leg 1 - populated in-place upgrade",
		"NAKPANEL_INSTALL_FAULT=before-migrate",
		"NAKPANEL_INSTALL_FAULT=unhealthy-panel",
		"leg 2 - production security",
		"leg 3 - reboot and reconcile",
		"multipass restart",
		"leg 4 - disaster recovery",
		"restore_entrypoint || fail",
	}
	last := -1
	for _, marker := range ordered {
		index := strings.Index(script, marker)
		if index < 0 {
			t.Fatalf("phase29-verify.sh is missing ordering marker %q", marker)
		}
		if index < last {
			t.Fatalf("phase29-verify.sh marker %q appears out of order", marker)
		}
		last = index
	}

	if strings.Contains(script, "nakpanel-soak") {
		t.Fatal("phase29-verify.sh must never touch the soak VM")
	}
	if strings.Contains(script, `mail add "phase29@${domain}"`) {
		t.Fatal("phase29-verify.sh must not assume mailbox quota has a free slot")
	}
	if strings.Contains(script, "create_server_backup(){ cli ") {
		t.Fatal("the long-running server backup must not use the short-command watchdog")
	}
	if strings.Contains(script, "backup-server run --destination phase29-local --wait") {
		t.Fatal("the verifier must enqueue the backup and poll its durable row instead of holding a Multipass exec channel open")
	}
	if strings.Count(script, "https://127.0.0.1:7443/login") < 3 {
		t.Fatal("phase29-verify.sh must exercise and recheck the durable throttle over VM loopback")
	}
	if strings.Contains(script, "Admin dashboard") {
		t.Fatal("phase29-verify.sh must not depend on the retired Phase 1 dashboard heading")
	}
	if strings.Count(script, "assert_no_failed_units") < 3 {
		t.Fatal("phase29-verify.sh must reject failed systemd units after reboot and disaster recovery")
	}
}

func TestUnifiedInstallerImplementsUpgradeRollback(t *testing.T) {
	script := readExecutableScript(t, "../install/install.sh")
	for _, want := range []string{
		"schema_migrated",
		"pg_dump --format=custom",
		"pg_restore",
		"dropdb --force",
		"sort -V",
		"refusing downgrade",
		"trap cleanup_upgrade EXIT",
		"health_gate",
		"/etc/nakpanel/version",
		"NAKPANEL_INSTALL_FAULT",
		"--rollback-schema",
		"phase8-install.sh",
		"phase18-install.sh",
		"phase21-25-install.sh",
		"fail2ban",
		"restore-server",
		"secret-key init",
		"goose-up",
		"river-up",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("install.sh is missing %q", want)
		}
	}
	// The post-migration rollback restores the database automatically by
	// default; the operator handoff is the explicit opt-out.
	autoRestore := strings.Index(script, "restoring database from pre-upgrade dump")
	manualHandoff := strings.Index(script, "new binaries kept")
	if autoRestore < 0 || manualHandoff < 0 || autoRestore > manualHandoff {
		t.Fatal("install.sh rollback contract changed: automatic pg_restore must be the default path")
	}
}

func TestUnifiedInstallerSerializesUbuntuBackgroundPackageWork(t *testing.T) {
	script := readExecutableScript(t, "../install/install.sh")
	for _, want := range []string{
		"pause_apt_background",
		"resume_apt_timers",
		"apt-daily.timer",
		"apt-daily-upgrade.timer",
		"apt-daily.service",
		"apt-daily-upgrade.service",
		"timed out waiting for Ubuntu background package activity",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("install.sh is missing package-lock safety %q", want)
		}
	}
	if strings.Count(script, "pause_apt_background") < 3 {
		t.Fatal("fresh and upgrade paths must both pause background package activity")
	}
	if !strings.Contains(script, "resume_apt_timers\n") {
		t.Fatal("installer cleanup must restore the package timers")
	}
}

func TestSoakVerifierIsNonDestructive(t *testing.T) {
	script := readExecutableScript(t, "soak-verify.sh")
	for _, want := range []string{
		"NAKPANEL_SOAK_VM",
		"require_nakpanel_vm_name",
		"--init",
		"healthz",
		"systemctl --failed",
		"reconcile --system",
		"backup-server key init",
		"soak.log",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("soak-verify.sh is missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`destroy_vm "${SOAK_VM}"`,
		"delete --purge",
		"destroy_legacy_phase_vms",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("soak-verify.sh contains destructive call %q", forbidden)
		}
	}
	data, err := os.ReadFile("common.sh")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "nakpanel-soak") {
		t.Fatal("the soak VM must never appear in common.sh destroy lists")
	}
}

func TestFail2BanFilterMatchesThePanelAuthLine(t *testing.T) {
	data, err := os.ReadFile("../fail2ban/nakpanel-login.conf")
	if err != nil {
		t.Fatalf("read fail2ban filter: %v", err)
	}
	filter := string(data)
	for _, want := range []string{
		"journalmatch = _SYSTEMD_UNIT=nakpanel.service",
		`nakpanel-auth: login failed for "[^"]*" from <HOST>`,
	} {
		if !strings.Contains(filter, want) {
			t.Fatalf("nakpanel-login.conf is missing %q", want)
		}
	}
}
