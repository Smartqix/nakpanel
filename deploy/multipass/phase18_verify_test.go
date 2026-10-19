package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase18VerifierCoversMailHosting(t *testing.T) {
	data, err := os.ReadFile("phase18-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"phase17-verify.sh", "phase18-install.sh", "TestMailTenantIsolationTwoTenants",
		"mail enable", "mail add", "mail list", "mail del", "mail alias add",
		"mail relay set", "quota exceeded", "nak1._domainkey", "v=spf1 mx ~all",
		"v=DMARC1", "DKIM-Signature", "imaps://127.0.0.1:993", "smtp://127.0.0.1:587",
		"_task=mail", "mail_outbound_spike", "smtpsink", "stalwart-mail.service",
		"Phase 18 mail hosting verification passed",
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("phase18-verify.sh is missing %q", want)
		}
	}
}

func TestRoundcubeMaintenanceUsesSupportedPHPRuntime(t *testing.T) {
	data, err := os.ReadFile("../install/phase18-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/etc/systemd/system/roundcube-gc.service.d",
		"../systemd/roundcube-gc.service.d/nakpanel.conf",
		"systemctl start roundcube-gc.service",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("mail installer must configure and verify Roundcube maintenance: missing %q", want)
		}
	}
	unit, err := os.ReadFile("../systemd/roundcube-gc.service.d/nakpanel.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "ExecStart=\nExecStart=/usr/bin/php8.3 /usr/share/roundcube/bin/gc.sh") {
		t.Fatal("Roundcube cleanup must override the package's unversioned PHP shebang")
	}
}
