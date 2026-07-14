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
