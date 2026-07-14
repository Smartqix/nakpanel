package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhase19VerifierCoversMailWorkspaceAndServerControls(t *testing.T) {
	data, err := os.ReadFile("phase19-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"phase18-verify.sh", "/sites/${site_id}?tab=mail", "domain_id=${mail_domain_id}",
		"provider sidebar still exposes Mail", "return_to=site-mail", "/mail/status", "/settings/mail",
		"phase19-ui", "smarthost_password", "client-mail.html", "stalwart-mail.service",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("phase19-verify.sh is missing %q", want)
		}
	}
}
