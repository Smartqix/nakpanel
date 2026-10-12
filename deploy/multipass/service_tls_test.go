package multipass

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestServiceTLSRenewalContract(t *testing.T) {
	path := "../install/sync-service-certificates.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("shell syntax: %v: %s", err, output)
	}
	for _, marker := range []string{
		"sync-panel-hostname-cert --check", "flock", "chmod 0600", "rollback", "-verify_return_error", "-verify_hostname",
		"stalwart-mail.service", "nakpanel-proftpd.service", "proftpd -t", "fullchain.pem", "privkey.pem",
	} {
		if !strings.Contains(string(data), marker) {
			t.Errorf("service certificate sync missing %q", marker)
		}
	}
	for _, path := range []string{"../systemd/nakpanel-service-cert@.service", "../systemd/nakpanel-service-cert@.timer"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "sync-service-certificates") && !strings.Contains(string(data), "nakpanel-service-cert@") {
			t.Fatalf("invalid renewal unit: %s", path)
		}
	}
}

func TestCertbotImportValidatesBeforePrivateFileActivation(t *testing.T) {
	path := "../install/import-service-certificate.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("syntax: %v: %s", err, output)
	}
	script := string(data)
	for _, marker := range []string{"/etc/letsencrypt/archive/", "-checkhost", "-checkend", "openssl verify", "cert_pub", "key_pub", "install -m 0600", "rollback", "sync-service-certificates"} {
		if !strings.Contains(script, marker) {
			t.Errorf("import hook missing %q", marker)
		}
	}
	if strings.Index(script, "openssl verify") > strings.Index(script, "installed=true") {
		t.Fatal("certificate changed before trust verification")
	}
}
