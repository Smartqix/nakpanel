package ops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundcubeUsesVerifiedConfiguredMailTLS(t *testing.T) {
	config := RenderRoundcubeConfig("test-key", "mail.example.test")
	for _, want := range []string{"'verify_peer' => true", "'verify_peer_name' => true", "'allow_self_signed' => false", "'peer_name' => 'mail.example.test'", "tls://127.0.0.1:143", "tls://127.0.0.1:587"} {
		if !strings.Contains(config, want) {
			t.Errorf("configured Roundcube missing %q", want)
		}
	}
	if strings.Contains(config, "'verify_peer' => false") {
		t.Error("configured TLS verification disabled")
	}
}

func TestRoundcubeRejectsInvalidMailTLSHostnameBeforeWriting(t *testing.T) {
	root := t.TempDir()
	p := NewWebmailProvisioner(WebmailProvisionerOptions{MailTLSHostname: "bad'host", DESKeyPath: filepath.Join(root, "key"), RoundcubeConfigPath: filepath.Join(root, "config"), PHPGroup: "nakpanel-test-missing-group"})
	if err := p.writeRoundcubeConfig(); err == nil {
		t.Fatal("invalid TLS hostname accepted")
	}
	if _, err := os.Stat(p.roundcubeConfigPath); !os.IsNotExist(err) {
		t.Fatal("invalid configuration written")
	}
}
