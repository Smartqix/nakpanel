package ops

import (
	"context"
	"github.com/nakroteck/nakpanel/internal/types"
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

func TestWebmailTLSRedirectsHTTPAndServesSecureRoundcube(t *testing.T) {
	config := renderWebmailTLSNginxConfig(types.ConfigureWebmailReq{Hostname: "webmail.example.test", RoundcubeRoot: "/usr/share/roundcube"}, "/root/cert.pem", "/root/key.pem")
	for _, want := range []string{"return 301 https://webmail.example.test$request_uri;", "listen 443 ssl;", "ssl_certificate /root/cert.pem;", "ssl_certificate_key /root/key.pem;", "root /usr/share/roundcube;", "fastcgi_pass unix:/run/php/php8.3-fpm.sock;"} {
		if !strings.Contains(config, want) {
			t.Errorf("secure webmail missing %q", want)
		}
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

func TestWebmailInvalidTLSRetainsPreviousConfiguration(t *testing.T) {
	root := t.TempDir()
	cert, key := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
	if err := os.WriteFile(cert, []byte("invalid certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("invalid key"), 0600); err != nil {
		t.Fatal(err)
	}
	available := filepath.Join(root, "available")
	if err := os.MkdirAll(available, 0700); err != nil {
		t.Fatal(err)
	}
	previous := filepath.Join(available, "webmail.example.test.conf")
	if err := os.WriteFile(previous, []byte("previous valid configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	p := NewWebmailProvisioner(WebmailProvisionerOptions{NginxAvailableDir: available, NginxEnabledDir: filepath.Join(root, "enabled"), TLSHostname: "webmail.example.test", TLSCertPath: cert, TLSKeyPath: key})
	if _, err := p.ConfigureWebmail(context.Background(), types.ConfigureWebmailReq{Domain: "example.test", Hostname: "webmail.example.test"}); err == nil {
		t.Fatal("invalid TLS accepted")
	}
	data, err := os.ReadFile(previous)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "previous valid configuration" {
		t.Fatal("previous configuration overwritten")
	}
}
