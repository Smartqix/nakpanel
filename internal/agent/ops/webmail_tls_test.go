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
	for _, want := range []string{"return 301 https://webmail.example.test$request_uri;", "listen 443 ssl;", "ssl_certificate /root/cert.pem;", "ssl_certificate_key /root/key.pem;", "root /usr/share/roundcube;", "fastcgi_pass unix:/run/php/php8.5-fpm.sock;"} {
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

func TestWebmailProvisionerUsesSelectedInternalPHPForHTTPAndHTTPS(t *testing.T) {
	req := types.ConfigureWebmailReq{Domain: "example.test", Hostname: "webmail.example.test", RoundcubeRoot: "/usr/share/roundcube"}
	for _, tls := range []bool{false, true} {
		p := NewWebmailProvisioner(WebmailProvisionerOptions{PHPFPMVersion: "8.5"})
		config, err := p.renderWebmailConfig(req, tls, "/root/cert.pem", "/root/key.pem")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(config, "fastcgi_pass unix:/run/php/php8.5-fpm.sock;") || strings.Contains(config, "php8.3") {
			t.Fatalf("selected internal runtime missing: %s", config)
		}
	}
	legacy := RenderWebmailNginxConfig(req)
	if !strings.Contains(legacy, "fastcgi_pass unix:/run/php/php8.5-fpm.sock;") {
		t.Fatal("legacy wrapper changed")
	}
}

func TestWebmailRejectsInvalidInternalPHPBeforeWriting(t *testing.T) {
	root := t.TempDir()
	p := NewWebmailProvisioner(WebmailProvisionerOptions{PHPFPMVersion: "8.4", NginxAvailableDir: root})
	if _, err := p.ConfigureWebmail(context.Background(), types.ConfigureWebmailReq{Domain: "example.test", Hostname: "webmail.example.test"}); err == nil {
		t.Fatal("invalid internal PHP accepted")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("wrote files for invalid PHP: %v %v", entries, err)
	}
}

func TestWebmailInternalRuntimeDefaultsTo85AndRejects83(t *testing.T) {
	p := NewWebmailProvisioner(WebmailProvisionerOptions{})
	runtime, err := p.internalRuntime()
	if err != nil || runtime.Version != "8.5" {
		t.Fatalf("default internal PHP=%+v err=%v", runtime, err)
	}
	p = NewWebmailProvisioner(WebmailProvisionerOptions{PHPFPMVersion: "8.3"})
	if _, err := p.internalRuntime(); err == nil {
		t.Fatal("retired internal PHP 8.3 accepted")
	}
}
