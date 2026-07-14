package ops

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeACMEIssuer struct {
	req    ACMEIssueRequest
	result ACMEIssueResult
	err    error
}

func (i *fakeACMEIssuer) Issue(ctx context.Context, req ACMEIssueRequest) (ACMEIssueResult, error) {
	i.req = req
	if i.err != nil {
		return ACMEIssueResult{}, i.err
	}
	return i.result, nil
}

func TestValidateIssueCertRequestRejectsUnsafeInputs(t *testing.T) {
	tests := []struct {
		name string
		req  types.IssueCertReq
	}{
		{
			name: "username path traversal",
			req:  types.IssueCertReq{Username: "../root", Domain: "example.test", PHPVersion: "8.3", Issuer: types.CertIssuerLocalSelfSigned},
		},
		{
			name: "domain shell metacharacter",
			req:  types.IssueCertReq{Username: "npdemo", Domain: "example.test;reboot", PHPVersion: "8.3", Issuer: types.CertIssuerLocalSelfSigned},
		},
		{
			name: "unsupported issuer",
			req:  types.IssueCertReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", Issuer: "shell"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateIssueCertRequest(tt.req); err == nil {
				t.Fatal("ValidateIssueCertRequest returned nil error")
			}
		})
	}
}

func TestValidateIssueCertRequestAllowsACME(t *testing.T) {
	err := ValidateIssueCertRequest(types.IssueCertReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
		Issuer:     types.CertIssuerACME,
	})
	if err != nil {
		t.Fatalf("ValidateIssueCertRequest returned error: %v", err)
	}
}

func TestLocalCertificateProvisionerCreatesCertAndTLSVHost(t *testing.T) {
	tmp := t.TempDir()
	paths := SitePathConfig{
		HomeRoot:          filepath.Join(tmp, "home"),
		NginxAvailableDir: filepath.Join(tmp, "etc", "nginx", "sites-available"),
		NginxEnabledDir:   filepath.Join(tmp, "etc", "nginx", "sites-enabled"),
		NginxLogDir:       filepath.Join(tmp, "var", "log", "nginx"),
		PHPFPMPoolDir:     filepath.Join(tmp, "etc", "php", "8.3", "fpm", "pool.d"),
		PHPFPMLogDir:      filepath.Join(tmp, "var", "log", "php-fpm"),
		PHPRunDir:         filepath.Join(tmp, "run", "php"),
		NginxSnippet:      "snippets/fastcgi-php.conf",
		WWWGroup:          "www-data",
		PHPTmpDir:         filepath.Join(tmp, "tmp"),
		DefaultFileMode:   0o644,
	}
	reloader := &recordingReloader{}
	provisioner := NewCertificateProvisioner(CertificateProvisionerOptions{
		Paths:    paths,
		CertRoot: filepath.Join(tmp, "var", "lib", "nakpanel", "certs"),
		Reloader: reloader,
	})

	result, err := provisioner.IssueCert(context.Background(), types.IssueCertReq{
		Username:      "npdemo",
		Domain:        "example.test",
		PHPVersion:    "8.3",
		Issuer:        types.CertIssuerLocalSelfSigned,
		SharedAccount: true,
		Limits:        types.SiteResourceLimits{RequestRatePerSecond: 4, RequestBurst: 8, MaxConnections: 12},
	})
	if err != nil {
		t.Fatalf("IssueCert returned error: %v", err)
	}
	if result.Domain != "example.test" || result.Issuer != types.CertIssuerLocalSelfSigned {
		t.Fatalf("result = %#v, want domain and local issuer", result)
	}
	if result.CertPath == "" || result.KeyPath == "" || result.ExpiresAt.IsZero() {
		t.Fatalf("result missing cert metadata: %#v", result)
	}
	for _, path := range []string{result.CertPath, result.KeyPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}

	keyInfo, err := os.Stat(result.KeyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if got, want := keyInfo.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("key mode = %o, want %o", got, want)
	}

	certPEM, err := os.ReadFile(result.CertPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("certificate PEM did not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if !slices.Contains(cert.DNSNames, "example.test") {
		t.Fatalf("certificate DNSNames = %#v, want example.test", cert.DNSNames)
	}

	nginxPath := filepath.Join(paths.NginxAvailableDir, "example.test.conf")
	nginx, err := os.ReadFile(nginxPath)
	if err != nil {
		t.Fatalf("read nginx config: %v", err)
	}
	for _, want := range []string{
		"listen 443 ssl;",
		"server_name example.test;",
		"root " + filepath.Join(paths.HomeRoot, "npdemo", "domains", "example.test", "public_html") + ";",
		"ssl_certificate " + result.CertPath + ";",
		"ssl_certificate_key " + result.KeyPath + ";",
		"fastcgi_pass unix:" + filepath.Join(paths.PHPRunDir, "nakpanel-npdemo-example-test.sock") + ";",
		"limit_req zone=",
		"limit_conn ",
	} {
		if !strings.Contains(string(nginx), want) {
			t.Fatalf("nginx config missing %q:\n%s", want, nginx)
		}
	}
	if got, want := reloader.services, []string{"nginx"}; !slices.Equal(got, want) {
		t.Fatalf("reloaded services = %#v, want %#v", got, want)
	}
}

func TestACMECertificateProvisionerUsesIssuerAndWritesTLSVHost(t *testing.T) {
	tmp := t.TempDir()
	paths := SitePathConfig{
		HomeRoot:          filepath.Join(tmp, "home"),
		NginxAvailableDir: filepath.Join(tmp, "etc", "nginx", "sites-available"),
		NginxEnabledDir:   filepath.Join(tmp, "etc", "nginx", "sites-enabled"),
		NginxLogDir:       filepath.Join(tmp, "var", "log", "nginx"),
		PHPFPMPoolDir:     filepath.Join(tmp, "etc", "php", "8.3", "fpm", "pool.d"),
		PHPFPMLogDir:      filepath.Join(tmp, "var", "log", "php-fpm"),
		PHPRunDir:         filepath.Join(tmp, "run", "php"),
		NginxSnippet:      "snippets/fastcgi-php.conf",
		WWWGroup:          "www-data",
		PHPTmpDir:         filepath.Join(tmp, "tmp"),
		DefaultFileMode:   0o644,
	}
	reloader := &recordingReloader{}
	issuer := &fakeACMEIssuer{
		result: ACMEIssueResult{
			CertPath:  filepath.Join(tmp, "var", "lib", "nakpanel", "certs", "example.test", "fullchain.pem"),
			KeyPath:   filepath.Join(tmp, "var", "lib", "nakpanel", "certs", "example.test", "privkey.pem"),
			ExpiresAt: mustParseTime(t, "2026-10-01T00:00:00Z"),
		},
	}
	provisioner := NewCertificateProvisioner(CertificateProvisionerOptions{
		Paths:      paths,
		CertRoot:   filepath.Join(tmp, "var", "lib", "nakpanel", "certs"),
		Reloader:   reloader,
		ACMEIssuer: issuer,
	})

	result, err := provisioner.IssueCert(context.Background(), types.IssueCertReq{
		Username:      "npdemo",
		Domain:        "example.test",
		PHPVersion:    "8.3",
		Issuer:        types.CertIssuerACME,
		SharedAccount: true,
	})
	if err != nil {
		t.Fatalf("IssueCert returned error: %v", err)
	}
	if issuer.req.Domain != "example.test" || issuer.req.Docroot != filepath.Join(paths.HomeRoot, "npdemo", "domains", "example.test", "public_html") {
		t.Fatalf("ACME request = %#v, want domain and docroot", issuer.req)
	}
	if issuer.req.CertPath != issuer.result.CertPath || issuer.req.KeyPath != issuer.result.KeyPath {
		t.Fatalf("ACME request paths = %#v, want cert/key result paths", issuer.req)
	}
	if result.Issuer != types.CertIssuerACME || result.CertPath != issuer.result.CertPath || result.KeyPath != issuer.result.KeyPath {
		t.Fatalf("result = %#v, want ACME issuer result paths", result)
	}
	nginx, err := os.ReadFile(filepath.Join(paths.NginxAvailableDir, "example.test.conf"))
	if err != nil {
		t.Fatalf("read nginx config: %v", err)
	}
	if !strings.Contains(string(nginx), "ssl_certificate "+issuer.result.CertPath+";") {
		t.Fatalf("nginx config missing ACME cert path:\n%s", nginx)
	}
	if got, want := reloader.services, []string{"nginx"}; !slices.Equal(got, want) {
		t.Fatalf("reloaded services = %#v, want %#v", got, want)
	}
}

func TestACMECertificateProvisionerRejectsInvalidIssuerResult(t *testing.T) {
	tmp := t.TempDir()
	paths := SitePathConfig{
		HomeRoot:          filepath.Join(tmp, "home"),
		NginxAvailableDir: filepath.Join(tmp, "etc", "nginx", "sites-available"),
		NginxEnabledDir:   filepath.Join(tmp, "etc", "nginx", "sites-enabled"),
		NginxLogDir:       filepath.Join(tmp, "var", "log", "nginx"),
		PHPFPMPoolDir:     filepath.Join(tmp, "etc", "php", "8.3", "fpm", "pool.d"),
		PHPFPMLogDir:      filepath.Join(tmp, "var", "log", "php-fpm"),
		PHPRunDir:         filepath.Join(tmp, "run", "php"),
		NginxSnippet:      "snippets/fastcgi-php.conf",
		WWWGroup:          "www-data",
		PHPTmpDir:         filepath.Join(tmp, "tmp"),
		DefaultFileMode:   0o644,
	}
	reloader := &recordingReloader{}
	issuer := &fakeACMEIssuer{
		result: ACMEIssueResult{
			KeyPath:   filepath.Join(tmp, "var", "lib", "nakpanel", "certs", "example.test", "privkey.pem"),
			ExpiresAt: mustParseTime(t, "2026-10-01T00:00:00Z"),
		},
	}
	provisioner := NewCertificateProvisioner(CertificateProvisionerOptions{
		Paths:      paths,
		CertRoot:   filepath.Join(tmp, "var", "lib", "nakpanel", "certs"),
		Reloader:   reloader,
		ACMEIssuer: issuer,
	})

	_, err := provisioner.IssueCert(context.Background(), types.IssueCertReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
		Issuer:     types.CertIssuerACME,
	})
	if err == nil {
		t.Fatal("IssueCert returned nil error")
	}
	if !strings.Contains(err.Error(), "missing certificate path") {
		t.Fatalf("IssueCert error = %q, want missing certificate path", err.Error())
	}
	if got, want := reloader.services, []string{"nginx"}; !slices.Equal(got, want) {
		t.Fatalf("rollback reloads = %#v, want %#v", got, want)
	}
	if _, err := os.Stat(filepath.Join(paths.NginxAvailableDir, "example.test.conf")); !os.IsNotExist(err) {
		t.Fatalf("nginx config was written or stat failed: %v", err)
	}
}

func TestCertificateProvisionerRestoresVHostAndCertificateOnReloadFailure(t *testing.T) {
	tmp := t.TempDir()
	paths := SitePathConfig{
		HomeRoot: filepath.Join(tmp, "home"), NginxAvailableDir: filepath.Join(tmp, "available"), NginxEnabledDir: filepath.Join(tmp, "enabled"),
		NginxLogDir: filepath.Join(tmp, "logs"), PHPFPMPoolDir: filepath.Join(tmp, "php"), PHPFPMLogDir: filepath.Join(tmp, "php-logs"),
		PHPRunDir: filepath.Join(tmp, "run"), NginxSnippet: "snippets/fastcgi-php.conf", WWWGroup: "www-data", PHPTmpDir: filepath.Join(tmp, "tmp"), DefaultFileMode: 0o644,
	}
	certRoot := filepath.Join(tmp, "certs")
	plan, err := NewSitePlan(types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3"}, paths)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(certRoot, "example.test", "fullchain.pem")
	keyPath := filepath.Join(certRoot, "example.test", "privkey.pem")
	for path, contents := range map[string]string{plan.NginxConfig: "old nginx\n", certPath: "old cert\n", keyPath: "old key\n"} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := NewCertificateProvisioner(CertificateProvisionerOptions{Paths: paths, CertRoot: certRoot, Reloader: &failingServiceReloader{failService: "nginx"}})
	if _, err := p.IssueCert(context.Background(), types.IssueCertReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", Issuer: types.CertIssuerLocalSelfSigned}); err == nil {
		t.Fatal("IssueCert returned nil, want reload failure")
	}
	for path, want := range map[string]string{plan.NginxConfig: "old nginx\n", certPath: "old cert\n", keyPath: "old key\n"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("restored %s = %q, %v; want %q", path, got, err, want)
		}
	}
}

func mustParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}
