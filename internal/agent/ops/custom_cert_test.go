package ops

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/certificates"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeNginxTester struct {
	called int
	err    error
}

type failOnceReloader struct{ calls int }

func (r *failOnceReloader) ReloadService(context.Context, string) error {
	r.calls++
	if r.calls == 1 {
		return errors.New("injected reload failure")
	}
	return nil
}

func (t *fakeNginxTester) TestNginxConfig(context.Context) error {
	t.called++
	return t.err
}

func TestInstallCustomCertWritesPrivateFilesAndTestsNginx(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	paths := customCertPaths(tmp)
	bundle, roots, now := trustedCustomBundle(t, "example.test")
	reloader := &recordingReloader{}
	tester := &fakeNginxTester{}
	provisioner := NewCertificateProvisioner(CertificateProvisionerOptions{
		Paths: paths, CertRoot: filepath.Join(tmp, "certs"), Reloader: reloader, NginxTester: tester,
		Validator: certificates.Validator{Roots: roots, Now: func() time.Time { return now }},
	})
	result, err := provisioner.InstallCustomCert(context.Background(), types.InstallCustomCertReq{
		Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", SharedAccount: true,
		CertificatePEM: string(bundle.CertificatePEM), PrivateKeyPEM: string(bundle.PrivateKeyPEM), ChainPEM: string(bundle.ChainPEM),
	})
	if err != nil {
		t.Fatalf("InstallCustomCert: %v", err)
	}
	if result.Issuer != types.CertIssuerCustom || result.Domain != "example.test" || tester.called != 1 {
		t.Fatalf("result=%#v tester.calls=%d", result, tester.called)
	}
	for _, path := range []string{result.CertPath, result.KeyPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode=%o, want 600", path, info.Mode().Perm())
		}
	}
	if info, err := os.Stat(filepath.Dir(result.KeyPath)); err != nil {
		t.Fatalf("stat certificate directory: %v", err)
	} else if info.Mode().Perm() != 0o700 {
		t.Fatalf("certificate directory mode = %o, want 700", info.Mode().Perm())
	}
}

func TestInstallCustomCertRollsBackOnNginxTestFailure(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	paths := customCertPaths(tmp)
	bundle, roots, now := trustedCustomBundle(t, "example.test")
	plan, err := NewSitePlan(types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", SharedAccount: true}, paths)
	if err != nil {
		t.Fatal(err)
	}
	certRoot := filepath.Join(tmp, "certs")
	certPath := filepath.Join(certRoot, "example.test", "fullchain.pem")
	keyPath := filepath.Join(certRoot, "example.test", "privkey.pem")
	for path, data := range map[string]string{plan.NginxConfig: "old nginx", certPath: "old cert", keyPath: "old key"} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reloader := &recordingReloader{}
	provisioner := NewCertificateProvisioner(CertificateProvisionerOptions{
		Paths: paths, CertRoot: certRoot, Reloader: reloader, NginxTester: &fakeNginxTester{err: errors.New("bad nginx")},
		Validator: certificates.Validator{Roots: roots, Now: func() time.Time { return now }},
	})
	_, err = provisioner.InstallCustomCert(context.Background(), types.InstallCustomCertReq{
		Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", SharedAccount: true,
		CertificatePEM: string(bundle.CertificatePEM), PrivateKeyPEM: string(bundle.PrivateKeyPEM),
	})
	if err == nil {
		t.Fatal("InstallCustomCert returned nil error")
	}
	for path, want := range map[string]string{plan.NginxConfig: "old nginx", certPath: "old cert", keyPath: "old key"} {
		got, readErr := os.ReadFile(path)
		if readErr != nil || string(got) != want {
			t.Fatalf("rollback %s = %q, %v; want %q", path, got, readErr, want)
		}
	}
	if len(reloader.services) != 1 || reloader.services[0] != "nginx" {
		t.Fatalf("rollback reloads = %#v", reloader.services)
	}
}

func TestInstallCustomCertRollsBackOnReloadFailure(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	paths := customCertPaths(tmp)
	bundle, roots, now := trustedCustomBundle(t, "example.test")
	plan, err := NewSitePlan(types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", SharedAccount: true}, paths)
	if err != nil {
		t.Fatal(err)
	}
	certRoot := filepath.Join(tmp, "certs")
	certPath := filepath.Join(certRoot, "example.test", "fullchain.pem")
	keyPath := filepath.Join(certRoot, "example.test", "privkey.pem")
	for path, data := range map[string]string{plan.NginxConfig: "old nginx", certPath: "old cert", keyPath: "old key"} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reloader := &failOnceReloader{}
	provisioner := NewCertificateProvisioner(CertificateProvisionerOptions{
		Paths: paths, CertRoot: certRoot, Reloader: reloader, NginxTester: &fakeNginxTester{},
		Validator: certificates.Validator{Roots: roots, Now: func() time.Time { return now }},
	})
	_, err = provisioner.InstallCustomCert(context.Background(), types.InstallCustomCertReq{
		Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", SharedAccount: true,
		CertificatePEM: string(bundle.CertificatePEM), PrivateKeyPEM: string(bundle.PrivateKeyPEM),
	})
	if err == nil || !strings.Contains(err.Error(), "injected reload failure") {
		t.Fatalf("reload failure error = %v", err)
	}
	for path, want := range map[string]string{plan.NginxConfig: "old nginx", certPath: "old cert", keyPath: "old key"} {
		got, readErr := os.ReadFile(path)
		if readErr != nil || string(got) != want {
			t.Fatalf("rollback %s = %q, %v; want %q", path, got, readErr, want)
		}
	}
	if reloader.calls != 2 {
		t.Fatalf("reload calls = %d, want failed apply plus rollback reload", reloader.calls)
	}
}

func TestInstallCustomCertRejectsMismatchedKeyBeforeWrite(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	bundle, roots, now := trustedCustomBundle(t, "example.test")
	other, _, _ := trustedCustomBundle(t, "example.test")
	bundle.PrivateKeyPEM = other.PrivateKeyPEM
	certRoot := filepath.Join(tmp, "certs")
	provisioner := NewCertificateProvisioner(CertificateProvisionerOptions{
		Paths: customCertPaths(tmp), CertRoot: certRoot, Reloader: &recordingReloader{}, NginxTester: &fakeNginxTester{},
		Validator: certificates.Validator{Roots: roots, Now: func() time.Time { return now }},
	})
	_, err := provisioner.InstallCustomCert(context.Background(), types.InstallCustomCertReq{
		Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", SharedAccount: true,
		CertificatePEM: string(bundle.CertificatePEM), PrivateKeyPEM: string(bundle.PrivateKeyPEM),
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key error = %v", err)
	}
	if _, statErr := os.Stat(certRoot); !os.IsNotExist(statErr) {
		t.Fatalf("certificate root exists after boundary validation failure: %v", statErr)
	}
}

func customCertPaths(tmp string) SitePathConfig {
	return SitePathConfig{
		HomeRoot: filepath.Join(tmp, "home"), NginxAvailableDir: filepath.Join(tmp, "nginx", "available"),
		NginxEnabledDir: filepath.Join(tmp, "nginx", "enabled"), NginxLogDir: filepath.Join(tmp, "log", "nginx"),
		PHPFPMPoolDir: filepath.Join(tmp, "php", "pool"), PHPFPMLogDir: filepath.Join(tmp, "log", "php"),
		PHPRunDir: filepath.Join(tmp, "run"), PHPTmpDir: filepath.Join(tmp, "tmp"),
		NginxSnippet: "snippets/fastcgi-php.conf", WWWGroup: "www-data", DefaultFileMode: 0o644,
	}
}

func trustedCustomBundle(t *testing.T, domain string) (certificates.Bundle, *x509.CertPool, time.Time) {
	t.Helper()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return certificates.Bundle{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, roots, now
}
