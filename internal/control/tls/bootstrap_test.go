package paneltls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureSelfSignedCreatesReusableCertificate(t *testing.T) {
	dir := t.TempDir()

	certFile, keyFile, err := EnsureSelfSigned(dir)
	if err != nil {
		t.Fatalf("EnsureSelfSigned returned error: %v", err)
	}

	if certFile != filepath.Join(dir, "panel.crt") {
		t.Fatalf("certFile = %q, want panel.crt in temp dir", certFile)
	}
	if keyFile != filepath.Join(dir, "panel.key") {
		t.Fatalf("keyFile = %q, want panel.key in temp dir", keyFile)
	}

	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("LoadX509KeyPair returned error: %v", err)
	}

	certFileAgain, keyFileAgain, err := EnsureSelfSigned(dir)
	if err != nil {
		t.Fatalf("second EnsureSelfSigned returned error: %v", err)
	}
	if certFileAgain != certFile || keyFileAgain != keyFile {
		t.Fatalf("second paths = %q/%q, want %q/%q", certFileAgain, keyFileAgain, certFile, keyFile)
	}

	certBytesAgain, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert again: %v", err)
	}
	keyBytesAgain, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read key again: %v", err)
	}

	if string(certBytesAgain) != string(certBytes) {
		t.Fatal("certificate changed on second EnsureSelfSigned call")
	}
	if string(keyBytesAgain) != string(keyBytes) {
		t.Fatal("private key changed on second EnsureSelfSigned call")
	}
}

func TestEnsureSelfSignedCreatesUsableSelfSignedLeaf(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, err := EnsureSelfSigned(dir)
	if err != nil {
		t.Fatalf("EnsureSelfSigned returned error: %v", err)
	}

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair returned error: %v", err)
	}
	if len(pair.Certificate) == 0 {
		t.Fatal("loaded certificate chain is empty")
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate returned error: %v", err)
	}
	if !leaf.IsCA {
		t.Fatal("self-signed bootstrap certificate should be marked as a CA")
	}
	if leaf.Subject.CommonName != "nakpanel self-signed panel certificate" {
		t.Fatalf("CommonName = %q", leaf.Subject.CommonName)
	}
}

func TestSelectPanelCertificateUsesTrustedHostnamePEM(t *testing.T) {
	dir := t.TempDir()
	roots := writeTestPanelPEM(t, dir, "panel.example.test")
	certFile, keyFile, err := selectPanelCertificate(dir, "panel.example.test", roots)
	if err != nil {
		t.Fatal(err)
	}
	if certFile != filepath.Join(dir, "panel.pem") || keyFile != certFile {
		t.Fatalf("managed certificate paths = %q, %q", certFile, keyFile)
	}
}

func TestSelectPanelCertificateRejectsWrongHostnameAndMalformedPEM(t *testing.T) {
	dir := t.TempDir()
	roots := writeTestPanelPEM(t, dir, "panel.example.test")
	if _, _, err := selectPanelCertificate(dir, "other.example.test", roots); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "panel.pem"), []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := selectPanelCertificate(dir, "panel.example.test", roots); err == nil {
		t.Fatal("malformed managed certificate silently fell back to self-signed")
	}
}

func TestSelectPanelCertificateRejectsUntrustedOrReadablePEM(t *testing.T) {
	dir := t.TempDir()
	roots := writeTestPanelPEM(t, dir, "panel.example.test")
	if _, _, err := selectPanelCertificate(dir, "panel.example.test", x509.NewCertPool()); err == nil {
		t.Fatal("untrusted managed certificate accepted")
	}
	if err := os.Chmod(filepath.Join(dir, "panel.pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := selectPanelCertificate(dir, "panel.example.test", roots); err == nil {
		t.Fatal("group/world-readable managed private key accepted")
	}
}

func TestSelectPanelCertificateBootstrapsWhenManagedPEMIsMissing(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, err := selectPanelCertificate(dir, "panel.example.test", x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	if certFile != filepath.Join(dir, "panel.crt") || keyFile != filepath.Join(dir, "panel.key") {
		t.Fatalf("bootstrap certificate paths = %q, %q", certFile, keyFile)
	}
}

func writeTestPanelPEM(t *testing.T, dir, hostname string) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	if err := os.WriteFile(filepath.Join(dir, "panel.pem"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return roots
}
