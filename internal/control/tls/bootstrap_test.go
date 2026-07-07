package paneltls

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
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
