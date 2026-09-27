package paneltls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	certFileName    = "panel.crt"
	keyFileName     = "panel.key"
	managedFileName = "panel.pem"
)

// SelectPanelCertificate uses the managed hostname certificate when present.
// A malformed managed certificate is fatal instead of silently downgrading to
// the bootstrap certificate.
func SelectPanelCertificate(dir, hostname string) (string, string, error) {
	return selectPanelCertificate(dir, hostname, nil)
}

func selectPanelCertificate(dir, hostname string, roots *x509.CertPool) (string, string, error) {
	if hostname == "" {
		return EnsureSelfSigned(dir)
	}
	managed := filepath.Join(dir, managedFileName)
	info, err := os.Lstat(managed)
	if os.IsNotExist(err) {
		return EnsureSelfSigned(dir)
	}
	if err != nil {
		return "", "", fmt.Errorf("inspect managed panel certificate: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", "", fmt.Errorf("managed panel certificate must be a private regular file")
	}
	pair, err := tls.LoadX509KeyPair(managed, managed)
	if err != nil {
		return "", "", fmt.Errorf("load managed panel certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", "", fmt.Errorf("parse managed panel certificate: %w", err)
	}
	if err := leaf.VerifyHostname(hostname); err != nil {
		return "", "", fmt.Errorf("managed panel certificate hostname: %w", err)
	}
	if roots == nil {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return "", "", fmt.Errorf("load system trust store: %w", err)
		}
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return "", "", fmt.Errorf("parse managed certificate chain: %w", err)
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: hostname, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return "", "", fmt.Errorf("verify managed panel certificate: %w", err)
	}
	return managed, managed, nil
}

func EnsureSelfSigned(dir string) (string, string, error) {
	certFile := filepath.Join(dir, certFileName)
	keyFile := filepath.Join(dir, keyFileName)

	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		return certFile, keyFile, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("create TLS directory: %w", err)
	}

	certPEM, keyPEM, err := generateSelfSigned()
	if err != nil {
		return "", "", err
	}

	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write TLS key: %w", err)
	}
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("write TLS certificate: %w", err)
	}

	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return "", "", fmt.Errorf("load generated TLS certificate: %w", err)
	}

	return certFile, keyFile, nil
}

func generateSelfSigned() ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate TLS private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate TLS serial number: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "nakpanel self-signed panel certificate",
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create self-signed TLS certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal TLS private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
