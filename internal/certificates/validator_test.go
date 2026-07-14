package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

type testChain struct {
	bundle Bundle
	roots  *x509.CertPool
	now    time.Time
	key    *ecdsa.PrivateKey
}

func TestValidatorAcceptsTrustedWildcardAndCNFallback(t *testing.T) {
	t.Parallel()
	chain := newTestChain(t, "*.example.test", []string{"*.example.test"}, 24*time.Hour)
	result, err := (Validator{Roots: chain.roots, Now: func() time.Time { return chain.now }}).Validate("www.example.test", chain.bundle)
	if err != nil {
		t.Fatalf("Validate wildcard: %v", err)
	}
	if result.Leaf.Subject.CommonName != "*.example.test" || !strings.Contains(string(result.FullChainPEM), "BEGIN CERTIFICATE") {
		t.Fatalf("unexpected result: %#v", result.Leaf.Subject)
	}

	cnOnly := newTestChain(t, "legacy.example.test", nil, 24*time.Hour)
	if _, err := (Validator{Roots: cnOnly.roots, Now: func() time.Time { return cnOnly.now }}).Validate("legacy.example.test", cnOnly.bundle); err != nil {
		t.Fatalf("Validate CN fallback: %v", err)
	}
}

func TestValidatorRejectsMismatchedKeyAndWrongDomain(t *testing.T) {
	t.Parallel()
	chain := newTestChain(t, "www.example.test", []string{"www.example.test"}, 24*time.Hour)
	other := newTestChain(t, "www.example.test", []string{"www.example.test"}, 24*time.Hour)
	chain.bundle.PrivateKeyPEM = other.bundle.PrivateKeyPEM
	if _, err := (Validator{Roots: chain.roots, Now: func() time.Time { return chain.now }}).Validate("www.example.test", chain.bundle); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key error = %v", err)
	}

	chain = newTestChain(t, "www.example.test", []string{"www.example.test"}, 24*time.Hour)
	if _, err := (Validator{Roots: chain.roots, Now: func() time.Time { return chain.now }}).Validate("other.example.test", chain.bundle); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("wrong domain error = %v", err)
	}
}

func TestValidatorRejectsExpiredFutureIncompleteAndUntrusted(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		shift time.Duration
		want  string
	}{
		"expired": {-48 * time.Hour, "expired"},
		"future":  {48 * time.Hour, "not valid before"},
	} {
		t.Run(name, func(t *testing.T) {
			chain := newTestChainAt(t, "www.example.test", []string{"www.example.test"}, test.shift)
			if _, err := (Validator{Roots: chain.roots, Now: func() time.Time { return chain.now }}).Validate("www.example.test", chain.bundle); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}

	chain := newTestChain(t, "www.example.test", []string{"www.example.test"}, 24*time.Hour)
	chain.bundle.ChainPEM = nil
	if _, err := (Validator{Roots: chain.roots, Now: func() time.Time { return chain.now }}).Validate("www.example.test", chain.bundle); err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("incomplete chain error = %v", err)
	}

	chain = newTestChain(t, "www.example.test", []string{"www.example.test"}, 24*time.Hour)
	untrusted := newTestChain(t, "other.example.test", []string{"other.example.test"}, 24*time.Hour)
	if _, err := (Validator{Roots: untrusted.roots, Now: func() time.Time { return chain.now }}).Validate("www.example.test", chain.bundle); err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("untrusted chain error = %v", err)
	}
}

func TestValidatorRejectsMalformedAndEncryptedKey(t *testing.T) {
	t.Parallel()
	chain := newTestChain(t, "www.example.test", []string{"www.example.test"}, 24*time.Hour)
	malformed := chain.bundle
	malformed.CertificatePEM = []byte("not pem")
	if _, err := (Validator{Roots: chain.roots}).Validate("www.example.test", malformed); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed error = %v", err)
	}
	der, err := x509.MarshalECPrivateKey(chain.key)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", der, []byte("secret"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	chain.bundle.PrivateKeyPEM = pem.EncodeToMemory(encrypted)
	if _, err := (Validator{Roots: chain.roots}).Validate("www.example.test", chain.bundle); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("encrypted key error = %v", err)
	}
}

func TestValidatorAcceptsOpenSSLECParametersAndRejectsExtraBlocks(t *testing.T) {
	t.Parallel()
	chain := newTestChain(t, "www.example.test", []string{"www.example.test"}, 24*time.Hour)
	parameters, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	if err != nil {
		t.Fatal(err)
	}
	chain.bundle.PrivateKeyPEM = append(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: parameters}), chain.bundle.PrivateKeyPEM...)
	result, err := (Validator{Roots: chain.roots, Now: func() time.Time { return chain.now }}).Validate("www.example.test", chain.bundle)
	if err != nil {
		t.Fatalf("Validate OpenSSL EC key: %v", err)
	}
	if strings.Contains(string(result.PrivateKeyPEM), "EC PARAMETERS") {
		t.Fatal("normalized private key retained the EC parameters block")
	}

	chain.bundle.PrivateKeyPEM = append(chain.bundle.PrivateKeyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("extra")})...)
	if _, err := (Validator{Roots: chain.roots}).Validate("www.example.test", chain.bundle); err == nil || !strings.Contains(err.Error(), "unsupported private key PEM block") {
		t.Fatalf("extra key block error = %v", err)
	}
}

func newTestChain(t *testing.T, commonName string, dnsNames []string, validity time.Duration) testChain {
	t.Helper()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	return buildTestChain(t, commonName, dnsNames, now.Add(-time.Hour), now.Add(validity), now)
}

func newTestChainAt(t *testing.T, commonName string, dnsNames []string, shift time.Duration) testChain {
	t.Helper()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	return buildTestChain(t, commonName, dnsNames, now.Add(shift), now.Add(shift+24*time.Hour), now)
}

func buildTestChain(t *testing.T, commonName string, dnsNames []string, notBefore, notAfter, now time.Time) testChain {
	t.Helper()
	rootKey := generateKey(t)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Nakpanel Test Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER := createCertificate(t, root, root, &rootKey.PublicKey, rootKey)
	rootCert := parseCertificate(t, rootDER)

	intermediateKey := generateKey(t)
	intermediate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Nakpanel Test Intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(180 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	intermediateDER := createCertificate(t, intermediate, rootCert, &intermediateKey.PublicKey, rootKey)
	intermediateCert := parseCertificate(t, intermediateDER)

	leafKey := generateKey(t)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames, NotBefore: notBefore, NotAfter: notAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER := createCertificate(t, leaf, intermediateCert, &leafKey.PublicKey, intermediateKey)
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	return testChain{now: now, roots: roots, key: leafKey, bundle: Bundle{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		ChainPEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER}),
	}}
}

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func createCertificate(t *testing.T, template, parent *x509.Certificate, publicKey any, signer any) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func parseCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
