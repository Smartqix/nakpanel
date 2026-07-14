package certificates

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	MaxPEMBytes    = 256 << 10
	MaxBundleBytes = 512 << 10
)

type Bundle struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	ChainPEM       []byte
}

type Result struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	ChainPEM       []byte
	FullChainPEM   []byte
	Leaf           *x509.Certificate
}

type Validator struct {
	Roots *x509.CertPool
	Now   func() time.Time
}

func Validate(domain string, bundle Bundle) (Result, error) {
	return (Validator{}).Validate(domain, bundle)
}

func (v Validator) Validate(domain string, bundle Bundle) (Result, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return Result{}, errors.New("certificate domain is required")
	}
	if len(bundle.CertificatePEM) == 0 || len(bundle.PrivateKeyPEM) == 0 {
		return Result{}, errors.New("certificate and private key are required")
	}
	if len(bundle.CertificatePEM) > MaxPEMBytes || len(bundle.PrivateKeyPEM) > MaxPEMBytes || len(bundle.ChainPEM) > MaxPEMBytes {
		return Result{}, errors.New("each certificate upload must be 256 KiB or smaller")
	}
	if len(bundle.CertificatePEM)+len(bundle.PrivateKeyPEM)+len(bundle.ChainPEM) > MaxBundleBytes {
		return Result{}, errors.New("certificate bundle must be 512 KiB or smaller")
	}

	leafCerts, leafPEM, err := parseCertificates(bundle.CertificatePEM)
	if err != nil {
		return Result{}, fmt.Errorf("parse leaf certificate: %w", err)
	}
	if len(leafCerts) != 1 {
		return Result{}, errors.New("leaf certificate input must contain exactly one certificate")
	}
	chainCerts, chainPEM, err := parseOptionalCertificates(bundle.ChainPEM)
	if err != nil {
		return Result{}, fmt.Errorf("parse certificate chain: %w", err)
	}
	privateKey, keyPEM, err := parsePrivateKey(bundle.PrivateKeyPEM)
	if err != nil {
		return Result{}, err
	}

	leaf := leafCerts[0]
	if err := matchingPublicKey(leaf, privateKey); err != nil {
		return Result{}, err
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	if now.Before(leaf.NotBefore) {
		return Result{}, fmt.Errorf("certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return Result{}, fmt.Errorf("certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if err := verifyDomain(leaf, domain); err != nil {
		return Result{}, err
	}

	roots := v.Roots
	if roots == nil {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return Result{}, fmt.Errorf("load system certificate roots: %w", err)
		}
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chainCerts {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return Result{}, fmt.Errorf("verify certificate chain: %w", err)
	}

	fullchain := append(append([]byte(nil), leafPEM...), chainPEM...)
	return Result{
		CertificatePEM: leafPEM,
		PrivateKeyPEM:  keyPEM,
		ChainPEM:       chainPEM,
		FullChainPEM:   fullchain,
		Leaf:           leaf,
	}, nil
}

func parseOptionalCertificates(data []byte) ([]*x509.Certificate, []byte, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil, nil
	}
	return parseCertificates(data)
}

func parseCertificates(data []byte) ([]*x509.Certificate, []byte, error) {
	var certificates []*x509.Certificate
	var normalized []byte
	rest := data
	for len(bytes.TrimSpace(rest)) > 0 {
		block, next := pem.Decode(rest)
		if block == nil {
			return nil, nil, errors.New("malformed PEM data")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certificates = append(certificates, certificate)
		normalized = append(normalized, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
		rest = next
	}
	if len(certificates) == 0 {
		return nil, nil, errors.New("no certificates found")
	}
	return certificates, normalized, nil
}

func parsePrivateKey(data []byte) (any, []byte, error) {
	var keyBlock *pem.Block
	seenECParameters := false
	rest := data
	for len(bytes.TrimSpace(rest)) > 0 {
		block, next := pem.Decode(rest)
		if block == nil {
			return nil, nil, errors.New("malformed private key PEM data")
		}
		if x509.IsEncryptedPEMBlock(block) || block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["Proc-Type"] != "" {
			return nil, nil, errors.New("encrypted private keys are not supported")
		}
		switch block.Type {
		case "EC PARAMETERS":
			if seenECParameters || keyBlock != nil || len(block.Headers) != 0 {
				return nil, nil, errors.New("private key contains unexpected EC parameters")
			}
			var curve asn1.ObjectIdentifier
			trailing, err := asn1.Unmarshal(block.Bytes, &curve)
			if err != nil || len(trailing) != 0 || len(curve) == 0 {
				return nil, nil, errors.New("invalid EC parameters")
			}
			seenECParameters = true
		case "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY":
			if keyBlock != nil || len(block.Headers) != 0 {
				return nil, nil, errors.New("private key must contain exactly one key block")
			}
			keyBlock = block
		default:
			return nil, nil, fmt.Errorf("unsupported private key PEM block %q", block.Type)
		}
		rest = next
	}
	if keyBlock == nil {
		return nil, nil, errors.New("private key PEM block is missing")
	}
	var key any
	var err error
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
	default:
		return nil, nil, errors.New("only RSA and ECDSA private keys are supported")
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: keyBlock.Type, Bytes: keyBlock.Bytes}), nil
}

func matchingPublicKey(certificate *x509.Certificate, privateKey any) error {
	var publicKey any
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &key.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &key.PublicKey
	default:
		return errors.New("unsupported private key")
	}
	certDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal certificate public key: %w", err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("marshal private-key public key: %w", err)
	}
	if !bytes.Equal(certDER, keyDER) {
		return errors.New("private key does not match certificate")
	}
	return nil
}

func verifyDomain(certificate *x509.Certificate, domain string) error {
	if len(certificate.DNSNames) > 0 {
		if err := certificate.VerifyHostname(domain); err != nil {
			return fmt.Errorf("certificate does not cover %q: %w", domain, err)
		}
		return nil
	}
	commonName := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(certificate.Subject.CommonName), "."))
	if commonName == "" || !matchDNSName(commonName, domain) {
		return fmt.Errorf("certificate common name does not cover %q", domain)
	}
	return nil
}

func matchDNSName(pattern, domain string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if pattern == domain {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") || strings.Count(pattern, "*") != 1 {
		return false
	}
	suffix := strings.TrimPrefix(pattern, "*.")
	return strings.HasSuffix(domain, "."+suffix) && strings.Count(domain, ".") == strings.Count(suffix, ".")+1
}
