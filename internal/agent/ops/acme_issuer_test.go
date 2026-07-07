package ops

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

type fakeACMEProtocolClient struct {
	registered bool
	accepted   bool
	csrDomain  string
	onAccept   func()
	certDER    []byte
}

func (c *fakeACMEProtocolClient) Register(ctx context.Context) error {
	c.registered = true
	return nil
}

func (c *fakeACMEProtocolClient) AuthorizeOrder(ctx context.Context, domain string) (*acme.Order, error) {
	return &acme.Order{
		URI:         "order-url",
		Status:      acme.StatusPending,
		AuthzURLs:   []string{"authz-url"},
		FinalizeURL: "finalize-url",
	}, nil
}

func (c *fakeACMEProtocolClient) GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	return &acme.Authorization{
		URI:    url,
		Status: acme.StatusPending,
		Challenges: []*acme.Challenge{
			{Type: "dns-01", Token: "dns-token", URI: "dns-challenge-url"},
			{Type: "http-01", Token: "http-token", URI: "http-challenge-url"},
		},
	}, nil
}

func (c *fakeACMEProtocolClient) HTTP01ChallengePath(token string) string {
	return "/.well-known/acme-challenge/" + token
}

func (c *fakeACMEProtocolClient) HTTP01ChallengeResponse(token string) (string, error) {
	return token + ".key-auth", nil
}

func (c *fakeACMEProtocolClient) Accept(ctx context.Context, challenge *acme.Challenge) (*acme.Challenge, error) {
	c.accepted = true
	if c.onAccept != nil {
		c.onAccept()
	}
	return challenge, nil
}

func (c *fakeACMEProtocolClient) WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	return &acme.Authorization{URI: url, Status: acme.StatusValid}, nil
}

func (c *fakeACMEProtocolClient) WaitOrder(ctx context.Context, url string) (*acme.Order, error) {
	return &acme.Order{URI: url, Status: acme.StatusReady, FinalizeURL: "finalize-url"}, nil
}

func (c *fakeACMEProtocolClient) CreateOrderCert(ctx context.Context, finalizeURL string, csrDER []byte, bundle bool) ([][]byte, string, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, "", err
	}
	if len(csr.DNSNames) > 0 {
		c.csrDomain = csr.DNSNames[0]
	}
	return [][]byte{c.certDER}, "cert-url", nil
}

func TestACMEHTTP01IssuerCompletesChallengeAndWritesCertificate(t *testing.T) {
	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "home", "npdemo", "public_html")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("create docroot: %v", err)
	}
	expiresAt := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	client := &fakeACMEProtocolClient{
		certDER: testCertificateDER(t, "example.test", expiresAt),
	}
	challengeFile := filepath.Join(docroot, ".well-known", "acme-challenge", "http-token")
	client.onAccept = func() {
		got, err := os.ReadFile(challengeFile)
		if err != nil {
			t.Fatalf("read challenge file during Accept: %v", err)
		}
		if string(got) != "http-token.key-auth" {
			t.Fatalf("challenge file = %q, want key authorization", got)
		}
	}
	issuer := NewACMEHTTP01Issuer(ACMEHTTP01IssuerOptions{Client: client})
	certPath := filepath.Join(tmp, "var", "lib", "nakpanel", "certs", "example.test", "fullchain.pem")
	keyPath := filepath.Join(tmp, "var", "lib", "nakpanel", "certs", "example.test", "privkey.pem")

	result, err := issuer.Issue(context.Background(), ACMEIssueRequest{
		Domain:   "example.test",
		Docroot:  docroot,
		CertPath: certPath,
		KeyPath:  keyPath,
	})
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if !client.registered || !client.accepted {
		t.Fatalf("ACME client registered=%v accepted=%v, want both true", client.registered, client.accepted)
	}
	if client.csrDomain != "example.test" {
		t.Fatalf("CSR domain = %q, want example.test", client.csrDomain)
	}
	if result.CertPath != certPath || result.KeyPath != keyPath || !result.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("result = %#v, want requested paths and cert expiry", result)
	}
	if _, err := os.Stat(challengeFile); !os.IsNotExist(err) {
		t.Fatalf("challenge file still exists or stat failed: %v", err)
	}

	certPEM, err := os.ReadFile(certPath)
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

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if got, want := keyInfo.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("key mode = %o, want %o", got, want)
	}
}

func testCertificateDER(t *testing.T, domain string, expiresAt time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    expiresAt.Add(-90 * 24 * time.Hour),
		NotAfter:     expiresAt,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    expiresAt.Add(-90 * 24 * time.Hour),
		NotAfter:     expiresAt,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return certDER
}
