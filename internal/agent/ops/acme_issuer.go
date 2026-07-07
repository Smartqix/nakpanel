package ops

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	defaultACMEAccountKeyPath = "/var/lib/nakpanel/acme/account.key"
	http01ChallengePrefix     = "/.well-known/acme-challenge/"
)

type ACMEProtocolClient interface {
	Register(ctx context.Context) error
	AuthorizeOrder(ctx context.Context, domain string) (*acme.Order, error)
	GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	HTTP01ChallengePath(token string) string
	HTTP01ChallengeResponse(token string) (string, error)
	Accept(ctx context.Context, challenge *acme.Challenge) (*acme.Challenge, error)
	WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	WaitOrder(ctx context.Context, url string) (*acme.Order, error)
	CreateOrderCert(ctx context.Context, finalizeURL string, csrDER []byte, bundle bool) ([][]byte, string, error)
}

type ACMEHTTP01IssuerOptions struct {
	Client         ACMEProtocolClient
	DirectoryURL   string
	AccountKeyPath string
	Email          string
}

type ACMEHTTP01Issuer struct {
	client         ACMEProtocolClient
	directoryURL   string
	accountKeyPath string
	email          string
}

func NewACMEHTTP01Issuer(opts ACMEHTTP01IssuerOptions) *ACMEHTTP01Issuer {
	accountKeyPath := opts.AccountKeyPath
	if accountKeyPath == "" {
		accountKeyPath = defaultACMEAccountKeyPath
	}
	return &ACMEHTTP01Issuer{
		client:         opts.Client,
		directoryURL:   opts.DirectoryURL,
		accountKeyPath: accountKeyPath,
		email:          strings.TrimSpace(opts.Email),
	}
}

func (i *ACMEHTTP01Issuer) Issue(ctx context.Context, req ACMEIssueRequest) (ACMEIssueResult, error) {
	if req.Domain == "" {
		return ACMEIssueResult{}, errors.New("domain is required")
	}
	if req.Docroot == "" {
		return ACMEIssueResult{}, errors.New("docroot is required")
	}
	if req.CertPath == "" || req.KeyPath == "" {
		return ACMEIssueResult{}, errors.New("certificate and key paths are required")
	}

	client := i.client
	if client == nil {
		created, err := i.newRealClient()
		if err != nil {
			return ACMEIssueResult{}, err
		}
		client = created
	}
	if err := client.Register(ctx); err != nil {
		return ACMEIssueResult{}, fmt.Errorf("register acme account: %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, req.Domain)
	if err != nil {
		return ACMEIssueResult{}, fmt.Errorf("authorize acme order: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		if err := i.completeHTTP01Authorization(ctx, client, req.Docroot, authzURL); err != nil {
			return ACMEIssueResult{}, err
		}
	}
	if order.URI != "" {
		order, err = client.WaitOrder(ctx, order.URI)
		if err != nil {
			return ACMEIssueResult{}, fmt.Errorf("wait acme order: %w", err)
		}
	}
	if order.FinalizeURL == "" {
		return ACMEIssueResult{}, errors.New("acme order is missing finalize URL")
	}

	certKey, keyPEM, err := generateCertificateKey()
	if err != nil {
		return ACMEIssueResult{}, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: req.Domain},
		DNSNames: []string{req.Domain},
	}, certKey)
	if err != nil {
		return ACMEIssueResult{}, fmt.Errorf("create certificate request: %w", err)
	}
	certsDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return ACMEIssueResult{}, fmt.Errorf("create acme certificate: %w", err)
	}
	certPEM, expiresAt, err := encodeCertificateChain(certsDER, req.Domain)
	if err != nil {
		return ACMEIssueResult{}, err
	}

	if err := writeFileAtomic(req.CertPath, certPEM, 0o644); err != nil {
		return ACMEIssueResult{}, fmt.Errorf("write acme certificate: %w", err)
	}
	if err := writeFileAtomic(req.KeyPath, keyPEM, 0o600); err != nil {
		return ACMEIssueResult{}, fmt.Errorf("write acme certificate key: %w", err)
	}
	return ACMEIssueResult{CertPath: req.CertPath, KeyPath: req.KeyPath, ExpiresAt: expiresAt}, nil
}

func (i *ACMEHTTP01Issuer) completeHTTP01Authorization(ctx context.Context, client ACMEProtocolClient, docroot, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("get acme authorization: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil
	}
	challenge := findHTTP01Challenge(authz)
	if challenge == nil {
		return errors.New("acme authorization has no http-01 challenge")
	}
	keyAuthorization, err := client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return fmt.Errorf("build http-01 challenge response: %w", err)
	}
	challengeFile, err := http01ChallengeFile(docroot, client.HTTP01ChallengePath(challenge.Token))
	if err != nil {
		return err
	}
	if err := writeFileAtomic(challengeFile, []byte(keyAuthorization), 0o644); err != nil {
		return fmt.Errorf("write http-01 challenge: %w", err)
	}
	defer os.Remove(challengeFile)

	if _, err := client.Accept(ctx, challenge); err != nil {
		return fmt.Errorf("accept http-01 challenge: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
		return fmt.Errorf("wait http-01 authorization: %w", err)
	}
	return nil
}

func (i *ACMEHTTP01Issuer) newRealClient() (ACMEProtocolClient, error) {
	key, err := loadOrCreateACMEAccountKey(i.accountKeyPath)
	if err != nil {
		return nil, err
	}
	return &realACMEProtocolClient{
		client: &acme.Client{
			Key:          key,
			DirectoryURL: i.directoryURL,
			UserAgent:    "nakpanel",
		},
		email: i.email,
	}, nil
}

func findHTTP01Challenge(authz *acme.Authorization) *acme.Challenge {
	for _, challenge := range authz.Challenges {
		if challenge.Type == "http-01" {
			return challenge
		}
	}
	return nil
}

func http01ChallengeFile(docroot, challengePath string) (string, error) {
	cleaned := filepath.ToSlash(filepath.Clean("/" + strings.TrimPrefix(challengePath, "/")))
	if !strings.HasPrefix(cleaned, http01ChallengePrefix) {
		return "", fmt.Errorf("unexpected http-01 challenge path %q", challengePath)
	}
	return filepath.Join(docroot, filepath.FromSlash(strings.TrimPrefix(cleaned, "/"))), nil
}

func generateCertificateKey() (crypto.Signer, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate acme certificate key: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal acme certificate key: %w", err)
	}
	return privateKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

func encodeCertificateChain(certsDER [][]byte, domain string) ([]byte, time.Time, error) {
	if len(certsDER) == 0 {
		return nil, time.Time{}, errors.New("acme response did not include a certificate")
	}
	leaf, err := x509.ParseCertificate(certsDER[0])
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse acme leaf certificate: %w", err)
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, time.Time{}, fmt.Errorf("acme certificate does not match domain %q: %w", domain, err)
	}

	var certPEM []byte
	for _, certDER := range certsDER {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	}
	return certPEM, leaf.NotAfter, nil
}

func loadOrCreateACMEAccountKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return parseACMEAccountKey(data)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read acme account key: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate acme account key: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal acme account key: %w", err)
	}
	if err := writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, fmt.Errorf("write acme account key: %w", err)
	}
	return key, nil
}

func parseACMEAccountKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("acme account key is not PEM encoded")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse acme EC account key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse acme PKCS8 account key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("acme PKCS8 account key is not a signing key")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported acme account key type %q", block.Type)
	}
}

type realACMEProtocolClient struct {
	client *acme.Client
	email  string
}

func (c *realACMEProtocolClient) Register(ctx context.Context) error {
	account := &acme.Account{}
	if c.email != "" {
		account.Contact = []string{"mailto:" + c.email}
	}
	_, err := c.client.Register(ctx, account, acme.AcceptTOS)
	if err == nil || errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil
	}
	var acmeErr *acme.Error
	if errors.As(err, &acmeErr) && acmeErr.StatusCode == http.StatusConflict {
		return nil
	}
	return err
}

func (c *realACMEProtocolClient) AuthorizeOrder(ctx context.Context, domain string) (*acme.Order, error) {
	return c.client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
}

func (c *realACMEProtocolClient) GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	return c.client.GetAuthorization(ctx, url)
}

func (c *realACMEProtocolClient) HTTP01ChallengePath(token string) string {
	return c.client.HTTP01ChallengePath(token)
}

func (c *realACMEProtocolClient) HTTP01ChallengeResponse(token string) (string, error) {
	return c.client.HTTP01ChallengeResponse(token)
}

func (c *realACMEProtocolClient) Accept(ctx context.Context, challenge *acme.Challenge) (*acme.Challenge, error) {
	return c.client.Accept(ctx, challenge)
}

func (c *realACMEProtocolClient) WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	return c.client.WaitAuthorization(ctx, url)
}

func (c *realACMEProtocolClient) WaitOrder(ctx context.Context, url string) (*acme.Order, error) {
	return c.client.WaitOrder(ctx, url)
}

func (c *realACMEProtocolClient) CreateOrderCert(ctx context.Context, finalizeURL string, csrDER []byte, bundle bool) ([][]byte, string, error) {
	return c.client.CreateOrderCert(ctx, finalizeURL, csrDER, bundle)
}
