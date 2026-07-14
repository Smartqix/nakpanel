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
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/nakroteck/nakpanel/internal/certificates"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

type CertificateProvisionerOptions struct {
	Paths       SitePathConfig
	CertRoot    string
	Reloader    SiteServiceReloader
	Now         func() time.Time
	ACMEIssuer  ACMEIssuer
	NginxTester NginxConfigTester
	Validator   certificates.Validator
}

type CertificateProvisioner struct {
	paths       SitePathConfig
	certRoot    string
	reloader    SiteServiceReloader
	now         func() time.Time
	acmeIssuer  ACMEIssuer
	nginxTester NginxConfigTester
	validator   certificates.Validator
}

type ACMEIssueRequest struct {
	Domain   string
	Docroot  string
	CertPath string
	KeyPath  string
}

type ACMEIssueResult struct {
	CertPath  string
	KeyPath   string
	ExpiresAt time.Time
}

type ACMEIssuer interface {
	Issue(ctx context.Context, req ACMEIssueRequest) (ACMEIssueResult, error)
}

func NewCertificateProvisioner(opts CertificateProvisionerOptions) *CertificateProvisioner {
	certRoot := opts.CertRoot
	if certRoot == "" {
		certRoot = "/var/lib/nakpanel/certs"
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &CertificateProvisioner{
		paths:       opts.Paths,
		certRoot:    certRoot,
		reloader:    opts.Reloader,
		now:         now,
		acmeIssuer:  opts.ACMEIssuer,
		nginxTester: opts.NginxTester,
		validator:   opts.Validator,
	}
}

func ValidateIssueCertRequest(req types.IssueCertReq) error {
	normalized := NormalizeIssueCertRequest(req)
	if normalized.Issuer == "" {
		normalized.Issuer = types.CertIssuerLocalSelfSigned
	}
	switch normalized.Issuer {
	case types.CertIssuerLocalSelfSigned:
	case types.CertIssuerACME:
	default:
		return fmt.Errorf("unsupported certificate issuer %q", normalized.Issuer)
	}
	return site.ValidateCreateSiteRequest(site.NormalizeCreateSiteRequest(types.CreateSiteReq{
		Username:   normalized.Username,
		Domain:     normalized.Domain,
		PHPVersion: normalized.PHPVersion,
	}))
}

func NormalizeIssueCertRequest(req types.IssueCertReq) types.IssueCertReq {
	siteReq := site.NormalizeCreateSiteRequest(types.CreateSiteReq{
		Username:   req.Username,
		Domain:     req.Domain,
		PHPVersion: req.PHPVersion,
	})
	req.Username = siteReq.Username
	req.Domain = siteReq.Domain
	req.PHPVersion = siteReq.PHPVersion
	if req.Issuer == "" {
		req.Issuer = types.CertIssuerLocalSelfSigned
	}
	return req
}

func (p *CertificateProvisioner) IssueCert(ctx context.Context, req types.IssueCertReq) (types.IssueCertResult, error) {
	siteConfigMutationMu.Lock()
	defer siteConfigMutationMu.Unlock()

	req = NormalizeIssueCertRequest(req)
	if err := ValidateIssueCertRequest(req); err != nil {
		return types.IssueCertResult{}, err
	}
	if p.reloader == nil {
		return types.IssueCertResult{}, errors.New("service reloader is not configured")
	}

	plan, err := NewSitePlan(types.CreateSiteReq{
		Username:      req.Username,
		Domain:        req.Domain,
		PHPVersion:    req.PHPVersion,
		SharedAccount: req.SharedAccount,
		Limits:        req.Limits,
	}, p.paths)
	if err != nil {
		return types.IssueCertResult{}, err
	}

	certDir := filepath.Join(p.certRoot, req.Domain)
	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")
	snapshots, err := snapshotFiles([]string{plan.NginxConfig, plan.NginxEnabled, certPath, keyPath})
	if err != nil {
		return types.IssueCertResult{}, err
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		_ = restoreSnapshots(snapshots)
		_ = p.reloader.ReloadService(context.Background(), "nginx")
	}()
	expiresAt := time.Time{}
	switch req.Issuer {
	case types.CertIssuerLocalSelfSigned:
		expiresAt, err = p.writeSelfSignedCertificate(req.Domain, certPath, keyPath)
		if err != nil {
			return types.IssueCertResult{}, err
		}
	case types.CertIssuerACME:
		if p.acmeIssuer == nil {
			return types.IssueCertResult{}, errors.New("acme certificate issuer is not configured")
		}
		result, err := p.acmeIssuer.Issue(ctx, ACMEIssueRequest{
			Domain:   req.Domain,
			Docroot:  plan.Docroot,
			CertPath: certPath,
			KeyPath:  keyPath,
		})
		if err != nil {
			return types.IssueCertResult{}, err
		}
		if err := validateACMEIssueResult(result, certPath, keyPath); err != nil {
			return types.IssueCertResult{}, fmt.Errorf("invalid acme certificate result: %w", err)
		}
		certPath = result.CertPath
		keyPath = result.KeyPath
		expiresAt = result.ExpiresAt
	}

	if err := writeFileAtomic(plan.NginxConfig, []byte(RenderNginxTLSVHost(plan, certPath, keyPath)), plan.FileMode); err != nil {
		return types.IssueCertResult{}, fmt.Errorf("write nginx tls site config: %w", err)
	}
	if err := ensureSymlink(plan.NginxConfig, plan.NginxEnabled); err != nil {
		return types.IssueCertResult{}, fmt.Errorf("enable nginx tls site: %w", err)
	}
	if p.nginxTester != nil {
		if err := p.nginxTester.TestNginxConfig(ctx); err != nil {
			return types.IssueCertResult{}, err
		}
	}
	if err := p.reloader.ReloadService(ctx, "nginx"); err != nil {
		return types.IssueCertResult{}, err
	}
	committed = true

	return types.IssueCertResult{
		Domain:    req.Domain,
		Issuer:    req.Issuer,
		CertPath:  certPath,
		KeyPath:   keyPath,
		ExpiresAt: expiresAt,
	}, nil
}

func (p *CertificateProvisioner) InstallCustomCert(ctx context.Context, req types.InstallCustomCertReq) (result types.InstallCustomCertResult, err error) {
	siteConfigMutationMu.Lock()
	defer siteConfigMutationMu.Unlock()

	normalized := NormalizeIssueCertRequest(types.IssueCertReq{
		Username: req.Username, Domain: req.Domain, PHPVersion: req.PHPVersion,
		SharedAccount: req.SharedAccount, Limits: req.Limits, Issuer: types.CertIssuerLocalSelfSigned,
	})
	if err := ValidateIssueCertRequest(normalized); err != nil {
		return types.InstallCustomCertResult{}, err
	}
	if p.reloader == nil {
		return types.InstallCustomCertResult{}, errors.New("service reloader is not configured")
	}
	if p.nginxTester == nil {
		return types.InstallCustomCertResult{}, errors.New("nginx configuration tester is not configured")
	}
	validated, err := p.validator.Validate(normalized.Domain, certificates.Bundle{
		CertificatePEM: []byte(req.CertificatePEM), PrivateKeyPEM: []byte(req.PrivateKeyPEM), ChainPEM: []byte(req.ChainPEM),
	})
	if err != nil {
		return types.InstallCustomCertResult{}, err
	}
	plan, err := NewSitePlan(types.CreateSiteReq{
		Username: normalized.Username, Domain: normalized.Domain, PHPVersion: normalized.PHPVersion,
		SharedAccount: normalized.SharedAccount, Limits: normalized.Limits,
	}, p.paths)
	if err != nil {
		return types.InstallCustomCertResult{}, err
	}
	certDir := filepath.Join(p.certRoot, normalized.Domain)
	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")
	snapshots, err := snapshotFiles([]string{plan.NginxConfig, plan.NginxEnabled, certPath, keyPath})
	if err != nil {
		return types.InstallCustomCertResult{}, err
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if restoreErr := restoreSnapshots(snapshots); restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore certificate files: %w", restoreErr))
		}
		if reloadErr := p.reloader.ReloadService(context.Background(), "nginx"); reloadErr != nil {
			err = errors.Join(err, fmt.Errorf("reload restored nginx configuration: %w", reloadErr))
		}
	}()
	if err = os.MkdirAll(certDir, 0o700); err != nil {
		return types.InstallCustomCertResult{}, fmt.Errorf("create certificate directory: %w", err)
	}
	if err = os.Chmod(certDir, 0o700); err != nil {
		return types.InstallCustomCertResult{}, fmt.Errorf("secure certificate directory: %w", err)
	}
	if err = writeFileAtomic(certPath, validated.FullChainPEM, 0o600); err != nil {
		return types.InstallCustomCertResult{}, fmt.Errorf("write custom certificate: %w", err)
	}
	if err = writeFileAtomic(keyPath, validated.PrivateKeyPEM, 0o600); err != nil {
		return types.InstallCustomCertResult{}, fmt.Errorf("write custom private key: %w", err)
	}
	if err = writeFileAtomic(plan.NginxConfig, []byte(RenderNginxTLSVHost(plan, certPath, keyPath)), plan.FileMode); err != nil {
		return types.InstallCustomCertResult{}, fmt.Errorf("write nginx TLS site config: %w", err)
	}
	if err = ensureSymlink(plan.NginxConfig, plan.NginxEnabled); err != nil {
		return types.InstallCustomCertResult{}, fmt.Errorf("enable nginx TLS site: %w", err)
	}
	if err = p.nginxTester.TestNginxConfig(ctx); err != nil {
		return types.InstallCustomCertResult{}, err
	}
	if err = p.reloader.ReloadService(ctx, "nginx"); err != nil {
		return types.InstallCustomCertResult{}, err
	}
	committed = true
	return types.InstallCustomCertResult{
		Domain: normalized.Domain, Issuer: types.CertIssuerCustom, CertPath: certPath,
		KeyPath: keyPath, ExpiresAt: validated.Leaf.NotAfter.UTC(),
	}, nil
}

func validateACMEIssueResult(result ACMEIssueResult, certPath, keyPath string) error {
	if result.CertPath == "" {
		return errors.New("missing certificate path")
	}
	if result.KeyPath == "" {
		return errors.New("missing certificate key path")
	}
	if result.ExpiresAt.IsZero() {
		return errors.New("missing certificate expiration")
	}
	if result.CertPath != certPath {
		return fmt.Errorf("certificate path %q does not match requested path %q", result.CertPath, certPath)
	}
	if result.KeyPath != keyPath {
		return fmt.Errorf("certificate key path %q does not match requested path %q", result.KeyPath, keyPath)
	}
	return nil
}

func RenderNginxTLSVHost(plan SitePlan, certPath, keyPath string) string {
	return fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %[1]s;
    root %[2]s;
    index index.php index.html;

    access_log %[3]s;
    error_log %[4]s;

    location / {
%[9]s
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include %[5]s;
        fastcgi_pass unix:%[6]s;
    }

    location ~ /\. {
        deny all;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name %[1]s;
    root %[2]s;
    index index.php index.html;

    ssl_certificate %[7]s;
    ssl_certificate_key %[8]s;
    ssl_protocols TLSv1.2 TLSv1.3;

    access_log %[3]s;
    error_log %[4]s;

    location / {
%[9]s
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include %[5]s;
        fastcgi_pass unix:%[6]s;
    }

    location ~ /\. {
        deny all;
    }
}
`, plan.Domain, plan.Docroot, plan.NginxAccessLog, plan.NginxErrorLog, plan.NginxSnippet, plan.PHPFPMSocket, certPath, keyPath, renderNginxLocationControls(plan))
}

func (p *CertificateProvisioner) writeSelfSignedCertificate(domain, certPath, keyPath string) (time.Time, error) {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return time.Time{}, fmt.Errorf("create certificate directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(certPath), 0o700); err != nil {
		return time.Time{}, fmt.Errorf("chmod certificate directory: %w", err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return time.Time{}, fmt.Errorf("generate certificate key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return time.Time{}, fmt.Errorf("generate certificate serial: %w", err)
	}

	now := p.now().UTC()
	expiresAt := now.Add(90 * 24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              expiresAt,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return time.Time{}, fmt.Errorf("create self-signed certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return time.Time{}, fmt.Errorf("marshal certificate key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return time.Time{}, fmt.Errorf("write certificate: %w", err)
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return time.Time{}, fmt.Errorf("write certificate key: %w", err)
	}
	return expiresAt, nil
}
