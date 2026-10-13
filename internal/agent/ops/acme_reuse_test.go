package ops

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/certificates"
	"github.com/nakroteck/nakpanel/internal/types"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProvisioningRetryReusesValidTrustedCertificateWithoutNewOrder(t *testing.T) {
	root := t.TempDir()
	bundle, roots, now := trustedCustomBundle(t, "example.test")
	directory := filepath.Join(root, "certs", "example.test")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "fullchain.pem"), bundle.CertificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "privkey.pem"), bundle.PrivateKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	issuer := &fakeACMEIssuer{err: errors.New("must not order another certificate")}
	provisioner := NewCertificateProvisioner(CertificateProvisionerOptions{Paths: customCertPaths(root), CertRoot: filepath.Join(root, "certs"), Reloader: &recordingReloader{}, NginxTester: &fakeNginxTester{}, ACMEIssuer: issuer, Validator: certificates.Validator{Roots: roots, Now: func() time.Time { return now }}})
	result, err := provisioner.IssueCert(context.Background(), types.IssueCertReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", Issuer: types.CertIssuerACME, SharedAccount: true, ReuseExisting: true})
	if err != nil || issuer.req.Domain != "" || result.ExpiresAt.IsZero() {
		t.Fatalf("result=%#v error=%v issuer=%#v", result, err, issuer)
	}
}
