package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestCertificateInstallationPreservesManagedRootAndDedicatedPHP(t *testing.T) {
	root := t.TempDir()
	paths := SitePathConfig{HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available"), NginxEnabledDir: filepath.Join(root, "enabled"), ACMEChallengeRoot: filepath.Join(root, "acme"), PHPFPMDedicatedRunDir: "/run/nakpanel-php"}
	plan, err := NewSitePlan(types.CreateSiteReq{SiteID: 30, Username: "npdemo", Domain: "example.test", PHPVersion: "8.4", SharedAccount: true}, paths)
	if err != nil {
		t.Fatal(err)
	}
	releaseRoot := filepath.Join(root, "home", "npdemo", "domains", "example.test", ".nakpanel", "releases", "7", "public")
	config, err := replaceManagedNginxRuntime([]byte(RenderNginxVHost(plan)), releaseRoot, "/run/nakpanel-php/site-30.sock")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(plan.NginxConfig, config, 0o600); err != nil {
		t.Fatal(err)
	}
	p := NewCertificateProvisioner(CertificateProvisionerOptions{Paths: paths, CertRoot: filepath.Join(root, "certs"), Reloader: &recordingReloader{}})
	if _, err := p.IssueCert(context.Background(), types.IssueCertReq{SiteID: 30, Username: "npdemo", Domain: "example.test", PHPVersion: "8.4", SharedAccount: true}); err != nil {
		t.Fatal(err)
	}
	applied, err := os.ReadFile(plan.NginxConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(applied), "root "+releaseRoot+";") || !strings.Contains(string(applied), "fastcgi_pass unix:/run/nakpanel-php/site-30.sock;") {
		t.Fatalf("certificate installation changed the deployed PHP runtime:\n%s", applied)
	}
}

type checkingACMEIssuer func(context.Context, ACMEIssueRequest) (ACMEIssueResult, error)

func (f checkingACMEIssuer) Issue(ctx context.Context, req ACMEIssueRequest) (ACMEIssueResult, error) {
	return f(ctx, req)
}

func TestACMEPreflightPreservesManagedTLSRuntimeAndRollsBackFailure(t *testing.T) {
	root := t.TempDir()
	paths := SitePathConfig{HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available"), NginxEnabledDir: filepath.Join(root, "enabled"), ACMEChallengeRoot: filepath.Join(root, "acme"), PHPFPMDedicatedRunDir: "/run/nakpanel-php"}
	plan, err := NewSitePlan(types.CreateSiteReq{SiteID: 30, Username: "npdemo", Domain: "example.test", PHPVersion: "8.4", SharedAccount: true}, paths)
	if err != nil {
		t.Fatal(err)
	}
	releaseRoot := filepath.Join(filepath.Dir(plan.Docroot), ".nakpanel", "releases", "7", "public")
	previous := []byte(RenderNginxRuntimeVHost(plan, "/previous/cert.pem", "/previous/key.pem", true))
	previous, err = replaceManagedNginxRuntime(previous, releaseRoot, plan.PHPFPMSocket)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a pre-upgrade vhost with no challenge exception.
	previous = []byte(strings.ReplaceAll(string(previous), renderNginxACMEChallenge(plan), ""))
	if err := writeFileAtomic(plan.NginxConfig, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	reloader := &recordingReloader{}
	p := NewCertificateProvisioner(CertificateProvisionerOptions{Paths: paths, CertRoot: filepath.Join(root, "certs"), Reloader: reloader, NginxTester: &fakeNginxTester{}})
	issuerCalled := false
	p.acmeIssuer = checkingACMEIssuer(func(ctx context.Context, req ACMEIssueRequest) (ACMEIssueResult, error) {
		issuerCalled = true
		prepared, err := os.ReadFile(plan.NginxConfig)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"root " + releaseRoot + ";", "fastcgi_pass unix:" + plan.PHPFPMSocket + ";", "return 301 https://$host$request_uri;", "ssl_certificate /previous/cert.pem;", "alias " + plan.ACMEWebroot} {
			if !strings.Contains(string(prepared), want) {
				t.Fatalf("ACME preparation lost %q: %s", want, prepared)
			}
		}
		if len(reloader.services) != 1 || req.Docroot != plan.ACMEWebroot {
			t.Fatal("issuer called before challenge route was reloaded")
		}
		return ACMEIssueResult{}, errors.New("simulated CA failure")
	})
	_, err = p.IssueCert(context.Background(), types.IssueCertReq{SiteID: 30, Username: plan.Username, Domain: plan.Domain, PHPVersion: plan.PHPVersion, SharedAccount: true, Issuer: types.CertIssuerACME})
	if err == nil || !issuerCalled {
		t.Fatal("expected the CA failure after preparation")
	}
	restored, err := os.ReadFile(plan.NginxConfig)
	if err != nil || string(restored) != string(previous) || len(reloader.services) != 2 {
		t.Fatal("failed issuance did not restore and reload the previous vhost")
	}
}

func TestACMEIssuanceKeepsSuspendedHostingClosed(t *testing.T) {
	root := t.TempDir()
	paths := SitePathConfig{HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available"), NginxEnabledDir: filepath.Join(root, "enabled"), ACMEChallengeRoot: filepath.Join(root, "acme")}
	plan, err := NewSitePlan(types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.4", SharedAccount: true}, paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(plan.NginxConfig, []byte(RenderSuspendedNginxVHost(plan)), 0o600); err != nil {
		t.Fatal(err)
	}
	p := NewCertificateProvisioner(CertificateProvisionerOptions{Paths: paths, CertRoot: filepath.Join(root, "certs"), Reloader: &recordingReloader{}})
	p.acmeIssuer = checkingACMEIssuer(func(ctx context.Context, req ACMEIssueRequest) (ACMEIssueResult, error) {
		prepared, err := os.ReadFile(plan.NginxConfig)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(prepared), "return 503;") || strings.Contains(string(prepared), "fastcgi_pass") || strings.Contains(string(prepared), "    root ") {
			t.Fatalf("ACME preflight reopened suspended hosting: %s", prepared)
		}
		expires, err := p.writeSelfSignedCertificate(req.Domain, req.CertPath, req.KeyPath)
		return ACMEIssueResult{CertPath: req.CertPath, KeyPath: req.KeyPath, ExpiresAt: expires}, err
	})
	if _, err := p.IssueCert(context.Background(), types.IssueCertReq{Username: plan.Username, Domain: plan.Domain, PHPVersion: plan.PHPVersion, SharedAccount: true, Issuer: types.CertIssuerACME}); err != nil {
		t.Fatal(err)
	}
	applied, err := os.ReadFile(plan.NginxConfig)
	if err != nil || !strings.Contains(string(applied), "return 503;") || strings.Contains(string(applied), "fastcgi_pass") || !strings.Contains(string(applied), "ssl_certificate ") {
		t.Fatalf("certificate activation changed suspended hosting: %s, %v", applied, err)
	}
}

func TestRetainedTLSDoesNotOverrideExplicitRedirectChange(t *testing.T) {
	cert, key, redirect, err := retainInstalledTLS(SitePlan{}, "/certs/new.pem", "/certs/new.key", false)
	if err != nil || cert != "/certs/new.pem" || key != "/certs/new.key" || redirect {
		t.Fatalf("explicit runtime change lost: %s %s %v %v", cert, key, redirect, err)
	}
}

func TestRetainedTLSRejectsUnrecognizedExistingDirectives(t *testing.T) {
	root := t.TempDir()
	plan, err := NewSitePlan(types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.4"}, SitePathConfig{HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available")})
	if err != nil {
		t.Fatal(err)
	}
	config := RenderNginxVHost(plan) + "\n  ssl_certificate /certs/current.pem;\n  ssl_certificate_key /certs/current.key;\n"
	if err = writeFileAtomic(plan.NginxConfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = retainInstalledTLS(plan, "", "", false); err == nil {
		t.Fatal("unrecognized TLS would be silently removed")
	}
}
