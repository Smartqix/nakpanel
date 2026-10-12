package ops

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagedPHPHTTPSActivationDoesNotAcknowledgeHTTPRedirect(t *testing.T) {
	for _, healthy := range []bool{false, true} {
		t.Run(fmt.Sprintf("https_healthy_%t", healthy), func(t *testing.T) {
			plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://example.com/up", http.StatusMovedPermanently)
			}))
			defer plain.Close()
			tlsCalls := 0
			secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tlsCalls++
				if !healthy {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			defer secure.Close()
			roots := x509.NewCertPool()
			roots.AddCert(secure.Certificate())
			probe := func(ctx context.Context, address, host string) error {
				if host != "example.test" {
					t.Fatalf("unexpected site identity %q", host)
				}
				if strings.HasPrefix(address, "https://127.0.0.1/") {
					return probePHPHTTPWithRoots(ctx, secure.URL+"/up", "example.com", roots)
				}
				return probePHPHTTPWithRoots(ctx, plain.URL+"/up", host, nil)
			}
			p, spec := newPHPApplicationTestProvisioner(t, &scriptedPHPAppRunner{}, probe)
			p.healthProbeWindow = 10 * time.Millisecond
			spec.HTTPSRedirect = true
			paths, err := p.pathsFor(spec, 22)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(paths.release, spec.PublicPath), 0o750); err != nil {
				t.Fatal(err)
			}
			envPath, err := p.writeEnvironment(spec, 22, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = p.activateRelease(context.Background(), spec, phpObservedMarker{ApplicationID: spec.ApplicationID, SiteID: spec.SiteID, ActiveDeploymentID: 22, ResolvedRevision: strings.Repeat("a", 40), ReleasePath: paths.release, EnvironmentPath: envPath}, envPath, nil)
			if (err == nil) != healthy {
				t.Fatalf("HTTPS health %t: activation error=%v", healthy, err)
			}
			if tlsCalls == 0 {
				t.Fatal("activation only checked the HTTP redirect, not the HTTPS application")
			}
		})
	}
}

func TestPHPHTTPSProbeVerifiesHostnameAndCertificateTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" || r.TLS.ServerName != "example.com" {
			w.WriteHeader(http.StatusMisdirectedRequest)
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	if err := probePHPHTTPWithRoots(context.Background(), server.URL, "example.com", roots); err != nil {
		t.Fatalf("trusted hostname-verified HTTPS probe failed: %v", err)
	}
	if err := probePHPHTTPWithRoots(context.Background(), server.URL, "wrong.example", roots); err == nil {
		t.Fatal("HTTPS probe accepted a certificate for the wrong hostname")
	}
	if err := probePHPHTTP(context.Background(), server.URL, "example.com"); err == nil {
		t.Fatal("default HTTPS probe accepted an untrusted certificate")
	}
}
