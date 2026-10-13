package ops

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

// Opt in on Ubuntu: NAKPANEL_TEST_NGINX=1 go test ./internal/agent/ops -run TestNginxACMEHTTPBoundary.
func TestNginxACMEHTTPBoundary(t *testing.T) {
	if os.Getenv("NAKPANEL_TEST_NGINX") != "1" {
		t.Skip("real nginx verification is opt-in")
	}
	nginx, err := exec.LookPath("nginx")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"plain", "tls", "redirect", "managed", "suspended", "preferred-www", "restricted", "protected", "application"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			paths := SitePathConfig{HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available"), NginxLogDir: root, NginxSnippet: filepath.Join(root, "fastcgi.conf"), ACMEChallengeRoot: filepath.Join(root, "acme")}
			plan, err := NewSitePlan(types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.4", SharedAccount: true}, paths)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "preferred-www" {
				plan.Limits.PreferredDomain = "www"
			}
			if mode == "restricted" {
				plan.Limits.AllowedCIDRs = "192.0.2.0/24"
			}
			put := func(path, value string) {
				t.Helper()
				if err := writeFileAtomic(path, []byte(value), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			put(paths.NginxSnippet, "")
			put(filepath.Join(plan.Docroot, "index.html"), "website-content")
			put(filepath.Join(plan.Docroot, ".env"), "NEVER_EXPOSE_THIS_SECRET")
			put(filepath.Join(plan.Docroot, ".git", "config"), "NEVER_EXPOSE_THIS_SECRET")
			put(filepath.Join(plan.Docroot, ".git", "config.php"), "NEVER_EXPOSE_THIS_SECRET")
			challengeDir := filepath.Join(plan.ACMEWebroot, ".well-known", "acme-challenge")
			put(filepath.Join(challengeDir, "test-token"), "test-token.key-authorization")
			put(filepath.Join(challengeDir, ".env"), "NEVER_EXPOSE_THIS_SECRET")
			if err := os.Symlink(filepath.Join(plan.Docroot, ".env"), filepath.Join(challengeDir, "linked-secret")); err != nil {
				t.Fatal(err)
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			keyDER, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			certPath, keyPath := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
			put(certPath, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
			if err := writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
				t.Fatal(err)
			}
			pool := x509.NewCertPool()
			certificate, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			pool.AddCert(certificate)
			config := RenderNginxVHost(plan)
			switch mode {
			case "tls":
				config = RenderNginxTLSVHost(plan, certPath, keyPath)
			case "redirect":
				config = RenderNginxRuntimeVHost(plan, certPath, keyPath, true)
			case "managed":
				managedRoot := filepath.Join(root, "release", "public")
				put(filepath.Join(managedRoot, ".env"), "NEVER_EXPOSE_THIS_SECRET")
				managed, err := replaceManagedNginxRuntime([]byte(config), managedRoot, plan.PHPFPMSocket)
				if err != nil {
					t.Fatal(err)
				}
				config = string(managed)
			case "suspended":
				config = RenderSuspendedNginxVHost(plan)
			case "protected":
				put(filepath.Join(plan.Docroot, "protected", ".git", "config.php"), "NEVER_EXPOSE_THIS_SECRET")
				put(filepath.Join(plan.Docroot, "protected", "index.html"), "protected-website-content")
				config = strings.Replace(config, "    server_name example.test;", "    server_name example.test;\n    location /protected/ {\n        try_files $uri =404;\n        location ~ \\.php$ { fastcgi_pass unix:"+plan.PHPFPMSocket+"; }\n    }", 1)
			case "application":
				put(filepath.Join(plan.Docroot, "app", ".env"), "NEVER_EXPOSE_THIS_SECRET")
				put(filepath.Join(plan.Docroot, "app", "index.html"), "application-content")
				config = strings.Replace(config, "    server_name example.test;", "    server_name example.test;\n    location ^~ /app/ { try_files $uri =404; }", 1)
			}
			port := func() int {
				t.Helper()
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				value := listener.Addr().(*net.TCPAddr).Port
				listener.Close()
				return value
			}
			httpPort, tlsPort := port(), port()
			config = strings.ReplaceAll(config, "listen [::]:80;", "")
			config = strings.ReplaceAll(config, "listen [::]:443 ssl;", "")
			config = strings.ReplaceAll(config, "listen 80;", fmt.Sprintf("listen 127.0.0.1:%d;", httpPort))
			config = strings.ReplaceAll(config, "listen 443 ssl;", fmt.Sprintf("listen 127.0.0.1:%d ssl;", tlsPort))
			config = fmt.Sprintf("daemon off; master_process off; pid %s; error_log %s; events {} http { access_log off; %s }", filepath.Join(root, "nginx.pid"), filepath.Join(root, "nginx.log"), config)
			configPath := filepath.Join(root, "nginx.conf")
			put(configPath, config)
			if output, err := exec.Command(nginx, "-t", "-p", root+"/", "-c", configPath).CombinedOutput(); err != nil {
				t.Fatalf("nginx configuration: %v\n%s", err, output)
			}
			logFile, err := os.Create(filepath.Join(root, "process.log"))
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(nginx, "-p", root+"/", "-c", configPath)
			cmd.Stdout, cmd.Stderr = logFile, logFile
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Signal(syscall.SIGTERM); _ = cmd.Wait(); _ = logFile.Close() })
			client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.test"}}}
			defer client.CloseIdleConnections()
			base := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
			deadline := time.Now().Add(5 * time.Second)
			for {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort), 100*time.Millisecond)
				if err == nil {
					conn.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("nginx did not start")
				}
				time.Sleep(20 * time.Millisecond)
			}
			check := func(base, path, method string, want int, wantBody string) {
				t.Helper()
				req, _ := http.NewRequest(method, base+path, nil)
				req.Host = "example.test"
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != want || (wantBody != "" && string(body) != wantBody) || strings.Contains(string(body), "NEVER_EXPOSE_THIS_SECRET") {
					t.Fatalf("%s %s: status=%d body=%q, want %d", method, path, resp.StatusCode, body, want)
				}
			}
			check(base, "/.well-known/acme-challenge/test-token", "GET", 200, "test-token.key-authorization")
			check(base, "/.well-known/acme-challenge/test-token", "HEAD", 200, "")
			check(base, "/.well-known/acme-challenge/missing-token", "GET", 404, "")
			check(base, "/.well-known/acme-challenge/test-token", "POST", 403, "")
			wantInvalid := 403
			if mode == "suspended" || mode == "redirect" {
				wantInvalid = 404
			}
			check(base, "/.well-known/acme-challenge/.env", "GET", wantInvalid, "")
			check(base, "/.well-known/acme-challenge/test.php", "GET", wantInvalid, "")
			check(base, "/.well-known/acme-challenge/linked-secret", "GET", 403, "")
			if mode == "tls" || mode == "redirect" {
				base = fmt.Sprintf("https://127.0.0.1:%d", tlsPort)
				check(base, "/.well-known/acme-challenge/test-token", "GET", 200, "test-token.key-authorization")
			}
			wantHidden := 403
			if mode == "suspended" {
				wantHidden = 503
			}
			check(base, "/.env", "GET", wantHidden, "")
			check(base, "/.git/config", "GET", wantHidden, "")
			check(base, "/.git/config.php", "GET", wantHidden, "")
			check(base, "/%2eenv", "GET", wantHidden, "")
			if mode == "protected" {
				check(base, "/protected/.git/config.php", "GET", 403, "")
				check(base, "/protected/%2egit/config.php", "GET", 403, "")
				check(base, "/protected/index.html", "GET", 200, "protected-website-content")
			}
			if mode == "application" {
				check(base, "/app/.env", "GET", 403, "")
				check(base, "/app/index.html", "GET", 200, "application-content")
			}
			if mode == "restricted" {
				check(base, "/index.html", "GET", 403, "")
			} else if mode == "preferred-www" {
				check(base, "/index.html", "GET", 301, "")
			}
		})
	}
}
