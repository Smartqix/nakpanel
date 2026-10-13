package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestManagedPHPResumesLastGoodReleaseFromHostingSuspension(t *testing.T) {
	for _, tls := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "tls"}[tls], func(t *testing.T) {
			p, spec := newPHPApplicationTestProvisioner(t, &scriptedPHPAppRunner{}, nil)
			if tls {
				if err := json.Unmarshal([]byte(`{"https_redirect":true}`), &spec); err != nil {
					t.Fatal(err)
				}
			}
			environment := []types.PHPEnvironmentPayload{{Name: "APP_KEY", Secret: "preserved-private-key"}}
			request := types.DeployPHPReleaseReq{Application: spec, Deployment: types.PHPDeployment{ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, RequestedRevision: "main"}, Environment: environment}
			deployed, err := p.DeployPHPRelease(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			marker, err := p.readMarker(spec.ApplicationID)
			if err != nil {
				t.Fatal(err)
			}
			envBefore, err := os.ReadFile(marker.EnvironmentPath)
			if err != nil {
				t.Fatal(err)
			}
			spec.DesiredState = "suspended"
			if _, err := p.ReconcilePHPApplication(context.Background(), types.ReconcilePHPApplicationReq{Application: spec, Environment: environment}); err != nil {
				t.Fatal(err)
			}
			cert, key := "", ""
			if tls {
				cert, key = "/certs/fullchain.pem", "/certs/privkey.pem"
			}
			nginxPath := filepath.Join(p.nginxAvailableDir, spec.Domain+".conf")
			suspended := renderSuspendedNginxRuntimeVHost(SitePlan{Domain: spec.Domain, Limits: siteLimitsFromPolicy(spec.Policy)}, cert, key)
			if err := os.WriteFile(nginxPath, []byte(suspended), 0o600); err != nil {
				t.Fatal(err)
			}
			spec.DesiredState = "active"
			active := types.PHPDeployment{ID: 22, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID, ResolvedRevision: deployed.ResolvedRevision}
			for pass := 0; pass < 2; pass++ {
				resumed, err := p.ReconcilePHPApplication(context.Background(), types.ReconcilePHPApplicationReq{Application: spec, ActiveDeployment: &active, Environment: environment})
				if err != nil || resumed.ObservedState != "healthy" || resumed.ActiveDeploymentID != active.ID {
					t.Fatalf("resume pass %d: result=%#v error=%v", pass, resumed, err)
				}
			}
			nginx, err := os.ReadFile(nginxPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(nginx), "root "+phpDocumentRoot(deployed.ReleasePath, spec.PublicPath)+";") || !strings.Contains(string(nginx), "fastcgi_pass unix:"+filepath.Join(p.phpRunDir, "site-7.sock")+";") || strings.Contains(string(nginx), "return 503;") {
				t.Fatalf("last-good runtime was not restored: %s", nginx)
			}
			if tls && (!strings.Contains(string(nginx), "ssl_certificate "+cert+";") || !strings.Contains(string(nginx), "ssl_certificate_key "+key+";")) {
				t.Fatalf("resume lost TLS: %s", nginx)
			}
			if tls && !strings.Contains(string(nginx), "return 301 https://$host$request_uri;") {
				t.Fatal("resume exposed HTTPS-only application over plaintext HTTP")
			}
			envAfter, err := os.ReadFile(marker.EnvironmentPath)
			if err != nil || !bytes.Equal(envBefore, envAfter) {
				t.Fatal("resume changed last-good release environment")
			}
		})
	}
}

func TestManagedPHPResumeRejectsUnrecognizedSuspendedVhosts(t *testing.T) {
	for _, test := range []struct{ name, config string }{
		{"arbitrary-vhost", "server { listen 80; server_name example.test; return 503; }\n"},
		{"wrong-domain", renderSuspendedNginxRuntimeVHost(SitePlan{Domain: "another.test"}, "", "")},
		{"injected-proxy", strings.Replace(RenderSuspendedNginxVHost(SitePlan{Domain: "example.test"}), "return 503;", "return 503;\n        proxy_pass http://untrusted;", 1)},
		{"redirect-without-certificate", RenderSuspendedNginxVHost(SitePlan{Domain: "example.test"})},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := test.config
			p, spec := newPHPApplicationTestProvisioner(t, &scriptedPHPAppRunner{}, nil)
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
			nginxPath := filepath.Join(p.nginxAvailableDir, spec.Domain+".conf")
			if err := os.WriteFile(nginxPath, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			err = p.activateRelease(context.Background(), spec, phpObservedMarker{ApplicationID: spec.ApplicationID, SiteID: spec.SiteID, ActiveDeploymentID: 22, ResolvedRevision: strings.Repeat("a", 40), ReleasePath: paths.release, EnvironmentPath: envPath}, envPath, nil)
			if err == nil {
				t.Fatal("unrecognized vhost accepted for managed resume")
			}
			after, err := os.ReadFile(nginxPath)
			if err != nil || string(after) != config {
				t.Fatal("rejected vhost was modified")
			}
		})
	}
}

func TestManagedPHPResumeAcceptsExactLegacySuspendedTemplate(t *testing.T) {
	for _, tls := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "tls"}[tls], func(t *testing.T) {
			p, spec := newPHPApplicationTestProvisioner(t, &scriptedPHPAppRunner{}, nil)
			config := "server {\n    listen 80;\n    listen [::]:80;\n"
			if tls {
				config += "    listen 443 ssl;\n    listen [::]:443 ssl;\n    ssl_certificate /certs/fullchain.pem;\n    ssl_certificate_key /certs/privkey.pem;\n"
				spec.HTTPSRedirect = true
			}
			config += "    server_name example.test;\n    location / {\n        add_header Retry-After \"3600\" always;\n        return 503;\n\t    }\n}\n"
			root := filepath.Join(p.homeRoot, spec.Username, "domains", spec.Domain, ".nakpanel", "releases", "22", "public")
			socket := filepath.Join(p.phpRunDir, "site-7.sock")
			active, err := p.resumeSuspendedManagedNginx(spec, []byte(config), root, socket)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(active), "root "+root+";") || !strings.Contains(string(active), "fastcgi_pass unix:"+socket+";") || strings.Contains(string(active), "return 503;") {
				t.Fatalf("legacy resume lost the managed runtime: %s", active)
			}
			if _, err := p.resumeSuspendedManagedNginx(spec, []byte(config+"# unexpected mutation\n"), root, socket); err == nil {
				t.Fatal("accepted a modified legacy template")
			}
		})
	}
}
