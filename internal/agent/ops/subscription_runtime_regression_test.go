package ops

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type convergenceRuntimeObserver struct {
	nginxPath string
	configs   []string
	phpStarts int
	stops     int
	fail      bool
	failOnce  bool
	stopErr   error
}

func (r *convergenceRuntimeObserver) ReloadService(_ context.Context, name string) error {
	if name != "nginx" {
		r.phpStarts++
		return nil
	}
	data, err := os.ReadFile(r.nginxPath)
	if err != nil {
		return err
	}
	r.configs = append(r.configs, string(data))
	if r.failOnce {
		r.failOnce = false
		return errors.New("injected one-shot nginx failure")
	}
	if r.fail {
		return errors.New("injected nginx reload failure")
	}
	return nil
}

type shutdownFailingUserManager struct{}

func (shutdownFailingUserManager) EnsureUser(context.Context, string) error {
	return errors.New("injected user failure")
}

type shutdownFailingQuotaManager struct{}

func (shutdownFailingQuotaManager) ApplyUserQuota(context.Context, string, string, int) error {
	return errors.New("injected quota failure")
}

func TestSuspendedAccountStopsPHPBeforeUnrelatedSetupFailures(t *testing.T) {
	for _, failure := range []string{"quota", "directory", "SFTP keys"} {
		t.Run(failure, func(t *testing.T) {
			p, req, observer, _ := convergenceRuntimeFixture(t)
			req.State = "suspended"
			if failure == "quota" {
				p.diskQuota = shutdownFailingQuotaManager{}
			} else {
				if err := os.MkdirAll(req.HomePath, 0o700); err != nil {
					t.Fatal(err)
				}
				blocker := filepath.Join(req.HomePath, ".wp-cli")
				if failure == "SFTP keys" {
					blocker = filepath.Join(req.HomePath, "keys-blocker")
					p.authorizedKeysDir = blocker
				}
				if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err == nil {
				t.Fatal("setup failure ignored")
			}
			if observer.stops == 0 || observer.phpStarts != 0 {
				t.Fatalf("setup failure bypassed shutdown: starts=%d stops=%d", observer.phpStarts, observer.stops)
			}
		})
	}
}

func TestSuspendedAccountStopsPHPBeforeUserSetupFailure(t *testing.T) {
	p, req, observer, _ := convergenceRuntimeFixture(t)
	req.State = "suspended"
	p.users = shutdownFailingUserManager{}
	if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err == nil {
		t.Fatal("setup failure ignored")
	}
	if observer.stops == 0 || observer.phpStarts != 0 {
		t.Fatalf("user setup failure bypassed shutdown: starts=%d stops=%d", observer.phpStarts, observer.stops)
	}
}

func TestStaleHTTPOnlyRuntimeCannotRemoveInstalledTLS(t *testing.T) {
	for _, operation := range []string{"account", "runtime", "creation retry", "suspension"} {
		t.Run(operation, func(t *testing.T) {
			p, req, _, plan := convergenceRuntimeFixture(t)
			if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			cert, key := req.Domains[0].TLSCertPath, req.Domains[0].TLSKeyPath
			req.Domains[0].TLSCertPath, req.Domains[0].TLSKeyPath, req.Domains[0].HTTPSRedirect = "", "", false
			var err error
			switch operation {
			case "account":
				_, err = p.EnsureSubscriptionAccount(context.Background(), req)
			case "suspension":
				req.State = "suspended"
				_, err = p.EnsureSubscriptionAccount(context.Background(), req)
			case "runtime":
				err = p.sites.ApplySiteRuntime(context.Background(), types.ApplySiteRuntimeReq{SiteID: 7, Username: req.Username, Domain: req.Domains[0].Domain, SharedAccount: true, CurrentPHPVersion: "8.4", DesiredPHPVersion: "8.4", State: "active"})
			case "creation retry":
				err = p.sites.CreateSite(context.Background(), types.CreateSiteReq{SiteID: 7, Username: req.Username, Domain: req.Domains[0].Domain, PHPVersion: "8.4", SharedAccount: true})
			}
			if err != nil {
				t.Fatal(err)
			}
			config, err := os.ReadFile(plan.NginxConfig)
			if err != nil {
				t.Fatal(err)
			}
			for _, directive := range []string{"ssl_certificate " + cert + ";", "ssl_certificate_key " + key + ";"} {
				if !strings.Contains(string(config), directive) {
					t.Fatalf("stale runtime removed %q:\n%s", directive, config)
				}
			}
			if operation == "suspension" {
				if !strings.Contains(string(config), "return 503;") || strings.Contains(string(config), "fastcgi_pass") {
					t.Fatal("TLS preservation reactivated suspended hosting")
				}
			} else if !strings.Contains(string(config), "return 301 https://$host$request_uri;") {
				t.Fatal("stale runtime removed HTTPS redirect")
			}
		})
	}
}

func TestSuspensionStopsPHPWhenExistingTLSCannotBeRetained(t *testing.T) {
	p, req, observer, plan := convergenceRuntimeFixture(t)
	if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	config := RenderNginxVHost(plan) + "\n  ssl_certificate /certs/current.pem;\n  ssl_certificate_key /certs/current.key;\n"
	if err := writeFileAtomic(plan.NginxConfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	observer.phpStarts, observer.stops = 0, 0
	err := p.sites.ApplySiteRuntime(context.Background(), types.ApplySiteRuntimeReq{SiteID: 7, Username: req.Username, Domain: req.Domains[0].Domain, SharedAccount: true, CurrentPHPVersion: "8.4", DesiredPHPVersion: "8.4", State: "suspended"})
	if err == nil || observer.stops == 0 || observer.phpStarts != 0 {
		t.Fatalf("invalid TLS bypassed suspension shutdown: err=%v stops=%d starts=%d", err, observer.stops, observer.phpStarts)
	}
}

func TestSuspendedSiteStopsPHPBeforeUserSetupFailure(t *testing.T) {
	p, req, observer, _ := convergenceRuntimeFixture(t)
	p.sites.users = shutdownFailingUserManager{}
	err := p.sites.createSiteRuntime(context.Background(), types.CreateSiteReq{SiteID: 7, Username: req.Username, Domain: req.Domains[0].Domain, PHPVersion: "8.4", SharedAccount: true}, "", "", false, "suspended")
	if err == nil {
		t.Fatal("setup failure ignored")
	}
	if observer.stops == 0 || observer.phpStarts != 0 {
		t.Fatalf("site setup failure bypassed shutdown: starts=%d stops=%d", observer.phpStarts, observer.stops)
	}
}

func TestApplySuspendedRuntimeFailureNeverRestoresActiveHosting(t *testing.T) {
	p, req, observer, plan := convergenceRuntimeFixture(t)
	if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	observer.phpStarts, observer.stops, observer.configs = 0, 0, nil
	observer.failOnce = true
	err := p.sites.ApplySiteRuntime(context.Background(), types.ApplySiteRuntimeReq{SiteID: 7, Username: req.Username, Domain: req.Domains[0].Domain, CurrentPHPVersion: "8.4", DesiredPHPVersion: "8.4", SharedAccount: true, State: "suspended", TLSCertPath: req.Domains[0].TLSCertPath, TLSKeyPath: req.Domains[0].TLSKeyPath})
	if err == nil {
		t.Fatal("one-shot failure ignored")
	}
	if observer.phpStarts != 0 || observer.stops == 0 {
		t.Fatalf("failure reactivated PHP: starts=%d stops=%d", observer.phpStarts, observer.stops)
	}
	config, err := os.ReadFile(plan.NginxConfig)
	if err != nil || !strings.Contains(string(config), "return 503;") || strings.Contains(string(config), "fastcgi_pass") {
		t.Fatalf("active configuration restored: %s, %v", config, err)
	}
	for _, config := range observer.configs {
		if strings.Contains(config, "fastcgi_pass") {
			t.Fatalf("active nginx published during recovery: %s", config)
		}
	}
}

func (r *convergenceRuntimeObserver) StopService(context.Context, string) error {
	r.stops++
	return r.stopErr
}

func TestSuspendedAccountAttemptsAllShutdownsWhenOneStopFails(t *testing.T) {
	p, req, observer, _ := convergenceRuntimeFixture(t)
	req.State = "suspended"
	second := req.Domains[0]
	second.SiteID, second.Domain, second.DocumentRoot = 8, "second.test", filepath.Join(req.HomePath, "domains", "second.test", "public_html")
	req.Domains = append(req.Domains, second)
	observer.stopErr = errors.New("injected stop failure")
	if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err == nil {
		t.Fatal("stop failure ignored")
	}
	if observer.stops != 2 || observer.phpStarts != 0 {
		t.Fatalf("first failure skipped remaining shutdowns: starts=%d stops=%d", observer.phpStarts, observer.stops)
	}
}

func convergenceRuntimeFixture(t *testing.T) (*SubscriptionAccountProvisioner, types.EnsureSubscriptionAccountReq, *convergenceRuntimeObserver, SitePlan) {
	t.Helper()
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	home := filepath.Join(homeRoot, "npaccount")
	paths := SitePathConfig{HomeRoot: homeRoot, NginxAvailableDir: filepath.Join(root, "nginx", "available"), NginxEnabledDir: filepath.Join(root, "nginx", "enabled"), NginxLogDir: filepath.Join(root, "logs"), PHPRunDir: filepath.Join(root, "run"), PHPFPMLogDir: filepath.Join(root, "php-logs"), PHPTmpDir: filepath.Join(root, "tmp")}
	observer := &convergenceRuntimeObserver{nginxPath: filepath.Join(paths.NginxAvailableDir, "example.test.conf")}
	sites := NewSiteProvisioner(SiteProvisionerOptions{Paths: paths, UserManager: &recordingUserManager{}, Reloader: observer, DiskQuotaManager: &accountTestQuota{}})
	p := NewSubscriptionAccountProvisioner(SubscriptionAccountProvisionerOptions{HomeRoot: homeRoot, SystemdUnitDir: filepath.Join(root, "units"), UserManager: &accountTestUsers{}, Ownership: accountTestOwnership{}, DiskQuota: &accountTestQuota{}, Runner: &accountTestRunner{}, SiteProvisioner: sites})
	policy := validAccountPolicy()
	policy.PHP.AllowedVersions = []string{"8.3", "8.4"}
	domain := types.SubscriptionDomain{SiteID: 7, Domain: "example.test", DocumentRoot: filepath.Join(home, "domains", "example.test", "public_html"), State: "active", Policy: policy, TLSCertPath: "/certs/fullchain.pem", TLSKeyPath: "/certs/privkey.pem", HTTPSRedirect: true}
	if err := json.Unmarshal([]byte(`{"current_php_version":"8.3","desired_php_version":"8.4"}`), &domain); err != nil {
		t.Fatal(err)
	}
	req := types.EnsureSubscriptionAccountReq{SubscriptionID: 42, Username: "npaccount", HomePath: home, State: "active", Policy: policy, Domains: []types.SubscriptionDomain{domain}}
	plan, err := NewSitePlan(types.CreateSiteReq{SiteID: 7, Username: req.Username, Domain: domain.Domain, PHPVersion: "8.4", SharedAccount: true}, paths)
	if err != nil {
		t.Fatal(err)
	}
	return p, req, observer, plan
}

func TestSubscriptionConvergencePreservesSelectedPHPVersion(t *testing.T) {
	p, req, _, plan := convergenceRuntimeFixture(t)
	for pass := 0; pass < 2; pass++ {
		if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		unit, err := os.ReadFile(plan.PHPServiceUnit)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(unit), "/usr/sbin/php-fpm8.4") {
			t.Fatalf("selected PHP version was reset: %s", unit)
		}
	}
}

func TestSubscriptionConvergenceRejectsDisallowedSelectedPHP(t *testing.T) {
	p, req, observer, _ := convergenceRuntimeFixture(t)
	req.Domains[0].Policy.PHP.AllowedVersions = []string{"8.3"}
	if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err == nil {
		t.Fatal("disallowed selected version silently reset")
	}
	if len(observer.configs) > 0 || observer.phpStarts > 0 {
		t.Fatal("invalid selection mutated hosting runtime")
	}
}

func TestSubscriptionSuspensionAllowsRetiredPHPVersion(t *testing.T) {
	for _, suspendedAccount := range []bool{false, true} {
		t.Run(map[bool]string{false: "domain", true: "account"}[suspendedAccount], func(t *testing.T) {
			p, req, observer, _ := convergenceRuntimeFixture(t)
			req.Domains[0].CurrentPHPVersion, req.Domains[0].DesiredPHPVersion = "8.5", "8.5"
			req.Domains[0].Policy.PHP.DefaultVersion = "8.4"
			req.Domains[0].Policy.PHP.AllowedVersions = []string{"8.4"}
			if suspendedAccount {
				req.State = "suspended"
			} else {
				req.Domains[0].State = "suspended"
			}
			if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err != nil {
				t.Fatalf("retired PHP prevented suspension: %v", err)
			}
			if observer.phpStarts != 0 || observer.stops == 0 {
				t.Fatalf("retired PHP not safely stopped: starts=%d stops=%d", observer.phpStarts, observer.stops)
			}
			req.State, req.Domains[0].State = "active", "active"
			if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err == nil {
				t.Fatal("retired PHP activation accepted")
			}
		})
	}
}

func TestSubscriptionActivationFailurePreservesSuspendedPool(t *testing.T) {
	p, req, observer, plan := convergenceRuntimeFixture(t)
	req.State = "suspended"
	if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	previous, err := os.ReadFile(plan.PHPFPMConfig + ".suspended")
	if err != nil {
		t.Fatal(err)
	}
	req.State = "active"
	observer.fail = true
	if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err == nil {
		t.Fatal("injected activation failure was ignored")
	}
	restored, err := os.ReadFile(plan.PHPFPMConfig + ".suspended")
	if err != nil || string(restored) != string(previous) {
		t.Fatalf("failed activation lost suspended pool: %v", err)
	}
}

func TestSuspendedSubscriptionConvergenceNeverActivatesHosting(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "reload_failure"}[fail], func(t *testing.T) {
			p, req, observer, plan := convergenceRuntimeFixture(t)
			req.State = "suspended"
			observer.fail = fail
			_, err := p.EnsureSubscriptionAccount(context.Background(), req)
			if (err != nil) != fail {
				t.Fatalf("unexpected result: %v", err)
			}
			if observer.phpStarts != 0 {
				t.Fatalf("suspended convergence started PHP %d times", observer.phpStarts)
			}
			if observer.stops == 0 {
				t.Fatal("suspended convergence did not stop PHP")
			}
			for _, config := range observer.configs {
				if !strings.Contains(config, "return 503;") || strings.Contains(config, "fastcgi_pass") {
					t.Fatalf("published active hosting: %s", config)
				}
				if !strings.Contains(config, "listen 443 ssl;") || !strings.Contains(config, "ssl_certificate /certs/fullchain.pem;") {
					t.Fatalf("suspended HTTPS unavailable: %s", config)
				}
			}
			if _, err := os.Stat(plan.PHPFPMConfig); !os.IsNotExist(err) {
				t.Fatalf("active PHP pool remains: %v", err)
			}
		})
	}
}
