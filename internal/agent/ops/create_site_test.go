package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type recordingUserManager struct {
	usernames []string
}

func (m *recordingUserManager) EnsureUser(ctx context.Context, username string) error {
	m.usernames = append(m.usernames, username)
	return nil
}

type recordingReloader struct {
	services []string
}

type failingServiceReloader struct {
	failService string
}

func (r *failingServiceReloader) ReloadService(_ context.Context, name string) error {
	if name == r.failService {
		return errors.New("injected reload failure")
	}
	return nil
}

func (r *recordingReloader) ReloadService(ctx context.Context, name string) error {
	r.services = append(r.services, name)
	return nil
}

func TestValidateCreateSiteRequestRejectsUnsafeInputs(t *testing.T) {
	tests := []struct {
		name string
		req  types.CreateSiteReq
	}{
		{
			name: "username path traversal",
			req:  types.CreateSiteReq{Username: "../root", Domain: "example.test", PHPVersion: "8.3"},
		},
		{
			name: "domain shell metacharacter",
			req:  types.CreateSiteReq{Username: "npdemo", Domain: "example.test;reboot", PHPVersion: "8.3"},
		},
		{
			name: "unsupported php",
			req:  types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "9.9"},
		},
		{
			name: "client supplied docroot",
			req:  types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", Docroot: "/tmp/evil"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateCreateSiteRequest(tt.req); err == nil {
				t.Fatal("ValidateCreateSiteRequest returned nil error")
			}
		})
	}
}

func TestRenderSiteConfigsAreDeterministicAndDerivePaths(t *testing.T) {
	req := types.CreateSiteReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
	}
	paths := SitePathConfig{
		HomeRoot:        "/home",
		PHPRunDir:       "/run/php",
		NginxLogDir:     "/var/log/nginx",
		PHPFPMLogDir:    "/var/log/php-fpm",
		NginxSnippet:    "snippets/fastcgi-php.conf",
		WWWGroup:        "www-data",
		PHPTmpDir:       "/tmp",
		DefaultFileMode: 0o644,
	}

	plan, err := NewSitePlan(req, paths)
	if err != nil {
		t.Fatalf("NewSitePlan returned error: %v", err)
	}

	nginx1 := RenderNginxVHost(plan)
	nginx2 := RenderNginxVHost(plan)
	if nginx1 != nginx2 {
		t.Fatal("RenderNginxVHost returned different content for the same plan")
	}
	for _, want := range []string{
		"server_name example.test;",
		"root /home/npdemo/public_html;",
		"fastcgi_pass unix:/run/php/nakpanel-npdemo-example-test.sock;",
	} {
		if !strings.Contains(nginx1, want) {
			t.Fatalf("nginx config missing %q:\n%s", want, nginx1)
		}
	}

	fpm := RenderPHPFPMPool(plan)
	for _, want := range []string{
		"[nakpanel-npdemo-example-test]",
		"user = npdemo",
		"group = npdemo",
		"listen = /run/php/nakpanel-npdemo-example-test.sock",
		"php_admin_value[open_basedir] = /home/npdemo/public_html:/tmp",
	} {
		if !strings.Contains(fpm, want) {
			t.Fatalf("fpm config missing %q:\n%s", want, fpm)
		}
	}
}

func TestRenderNginxRuntimeVHostRedirectsHTTPAndKeepsTLSHosting(t *testing.T) {
	plan, err := NewSitePlan(types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", Limits: types.SiteResourceLimits{RequestRatePerSecond: 5, RequestBurst: 10, MaxConnections: 20}}, SitePathConfig{})
	if err != nil {
		t.Fatal(err)
	}
	config := RenderNginxRuntimeVHost(plan, "/cert.pem", "/key.pem", true)
	for _, want := range []string{"return 301 https://$host$request_uri;", "listen 443 ssl;", "ssl_certificate /cert.pem;", "fastcgi_pass unix:", "limit_req zone=", "limit_conn "} {
		if !strings.Contains(config, want) {
			t.Fatalf("runtime nginx config missing %q:\n%s", want, config)
		}
	}
}

func TestApplySiteRuntimeRestoresConfigsAndNewSymlinkOnReloadFailure(t *testing.T) {
	root := t.TempDir()
	paths := SitePathConfig{
		HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available"), NginxEnabledDir: filepath.Join(root, "enabled"),
		NginxLogDir: filepath.Join(root, "logs"), PHPFPMPoolDir: filepath.Join(root, "php"), PHPFPMLogDir: filepath.Join(root, "php-logs"),
		PHPRunDir: filepath.Join(root, "run"), NginxSnippet: "snippets/fastcgi-php.conf", WWWGroup: "www-data", PHPTmpDir: filepath.Join(root, "tmp"), DefaultFileMode: 0o644,
	}
	plan, err := NewSitePlan(types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3"}, paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(plan.NginxConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(plan.PHPFPMConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plan.NginxConfig, []byte("old nginx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plan.PHPFPMConfig, []byte("old php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	provisioner := NewSiteProvisioner(SiteProvisionerOptions{Paths: paths, Reloader: &failingServiceReloader{failService: "nginx"}})
	err = provisioner.ApplySiteRuntime(context.Background(), types.ApplySiteRuntimeReq{Username: "npdemo", Domain: "example.test", CurrentPHPVersion: "8.3", DesiredPHPVersion: "8.3", State: "active"})
	if err == nil {
		t.Fatal("ApplySiteRuntime returned nil, want reload failure")
	}
	for path, want := range map[string]string{plan.NginxConfig: "old nginx\n", plan.PHPFPMConfig: "old php\n"} {
		got, readErr := os.ReadFile(path)
		if readErr != nil || string(got) != want {
			t.Fatalf("restored %s = %q, %v; want %q", path, got, readErr, want)
		}
	}
	if _, err := os.Lstat(plan.NginxEnabled); !os.IsNotExist(err) {
		t.Fatalf("new nginx symlink survived rollback: %v", err)
	}
}

func TestCreateSiteRestoresPolicyAndRuntimeConfigsOnReloadFailure(t *testing.T) {
	root := t.TempDir()
	paths := SitePathConfig{
		HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available"), NginxEnabledDir: filepath.Join(root, "enabled"),
		NginxConfDir: filepath.Join(root, "conf.d"), NginxLogDir: filepath.Join(root, "logs"), PHPFPMPoolDir: filepath.Join(root, "php"),
		PHPFPMLogDir: filepath.Join(root, "php-logs"), PHPRunDir: filepath.Join(root, "run"), NginxSnippet: "snippets/fastcgi-php.conf",
		WWWGroup: "www-data", PHPTmpDir: filepath.Join(root, "tmp"), DefaultFileMode: 0o644,
	}
	plan, err := NewSitePlan(types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3"}, paths)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{plan.NginxConfig, plan.PHPFPMConfig, plan.NginxPolicyConfig} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := NewSiteProvisioner(SiteProvisionerOptions{Paths: paths, UserManager: &recordingUserManager{}, Reloader: &failingServiceReloader{failService: "nginx"}})
	err = p.CreateSite(context.Background(), types.CreateSiteReq{
		Username: "npdemo", Domain: "example.test", PHPVersion: "8.3",
		Limits: types.SiteResourceLimits{RequestRatePerSecond: 5, MaxConnections: 10},
	})
	if err == nil {
		t.Fatal("CreateSite returned nil, want reload failure")
	}
	for _, path := range []string{plan.NginxConfig, plan.PHPFPMConfig, plan.NginxPolicyConfig} {
		got, readErr := os.ReadFile(path)
		if readErr != nil || string(got) != "old\n" {
			t.Fatalf("restored %s = %q, %v", path, got, readErr)
		}
	}
	if _, err := os.Lstat(plan.NginxEnabled); !os.IsNotExist(err) {
		t.Fatalf("new nginx symlink survived rollback: %v", err)
	}
}

func TestSiteRuntimeDriftDetectsAndRepairsHandEditedVHost(t *testing.T) {
	root := t.TempDir()
	paths := SitePathConfig{HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available"), NginxEnabledDir: filepath.Join(root, "enabled"), NginxLogDir: filepath.Join(root, "logs"), PHPFPMPoolDir: filepath.Join(root, "php"), PHPFPMLogDir: filepath.Join(root, "php-logs"), PHPRunDir: filepath.Join(root, "run"), NginxSnippet: "snippets/fastcgi-php.conf", WWWGroup: "www-data", PHPTmpDir: filepath.Join(root, "tmp"), DefaultFileMode: 0o644}
	plan, err := NewSitePlan(types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3"}, paths)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(plan.NginxConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(plan.PHPFPMConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(plan.NginxEnabled), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(plan.NginxConfig, []byte("hand edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(plan.PHPFPMConfig, []byte(RenderPHPFPMPool(plan)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(plan.NginxConfig, plan.NginxEnabled); err != nil {
		t.Fatal(err)
	}
	p := NewSiteProvisioner(SiteProvisionerOptions{Paths: paths, Reloader: &recordingReloader{}})
	req := types.ApplySiteRuntimeReq{Username: "npdemo", Domain: "example.test", CurrentPHPVersion: "8.3", DesiredPHPVersion: "8.3", State: "active"}
	drift, err := p.SiteRuntimeDrift(context.Background(), req)
	if err != nil || !drift {
		t.Fatalf("drift=%v err=%v, want detected", drift, err)
	}
	if err = p.ApplySiteRuntime(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	drift, err = p.SiteRuntimeDrift(context.Background(), req)
	if err != nil || drift {
		t.Fatalf("drift=%v err=%v after repair", drift, err)
	}
}

func TestApplySiteRuntimePreservesSharedAccountDocumentRoot(t *testing.T) {
	root := t.TempDir()
	paths := SitePathConfig{HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available"), NginxEnabledDir: filepath.Join(root, "enabled"), NginxLogDir: filepath.Join(root, "logs"), PHPFPMPoolDir: filepath.Join(root, "php"), PHPFPMLogDir: filepath.Join(root, "php-logs"), PHPRunDir: filepath.Join(root, "run"), NginxSnippet: "snippets/fastcgi-php.conf", WWWGroup: "www-data", PHPTmpDir: filepath.Join(root, "tmp"), DefaultFileMode: 0o644}
	p := NewSiteProvisioner(SiteProvisionerOptions{Paths: paths, Reloader: &recordingReloader{}})
	req := types.ApplySiteRuntimeReq{Username: "npdemo", Domain: "example.test", SharedAccount: true, CurrentPHPVersion: "8.3", DesiredPHPVersion: "8.3", State: "active"}
	if err := p.ApplySiteRuntime(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	plan, err := NewSitePlan(types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", SharedAccount: true}, paths)
	if err != nil {
		t.Fatal(err)
	}
	nginx, err := os.ReadFile(plan.NginxConfig)
	if err != nil {
		t.Fatal(err)
	}
	want := "root " + filepath.Join(paths.HomeRoot, "npdemo", "domains", "example.test", "public_html") + ";"
	if !strings.Contains(string(nginx), want) {
		t.Fatalf("shared runtime vhost missing %q:\n%s", want, nginx)
	}
}

func TestNewSitePlanUsesRequestedPHPVersionInDefaultPoolDir(t *testing.T) {
	plan, err := NewSitePlan(types.CreateSiteReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.2",
	}, SitePathConfig{})
	if err != nil {
		t.Fatalf("NewSitePlan returned error: %v", err)
	}
	if got, want := plan.PHPFPMConfig, "/etc/php/8.2/fpm/pool.d/nakpanel-npdemo-example-test.conf"; got != want {
		t.Fatalf("PHPFPMConfig = %q, want %q", got, want)
	}
}

func TestNewSitePlanWithDefaultConfigUsesRequestedPHPVersionInPoolDir(t *testing.T) {
	plan, err := NewSitePlan(types.CreateSiteReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.2",
	}, DefaultSitePathConfig())
	if err != nil {
		t.Fatalf("NewSitePlan returned error: %v", err)
	}
	if got, want := plan.PHPFPMConfig, "/etc/php/8.2/fpm/pool.d/nakpanel-npdemo-example-test.conf"; got != want {
		t.Fatalf("PHPFPMConfig = %q, want %q", got, want)
	}
}

func TestSiteProvisionerUsesRequestedPHPVersionInDefaultPoolDir(t *testing.T) {
	provisioner := NewSiteProvisioner(SiteProvisionerOptions{})

	req := types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.2"}
	plan, err := NewSitePlan(req, provisioner.paths)
	if err != nil {
		t.Fatalf("NewSitePlan returned error: %v", err)
	}
	if got, want := plan.PHPFPMConfig, "/etc/php/8.2/fpm/pool.d/nakpanel-npdemo-example-test.conf"; got != want {
		t.Fatalf("PHPFPMConfig = %q, want %q", got, want)
	}
}

func TestSiteProvisionerCreatesExpectedStateAndIsIdempotent(t *testing.T) {
	tmp := t.TempDir()
	paths := SitePathConfig{
		HomeRoot:          filepath.Join(tmp, "home"),
		NginxAvailableDir: filepath.Join(tmp, "etc", "nginx", "sites-available"),
		NginxEnabledDir:   filepath.Join(tmp, "etc", "nginx", "sites-enabled"),
		NginxLogDir:       filepath.Join(tmp, "var", "log", "nginx"),
		PHPFPMPoolDir:     filepath.Join(tmp, "etc", "php", "8.3", "fpm", "pool.d"),
		PHPFPMLogDir:      filepath.Join(tmp, "var", "log", "php-fpm"),
		PHPRunDir:         filepath.Join(tmp, "run", "php"),
		NginxSnippet:      "snippets/fastcgi-php.conf",
		WWWGroup:          "www-data",
		PHPTmpDir:         filepath.Join(tmp, "tmp"),
		DefaultFileMode:   0o644,
	}
	users := &recordingUserManager{}
	reloader := &recordingReloader{}
	provisioner := NewSiteProvisioner(SiteProvisionerOptions{
		Paths:       paths,
		UserManager: users,
		Reloader:    reloader,
	})

	req := types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3"}
	siteHome := filepath.Join(paths.HomeRoot, "npdemo")
	if err := os.MkdirAll(siteHome, 0o750); err != nil {
		t.Fatalf("seed restrictive site home: %v", err)
	}
	if err := provisioner.CreateSite(context.Background(), req); err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}
	if err := provisioner.CreateSite(context.Background(), req); err != nil {
		t.Fatalf("second CreateSite returned error: %v", err)
	}

	if got, want := users.usernames, []string{"npdemo", "npdemo"}; !slices.Equal(got, want) {
		t.Fatalf("ensured users = %#v, want %#v", got, want)
	}
	if got, want := reloader.services, []string{"php8.3-fpm", "nginx", "php8.3-fpm", "nginx"}; !slices.Equal(got, want) {
		t.Fatalf("reloaded services = %#v, want %#v", got, want)
	}

	homeInfo, err := os.Stat(siteHome)
	if err != nil {
		t.Fatalf("stat site home: %v", err)
	}
	if got, want := homeInfo.Mode().Perm(), os.FileMode(0o755); got != want {
		t.Fatalf("site home mode = %o, want %o", got, want)
	}

	indexPath := filepath.Join(paths.HomeRoot, "npdemo", "public_html", "index.php")
	index, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read index.php: %v", err)
	}
	if !strings.Contains(string(index), "nakpanel placeholder") {
		t.Fatalf("index.php = %q, want placeholder content", string(index))
	}

	plan, err := NewSitePlan(req, paths)
	if err != nil {
		t.Fatalf("NewSitePlan returned error: %v", err)
	}
	nginxPath := filepath.Join(paths.NginxAvailableDir, "example.test.conf")
	nginx, err := os.ReadFile(nginxPath)
	if err != nil {
		t.Fatalf("read nginx config: %v", err)
	}
	if got, want := string(nginx), RenderNginxVHost(plan); got != want {
		t.Fatalf("nginx config mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	linkPath := filepath.Join(paths.NginxEnabledDir, "example.test.conf")
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("read nginx enabled symlink: %v", err)
	}
	if target != nginxPath {
		t.Fatalf("nginx symlink target = %q, want %q", target, nginxPath)
	}

	fpmPath := filepath.Join(paths.PHPFPMPoolDir, "nakpanel-npdemo-example-test.conf")
	fpm, err := os.ReadFile(fpmPath)
	if err != nil {
		t.Fatalf("read fpm config: %v", err)
	}
	if got, want := string(fpm), RenderPHPFPMPool(plan); got != want {
		t.Fatalf("fpm config mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestSiteProvisionerMakesSharedAccountPathTraversableByNginx(t *testing.T) {
	tmp := t.TempDir()
	paths := SitePathConfig{
		HomeRoot: filepath.Join(tmp, "home"), NginxAvailableDir: filepath.Join(tmp, "available"),
		NginxEnabledDir: filepath.Join(tmp, "enabled"), NginxLogDir: filepath.Join(tmp, "logs"),
		PHPFPMPoolDir: filepath.Join(tmp, "php"), PHPFPMLogDir: filepath.Join(tmp, "php-logs"),
		PHPRunDir: filepath.Join(tmp, "run"), NginxConfDir: filepath.Join(tmp, "conf.d"),
		NginxSnippet: "snippets/fastcgi-php.conf", WWWGroup: "www-data", PHPTmpDir: filepath.Join(tmp, "tmp"), DefaultFileMode: 0o644,
	}
	home := filepath.Join(paths.HomeRoot, "npdemo")
	if err := os.MkdirAll(filepath.Join(home, "domains"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := NewSiteProvisioner(SiteProvisionerOptions{Paths: paths, UserManager: &recordingUserManager{}, Reloader: &recordingReloader{}})
	if err := p.CreateSite(context.Background(), types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", SharedAccount: true}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		filepath.Join(home, "domains"):                                0o711,
		filepath.Join(home, "domains", "example.test"):                0o711,
		filepath.Join(home, "domains", "example.test", "public_html"): 0o755,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s mode = %o, want %o", path, got, want)
		}
	}
}
