package ops

import (
	"context"
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
