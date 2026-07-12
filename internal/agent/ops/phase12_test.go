package ops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestSetHostingStateIsReversibleAndIdempotent(t *testing.T) {
	tmp := t.TempDir()
	paths := SitePathConfig{
		HomeRoot: filepath.Join(tmp, "home"), NginxAvailableDir: filepath.Join(tmp, "nginx", "available"),
		NginxEnabledDir: filepath.Join(tmp, "nginx", "enabled"), NginxLogDir: filepath.Join(tmp, "logs", "nginx"),
		PHPFPMPoolDir: filepath.Join(tmp, "php", "pool.d"), PHPFPMLogDir: filepath.Join(tmp, "logs", "php"),
		PHPRunDir: filepath.Join(tmp, "run", "php"), NginxSnippet: "snippets/fastcgi-php.conf",
		WWWGroup: "www-data", PHPTmpDir: filepath.Join(tmp, "tmp"), DefaultFileMode: 0o644,
	}
	reloader := &recordingReloader{}
	provisioner := NewSiteProvisioner(SiteProvisionerOptions{Paths: paths, UserManager: &recordingUserManager{}, Reloader: reloader})
	req := types.CreateSiteReq{Username: "provider", Domain: "provider.test", PHPVersion: "8.3"}
	if err := provisioner.CreateSite(context.Background(), req); err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	plan, err := NewSitePlan(req, paths)
	if err != nil {
		t.Fatal(err)
	}
	webmail := filepath.Join(paths.NginxEnabledDir, "webmail.provider.test.conf")
	if err := os.WriteFile(webmail, []byte("webmail"), 0o644); err != nil {
		t.Fatal(err)
	}
	reloader.services = nil

	state := types.SetHostingStateReq{Username: req.Username, Domain: req.Domain, PHPVersion: req.PHPVersion, State: "suspended"}
	for i := 0; i < 2; i++ {
		if err := provisioner.SetHostingState(context.Background(), state); err != nil {
			t.Fatalf("suspend pass %d: %v", i+1, err)
		}
	}
	nginx, err := os.ReadFile(plan.NginxConfig)
	if err != nil || !strings.Contains(string(nginx), "return 503;") || !strings.Contains(string(nginx), "Retry-After") {
		t.Fatalf("suspended nginx config = %q, %v", nginx, err)
	}
	if _, err := os.Stat(plan.PHPFPMConfig + ".suspended"); err != nil {
		t.Fatalf("suspended PHP-FPM pool: %v", err)
	}
	if _, err := os.Stat(webmail + ".suspended"); err != nil {
		t.Fatalf("suspended webmail config: %v", err)
	}
	if got := strings.Join(reloader.services[:3], ","); got != "nginx,php8.3-fpm,nginx" {
		t.Fatalf("suspension reload order = %q, want nginx,php8.3-fpm,nginx", got)
	}

	state.State = "active"
	for i := 0; i < 2; i++ {
		if err := provisioner.SetHostingState(context.Background(), state); err != nil {
			t.Fatalf("activate pass %d: %v", i+1, err)
		}
	}
	nginx, err = os.ReadFile(plan.NginxConfig)
	if err != nil || !strings.Contains(string(nginx), "fastcgi_pass") || strings.Contains(string(nginx), "return 503") {
		t.Fatalf("active nginx config = %q, %v", nginx, err)
	}
	if _, err := os.Stat(plan.PHPFPMConfig); err != nil {
		t.Fatalf("active PHP-FPM pool: %v", err)
	}
	if _, err := os.Stat(webmail); err != nil {
		t.Fatalf("active webmail config: %v", err)
	}
}
