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

type recordingDiskQuotaManager struct {
	username string
	path     string
	limitMB  int
	calls    int
}

func (m *recordingDiskQuotaManager) ApplyUserQuota(ctx context.Context, username, path string, limitMB int) error {
	m.username = username
	m.path = path
	m.limitMB = limitMB
	m.calls++
	return nil
}

func TestRenderPHPFPMPoolUsesResourceLimits(t *testing.T) {
	plan, err := NewSitePlan(types.CreateSiteReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
		Limits: types.SiteResourceLimits{
			PHPFPMMaxChildren: 3,
			PHPMemoryMB:       64,
		},
	}, SitePathConfig{})
	if err != nil {
		t.Fatalf("NewSitePlan returned error: %v", err)
	}

	pool := RenderPHPFPMPool(plan)
	for _, want := range []string{
		"pm.max_children = 3",
		"php_admin_value[memory_limit] = 64M",
	} {
		if !strings.Contains(pool, want) {
			t.Fatalf("PHP-FPM pool missing %q:\n%s", want, pool)
		}
	}
}

func TestSiteProvisionerAppliesUserDiskQuota(t *testing.T) {
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
	quota := &recordingDiskQuotaManager{}
	provisioner := NewSiteProvisioner(SiteProvisionerOptions{
		Paths:            paths,
		UserManager:      &recordingUserManager{},
		OwnershipManager: NewLinuxOwnershipManager(noopCommandRunner{}),
		DiskQuotaManager: quota,
		Reloader:         &recordingReloader{},
	})

	err := provisioner.CreateSite(context.Background(), types.CreateSiteReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
		Limits:     types.SiteResourceLimits{DiskQuotaMB: 256},
	})
	if err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}
	if quota.calls != 1 || quota.username != "npdemo" || quota.limitMB != 256 {
		t.Fatalf("quota call = %#v, want npdemo 256MB", quota)
	}
	if got, want := quota.path, filepath.Join(paths.HomeRoot, "npdemo"); got != want {
		t.Fatalf("quota path = %q, want %q", got, want)
	}
}

func TestLinuxDiskQuotaManagerUsesFindmntAndSetquota(t *testing.T) {
	runner := &quotaCommandRunner{}
	manager := NewLinuxDiskQuotaManager(runner)

	if err := manager.ApplyUserQuota(context.Background(), "npdemo", "/home/npdemo", 512); err != nil {
		t.Fatalf("ApplyUserQuota returned error: %v", err)
	}

	want := []commandCall{
		{name: "findmnt", args: []string{"-n", "-o", "TARGET", "--target", "/home/npdemo"}},
		{name: "setquota", args: []string{"-u", "npdemo", "0", "524288", "0", "0", "/"}},
	}
	if len(runner.calls) != len(want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
	for i := range want {
		if runner.calls[i].name != want[i].name || !slices.Equal(runner.calls[i].args, want[i].args) {
			t.Fatalf("call %d = %#v, want %#v", i, runner.calls[i], want[i])
		}
	}
}

type noopCommandRunner struct{}

func (noopCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "chown" {
		return nil, nil
	}
	return nil, nil
}

type quotaCommandRunner struct {
	calls []commandCall
}

func (r *quotaCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, commandCall{name: name, args: append([]string(nil), args...)})
	if name == "findmnt" {
		return []byte("/\n"), nil
	}
	return nil, nil
}

var _ = os.FileMode(0)
