package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
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

type recordingOwnershipManager struct {
	paths []string
}

func (m *recordingOwnershipManager) ChownRecursive(_ context.Context, path, _ string) error {
	m.paths = append(m.paths, path)
	return nil
}

type linuxUserTestRunner struct {
	home       string
	username   string
	uid        int
	gid        int
	subUIDPath string
	subGIDPath string
	exists     bool
	calls      []string
}

func (r *linuxUserTestRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "getent":
		if !r.exists {
			return nil, errors.New("not found")
		}
		gid := r.gid
		if gid == 0 {
			gid = r.uid
		}
		return []byte(r.username + ":x:" + fmt.Sprint(r.uid) + ":" + fmt.Sprint(gid) + "::" + filepath.Join(r.home, r.username) + ":/usr/sbin/nologin\n"), nil
	case "useradd":
		r.exists = true
		return nil, nil
	case "usermod":
		if len(args) != 3 {
			return nil, errors.New("unexpected usermod arguments")
		}
		path := r.subUIDPath
		if args[0] == "--add-subgids" {
			path = r.subGIDPath
		}
		bounds := strings.Split(args[1], "-")
		if len(bounds) != 2 {
			return nil, errors.New("unexpected subordinate range")
		}
		start, err := strconv.ParseUint(bounds[0], 10, 64)
		if err != nil {
			return nil, err
		}
		end, err := strconv.ParseUint(bounds[1], 10, 64)
		if err != nil || end < start {
			return nil, errors.New("invalid subordinate range")
		}
		return nil, os.WriteFile(path, []byte(fmt.Sprintf("%s:%d:%d\n", args[2], start, end-start+1)), 0o600)
	case "userdel":
		r.exists = false
		return nil, nil
	default:
		return nil, nil
	}
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
			req:  types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "9.9;reboot"},
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

func TestLinuxUserManagerRefusesUnmarkedExistingAccount(t *testing.T) {
	home := t.TempDir()
	runner := &linuxUserTestRunner{home: home, username: "nps42", uid: 4242, exists: true}
	manager := NewLinuxUserManager(LinuxUserManagerOptions{
		HomeRoot: home, MarkerDir: filepath.Join(t.TempDir(), "markers"), Runner: runner,
	})
	err := manager.EnsureUser(context.Background(), runner.username)
	if err == nil || !strings.Contains(err.Error(), "ownership marker is missing") {
		t.Fatalf("unmarked existing account error = %v", err)
	}
}

// Missing or altered useradd range overrides would allow OS-dependent low IDs
// that can be occupied by base-system accounts on another supported release.
func TestLinuxUserManagerCreatesOnlyInDedicatedSystemIDRange(t *testing.T) {
	for _, uid := range []int{10000, 59999} {
		t.Run(strconv.Itoa(uid), func(t *testing.T) {
			home := t.TempDir()
			runner := &linuxUserTestRunner{home: home, username: "npsnew", uid: uid}
			manager := NewLinuxUserManager(LinuxUserManagerOptions{HomeRoot: home, MarkerDir: t.TempDir(), Runner: runner})
			if err := manager.EnsureUser(context.Background(), runner.username); err != nil {
				t.Fatal(err)
			}
			want := "useradd --system --user-group -K SYS_UID_MIN=10000 -K SYS_UID_MAX=59999 -K SYS_GID_MIN=10000 -K SYS_GID_MAX=59999 --home-dir " + filepath.Join(home, runner.username) + " --create-home --shell /usr/sbin/nologin " + runner.username
			if !slices.Contains(runner.calls, want) {
				t.Fatalf("creation did not constrain UID and GID allocation: %v", runner.calls)
			}
		})
	}
}

// A successful useradd command is insufficient: unexpected UID/GID results
// must be removed before Nakpanel writes an ownership marker.
func TestLinuxUserManagerRemovesOutOfRangeNewAccountBeforeMarking(t *testing.T) {
	for _, test := range []struct {
		name     string
		uid, gid int
	}{
		{"low_uid", 997, 10000},
		{"high_uid", 60000, 10000},
		{"low_gid", 10000, 996},
		{"high_gid", 10000, 60000},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			markers := t.TempDir()
			runner := &linuxUserTestRunner{home: home, username: "npsbad", uid: test.uid, gid: test.gid}
			manager := NewLinuxUserManager(LinuxUserManagerOptions{HomeRoot: home, MarkerDir: markers, Runner: runner})
			if err := manager.EnsureUser(context.Background(), runner.username); err == nil {
				t.Fatal("new account outside the dedicated UID/GID range was accepted")
			}
			if runner.exists || !slices.Contains(runner.calls, "userdel --remove npsbad") {
				t.Fatalf("unexpected new account was not removed: %v", runner.calls)
			}
			if _, err := os.Lstat(filepath.Join(markers, runner.username)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unexpected account left an ownership marker: %v", err)
			}
		})
	}
}

// Existing marked low IDs are valid historical identities and must never be
// silently allocated again, renumbered, or have their marker rewritten.
func TestLinuxUserManagerReusesExistingLowIDWithoutMutation(t *testing.T) {
	home := t.TempDir()
	markers := t.TempDir()
	runner := &linuxUserTestRunner{home: home, username: "npsold", uid: 997, gid: 995, exists: true}
	markerPath := filepath.Join(markers, runner.username)
	marker := []byte("997:" + filepath.Join(home, runner.username) + "\n")
	if err := os.WriteFile(markerPath, marker, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewLinuxUserManager(LinuxUserManagerOptions{HomeRoot: home, MarkerDir: markers, Runner: runner})
	for range 2 {
		if err := manager.EnsureUser(context.Background(), runner.username); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.Stat(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(marker) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("existing marker changed: %q", got)
	}
	if !slices.Equal(runner.calls, []string{"getent passwd npsold", "getent passwd npsold"}) {
		t.Fatalf("existing identity was mutated: %v", runner.calls)
	}
}

// At UID 59999 both generated subordinate ranges end at 4032159999, below
// Linux's last usable UID/GID (4294967294), and retain all 65536 IDs.
func TestLinuxUserManagerMaximumNewUIDHasUsableSubordinateRange(t *testing.T) {
	home := t.TempDir()
	subUIDPath, subGIDPath := filepath.Join(t.TempDir(), "subuid"), filepath.Join(t.TempDir(), "subgid")
	for _, path := range []string{subUIDPath, subGIDPath} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &linuxUserTestRunner{home: home, username: "npsmax", uid: 59999, subUIDPath: subUIDPath, subGIDPath: subGIDPath}
	manager := NewLinuxUserManager(LinuxUserManagerOptions{HomeRoot: home, MarkerDir: t.TempDir(), Runner: runner, ManageSubIDs: true, SubUIDPath: subUIDPath, SubGIDPath: subGIDPath})
	if err := manager.EnsureUser(context.Background(), runner.username); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{subUIDPath, subGIDPath} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "npsmax:4032094464:65536\n" {
			t.Fatalf("subordinate range = %q", got)
		}
	}
	for _, kind := range []string{"--add-subuids", "--add-subgids"} {
		want := "usermod " + kind + " 4032094464-4032159999 npsmax"
		if !slices.Contains(runner.calls, want) {
			t.Fatalf("maximum subordinate allocation was not usable: %v", runner.calls)
		}
	}
	const lastMappedID uint64 = 4032159999
	if lastMappedID > uint64(4294967294) {
		t.Fatal("subordinate mapping exceeds the Linux UID/GID limit")
	}
}

func TestLinuxUserManagerMarksNewAccountAndAllowsReuse(t *testing.T) {
	home := t.TempDir()
	markers := filepath.Join(t.TempDir(), "markers")
	runner := &linuxUserTestRunner{home: home, username: "nps43", uid: 43434}
	manager := NewLinuxUserManager(LinuxUserManagerOptions{HomeRoot: home, MarkerDir: markers, Runner: runner})
	if err := manager.EnsureUser(context.Background(), runner.username); err != nil {
		t.Fatal(err)
	}
	if err := manager.EnsureUser(context.Background(), runner.username); err != nil {
		t.Fatalf("marked account was not reusable: %v", err)
	}
	info, err := os.Stat(filepath.Join(markers, runner.username))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("marker mode = %o, want 600", info.Mode().Perm())
	}
}

func TestLinuxUserManagerSerializesConcurrentCreation(t *testing.T) {
	home := t.TempDir()
	markers := filepath.Join(t.TempDir(), "markers")
	runner := &linuxUserTestRunner{home: home, username: "nps45", uid: 45454}
	manager := NewLinuxUserManager(LinuxUserManagerOptions{HomeRoot: home, MarkerDir: markers, Runner: runner})

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- manager.EnsureUser(context.Background(), runner.username)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent EnsureUser returned %v", err)
		}
	}
	var userAdds int
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "useradd ") {
			userAdds++
		}
	}
	if userAdds != 1 {
		t.Fatalf("useradd calls = %d, want 1: %#v", userAdds, runner.calls)
	}
}

func TestLinuxUserManagerRecoversOwnedStaleMarker(t *testing.T) {
	home := t.TempDir()
	markers := filepath.Join(t.TempDir(), "markers")
	if err := os.MkdirAll(markers, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(markers, "nps46")
	if err := os.WriteFile(marker, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &linuxUserTestRunner{home: home, username: "nps46", uid: 46464}
	manager := NewLinuxUserManager(LinuxUserManagerOptions{HomeRoot: home, MarkerDir: markers, Runner: runner})
	if err := manager.EnsureUser(context.Background(), runner.username); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(contents)), "46464:"+filepath.Join(home, "nps46"); got != want {
		t.Fatalf("marker = %q, want %q", got, want)
	}
}

func TestLinuxUserManagerLegacyAdoptionIsExplicit(t *testing.T) {
	home := t.TempDir()
	runner := &linuxUserTestRunner{home: home, username: "legacyuser", uid: 4444, exists: true}
	manager := NewLinuxUserManager(LinuxUserManagerOptions{
		HomeRoot: home, MarkerDir: filepath.Join(t.TempDir(), "markers"), Runner: runner,
	})
	if err := manager.AdoptLegacyUser(context.Background(), runner.username); err != nil {
		t.Fatal(err)
	}
	if err := manager.EnsureUser(context.Background(), runner.username); err != nil {
		t.Fatalf("explicitly adopted legacy account was rejected: %v", err)
	}
}

func TestCreateSiteUsesTenantPrivateContentModes(t *testing.T) {
	root := t.TempDir()
	paths := SitePathConfig{
		HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available"),
		NginxEnabledDir: filepath.Join(root, "enabled"), NginxConfDir: filepath.Join(root, "conf"),
		NginxLogDir: filepath.Join(root, "logs"), NginxCacheDir: filepath.Join(root, "cache"),
		NginxProtectedDir: filepath.Join(root, "protected"), PHPFPMPoolDir: filepath.Join(root, "php"),
		PHPFPMLogDir: filepath.Join(root, "php-logs"), PHPRunDir: filepath.Join(root, "run"),
		PHPTmpDir: filepath.Join(root, "tmp"), NginxSnippet: "snippets/fastcgi-php.conf",
		WWWGroup: "www-data", DefaultFileMode: 0o640,
	}
	provisioner := NewSiteProvisioner(SiteProvisionerOptions{
		Paths: paths, UserManager: &recordingUserManager{}, Reloader: &recordingReloader{},
	})
	req := types.CreateSiteReq{Username: "nps44", Domain: "private.example.test", PHPVersion: "8.3"}
	if err := provisioner.CreateSite(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	plan, err := NewSitePlan(req, paths)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{plan.SiteHome: 0o700, plan.Docroot: 0o750} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s mode = %o, want %o", path, got, want)
		}
	}
}

func TestCreateSiteKeepsRuntimeArtifactsTenantPrivate(t *testing.T) {
	root := t.TempDir()
	paths := SitePathConfig{
		HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available"),
		NginxEnabledDir: filepath.Join(root, "enabled"), NginxConfDir: filepath.Join(root, "conf"),
		NginxLogDir: filepath.Join(root, "logs"), NginxCacheDir: filepath.Join(root, "cache"),
		NginxProtectedDir: filepath.Join(root, "protected"), PHPFPMPoolDir: filepath.Join(root, "php"),
		PHPFPMLogDir: filepath.Join(root, "php-logs"), PHPRunDir: filepath.Join(root, "run"),
		PHPTmpDir: filepath.Join(root, "tmp"), NginxSnippet: "snippets/fastcgi-php.conf",
		WWWGroup: "www-data", DefaultFileMode: 0o644,
	}
	req := types.CreateSiteReq{SiteID: 44, Username: "nps44", Domain: "private.example.test", PHPVersion: "8.3"}
	plan, err := NewSitePlan(req, paths)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{plan.NginxAccessLog, plan.NginxErrorLog, plan.PHPFPMErrorLog} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("existing\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	provisioner := NewSiteProvisioner(SiteProvisionerOptions{
		Paths: paths, UserManager: &recordingUserManager{}, Reloader: &recordingReloader{},
	})
	if err := provisioner.CreateSite(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		plan.NginxConfig, plan.PHPFPMConfig, plan.NginxAccessLog, plan.NginxErrorLog, plan.PHPFPMErrorLog,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %o, want 600", path, got)
		}
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
		"clear_env = yes",
		"security.limit_extensions = .php",
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

func TestApplySiteRuntimeInitializesManagedIncludesForExistingSite(t *testing.T) {
	root := t.TempDir()
	paths := SitePathConfig{
		HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available"),
		NginxEnabledDir: filepath.Join(root, "enabled"), NginxLogDir: filepath.Join(root, "logs"),
		PHPFPMPoolDir: filepath.Join(root, "php"), PHPFPMLogDir: filepath.Join(root, "php-logs"),
		PHPRunDir: filepath.Join(root, "run"), NginxSnippet: "snippets/fastcgi-php.conf",
		WWWGroup: "www-data", PHPTmpDir: filepath.Join(root, "tmp"), DefaultFileMode: 0o644,
	}
	p := NewSiteProvisioner(SiteProvisionerOptions{Paths: paths, Reloader: &recordingReloader{}})
	req := types.ApplySiteRuntimeReq{
		SiteID: 7, Username: "npdemo", Domain: "example.test",
		CurrentPHPVersion: "8.3", DesiredPHPVersion: "8.3", State: "active",
	}
	if err := p.ApplySiteRuntime(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	plan, err := NewSitePlan(types.CreateSiteReq{
		SiteID: 7, Username: "npdemo", Domain: "example.test", PHPVersion: "8.3",
	}, paths)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{plan.NginxProtectedConfig, plan.NginxApplicationConfig} {
		if content, err := os.ReadFile(path); err != nil || !strings.Contains(string(content), "Managed by Nakpanel") {
			t.Fatalf("managed include %s = %q, %v", path, content, err)
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

func TestNewSitePlanIsolatesDedicatedPathsForCustomHomeRoot(t *testing.T) {
	root := t.TempDir()
	plan, err := NewSitePlan(types.CreateSiteReq{
		SiteID: 17, SubscriptionID: 4, Username: "npdemo",
		Domain: "example.test", PHPVersion: "8.3", SharedAccount: true,
	}, SitePathConfig{HomeRoot: filepath.Join(root, "home")})
	if err != nil {
		t.Fatalf("NewSitePlan returned error: %v", err)
	}
	for label, path := range map[string]string{
		"config": plan.PHPFPMConfig,
		"socket": plan.PHPFPMSocket,
		"unit":   plan.PHPServiceUnit,
	} {
		if !strings.HasPrefix(path, root+string(filepath.Separator)) {
			t.Fatalf("dedicated PHP %s escaped custom root: %q", label, path)
		}
	}
}

func TestRenderPHPFPMUnitPreservesSharedRuntimeDirectory(t *testing.T) {
	unit := RenderPHPFPMUnit(SitePlan{
		SiteID:         7,
		PHPVersion:     "8.4",
		PHPFPMConfig:   "/etc/nakpanel/php-fpm/sites/7.conf",
		PHPFPMSocket:   "/run/nakpanel-php/site-7.sock",
		PHPFPMErrorLog: "/var/log/php-fpm/site-7.log",
		Docroot:        "/home/client/domains/example.test/public_html",
		PHPTmpDir:      "/home/client/tmp",
	})
	if !strings.Contains(unit, "RuntimeDirectory=nakpanel-php") || !strings.Contains(unit, "RuntimeDirectoryPreserve=yes") {
		t.Fatalf("shared PHP runtime directory can be removed when one site stops:\n%s", unit)
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
	if got, want := homeInfo.Mode().Perm(), os.FileMode(0o700); got != want {
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
	ownership := &recordingOwnershipManager{}
	p := NewSiteProvisioner(SiteProvisionerOptions{
		Paths: paths, UserManager: &recordingUserManager{}, OwnershipManager: ownership, Reloader: &recordingReloader{},
	})
	if err := p.CreateSite(context.Background(), types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3", SharedAccount: true}); err != nil {
		t.Fatal(err)
	}
	documentRoot := filepath.Join(home, "domains", "example.test", "public_html")
	if !slices.Equal(ownership.paths, []string{documentRoot}) {
		t.Fatalf("ownership paths = %v, want only %q", ownership.paths, documentRoot)
	}
	for path, want := range map[string]os.FileMode{
		filepath.Join(home, "domains"):                 0o711,
		filepath.Join(home, "domains", "example.test"): 0o711,
		documentRoot: 0o750,
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

func TestSubordinateIDRangeReadyRequiresFullAllocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subuid")
	content := strings.Join([]string{
		"other:100000:65536",
		"short:200000:4096",
		"malformed:not-a-number:65536",
		"ready:300000:65536",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		username string
		want     bool
	}{
		{username: "ready", want: true},
		{username: "short", want: false},
		{username: "malformed", want: false},
		{username: "missing", want: false},
	} {
		got, err := subordinateIDRangeReady(path, test.username, 65536)
		if err != nil {
			t.Fatalf("subordinateIDRangeReady(%q): %v", test.username, err)
		}
		if got != test.want {
			t.Fatalf("subordinateIDRangeReady(%q) = %v, want %v", test.username, got, test.want)
		}
	}
}
