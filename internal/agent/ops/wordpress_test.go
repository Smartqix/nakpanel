package ops

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type wordpressCommand struct {
	name string
	args []string
}

type wordpressRunner struct {
	commands []wordpressCommand
	inputs   [][]byte
	outputs  map[string][]byte
	fail     map[string]error
	onRun    func(string, []string)
}

func (r *wordpressRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.commands = append(r.commands, wordpressCommand{name: name, args: append([]string(nil), args...)})
	if r.onRun != nil {
		r.onRun(name, args)
	}
	key := wordpressCommandKey(name, args)
	if err := r.fail[key]; err != nil {
		return nil, err
	}
	return append([]byte(nil), r.outputs[key]...), nil
}

func (r *wordpressRunner) RunInput(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	r.inputs = append(r.inputs, append([]byte(nil), input...))
	return r.Run(ctx, name, args...)
}

func wordpressCommandKey(name string, args []string) string {
	return name + "\x00" + strings.Join(args, "\x00")
}

func wordpressSpec() types.WordPressSiteSpec {
	return types.WordPressSiteSpec{
		InstanceID: 1, SubscriptionID: 2, SiteID: 3, DesiredRevision: 1,
		Username: "npdemo", Domain: "example.test", PHPVersion: "8.4",
		HostingMode: types.PHPHostingModeClassic,
		Policy: types.HostingPolicy{SchemaVersion: 4,
			Resources:   types.HostingResourcePolicy{MaxWordPressSites: 1},
			Permissions: types.HostingPermissionPolicy{Hosting: true, WordPressToolkit: true}},
	}
}

func newWordPressProvisionerForTest(t *testing.T, runner *wordpressRunner) *WordPressProvisioner {
	t.Helper()
	root := t.TempDir()
	return NewWordPressProvisioner(WordPressProvisionerOptions{
		HomeRoot: filepath.Join(root, "home"), WPBinary: "/usr/local/bin/wp", Runner: runner,
		LookupUser: func(string) (*user.User, error) { return &user.User{Uid: "501", Gid: "20", Username: "npdemo"}, nil },
		Chown:      func(string, int, int) error { return nil },
	})
}

func TestWordPressProvisionerDerivesDocumentRootAndRejectsManagedSites(t *testing.T) {
	p := newWordPressProvisionerForTest(t, &wordpressRunner{})
	spec := wordpressSpec()
	want := filepath.Join(p.homeRoot, "npdemo", "domains", "example.test", "public_html")
	got, err := p.documentRoot(spec)
	if err != nil || got != want {
		t.Fatalf("documentRoot = %q, %v; want %q", got, err, want)
	}
	spec.HostingMode = types.PHPHostingModeManaged
	if _, err := p.InspectWordPress(context.Background(), types.WordPressOperationReq{Action: types.WordPressActionInspect, Site: spec}); err == nil {
		t.Fatal("managed PHP site was accepted")
	}
}

func TestWordPressInstallURLUsesObservedTLS(t *testing.T) {
	site := wordpressSpec()
	if got := wordpressInstallURL(site); got != "http://example.test" {
		t.Fatalf("site without TLS URL = %q", got)
	}
	site.TLSActive = true
	if got := wordpressInstallURL(site); got != "https://example.test" {
		t.Fatalf("site with TLS URL = %q", got)
	}
}

func TestInstallWordPressNeverPlacesCredentialsInCommandArgumentsAndCleansBootstrap(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, err := p.documentRoot(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "index.php"), []byte(renderPlaceholderIndex(SitePlan{Domain: spec.Domain})), 0o640); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(filepath.Dir(root), ".nakpanel-wordpress-install-11")
	versionCommand := []string{"-u", spec.Username, "--", p.wpBinary, "--path=" + stage, "--no-color", "core", "version"}
	runner.outputs[wordpressCommandKey("runuser", versionCommand)] = []byte("7.1\n")
	request := types.WordPressOperationReq{OperationID: 11, Action: types.WordPressActionInstall, Site: spec,
		RequestedVersion: "7.1", Credentials: &types.WordPressCredentials{
			DatabaseName: "np_wp", DatabaseUser: "np_wp_user", DatabasePassword: "database-secret-1",
			AdminUser: "siteadmin", AdminEmail: "admin@example.test", AdminPassword: "admin-secret", SiteTitle: "Example",
		}}
	if _, err := p.InstallWordPress(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if strings.Contains(joined, "database-secret-1") || strings.Contains(joined, "admin-secret") {
			t.Fatalf("credential leaked into command: %s %s", command.name, joined)
		}
	}
	downloadIndex, checksumIndex := -1, -1
	for index, command := range runner.commands {
		if slices.Contains(command.args, "download") {
			downloadIndex = index
			if !slices.Contains(command.args, "https://wordpress.org/wordpress-7.1.zip") {
				t.Fatalf("WordPress download did not use the fixed official ZIP: %v", command.args)
			}
			if slices.Contains(command.args, "--version=7.1") {
				t.Fatalf("WordPress URL download used WP-CLI's incompatible version option: %v", command.args)
			}
		}
		if slices.Contains(command.args, "verify-checksums") {
			checksumIndex = index
		}
	}
	if downloadIndex < 0 || checksumIndex <= downloadIndex {
		t.Fatalf("WordPress core was not verified after download: %#v", runner.commands)
	}
	if len(runner.inputs) != 1 || string(runner.inputs[0]) != "admin-secret\n" {
		t.Fatalf("WordPress install input = %q, want one password prompt response", runner.inputs)
	}
	installCommand := runner.commands[len(runner.commands)-1].args
	if !slices.Contains(installCommand, "install") || !slices.Contains(installCommand, "--prompt=admin_password") ||
		!slices.Contains(installCommand, "--url=http://example.test") {
		t.Fatalf("WordPress install command does not use protected prompt input: %v", installCommand)
	}
	if !slices.Contains(installCommand, "--path="+stage) {
		t.Fatalf("WordPress was bootstrapped after activation instead of in staging: %v", installCommand)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".nakpanel-wordpress-") {
			t.Fatalf("temporary credential file remains: %s", entry.Name())
		}
	}
	config, err := os.ReadFile(filepath.Join(root, "wp-config.php"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "database-secret-1") || !strings.Contains(string(config), "DISALLOW_FILE_EDIT") {
		t.Fatalf("generated config is incomplete: %s", config)
	}
}

func TestInstallWordPressRefusesModifiedPlaceholderOrCustomerContent(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, err := p.documentRoot(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php echo 'customer content';\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	request := types.WordPressOperationReq{OperationID: 12, Action: types.WordPressActionInstall, Site: spec,
		RequestedVersion: "7.1", Credentials: &types.WordPressCredentials{
			DatabaseName: "np_wp", DatabaseUser: "np_wp_user", DatabasePassword: "database-secret-1",
			AdminUser: "siteadmin", AdminEmail: "admin@example.test", AdminPassword: "admin-secret", SiteTitle: "Example",
		}}
	if _, err = p.InstallWordPress(context.Background(), request); err == nil || !strings.Contains(err.Error(), "empty document root") {
		t.Fatalf("customer content rejection = %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("customer content triggered WP-CLI: %#v", runner.commands)
	}
}

func TestInstallWordPressStagesFailedDownloadWithoutPollutingLiveRoot(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, err := p.documentRoot(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(filepath.Dir(root), ".nakpanel-wordpress-install-19")
	download := []string{"-u", spec.Username, "--", p.wpBinary, "--path=" + stage, "--no-color", "core", "download", "https://wordpress.org/wordpress-7.1.zip", "--force"}
	runner.fail[wordpressCommandKey("runuser", download)] = errors.New("download interrupted")
	runner.onRun = func(_ string, args []string) {
		if slices.Contains(args, "download") {
			if writeErr := os.WriteFile(filepath.Join(stage, "partial.php"), []byte("partial"), 0o640); writeErr != nil {
				t.Fatal(writeErr)
			}
		}
	}
	req := types.WordPressOperationReq{OperationID: 19, Action: types.WordPressActionInstall, Site: spec, RequestedVersion: "7.1", Credentials: &types.WordPressCredentials{
		DatabaseName: "np_wp", DatabaseUser: "np_wp_user", DatabasePassword: "database-secret-1",
		AdminUser: "siteadmin", AdminEmail: "admin@example.test", AdminPassword: "admin-secret", SiteTitle: "Example",
	}}
	if _, err = p.InstallWordPress(context.Background(), req); err == nil {
		t.Fatal("failed staged download was accepted")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed staged download polluted live document root: %v", entries)
	}
	if _, err = os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("failed staging directory remains: %v", err)
	}
}

func TestRunWordPressInstallRetryObservesMatchingExistingInstallation(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, _ := p.documentRoot(spec)
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-load.php"), []byte("<?php"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte("<?php\ndefine('DB_NAME', 'np_wp');\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.setTestWPOutput(runner, spec, []string{"core", "version"}, []byte("7.1\n"))
	p.setTestWPIdentityOutputs(runner, spec)
	p.setTestWPOutput(runner, spec, []string{"option", "get", "siteurl"}, []byte("https://example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"option", "get", "home"}, []byte("https://example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"plugin", "list", "--format=json"}, []byte(`[]`))
	p.setTestWPOutput(runner, spec, []string{"theme", "list", "--format=json"}, []byte(`[]`))
	p.setTestWPOutput(runner, spec, []string{"core", "check-update", "--format=json"}, []byte(`[]`))
	p.setTestWPOutput(runner, spec, []string{"core", "verify-checksums"}, []byte("Success\n"))
	req := types.WordPressOperationReq{OperationID: 17, Action: types.WordPressActionInstall, Site: spec, RequestedVersion: "7.1", Credentials: &types.WordPressCredentials{
		DatabaseName: "np_wp", DatabaseUser: "np_wp_user", DatabasePassword: "database-secret-1",
		AdminUser: "siteadmin", AdminEmail: "admin@example.test", AdminPassword: "admin-secret", SiteTitle: "Example",
	}}
	result, err := p.RunWordPress(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Inventory.CoreVersion != "7.1" {
		t.Fatalf("idempotent install retry = %#v", result)
	}
	for _, command := range runner.commands {
		if slices.Contains(command.args, "download") || slices.Contains(command.args, "eval-file") {
			t.Fatalf("install retry mutated an existing matching installation: %v", command.args)
		}
	}
}

func TestWordPressConfigSymlinkIsNeverReadOrRewrittenByRoot(t *testing.T) {
	p := newWordPressProvisionerForTest(t, &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}})
	spec := wordpressSpec()
	root, _ := p.documentRoot(spec)
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-load.php"), []byte("<?php"), 0o640); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "root-owned-secret")
	const sentinel = "must-not-be-copied-into-the-site"
	if err := os.WriteFile(external, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "wp-config.php")
	if err := os.Symlink(external, config); err != nil {
		t.Fatal(err)
	}
	if matchingWordPressInstall(root, "np_wp") {
		t.Fatal("symlinked wp-config.php was trusted as a matching installation")
	}
	if _, err := p.hardenWordPress(context.Background(), types.WordPressOperationReq{OperationID: 20, Action: types.WordPressActionHarden, Site: spec}); err == nil {
		t.Fatal("hardening followed a symlinked wp-config.php")
	}
	data, err := os.ReadFile(external)
	if err != nil || string(data) != sentinel {
		t.Fatalf("external file changed: %q, %v", data, err)
	}
}

func TestWordPressHardeningRejectsSymlinkedDocumentRootBeforeMutation(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, err := p.documentRoot(spec)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	configPath := filepath.Join(outside, "wp-config.php")
	original := "<?php\ndefine('WP_DEBUG', true);\n"
	if err = os.WriteFile(filepath.Join(outside, "wp-load.php"), []byte("<?php"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(root), 0o750); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}

	if _, err = p.hardenWordPress(context.Background(), types.WordPressOperationReq{OperationID: 29, Action: types.WordPressActionHarden, Site: spec}); err == nil {
		t.Fatal("hardening accepted a symlinked WordPress document root")
	}
	after, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != original {
		t.Fatalf("hardening mutated the symlink target before rejecting it: %q", after)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("hardening executed WP-CLI through a symlinked root: %#v", runner.commands)
	}
}

func TestWordPressHardeningPreservesCrossSubscriptionFileIsolation(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, _ := p.documentRoot(spec)
	content := filepath.Join(root, "wp-content", "plugins")
	if err := os.MkdirAll(content, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-load.php"), []byte("<?php"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte("<?php\ndefine('WP_DEBUG', false);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(content, "plugin.php")
	if err := os.WriteFile(plugin, []byte("<?php"), 0o640); err != nil {
		t.Fatal(err)
	}
	p.setTestWPOutput(runner, spec, []string{"option", "get", "siteurl"}, []byte("https://example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"core", "verify-checksums"}, []byte("Success\n"))
	if _, err := p.hardenWordPress(context.Background(), types.WordPressOperationReq{OperationID: 21, Action: types.WordPressActionHarden, Site: spec}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, content} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0o007 != 0 {
			t.Fatalf("directory %s is accessible to unrelated accounts: mode=%v err=%v", path, info.Mode(), err)
		}
	}
	for _, path := range []string{plugin, filepath.Join(root, "wp-load.php")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0o007 != 0 {
			t.Fatalf("file %s is accessible to unrelated accounts: mode=%v err=%v", path, info.Mode(), err)
		}
	}
	config, err := os.Stat(filepath.Join(root, "wp-config.php"))
	if err != nil || config.Mode().Perm() != 0o600 {
		t.Fatalf("wp-config.php mode=%v err=%v", config.Mode(), err)
	}
}

func TestWordPressHardeningCorrectsExplicitlyUnsafeBooleanSettings(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, err := p.documentRoot(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "wp-load.php"), []byte("<?php"), 0o640); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "wp-config.php")
	config := "<?php\ndefine(\"DISALLOW_FILE_EDIT\", false);\ndefine('WP_DEBUG', true);\n"
	if err = os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	p.setTestWPOutput(runner, spec, []string{"option", "get", "siteurl"}, []byte("https://example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"core", "verify-checksums"}, []byte("Success\n"))

	result, err := p.hardenWordPress(context.Background(), types.WordPressOperationReq{OperationID: 30, Action: types.WordPressActionHarden, Site: spec})
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !wordpressFileEditDisabledRE.Match(after) || !wordpressDebugDisabledRE.Match(after) {
		t.Fatalf("hardening did not converge WordPress booleans: %s", after)
	}
	if !result.Security.FileEditingDisabled || !result.Security.DebugDisabled {
		t.Fatalf("hardening security result = %#v", result.Security)
	}
}

func TestInspectWordPressReturnsBoundedTypedInventory(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, _ := p.documentRoot(spec)
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-load.php"), []byte("<?php"), 0o640); err != nil {
		t.Fatal(err)
	}
	p.commandOutputLimit = 4096
	p.setTestWPOutput(runner, spec, []string{"core", "version"}, []byte("7.1\n"))
	p.setTestWPIdentityOutputs(runner, spec)
	p.setTestWPOutput(runner, spec, []string{"option", "get", "siteurl"}, []byte("https://example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"option", "get", "home"}, []byte("https://example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"option", "get", "blogname"}, []byte("Example publishing\n"))
	p.setTestWPOutput(runner, spec, []string{"option", "get", "admin_email"}, []byte("owner@example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"user", "list", "--role=administrator", "--fields=user_login", "--format=json"}, []byte(`[{"user_login":"siteadmin"}]`))
	p.setTestWPOutput(runner, spec, []string{"plugin", "list", "--format=json"}, []byte(`[{"name":"akismet","status":"active","version":"5.4","update":"available","update_version":"5.5","auto_update":"off"}]`))
	p.setTestWPOutput(runner, spec, []string{"theme", "list", "--format=json"}, []byte(`[{"name":"twentytwentyfive","status":"active","version":"1.0","update":"none","update_version":"","auto_update":"off"}]`))
	p.setTestWPOutput(runner, spec, []string{"core", "check-update", "--format=json"}, []byte(`[]`))
	p.setTestWPOutput(runner, spec, []string{"core", "verify-checksums"}, []byte("Success: WordPress installation verifies against checksums.\n"))

	result, err := p.InspectWordPress(context.Background(), types.WordPressOperationReq{OperationID: 12, Action: types.WordPressActionInspect, Site: spec})
	if err != nil {
		t.Fatal(err)
	}
	if result.Inventory.CoreVersion != "7.1" || result.Inventory.SiteURL != "https://example.test" || len(result.Inventory.Plugins) != 1 || result.Inventory.Plugins[0].Slug != "akismet" {
		t.Fatalf("inventory = %#v", result.Inventory)
	}
	if result.Inventory.SiteTitle != "Example publishing" || result.Inventory.AdminUser != "siteadmin" || result.Inventory.AdminEmail != "owner@example.test" {
		t.Fatalf("discovered identity = %#v", result.Inventory)
	}
	if !result.Security.CoreChecksumsValid {
		t.Fatalf("security = %#v", result.Security)
	}
}

func TestInspectWordPressReportsHTTPSFromObservedSiteURL(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, _ := p.documentRoot(spec)
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-load.php"), []byte("<?php"), 0o640); err != nil {
		t.Fatal(err)
	}
	p.setTestWPOutput(runner, spec, []string{"core", "version"}, []byte("7.1\n"))
	p.setTestWPIdentityOutputs(runner, spec)
	p.setTestWPOutput(runner, spec, []string{"option", "get", "siteurl"}, []byte("http://example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"option", "get", "home"}, []byte("http://example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"plugin", "list", "--format=json"}, []byte(`[]`))
	p.setTestWPOutput(runner, spec, []string{"theme", "list", "--format=json"}, []byte(`[]`))
	p.setTestWPOutput(runner, spec, []string{"core", "check-update", "--format=json"}, []byte(`[]`))
	p.setTestWPOutput(runner, spec, []string{"core", "verify-checksums"}, []byte("Success\n"))

	result, err := p.InspectWordPress(context.Background(), types.WordPressOperationReq{OperationID: 15, Action: types.WordPressActionInspect, Site: spec})
	if err != nil {
		t.Fatal(err)
	}
	if result.Security.HTTPSConfigured {
		t.Fatalf("HTTP site was reported as HTTPS configured: %#v", result.Security)
	}
}

func TestRunWordPressRefreshesInventoryAfterMutation(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, _ := p.documentRoot(spec)
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-load.php"), []byte("<?php"), 0o640); err != nil {
		t.Fatal(err)
	}
	p.setTestWPOutput(runner, spec, []string{"core", "version"}, []byte("7.1\n"))
	p.setTestWPIdentityOutputs(runner, spec)
	p.setTestWPOutput(runner, spec, []string{"option", "get", "siteurl"}, []byte("https://example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"option", "get", "home"}, []byte("https://example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"plugin", "list", "--format=json"}, []byte(`[]`))
	p.setTestWPOutput(runner, spec, []string{"theme", "list", "--format=json"}, []byte(`[]`))
	p.setTestWPOutput(runner, spec, []string{"core", "check-update", "--format=json"}, []byte(`[]`))
	p.setTestWPOutput(runner, spec, []string{"core", "verify-checksums"}, []byte("Success\n"))

	result, err := p.RunWordPress(context.Background(), types.WordPressOperationReq{OperationID: 16, Action: types.WordPressActionUpdate, Site: spec, TargetType: types.WordPressTargetCore})
	if err != nil {
		t.Fatal(err)
	}
	if result.Inventory.CoreVersion != "7.1" || result.Inventory.SiteURL != "https://example.test" || !result.Security.HTTPSConfigured {
		t.Fatalf("mutation result did not include refreshed inventory: %#v", result)
	}
}

func TestVerifyWordPressReturnsCompleteInventoryWithSecurity(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, err := p.documentRoot(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "wp-load.php"), []byte("<?php"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "wp-config.php"), []byte("<?php\ndefine('DISALLOW_FILE_EDIT', true);\ndefine('WP_DEBUG', false);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.setTestWPOutput(runner, spec, []string{"core", "version"}, []byte("7.1\n"))
	p.setTestWPIdentityOutputs(runner, spec)
	p.setTestWPOutput(runner, spec, []string{"option", "get", "siteurl"}, []byte("https://example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"option", "get", "home"}, []byte("https://example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"plugin", "list", "--format=json"}, []byte(`[]`))
	p.setTestWPOutput(runner, spec, []string{"theme", "list", "--format=json"}, []byte(`[]`))
	p.setTestWPOutput(runner, spec, []string{"core", "check-update", "--format=json"}, []byte(`[]`))
	p.setTestWPOutput(runner, spec, []string{"core", "verify-checksums"}, []byte("Success\n"))

	result, err := p.RunWordPress(context.Background(), types.WordPressOperationReq{
		OperationID: 31, Action: types.WordPressActionVerify, Site: spec,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Inventory.CoreVersion != "7.1" || result.Inventory.CollectedAt.IsZero() || !result.Security.CoreChecksumsValid {
		t.Fatalf("verify result was incomplete: %#v", result)
	}
}

func TestWordPressPasswordResetUsesProtectedInputWithoutCredentialFile(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, err := p.documentRoot(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "wp-load.php"), []byte("<?php"), 0o640); err != nil {
		t.Fatal(err)
	}

	password := "replacement-admin-secret"
	_, err = p.resetWordPressPassword(context.Background(), types.WordPressOperationReq{
		OperationID: 23,
		Action:      types.WordPressActionPasswordReset,
		Site:        spec,
		Credentials: &types.WordPressCredentials{AdminUser: "siteadmin", AdminPassword: password},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.inputs) != 1 || string(runner.inputs[0]) != password+"\n" {
		t.Fatalf("password reset input = %q, want one protected prompt response", runner.inputs)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("password reset commands = %#v, want one command", runner.commands)
	}
	command := runner.commands[0].args
	if !slices.Contains(command, "user") || !slices.Contains(command, "update") ||
		!slices.Contains(command, "siteadmin") || !slices.Contains(command, "--prompt=user_pass") {
		t.Fatalf("password reset command does not use the protected WP-CLI prompt: %v", command)
	}
	if strings.Contains(strings.Join(command, " "), password) {
		t.Fatalf("password reset leaked the secret into command arguments: %v", command)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".nakpanel-wordpress-") {
			t.Fatalf("password reset left a credential file: %s", entry.Name())
		}
	}
}

func (p *WordPressProvisioner) setTestWPOutput(runner *wordpressRunner, spec types.WordPressSiteSpec, args []string, output []byte) {
	root, _ := p.documentRoot(spec)
	full := []string{"-u", spec.Username, "--", p.wpBinary, "--path=" + root, "--no-color"}
	full = append(full, args...)
	runner.outputs[wordpressCommandKey("runuser", full)] = output
}

func (p *WordPressProvisioner) setTestWPIdentityOutputs(runner *wordpressRunner, spec types.WordPressSiteSpec) {
	p.setTestWPOutput(runner, spec, []string{"option", "get", "blogname"}, []byte("Example\n"))
	p.setTestWPOutput(runner, spec, []string{"option", "get", "admin_email"}, []byte("admin@example.test\n"))
	p.setTestWPOutput(runner, spec, []string{"user", "list", "--role=administrator", "--orderby=ID", "--order=ASC", "--fields=user_login", "--format=json"}, []byte(`[{"user_login":"siteadmin"}]`))
}

func TestWordPressUpdateAcceptsOnlyTypedTargets(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, _ := p.documentRoot(spec)
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-load.php"), []byte("<?php"), 0o640); err != nil {
		t.Fatal(err)
	}
	request := types.WordPressOperationReq{OperationID: 13, Action: types.WordPressActionUpdate, Site: spec, TargetType: types.WordPressTargetPlugin, TargetSlug: "akismet"}
	if _, err := p.UpdateWordPress(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	last := runner.commands[len(runner.commands)-1].args
	if !slices.Contains(last, "plugin") || !slices.Contains(last, "akismet") {
		t.Fatalf("plugin update command = %v", last)
	}
	request.TargetSlug = "../../etc/passwd"
	if _, err := p.UpdateWordPress(context.Background(), request); err == nil {
		t.Fatal("unsafe plugin slug was accepted")
	}
	request.TargetType = "shell"
	request.TargetSlug = ""
	if _, err := p.UpdateWordPress(context.Background(), request); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("arbitrary update target error = %v", err)
	}
}

func TestWordPressSecurityStateReportsEveryFailedControl(t *testing.T) {
	runner := &wordpressRunner{outputs: map[string][]byte{}, fail: map[string]error{}}
	p := newWordPressProvisionerForTest(t, runner)
	spec := wordpressSpec()
	root, err := p.documentRoot(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "wp-config.php"), []byte("<?php\ndefine('WP_DEBUG', true);\ndefine('DISALLOW_FILE_EDIT', false);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p.setTestWPOutput(runner, spec, []string{"core", "verify-checksums"}, []byte("Success\n"))

	state := p.securityState(context.Background(), spec, root, "http://example.test")
	if !state.CoreChecksumsValid || state.Score != 20 {
		t.Fatalf("security state = %#v, want only checksum control passing", state)
	}
	for _, want := range []string{
		"WordPress configuration permissions are unsafe",
		"WordPress dashboard file editing is enabled",
		"WordPress debugging is enabled",
		"WordPress site URL is not HTTPS",
	} {
		if !slices.Contains(state.Findings, want) {
			t.Errorf("security findings = %q, missing %q", state.Findings, want)
		}
	}
}
