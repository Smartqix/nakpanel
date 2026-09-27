package ops

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
	"golang.org/x/sys/unix"
)

const defaultWordPressOutputLimit = 1 << 20

var (
	wordpressVersionRE          = regexp.MustCompile(`^(?:latest|[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[A-Za-z0-9.-]+)?)$`)
	wordpressSlugRE             = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	wordpressAdminRE            = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,60}$`)
	wordpressDBRE               = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	wordpressFileEditDisabledRE = regexp.MustCompile(`(?i)define\s*\(\s*['"]DISALLOW_FILE_EDIT['"]\s*,\s*true\s*\)`)
	wordpressDebugDisabledRE    = regexp.MustCompile(`(?i)define\s*\(\s*['"]WP_DEBUG['"]\s*,\s*false\s*\)`)
	wordpressFileEditDefineRE   = regexp.MustCompile(`(?i)define\s*\(\s*['"]DISALLOW_FILE_EDIT['"]\s*,\s*(?:true|false)\s*\)\s*;?`)
	wordpressDebugDefineRE      = regexp.MustCompile(`(?i)define\s*\(\s*['"]WP_DEBUG['"]\s*,\s*(?:true|false)\s*\)\s*;?`)
)

type WordPressProvisionerOptions struct {
	HomeRoot        string
	WPBinary        string
	Runner          CommandRunner
	LookupUser      func(string) (*user.User, error)
	Chown           func(string, int, int) error
	DatabaseRemover WordPressDatabaseRemover
}

type WordPressProvisioner struct {
	homeRoot           string
	wpBinary           string
	runner             CommandRunner
	lookupUser         func(string) (*user.User, error)
	chown              func(string, int, int) error
	commandOutputLimit int
	databaseRemover    WordPressDatabaseRemover
}

func NewWordPressProvisioner(opts WordPressProvisionerOptions) *WordPressProvisioner {
	if opts.HomeRoot == "" {
		opts.HomeRoot = DefaultSitePathConfig().HomeRoot
	}
	if opts.WPBinary == "" {
		opts.WPBinary = "/usr/local/bin/wp"
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	if opts.LookupUser == nil {
		opts.LookupUser = user.Lookup
	}
	if opts.Chown == nil {
		opts.Chown = os.Chown
	}
	return &WordPressProvisioner{
		homeRoot: filepath.Clean(opts.HomeRoot), wpBinary: opts.WPBinary, runner: opts.Runner,
		lookupUser: opts.LookupUser, chown: opts.Chown, commandOutputLimit: defaultWordPressOutputLimit,
		databaseRemover: opts.DatabaseRemover,
	}
}

func (p *WordPressProvisioner) documentRoot(spec types.WordPressSiteSpec) (string, error) {
	if spec.InstanceID <= 0 || spec.SubscriptionID <= 0 || spec.SiteID <= 0 || spec.DesiredRevision <= 0 ||
		site.ValidateUsername(spec.Username) != nil || site.ValidateDomain(spec.Domain) != nil ||
		!phpVersionRE.MatchString(spec.PHPVersion) {
		return "", errors.New("validated WordPress site identity is required")
	}
	if spec.HostingMode != types.PHPHostingModeClassic {
		return "", errors.New("WordPress Toolkit requires Classic PHP hosting")
	}
	if !spec.Policy.Permissions.Hosting || !spec.Policy.Permissions.WordPressToolkit || spec.Policy.Resources.MaxWordPressSites == 0 {
		return "", errors.New("WordPress Toolkit is disabled by the subscription policy")
	}
	root := filepath.Join(p.homeRoot, spec.Username, "domains", spec.Domain, "public_html")
	base := filepath.Join(p.homeRoot, spec.Username, "domains", spec.Domain)
	if !pathWithin(base, root) {
		return "", errors.New("invalid WordPress document root")
	}
	return root, nil
}

func (p *WordPressProvisioner) RunWordPress(ctx context.Context, req types.WordPressOperationReq) (types.WordPressOperationResult, error) {
	var result types.WordPressOperationResult
	var err error
	switch req.Action {
	case types.WordPressActionInstall:
		result, err = p.InstallWordPress(ctx, req)
	case types.WordPressActionInspect, types.WordPressActionDiscover, types.WordPressActionRefresh:
		return p.InspectWordPress(ctx, req)
	case types.WordPressActionUpdate:
		result, err = p.UpdateWordPress(ctx, req)
	case types.WordPressActionVerify:
		return p.verifyWordPress(ctx, req)
	case types.WordPressActionHarden:
		result, err = p.hardenWordPress(ctx, req)
	case types.WordPressActionMaintenance:
		result, err = p.setWordPressMaintenance(ctx, req)
	case types.WordPressActionPasswordReset:
		result, err = p.resetWordPressPassword(ctx, req)
	case types.WordPressActionUninstall:
		if req.Removal == nil {
			return types.WordPressOperationResult{}, errors.New("WordPress removal specification is required")
		}
		if req.Removal.Finalize {
			return p.finalizeWordPressRemoval(ctx, req)
		}
		return p.uninstallWordPress(ctx, req)
	default:
		return types.WordPressOperationResult{}, errors.New("unsupported WordPress operation")
	}
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	observed, err := p.InspectWordPress(ctx, types.WordPressOperationReq{OperationID: req.OperationID, Action: req.Action, Site: req.Site})
	if err != nil {
		return types.WordPressOperationResult{}, fmt.Errorf("refresh WordPress state after %s: %w", req.Action, err)
	}
	result.Inventory, result.Security = observed.Inventory, observed.Security
	return result, nil
}

func wordpressInstallURL(site types.WordPressSiteSpec) string {
	scheme := "http://"
	if site.TLSActive {
		scheme = "https://"
	}
	return scheme + site.Domain
}

func (p *WordPressProvisioner) InstallWordPress(ctx context.Context, req types.WordPressOperationReq) (types.WordPressOperationResult, error) {
	root, err := p.documentRoot(req.Site)
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	if req.OperationID <= 0 || req.Credentials == nil {
		return types.WordPressOperationResult{}, errors.New("WordPress installation credentials are required")
	}
	credentials := *req.Credentials
	if err := validateWordPressCredentials(credentials); err != nil {
		return types.WordPressOperationResult{}, err
	}
	version := strings.TrimSpace(req.RequestedVersion)
	if version == "" {
		version = "latest"
	}
	if !wordpressVersionRE.MatchString(version) {
		return types.WordPressOperationResult{}, errors.New("invalid WordPress version")
	}
	if err := validateManagedDirectoryPath(p.homeRoot, filepath.Dir(root)); err != nil {
		return types.WordPressOperationResult{}, fmt.Errorf("validate WordPress domain root: %w", err)
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return types.WordPressOperationResult{}, fmt.Errorf("prepare WordPress document root: %w", err)
	}
	if err := validateManagedDirectoryPath(p.homeRoot, root); err != nil {
		return types.WordPressOperationResult{}, fmt.Errorf("validate WordPress document root: %w", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	if len(entries) != 0 && !isNakpanelPlaceholderDocumentRoot(root, req.Site.Domain, entries) {
		if !matchingWordPressInstall(root, credentials.DatabaseName) {
			return types.WordPressOperationResult{}, errors.New("WordPress installation requires an empty document root")
		}
		if _, installedErr := p.runWP(ctx, req.Site, "core", "is-installed"); installedErr == nil {
			return types.WordPressOperationResult{Action: req.Action, Changed: false, Output: "WordPress installation already present"}, nil
		}
		passwordInput := []byte(credentials.AdminPassword + "\n")
		defer clear(passwordInput)
		if _, err = p.runWPAtPathInput(ctx, req.Site, root, passwordInput,
			"core", "install", "--url="+wordpressInstallURL(req.Site), "--title="+credentials.SiteTitle,
			"--admin_user="+credentials.AdminUser, "--admin_email="+credentials.AdminEmail,
			"--skip-email", "--prompt=admin_password"); err != nil {
			return types.WordPressOperationResult{}, fmt.Errorf("install WordPress: %w", err)
		}
		if err = p.secureWordPressTree(root); err != nil {
			return types.WordPressOperationResult{}, err
		}
	} else {
		stage := filepath.Join(filepath.Dir(root), fmt.Sprintf(".nakpanel-wordpress-install-%d", req.OperationID))
		if err = p.prepareWordPressStage(req.Site.Username, stage); err != nil {
			return types.WordPressOperationResult{}, err
		}
		defer os.RemoveAll(stage)
		downloadURL := "https://wordpress.org/latest.zip"
		if version != "latest" {
			downloadURL = "https://wordpress.org/wordpress-" + version + ".zip"
		}
		if _, err = p.runWPAtPath(ctx, req.Site, stage, "core", "download", downloadURL, "--force"); err != nil {
			return types.WordPressOperationResult{}, fmt.Errorf("download WordPress: %w", err)
		}
		downloadedVersionOutput, versionErr := p.runWPAtPath(ctx, req.Site, stage, "core", "version")
		downloadedVersion := strings.TrimSpace(string(downloadedVersionOutput))
		if versionErr != nil || !wordpressVersionRE.MatchString(downloadedVersion) || downloadedVersion == "latest" {
			return types.WordPressOperationResult{}, errors.New("downloaded WordPress version could not be verified")
		}
		if _, err = p.runWPAtPath(ctx, req.Site, stage, "core", "verify-checksums", "--version="+downloadedVersion, "--locale=en_US"); err != nil {
			return types.WordPressOperationResult{}, fmt.Errorf("verify downloaded WordPress core: %w", err)
		}
		if err = p.writeConfig(req.Site, stage, credentials); err != nil {
			return types.WordPressOperationResult{}, err
		}
		passwordInput := []byte(credentials.AdminPassword + "\n")
		defer clear(passwordInput)
		if _, err = p.runWPAtPathInput(ctx, req.Site, stage, passwordInput,
			"core", "install", "--url="+wordpressInstallURL(req.Site), "--title="+credentials.SiteTitle,
			"--admin_user="+credentials.AdminUser, "--admin_email="+credentials.AdminEmail,
			"--skip-email", "--prompt=admin_password"); err != nil {
			return types.WordPressOperationResult{}, fmt.Errorf("install WordPress: %w", err)
		}
		if err = p.secureWordPressTree(stage); err != nil {
			return types.WordPressOperationResult{}, err
		}
		if err = activateWordPressStage(stage, root, req.OperationID); err != nil {
			return types.WordPressOperationResult{}, err
		}
	}
	return types.WordPressOperationResult{Action: req.Action, Changed: true, Output: "WordPress installed"}, nil
}

func isNakpanelPlaceholderDocumentRoot(root, domain string, entries []os.DirEntry) bool {
	if len(entries) != 1 || entries[0].Name() != "index.php" || entries[0].Type()&os.ModeSymlink != 0 {
		return false
	}
	info, err := entries[0].Info()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	content, err := readWordPressConfig(filepath.Join(root, entries[0].Name()))
	if err != nil {
		return false
	}
	return string(content) == renderPlaceholderIndex(SitePlan{Domain: domain})
}

func (p *WordPressProvisioner) secureWordPressTree(root string) error {
	if err := secureHostedDocumentTree(root); err != nil {
		return fmt.Errorf("grant nginx WordPress document access: %w", err)
	}
	if err := chmodWordPressConfig(filepath.Join(root, "wp-config.php"), 0o600); err != nil {
		return fmt.Errorf("protect WordPress configuration: %w", err)
	}
	return nil
}

func matchingWordPressInstall(root, databaseName string) bool {
	if _, err := os.Stat(filepath.Join(root, "wp-load.php")); err != nil {
		return false
	}
	config, err := readWordPressConfig(filepath.Join(root, "wp-config.php"))
	if err != nil {
		return false
	}
	want := "define('DB_NAME', '" + phpSingleQuote(databaseName) + "');"
	return strings.Contains(string(config), want)
}

func validateWordPressCredentials(value types.WordPressCredentials) error {
	if !wordpressDBRE.MatchString(value.DatabaseName) || !wordpressDBRE.MatchString(value.DatabaseUser) ||
		len(value.DatabasePassword) < 16 || len(value.DatabasePassword) > 256 ||
		!wordpressAdminRE.MatchString(value.AdminUser) || len(value.AdminPassword) < 12 || len(value.AdminPassword) > 256 ||
		strings.TrimSpace(value.SiteTitle) == "" || len(value.SiteTitle) > 200 || strings.ContainsAny(value.SiteTitle, "\x00\r\n") {
		return errors.New("invalid WordPress installation credentials")
	}
	address, err := mail.ParseAddress(strings.TrimSpace(value.AdminEmail))
	if err != nil || address.Address != strings.TrimSpace(value.AdminEmail) || len(address.Address) > 254 {
		return errors.New("invalid WordPress administrator email")
	}
	return nil
}

func (p *WordPressProvisioner) writeConfig(spec types.WordPressSiteSpec, root string, credentials types.WordPressCredentials) error {
	salts := make([]string, 8)
	for index := range salts {
		value, err := randomWordPressSecret()
		if err != nil {
			return err
		}
		salts[index] = value
	}
	content := renderWordPressConfig(credentials, salts)
	return p.writeAccountFile(spec.Username, filepath.Join(root, "wp-config.php"), []byte(content), 0o600)
}

func readWordPressConfig(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open WordPress configuration")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > defaultWordPressOutputLimit {
		return nil, errors.New("WordPress configuration must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, defaultWordPressOutputLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > defaultWordPressOutputLimit {
		return nil, errors.New("WordPress configuration exceeded the limit")
	}
	return data, nil
}

func chmodWordPressConfig(path string, mode os.FileMode) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("WordPress configuration must be a regular file")
	}
	return unix.Fchmod(fd, uint32(mode.Perm()))
}

func (p *WordPressProvisioner) prepareWordPressStage(username, stage string) error {
	if err := os.RemoveAll(stage); err != nil {
		return fmt.Errorf("clear WordPress staging directory: %w", err)
	}
	if err := os.Mkdir(stage, 0o750); err != nil {
		return fmt.Errorf("create WordPress staging directory: %w", err)
	}
	account, err := p.lookupUser(username)
	if err != nil {
		return fmt.Errorf("resolve WordPress account: %w", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return errors.New("invalid WordPress account UID")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return errors.New("invalid WordPress account GID")
	}
	if err = p.chown(stage, uid, gid); err != nil {
		return fmt.Errorf("own WordPress staging directory: %w", err)
	}
	return nil
}

func activateWordPressStage(stage, root string, operationID int64) error {
	parent := filepath.Dir(root)
	previous := filepath.Join(parent, fmt.Sprintf(".nakpanel-wordpress-empty-%d", operationID))
	if err := os.RemoveAll(previous); err != nil {
		return fmt.Errorf("clear previous WordPress activation marker: %w", err)
	}
	if err := os.Rename(root, previous); err != nil {
		return fmt.Errorf("prepare WordPress document root activation: %w", err)
	}
	if err := os.Rename(stage, root); err != nil {
		if rollbackErr := os.Rename(previous, root); rollbackErr != nil {
			return errors.Join(fmt.Errorf("activate WordPress document root: %w", err), fmt.Errorf("restore empty document root: %w", rollbackErr))
		}
		return fmt.Errorf("activate WordPress document root: %w", err)
	}
	if err := syncDir(parent); err != nil {
		return fmt.Errorf("sync WordPress document root: %w", err)
	}
	if err := os.RemoveAll(previous); err != nil {
		return fmt.Errorf("remove WordPress activation marker: %w", err)
	}
	return nil
}

func randomWordPressSecret() (string, error) {
	buffer := make([]byte, 48)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func renderWordPressConfig(c types.WordPressCredentials, salts []string) string {
	keys := []string{"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"}
	var out strings.Builder
	out.WriteString("<?php\n")
	for _, item := range [][2]string{{"DB_NAME", c.DatabaseName}, {"DB_USER", c.DatabaseUser}, {"DB_PASSWORD", c.DatabasePassword}, {"DB_HOST", "localhost"}, {"DB_CHARSET", "utf8mb4"}, {"DB_COLLATE", ""}} {
		fmt.Fprintf(&out, "define('%s', '%s');\n", item[0], phpSingleQuote(item[1]))
	}
	for index, key := range keys {
		fmt.Fprintf(&out, "define('%s', '%s');\n", key, phpSingleQuote(salts[index]))
	}
	out.WriteString("$table_prefix = 'wp_';\ndefine('DISALLOW_FILE_EDIT', true);\ndefine('WP_DEBUG', false);\n")
	out.WriteString("if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');\nrequire_once ABSPATH . 'wp-settings.php';\n")
	return out.String()
}

func phpSingleQuote(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `'`, `\'`)
}

func (p *WordPressProvisioner) writeAccountFile(username, target string, data []byte, mode os.FileMode) error {
	account, err := p.lookupUser(username)
	if err != nil {
		return fmt.Errorf("resolve WordPress account: %w", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return errors.New("invalid WordPress account UID")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return errors.New("invalid WordPress account GID")
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".nakpanel-wordpress-write-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if _, err = temporary.Write(data); err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Chmod(temporaryName, mode); err != nil {
		return err
	}
	if err = p.chown(temporaryName, uid, gid); err != nil {
		return err
	}
	return os.Rename(temporaryName, target)
}

func (p *WordPressProvisioner) runWP(ctx context.Context, spec types.WordPressSiteSpec, args ...string) ([]byte, error) {
	root, err := p.documentRoot(spec)
	if err != nil {
		return nil, err
	}
	return p.runWPAtPath(ctx, spec, root, args...)
}

func (p *WordPressProvisioner) runWPInput(ctx context.Context, spec types.WordPressSiteSpec, input []byte, args ...string) ([]byte, error) {
	root, err := p.documentRoot(spec)
	if err != nil {
		return nil, err
	}
	return p.runWPAtPathInput(ctx, spec, root, input, args...)
}

func (p *WordPressProvisioner) runWPAtPathInput(ctx context.Context, spec types.WordPressSiteSpec, root string, input []byte, args ...string) ([]byte, error) {
	if _, err := p.validateWPCommandRoot(spec, root); err != nil {
		return nil, err
	}
	runner, ok := p.runner.(InputCommandRunner)
	if !ok {
		return nil, errors.New("WordPress command runner does not support protected input")
	}
	command := []string{"-u", spec.Username, "--", p.wpBinary, "--path=" + root, "--no-color"}
	command = append(command, args...)
	output, err := runner.RunInput(ctx, input, "runuser", command...)
	if len(output) > p.commandOutputLimit {
		return nil, errors.New("WordPress command output exceeded the limit")
	}
	return output, err
}

func (p *WordPressProvisioner) runWPAtPath(ctx context.Context, spec types.WordPressSiteSpec, root string, args ...string) ([]byte, error) {
	root, err := p.validateWPCommandRoot(spec, root)
	if err != nil {
		return nil, err
	}
	command := []string{"-u", spec.Username, "--", p.wpBinary, "--path=" + root, "--no-color"}
	command = append(command, args...)
	output, err := p.runner.Run(ctx, "runuser", command...)
	if len(output) > p.commandOutputLimit {
		return nil, errors.New("WordPress command output exceeded the limit")
	}
	return output, err
}

func (p *WordPressProvisioner) validateWPCommandRoot(spec types.WordPressSiteSpec, root string) (string, error) {
	documentRoot, err := p.documentRoot(spec)
	if err != nil {
		return "", err
	}
	root = filepath.Clean(root)
	domainRoot := filepath.Dir(documentRoot)
	if root != documentRoot && (filepath.Dir(root) != domainRoot || !strings.HasPrefix(filepath.Base(root), ".nakpanel-wordpress-install-")) {
		return "", errors.New("invalid WordPress command root")
	}
	if err := validateManagedDirectoryPath(p.homeRoot, root); err != nil {
		return "", fmt.Errorf("unsafe WordPress command root: %w", err)
	}
	return root, nil
}

func (p *WordPressProvisioner) InspectWordPress(ctx context.Context, req types.WordPressOperationReq) (types.WordPressOperationResult, error) {
	root, err := p.documentRoot(req.Site)
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	if _, err = os.Stat(filepath.Join(root, "wp-load.php")); err != nil {
		return types.WordPressOperationResult{}, errors.New("WordPress installation was not found")
	}
	version, err := p.runWP(ctx, req.Site, "core", "version")
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	siteURL, err := p.runWP(ctx, req.Site, "option", "get", "siteurl")
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	homeURL, err := p.runWP(ctx, req.Site, "option", "get", "home")
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	siteTitle, adminUser, adminEmail, err := p.wordpressIdentity(ctx, req.Site)
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	plugins, err := p.componentList(ctx, req.Site, "plugin")
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	themes, err := p.componentList(ctx, req.Site, "theme")
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	coreUpdate := ""
	if output, updateErr := p.runWP(ctx, req.Site, "core", "check-update", "--format=json"); updateErr == nil {
		var updates []struct {
			Version string `json:"version"`
		}
		if len(strings.TrimSpace(string(output))) > 0 && json.Unmarshal(output, &updates) == nil && len(updates) > 0 {
			coreUpdate = updates[0].Version
		}
	}
	security := p.securityState(ctx, req.Site, root, strings.TrimSpace(string(siteURL)))
	updates := 0
	if coreUpdate != "" {
		updates++
	}
	for _, item := range append(append([]types.WordPressComponent{}, plugins...), themes...) {
		if item.Update != "" && item.Update != "none" {
			updates++
		}
	}
	inventory := types.WordPressInventory{
		CoreVersion: strings.TrimSpace(string(version)), CoreUpdate: coreUpdate,
		SiteTitle: siteTitle, AdminUser: adminUser, AdminEmail: adminEmail,
		SiteURL: strings.TrimSpace(string(siteURL)), HomeURL: strings.TrimSpace(string(homeURL)),
		PHPVersion: req.Site.PHPVersion, Plugins: plugins, Themes: themes,
		UpdatesAvailable: updates, CollectedAt: time.Now().UTC(),
	}
	return types.WordPressOperationResult{Action: req.Action, Inventory: inventory, Security: security}, nil
}

func (p *WordPressProvisioner) wordpressIdentity(ctx context.Context, spec types.WordPressSiteSpec) (string, string, string, error) {
	titleOutput, err := p.runWP(ctx, spec, "option", "get", "blogname")
	if err != nil {
		return "", "", "", fmt.Errorf("read WordPress site title: %w", err)
	}
	emailOutput, err := p.runWP(ctx, spec, "option", "get", "admin_email")
	if err != nil {
		return "", "", "", fmt.Errorf("read WordPress administrator email: %w", err)
	}
	usersOutput, err := p.runWP(ctx, spec, "user", "list", "--role=administrator", "--orderby=ID", "--order=ASC", "--fields=user_login", "--format=json")
	if err != nil {
		return "", "", "", fmt.Errorf("read WordPress administrators: %w", err)
	}
	var administrators []struct {
		UserLogin string `json:"user_login"`
	}
	if err = json.Unmarshal(usersOutput, &administrators); err != nil || len(administrators) == 0 {
		return "", "", "", errors.New("WordPress administrator inventory is invalid")
	}
	title := strings.TrimSpace(string(titleOutput))
	adminUser := strings.TrimSpace(administrators[0].UserLogin)
	adminEmail := strings.TrimSpace(string(emailOutput))
	address, emailErr := mail.ParseAddress(adminEmail)
	if title == "" || len(title) > 200 || strings.ContainsAny(title, "\x00\r\n") ||
		!wordpressAdminRE.MatchString(adminUser) || emailErr != nil || address.Address != adminEmail || len(adminEmail) > 254 {
		return "", "", "", errors.New("WordPress identity inventory is invalid")
	}
	return title, adminUser, adminEmail, nil
}

func (p *WordPressProvisioner) componentList(ctx context.Context, spec types.WordPressSiteSpec, kind string) ([]types.WordPressComponent, error) {
	output, err := p.runWP(ctx, spec, kind, "list", "--format=json")
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Name          string `json:"name"`
		Status        string `json:"status"`
		Version       string `json:"version"`
		Update        string `json:"update"`
		UpdateVersion string `json:"update_version"`
		AutoUpdate    string `json:"auto_update"`
	}
	if err = json.Unmarshal(output, &raw); err != nil {
		return nil, fmt.Errorf("decode WordPress %s inventory: %w", kind, err)
	}
	items := make([]types.WordPressComponent, 0, len(raw))
	for _, item := range raw {
		if !wordpressSlugRE.MatchString(item.Name) || len(item.Version) > 64 || len(item.Status) > 32 || len(item.UpdateVersion) > 64 {
			return nil, fmt.Errorf("invalid WordPress %s inventory", kind)
		}
		items = append(items, types.WordPressComponent{Slug: item.Name, Status: item.Status, Version: item.Version, Update: item.Update, UpdateVersion: item.UpdateVersion, AutoUpdate: item.AutoUpdate})
	}
	return items, nil
}

func (p *WordPressProvisioner) securityState(ctx context.Context, spec types.WordPressSiteSpec, root, siteURL string) types.WordPressSecurityState {
	state := types.WordPressSecurityState{FilePermissionsSafe: wordpressPermissionsSafe(root), HTTPSConfigured: strings.HasPrefix(strings.ToLower(strings.TrimSpace(siteURL)), "https://")}
	if _, err := p.runWP(ctx, spec, "core", "verify-checksums"); err == nil {
		state.CoreChecksumsValid = true
	} else {
		state.Findings = append(state.Findings, "WordPress core checksums do not match")
	}
	config, err := readWordPressConfig(filepath.Join(root, "wp-config.php"))
	if err == nil {
		state.FileEditingDisabled = wordpressFileEditDisabledRE.Match(config)
		state.DebugDisabled = wordpressDebugDisabledRE.Match(config)
	}
	if !state.FilePermissionsSafe {
		state.Findings = append(state.Findings, "WordPress configuration permissions are unsafe")
	}
	if !state.FileEditingDisabled {
		state.Findings = append(state.Findings, "WordPress dashboard file editing is enabled")
	}
	if !state.DebugDisabled {
		state.Findings = append(state.Findings, "WordPress debugging is enabled")
	}
	if !state.HTTPSConfigured {
		state.Findings = append(state.Findings, "WordPress site URL is not HTTPS")
	}
	for _, ok := range []bool{state.CoreChecksumsValid, state.FilePermissionsSafe, state.FileEditingDisabled, state.DebugDisabled, state.HTTPSConfigured} {
		if ok {
			state.Score += 20
		}
	}
	return state
}

func wordpressPermissionsSafe(root string) bool {
	config, err := os.Lstat(filepath.Join(root, "wp-config.php"))
	if err != nil || !config.Mode().IsRegular() {
		return false
	}
	return config.Mode().Perm()&0o077 == 0
}

func (p *WordPressProvisioner) UpdateWordPress(ctx context.Context, req types.WordPressOperationReq) (types.WordPressOperationResult, error) {
	if _, err := p.requireInstalled(req.Site); err != nil {
		return types.WordPressOperationResult{}, err
	}
	var args []string
	switch req.TargetType {
	case types.WordPressTargetCore:
		if req.TargetSlug != "" {
			return types.WordPressOperationResult{}, errors.New("core update does not accept a slug")
		}
		args = []string{"core", "update"}
	case types.WordPressTargetPlugin, types.WordPressTargetTheme:
		if !wordpressSlugRE.MatchString(req.TargetSlug) {
			return types.WordPressOperationResult{}, errors.New("invalid WordPress component slug")
		}
		args = []string{string(req.TargetType), "update", req.TargetSlug}
	case types.WordPressTargetAll:
		if req.TargetSlug != "" {
			return types.WordPressOperationResult{}, errors.New("all update does not accept a slug")
		}
		for _, command := range [][]string{{"core", "update"}, {"plugin", "update", "--all"}, {"theme", "update", "--all"}} {
			if _, err := p.runWP(ctx, req.Site, command...); err != nil {
				return types.WordPressOperationResult{}, err
			}
		}
		return types.WordPressOperationResult{Action: req.Action, Changed: true, Output: "WordPress core, plugins, and themes updated"}, nil
	default:
		return types.WordPressOperationResult{}, errors.New("invalid WordPress update target")
	}
	if _, err := p.runWP(ctx, req.Site, args...); err != nil {
		return types.WordPressOperationResult{}, err
	}
	return types.WordPressOperationResult{Action: req.Action, Changed: true, Output: "WordPress update completed"}, nil
}

func (p *WordPressProvisioner) requireInstalled(spec types.WordPressSiteSpec) (string, error) {
	root, err := p.documentRoot(spec)
	if err != nil {
		return "", err
	}
	if err = validateManagedDirectoryPath(p.homeRoot, root); err != nil {
		return "", fmt.Errorf("unsafe WordPress document root: %w", err)
	}
	if _, err = os.Stat(filepath.Join(root, "wp-load.php")); err != nil {
		return "", errors.New("WordPress installation was not found")
	}
	return root, nil
}

func (p *WordPressProvisioner) verifyWordPress(ctx context.Context, req types.WordPressOperationReq) (types.WordPressOperationResult, error) {
	result, err := p.InspectWordPress(ctx, req)
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	result.Output = "WordPress security verification completed"
	return result, nil
}

func (p *WordPressProvisioner) hardenWordPress(ctx context.Context, req types.WordPressOperationReq) (types.WordPressOperationResult, error) {
	root, err := p.requireInstalled(req.Site)
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	configPath := filepath.Join(root, "wp-config.php")
	config, err := readWordPressConfig(configPath)
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	text := string(config)
	text, err = enforceWordPressBooleanDefine(text, wordpressFileEditDefineRE, "define('DISALLOW_FILE_EDIT', true);")
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	text, err = enforceWordPressBooleanDefine(text, wordpressDebugDefineRE, "define('WP_DEBUG', false);")
	if err != nil {
		return types.WordPressOperationResult{}, err
	}
	if err = p.writeAccountFile(req.Site.Username, configPath, []byte(text), 0o600); err != nil {
		return types.WordPressOperationResult{}, err
	}
	if err = secureHostedDocumentTree(root); err != nil {
		return types.WordPressOperationResult{}, fmt.Errorf("apply WordPress file permissions: %w", err)
	}
	if err = chmodWordPressConfig(configPath, 0o600); err != nil {
		return types.WordPressOperationResult{}, fmt.Errorf("protect WordPress configuration: %w", err)
	}
	siteURL, _ := p.runWP(ctx, req.Site, "option", "get", "siteurl")
	return types.WordPressOperationResult{Action: req.Action, Changed: true, Security: p.securityState(ctx, req.Site, root, string(siteURL)), Output: "WordPress hardening applied"}, nil
}

func enforceWordPressBooleanDefine(text string, matcher *regexp.Regexp, declaration string) (string, error) {
	if matcher.MatchString(text) {
		return matcher.ReplaceAllString(text, declaration), nil
	}
	if !strings.Contains(text, "<?php") {
		return "", errors.New("WordPress configuration is missing its PHP opening tag")
	}
	return strings.Replace(text, "<?php", "<?php\n"+declaration, 1), nil
}

func (p *WordPressProvisioner) setWordPressMaintenance(ctx context.Context, req types.WordPressOperationReq) (types.WordPressOperationResult, error) {
	if _, err := p.requireInstalled(req.Site); err != nil {
		return types.WordPressOperationResult{}, err
	}
	action := "deactivate"
	if req.Maintenance {
		action = "activate"
	}
	if _, err := p.runWP(ctx, req.Site, "maintenance-mode", action); err != nil {
		return types.WordPressOperationResult{}, err
	}
	return types.WordPressOperationResult{Action: req.Action, Changed: true, Output: "WordPress maintenance mode " + action + "d"}, nil
}

func (p *WordPressProvisioner) resetWordPressPassword(ctx context.Context, req types.WordPressOperationReq) (types.WordPressOperationResult, error) {
	if _, err := p.requireInstalled(req.Site); err != nil {
		return types.WordPressOperationResult{}, err
	}
	if req.Credentials == nil || !wordpressAdminRE.MatchString(req.Credentials.AdminUser) || len(req.Credentials.AdminPassword) < 12 || len(req.Credentials.AdminPassword) > 256 {
		return types.WordPressOperationResult{}, errors.New("invalid WordPress password reset")
	}
	passwordInput := []byte(req.Credentials.AdminPassword + "\n")
	defer clear(passwordInput)
	if _, err := p.runWPInput(ctx, req.Site, passwordInput, "user", "update", req.Credentials.AdminUser, "--prompt=user_pass"); err != nil {
		return types.WordPressOperationResult{}, err
	}
	return types.WordPressOperationResult{Action: req.Action, Changed: true, Output: "WordPress administrator password reset"}, nil
}
