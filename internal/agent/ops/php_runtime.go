package ops

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"
)

// PHPRuntimeDescriptor is trusted host configuration, never an RPC payload.
// Version-only records remain unambiguous while one provider serves a version.
type PHPRuntimeDescriptor struct {
	Provider, Version                    string
	CLIPath, FPMPath                     string
	CLIINIPath, FPMINIPath               string
	CLIScanDir, FPMScanDir, ExtensionDir string
	PoolDir, ManagedSocket               string
}
type PHPRuntimeResolver interface {
	ResolvePHP(string) (PHPRuntimeDescriptor, error)
}
type installedPHPRuntimeResolver struct {
	path     string
	ownerUID uint32
}

func defaultPHPRuntimeResolver() PHPRuntimeResolver {
	return installedPHPRuntimeResolver{path: "/etc/nakpanel/platform.json"}
}
func distroPHPRuntime(version string) PHPRuntimeDescriptor {
	root := "/etc/php/" + version
	// Ubuntu's packaged non-ZTS modules use the upstream PHP API directory.
	extensionAPI := map[string]string{"8.1": "20210902", "8.2": "20220829", "8.3": "20230831", "8.4": "20240924", "8.5": "20250925"}[version]
	return PHPRuntimeDescriptor{Provider: "distro", Version: version, CLIPath: "/usr/bin/php" + version, FPMPath: "/usr/sbin/php-fpm" + version, CLIINIPath: root + "/cli/php.ini", FPMINIPath: root + "/fpm/php.ini", CLIScanDir: root + "/cli/conf.d", FPMScanDir: root + "/fpm/conf.d", ExtensionDir: "/usr/lib/php/" + extensionAPI, PoolDir: root + "/fpm/pool.d", ManagedSocket: "/run/php/php" + version + "-fpm.sock"}
}
func privatePHPRuntime(version string) PHPRuntimeDescriptor {
	root := "/opt/nakpanel/php/" + version
	return PHPRuntimeDescriptor{Provider: "private", Version: version, CLIPath: root + "/bin/php", FPMPath: root + "/sbin/php-fpm", CLIINIPath: root + "/etc/cli/php.ini", FPMINIPath: root + "/etc/fpm/php.ini", CLIScanDir: root + "/etc/cli/conf.d", FPMScanDir: root + "/etc/fpm/conf.d", ExtensionDir: root + "/lib/php/extensions", PoolDir: root + "/etc/fpm/pool.d", ManagedSocket: "/run/php/php" + version + "-fpm.sock"}
}
func (d PHPRuntimeDescriptor) Validate() error {
	if !phpVersionRE.MatchString(d.Version) {
		return fmt.Errorf("invalid PHP version %q", d.Version)
	}
	expected := distroPHPRuntime(d.Version)
	if d.Provider == "private" {
		expected = privatePHPRuntime(d.Version)
	}
	if d != expected {
		return fmt.Errorf("PHP %s descriptor violates provider path policy", d.Version)
	}
	return nil
}

func resolvePHPRuntime(resolver PHPRuntimeResolver, version string) (PHPRuntimeDescriptor, error) {
	if resolver == nil {
		resolver = defaultPHPRuntimeResolver()
	}
	d, err := resolver.ResolvePHP(version)
	if err != nil {
		return PHPRuntimeDescriptor{}, err
	}
	if d.Version != version {
		return PHPRuntimeDescriptor{}, fmt.Errorf("PHP resolver returned mismatched version")
	}
	return d, d.Validate()
}

// The installed profile selects fixed, audited mappings. It cannot register paths.
func (r installedPHPRuntimeResolver) ResolvePHP(version string) (PHPRuntimeDescriptor, error) {
	if !phpVersionRE.MatchString(version) {
		return PHPRuntimeDescriptor{}, fmt.Errorf("invalid PHP version")
	}
	file, err := os.OpenFile(r.path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		if !containsExact([]string{"8.1", "8.2", "8.3", "8.4", "8.5"}, version) {
			return PHPRuntimeDescriptor{}, fmt.Errorf("unsupported PHP version %s", version)
		}
		return distroPHPRuntime(version), nil
	}
	if err != nil {
		return PHPRuntimeDescriptor{}, fmt.Errorf("inspect PHP platform profile: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return PHPRuntimeDescriptor{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || !ok || stat.Uid != r.ownerUID {
		return PHPRuntimeDescriptor{}, fmt.Errorf("PHP platform profile must be a root-owned regular file without group/world write access")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return PHPRuntimeDescriptor{}, err
	}
	if len(data) > 65536 {
		return PHPRuntimeDescriptor{}, fmt.Errorf("PHP platform profile exceeds size limit")
	}
	var profile struct {
		OSID         string   `json:"os_id"`
		VersionID    string   `json:"version_id"`
		Codename     string   `json:"codename"`
		Architecture string   `json:"architecture"`
		Profile      string   `json:"profile"`
		Internal     string   `json:"internal_php_version"`
		Hosting      []string `json:"hosting_php_versions"`
		Pending      bool     `json:"bootstrap_pending"`
	}
	if err := json.Unmarshal(data, &profile); err != nil {
		return PHPRuntimeDescriptor{}, fmt.Errorf("decode PHP platform profile: %w", err)
	}
	allowed := []string{"8.3", "8.4", "8.5"}
	if profile.OSID != "ubuntu" || (profile.Architecture != "amd64" && profile.Architecture != "arm64") {
		return PHPRuntimeDescriptor{}, fmt.Errorf("invalid PHP platform identity")
	}
	switch profile.Profile {
	case "ubuntu-26.04-sury":
		if profile.VersionID != "26.04" || profile.Codename != "resolute" || profile.Internal != "8.5" || len(profile.Hosting) != len(allowed) {
			return PHPRuntimeDescriptor{}, fmt.Errorf("invalid Resolute Sury PHP profile")
		}
	case "ubuntu-26.04-native":
		if profile.VersionID != "26.04" || profile.Codename != "resolute" || profile.Internal != "8.5" {
			return PHPRuntimeDescriptor{}, fmt.Errorf("invalid Resolute PHP profile")
		}
		allowed = []string{"8.5"}
	default:
		return PHPRuntimeDescriptor{}, fmt.Errorf("unsupported PHP platform profile %q", profile.Profile)
	}
	// bootstrap_pending guards first-time plan initialization in panelctl.
	// Runtime readiness is its prerequisite, so the marker must not hide
	// validated installed runtimes from either probes or execution consumers.
	seen := map[string]bool{}
	for _, candidate := range profile.Hosting {
		if seen[candidate] || !containsExact(allowed, candidate) {
			return PHPRuntimeDescriptor{}, fmt.Errorf("ambiguous or unsupported PHP profile mapping")
		}
		seen[candidate] = true
	}
	if !seen[version] {
		return PHPRuntimeDescriptor{}, fmt.Errorf("PHP %s is unavailable in installed profile", version)
	}
	return distroPHPRuntime(version), nil
}
func (d PHPRuntimeDescriptor) CLICommand(args ...string) (string, []string) {
	if d.Provider == "distro" {
		return d.CLIPath, args
	}
	return "/usr/bin/env", append([]string{"PHP_INI_SCAN_DIR=" + d.CLIScanDir, d.CLIPath, "-c", d.CLIINIPath, "-d", "extension_dir=" + d.ExtensionDir}, args...)
}
func (d PHPRuntimeDescriptor) FPMCommand(args ...string) (string, []string) {
	if d.Provider == "distro" {
		return d.FPMPath, args
	}
	return "/usr/bin/env", append([]string{"PHP_INI_SCAN_DIR=" + d.FPMScanDir, d.FPMPath, "-c", d.FPMINIPath, "-d", "extension_dir=" + d.ExtensionDir}, args...)
}
func (d PHPRuntimeDescriptor) fpmUnitCommand() (string, string) {
	if d.Provider == "distro" {
		return d.FPMPath, ""
	}
	return d.FPMPath + " -c " + d.FPMINIPath + " -d extension_dir=" + d.ExtensionDir, "Environment=PHP_INI_SCAN_DIR=" + d.FPMScanDir + "\n"
}

func runtimeFPMCommand(runtime PHPRuntimeDescriptor, args ...string) []string {
	name, args := runtime.FPMCommand(args...)
	return append([]string{name}, args...)
}
