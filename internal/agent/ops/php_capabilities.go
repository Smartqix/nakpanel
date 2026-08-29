package ops

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	composerVersionRE = regexp.MustCompile(`(?i)\bcomposer(?:\s+version)?\s+([0-9]+(?:\.[0-9]+){1,2})\b`)
	wpCLIVersionRE    = regexp.MustCompile(`(?i)\bwp-cli\s+([0-9]+(?:\.[0-9]+){1,2})\b`)
)

var supportedPHPRuntimes = []struct {
	version string
	status  types.PHPSupportStatus
}{
	{version: "8.5", status: types.PHPSupportActive},
	{version: "8.4", status: types.PHPSupportActive},
	{version: "8.3", status: types.PHPSupportSecuritySupported},
}

var requiredPHPExtensions = []string{
	"bcmath", "curl", "dom", "exif", "fileinfo", "gd", "imagick", "intl",
	"mbstring", "mysqli", "openssl", "redis", "SimpleXML", "soap", "xml",
	"zip", "Zend OPcache",
}

// RuntimeCapabilityProbe isolates host binary discovery and execution so PHP
// readiness can be tested without depending on the test host's installed PHP.
type RuntimeCapabilityProbe interface {
	LookPath(name string) (string, error)
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type systemRuntimeCapabilityProbe struct{}

func (systemRuntimeCapabilityProbe) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (systemRuntimeCapabilityProbe) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func probePHPRuntimes(ctx context.Context, probe RuntimeCapabilityProbe) ([]types.PHPRuntimeCapability, []string) {
	runtimes := make([]types.PHPRuntimeCapability, 0, len(supportedPHPRuntimes))
	readyVersions := make([]string, 0, len(supportedPHPRuntimes))
	for _, supported := range supportedPHPRuntimes {
		runtime, discovered := probePHPRuntime(ctx, probe, supported.version, supported.status)
		if !discovered {
			continue
		}
		runtimes = append(runtimes, runtime)
		if runtime.Ready {
			readyVersions = append(readyVersions, runtime.Version)
		}
	}
	return runtimes, readyVersions
}

func probePHPRuntime(ctx context.Context, probe RuntimeCapabilityProbe, version string, status types.PHPSupportStatus) (types.PHPRuntimeCapability, bool) {
	runtime := types.PHPRuntimeCapability{Version: version, SupportStatus: status}
	phpPath, phpErr := probe.LookPath("php" + version)
	fpmPath, fpmErr := probe.LookPath("php-fpm" + version)
	if phpErr != nil && fpmErr != nil {
		return runtime, false
	}

	if phpErr != nil {
		runtime.ValidationErrors = append(runtime.ValidationErrors, "PHP CLI binary php"+version+" is unavailable")
		runtime.MissingExtensions = append([]string(nil), requiredPHPExtensions...)
		for _, extension := range runtime.MissingExtensions {
			runtime.ValidationErrors = append(runtime.ValidationErrors, "required PHP extension "+extension+" is unavailable")
		}
	} else {
		runtime.CLIAvailable = validatePHPCLIVersion(ctx, probe, phpPath, version, &runtime.ValidationErrors)
		loaded, err := loadedPHPExtensions(ctx, probe, phpPath)
		if err != nil {
			runtime.ValidationErrors = append(runtime.ValidationErrors, err.Error())
		} else {
			runtime.Extensions = loaded
		}
		runtime.MissingExtensions = missingPHPExtensions(loaded)
		for _, extension := range runtime.MissingExtensions {
			runtime.ValidationErrors = append(runtime.ValidationErrors, "required PHP extension "+extension+" is unavailable")
		}
		runtime.OPcacheAvailable = containsFold(loaded, "Zend OPcache")
	}

	if fpmErr != nil {
		runtime.ValidationErrors = append(runtime.ValidationErrors, "PHP-FPM binary php-fpm"+version+" is unavailable")
	} else {
		runtime.FPMAvailable = true
		if err := validateIsolatedFPMConfig(ctx, probe, fpmPath); err != nil {
			runtime.ValidationErrors = append(runtime.ValidationErrors, err.Error())
		} else {
			runtime.FPMConfigValid = true
		}
	}

	runtime.Ready = runtime.CLIAvailable && runtime.FPMAvailable && runtime.FPMConfigValid &&
		runtime.OPcacheAvailable && len(runtime.MissingExtensions) == 0
	return runtime, true
}

func validatePHPCLIVersion(ctx context.Context, probe RuntimeCapabilityProbe, path, expected string, validationErrors *[]string) bool {
	output, err := probe.Run(ctx, path, "-r", `echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;`)
	if err != nil {
		*validationErrors = append(*validationErrors, fmt.Sprintf("PHP CLI version check failed: %v: %s", err, strings.TrimSpace(string(output))))
		return false
	}
	actual := strings.TrimSpace(string(output))
	if actual != expected {
		*validationErrors = append(*validationErrors, fmt.Sprintf("PHP CLI reported %q; expected %s", actual, expected))
		return false
	}
	return true
}

func loadedPHPExtensions(ctx context.Context, probe RuntimeCapabilityProbe, path string) ([]string, error) {
	output, err := probe.Run(ctx, path, "-m")
	if err != nil {
		return nil, fmt.Errorf("list loaded PHP extensions: %w: %s", err, strings.TrimSpace(string(output)))
	}
	seen := make(map[string]struct{})
	var loaded []string
	for _, line := range strings.Split(string(output), "\n") {
		extension := strings.TrimSpace(line)
		if extension == "" || strings.HasPrefix(extension, "[") {
			continue
		}
		key := strings.ToLower(extension)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		loaded = append(loaded, extension)
	}
	sort.Slice(loaded, func(i, j int) bool {
		return strings.ToLower(loaded[i]) < strings.ToLower(loaded[j])
	})
	return loaded, nil
}

func missingPHPExtensions(loaded []string) []string {
	missing := make([]string, 0)
	for _, required := range requiredPHPExtensions {
		if !containsFold(loaded, required) {
			missing = append(missing, required)
		}
	}
	return missing
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

func validateIsolatedFPMConfig(ctx context.Context, probe RuntimeCapabilityProbe, fpmPath string) error {
	file, err := os.CreateTemp("", "nakpanel-php-fpm-probe-*.conf")
	if err != nil {
		return fmt.Errorf("create isolated PHP-FPM configuration: %w", err)
	}
	path := file.Name()
	defer os.Remove(path)
	config := fmt.Sprintf(`[global]
pid = %s.pid
error_log = /dev/stderr
daemonize = no

[nakpanel-probe]
user = www-data
group = www-data
listen = %s.sock
pm = static
pm.max_children = 1
`, path, path)
	if _, err := file.WriteString(config); err != nil {
		_ = file.Close()
		return fmt.Errorf("write isolated PHP-FPM configuration: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close isolated PHP-FPM configuration: %w", err)
	}
	output, err := probe.Run(ctx, fpmPath, "-t", "-y", path)
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return fmt.Errorf("validate isolated PHP-FPM configuration: %w", err)
		}
		return fmt.Errorf("validate isolated PHP-FPM configuration: %w: %s", err, message)
	}
	return nil
}

func probeToolVersion(ctx context.Context, probe RuntimeCapabilityProbe, name string, args []string, versionRE *regexp.Regexp) (bool, string) {
	path, err := probe.LookPath(name)
	if err != nil {
		return false, ""
	}
	output, err := probe.Run(ctx, path, args...)
	if err != nil {
		return false, ""
	}
	match := versionRE.FindStringSubmatch(string(output))
	if len(match) != 2 {
		return false, ""
	}
	return true, match[1]
}

var _ RuntimeCapabilityProbe = systemRuntimeCapabilityProbe{}
