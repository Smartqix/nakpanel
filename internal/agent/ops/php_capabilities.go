package ops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	composerVersionRE = regexp.MustCompile(`(?i)\bcomposer(?:\s+version)?\s+([0-9]+(?:\.[0-9]+){1,2})\b`)
	wpCLIVersionRE    = regexp.MustCompile(`(?i)\bwp-cli\s+([0-9]+(?:\.[0-9]+){1,2})\b`)
	phpFPMVersionRE   = regexp.MustCompile(`(?i)\bPHP\s+([0-9]+\.[0-9]+)(?:\.[0-9]+)?\b`)
)

const (
	phpFPMProbeTimeout      = 3 * time.Second
	phpFPMStopTimeout       = time.Second
	phpFPMProbePollInterval = 20 * time.Millisecond
	phpFPMProbeStability    = 100 * time.Millisecond
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
	Start(ctx context.Context, name string, args ...string) (RuntimeCapabilityProcess, error)
}

type RuntimeCapabilityProcess interface {
	Wait() error
	Signal(signal os.Signal) error
	Kill() error
	Output() []byte
}

type systemRuntimeCapabilityProbe struct{}

type execRuntimeCapabilityProcess struct {
	command *exec.Cmd
	output  bytes.Buffer
}

func (systemRuntimeCapabilityProbe) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (systemRuntimeCapabilityProbe) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (systemRuntimeCapabilityProbe) Start(ctx context.Context, name string, args ...string) (RuntimeCapabilityProcess, error) {
	process := &execRuntimeCapabilityProcess{command: exec.CommandContext(ctx, name, args...)}
	process.command.Stdout = &process.output
	process.command.Stderr = &process.output
	if err := process.command.Start(); err != nil {
		return nil, err
	}
	return process, nil
}

func (p *execRuntimeCapabilityProcess) Wait() error {
	return p.command.Wait()
}

func (p *execRuntimeCapabilityProcess) Signal(signal os.Signal) error {
	return p.command.Process.Signal(signal)
}

func (p *execRuntimeCapabilityProcess) Kill() error {
	return p.command.Process.Kill()
}

func (p *execRuntimeCapabilityProcess) Output() []byte {
	return append([]byte(nil), p.output.Bytes()...)
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
	fpmHealthy := false
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
		phpPath = absoluteRuntimeBinaryPath(phpPath)
		runtime.CLIPath = phpPath
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
		fpmPath = absoluteRuntimeBinaryPath(fpmPath)
		runtime.FPMPath = fpmPath
		runtime.FPMAvailable = true
		if validatePHPFPMVersion(ctx, probe, fpmPath, version, &runtime.ValidationErrors) {
			runtime.FPMConfigValid, fpmHealthy = validateIsolatedFPMRuntime(ctx, probe, fpmPath, &runtime.ValidationErrors)
		}
	}

	runtime.Ready = runtime.CLIAvailable && runtime.FPMAvailable && runtime.FPMConfigValid &&
		fpmHealthy && runtime.OPcacheAvailable && len(runtime.MissingExtensions) == 0
	return runtime, true
}

func absoluteRuntimeBinaryPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return filepath.Clean(absolute)
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

func validatePHPFPMVersion(ctx context.Context, probe RuntimeCapabilityProbe, path, expected string, validationErrors *[]string) bool {
	output, err := probe.Run(ctx, path, "-v")
	if err != nil {
		*validationErrors = append(*validationErrors, fmt.Sprintf("PHP-FPM version check failed: %v: %s", err, strings.TrimSpace(string(output))))
		return false
	}
	match := phpFPMVersionRE.FindStringSubmatch(string(output))
	if len(match) != 2 {
		*validationErrors = append(*validationErrors, fmt.Sprintf("PHP-FPM reported an unrecognized version: %q", strings.TrimSpace(string(output))))
		return false
	}
	if match[1] != expected {
		*validationErrors = append(*validationErrors, fmt.Sprintf("PHP-FPM reported %q; expected %s", match[1], expected))
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

func validateIsolatedFPMRuntime(ctx context.Context, probe RuntimeCapabilityProbe, fpmPath string, validationErrors *[]string) (bool, bool) {
	file, err := os.CreateTemp("", "nakpanel-php-fpm-probe-*.conf")
	if err != nil {
		*validationErrors = append(*validationErrors, fmt.Sprintf("create isolated PHP-FPM configuration: %v", err))
		return false, false
	}
	path := file.Name()
	pidPath := path + ".pid"
	logPath := path + ".log"
	socketPath := path + ".sock"
	defer func() {
		_ = os.Remove(socketPath)
		_ = os.Remove(pidPath)
		_ = os.Remove(logPath)
		_ = os.Remove(path)
	}()
	config := fmt.Sprintf(`[global]
pid = %s
error_log = %s
daemonize = no

[nakpanel-probe]
user = www-data
group = www-data
listen = %s
pm = static
pm.max_children = 1
`, pidPath, logPath, socketPath)
	if _, err := file.WriteString(config); err != nil {
		_ = file.Close()
		*validationErrors = append(*validationErrors, fmt.Sprintf("write isolated PHP-FPM configuration: %v", err))
		return false, false
	}
	if err := file.Close(); err != nil {
		*validationErrors = append(*validationErrors, fmt.Sprintf("close isolated PHP-FPM configuration: %v", err))
		return false, false
	}
	output, err := probe.Run(ctx, fpmPath, "-t", "-y", path)
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			*validationErrors = append(*validationErrors, fmt.Sprintf("validate isolated PHP-FPM configuration: %v", err))
			return false, false
		}
		*validationErrors = append(*validationErrors, fmt.Sprintf("validate isolated PHP-FPM configuration: %v: %s", err, message))
		return false, false
	}

	probeCtx, cancel := context.WithTimeout(ctx, phpFPMProbeTimeout)
	defer cancel()
	process, err := probe.Start(probeCtx, fpmPath, "-F", "-y", path)
	if err != nil {
		*validationErrors = append(*validationErrors, fmt.Sprintf("start isolated PHP-FPM probe: %v", err))
		return true, false
	}
	done := make(chan error, 1)
	go func() {
		done <- process.Wait()
	}()
	reaped, readinessErr := waitForFPMSocket(probeCtx, socketPath, done)
	cleanupErr := stopAndReapRuntimeProcess(process, done, reaped)
	if readinessErr != nil {
		*validationErrors = append(*validationErrors, withRuntimeProcessOutput(readinessErr, process.Output()))
	}
	if cleanupErr != nil {
		*validationErrors = append(*validationErrors, withRuntimeProcessOutput(cleanupErr, process.Output()))
	}
	return true, readinessErr == nil && cleanupErr == nil
}

func waitForFPMSocket(ctx context.Context, socketPath string, done <-chan error) (bool, error) {
	ticker := time.NewTicker(phpFPMProbePollInterval)
	defer ticker.Stop()
	var readySince time.Time
	for {
		info, err := os.Stat(socketPath)
		if err == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return false, errors.New("isolated PHP-FPM probe created a non-socket listener path")
			}
			select {
			case exitErr := <-done:
				return true, fmt.Errorf("isolated PHP-FPM probe exited before readiness: %v", exitErr)
			default:
			}
			if readySince.IsZero() {
				readySince = time.Now()
			}
			if time.Since(readySince) >= phpFPMProbeStability {
				return false, nil
			}
		} else if os.IsNotExist(err) {
			readySince = time.Time{}
		} else {
			return false, fmt.Errorf("inspect isolated PHP-FPM socket: %w", err)
		}
		select {
		case exitErr := <-done:
			return true, fmt.Errorf("isolated PHP-FPM probe exited before creating its socket: %v", exitErr)
		case <-ctx.Done():
			return false, fmt.Errorf("isolated PHP-FPM probe did not become ready: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func stopAndReapRuntimeProcess(process RuntimeCapabilityProcess, done <-chan error, reaped bool) error {
	if reaped {
		return nil
	}
	if err := process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		_ = process.Kill()
	}
	timer := time.NewTimer(phpFPMStopTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		if err := process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("kill isolated PHP-FPM probe after shutdown timeout: %w", err)
		}
	}
	timer.Reset(phpFPMStopTimeout)
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errors.New("reap isolated PHP-FPM probe after forced termination: timeout")
	}
}

func withRuntimeProcessOutput(err error, output []byte) string {
	message := strings.TrimSpace(string(output))
	if message == "" {
		return err.Error()
	}
	return fmt.Sprintf("%v: %s", err, message)
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
