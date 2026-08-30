package ops

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

type PHPReleaseExporter interface {
	Export(context.Context, CommandRunner, string, string, string, string) error
}

type defaultPHPReleaseExporter struct{}

func (defaultPHPReleaseExporter) Export(ctx context.Context, runner CommandRunner, username, repository, revision, target string) error {
	return exportGitRevisionAsUser(ctx, runner, username, repository, revision, target)
}

type PHPApplicationProvisionerOptions struct {
	HomeRoot          string
	GitRoot           string
	StateRoot         string
	SystemdUnitDir    string
	PHPConfigDir      string
	PHPRunDir         string
	NginxAvailableDir string
	NginxCandidateDir string
	ComposerBinary    string
	MalwareScanner    string
	Runner            CommandRunner
	Exporter          PHPReleaseExporter
	RuntimeReady      func(context.Context, string) error
	Probe             func(context.Context, string, string) error
}

type PHPApplicationProvisioner struct {
	homeRoot          string
	gitRoot           string
	stateRoot         string
	systemdUnitDir    string
	phpConfigDir      string
	phpRunDir         string
	nginxAvailableDir string
	nginxCandidateDir string
	composerBinary    string
	malwareScanner    string
	runner            CommandRunner
	exporter          PHPReleaseExporter
	runtimeReady      func(context.Context, string) error
	probe             func(context.Context, string, string) error
	locks             sync.Map
	portMu            sync.Mutex
	reservedPorts     map[int]struct{}
}

type phpObservedMarker struct {
	ApplicationID        int64  `json:"application_id"`
	SiteID               int64  `json:"site_id"`
	DesiredRevision      int64  `json:"desired_revision"`
	ActiveDeploymentID   int64  `json:"active_deployment_id"`
	PreviousDeploymentID int64  `json:"previous_deployment_id,omitempty"`
	ResolvedRevision     string `json:"resolved_revision"`
	ReleasePath          string `json:"release_path"`
	EnvironmentPath      string `json:"environment_path"`
}

type phpCandidateMarker struct {
	ApplicationID    int64  `json:"application_id"`
	SiteID           int64  `json:"site_id"`
	DeploymentID     int64  `json:"deployment_id"`
	DesiredRevision  int64  `json:"desired_revision"`
	ResolvedRevision string `json:"resolved_revision"`
}

func NewPHPApplicationProvisioner(opts PHPApplicationProvisionerOptions) *PHPApplicationProvisioner {
	defaults := DefaultSitePathConfig()
	if opts.HomeRoot == "" {
		opts.HomeRoot = defaults.HomeRoot
	}
	if opts.GitRoot == "" {
		opts.GitRoot = "/var/lib/nakpanel/git"
	}
	if opts.StateRoot == "" {
		opts.StateRoot = "/var/lib/nakpanel/php-applications"
	}
	if opts.SystemdUnitDir == "" {
		opts.SystemdUnitDir = defaults.SystemdUnitDir
	}
	if opts.PHPConfigDir == "" {
		opts.PHPConfigDir = defaults.PHPFPMDedicatedDir
	}
	if opts.PHPRunDir == "" {
		opts.PHPRunDir = defaults.PHPFPMDedicatedRunDir
	}
	if opts.NginxAvailableDir == "" {
		opts.NginxAvailableDir = defaults.NginxAvailableDir
	}
	if opts.NginxCandidateDir == "" {
		opts.NginxCandidateDir = defaults.NginxConfDir
	}
	if opts.ComposerBinary == "" {
		opts.ComposerBinary = "/usr/local/lib/nakpanel/composer.phar"
	}
	if opts.MalwareScanner == "" {
		opts.MalwareScanner = "/usr/bin/clamscan"
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	if opts.Exporter == nil {
		opts.Exporter = defaultPHPReleaseExporter{}
	}
	if opts.RuntimeReady == nil {
		opts.RuntimeReady = func(ctx context.Context, version string) error {
			status := types.PHPSupportActive
			if version == "8.3" {
				status = types.PHPSupportSecuritySupported
			}
			runtime, discovered := probePHPRuntime(ctx, systemRuntimeCapabilityProbe{}, version, status)
			if !discovered || !runtime.Ready {
				return fmt.Errorf("PHP %s is not ready: %s", version, strings.Join(runtime.ValidationErrors, "; "))
			}
			return nil
		}
	}
	if opts.Probe == nil {
		opts.Probe = probePHPHTTP
	}
	return &PHPApplicationProvisioner{
		homeRoot: filepath.Clean(opts.HomeRoot), gitRoot: filepath.Clean(opts.GitRoot), stateRoot: filepath.Clean(opts.StateRoot),
		systemdUnitDir: filepath.Clean(opts.SystemdUnitDir), phpConfigDir: filepath.Clean(opts.PHPConfigDir),
		phpRunDir: filepath.Clean(opts.PHPRunDir), nginxAvailableDir: filepath.Clean(opts.NginxAvailableDir),
		nginxCandidateDir: filepath.Clean(opts.NginxCandidateDir), composerBinary: opts.ComposerBinary,
		malwareScanner: opts.MalwareScanner,
		runner:         opts.Runner, exporter: opts.Exporter, runtimeReady: opts.RuntimeReady, probe: opts.Probe,
		reservedPorts: make(map[int]struct{}),
	}
}

var (
	phpVersionRE     = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
	phpGitRefRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	phpResolvedRefRE = regexp.MustCompile(`^[a-f0-9]{40}([a-f0-9]{24})?$`)
	phpWorkerNameRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
	phpHealthPathRE  = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@/-]*$`)
)

func validatePHPApplicationSpec(spec types.PHPApplicationSpec) (types.PHPApplicationSpec, error) {
	if spec.ApplicationID <= 0 || spec.SubscriptionID <= 0 || spec.SiteID <= 0 || spec.DesiredRevision <= 0 || spec.RepositoryID <= 0 {
		return spec, errors.New("application, subscription, site, repository, and revision are required")
	}
	if site.ValidateUsername(spec.Username) != nil || site.ValidateDomain(spec.Domain) != nil {
		return spec, errors.New("validated PHP application identity is required")
	}
	if spec.HostingMode != types.PHPHostingModeManaged || spec.DesiredState != "active" {
		return spec, errors.New("PHP release deployment requires an active managed application")
	}
	if !spec.Policy.Permissions.Hosting || !spec.Policy.Permissions.Git || !spec.Policy.Permissions.ManagedPHPDeployments {
		return spec, errors.New("managed PHP deployments are disabled by the subscription policy")
	}
	if !phpVersionRE.MatchString(spec.PHPVersion) || !containsExact(spec.Policy.PHP.AllowedVersions, spec.PHPVersion) {
		return spec, errors.New("PHP version is not allowed by the subscription policy")
	}
	if !phpGitRefRE.MatchString(spec.RepositoryRef) || strings.Contains(spec.RepositoryRef, "..") || strings.HasPrefix(spec.RepositoryRef, "-") {
		return spec, errors.New("repository reference is invalid")
	}
	if spec.ReleaseRetention < 1 || spec.ReleaseRetention > 100 ||
		(spec.Policy.Resources.MaxPHPReleases >= 0 && spec.ReleaseRetention > spec.Policy.Resources.MaxPHPReleases) {
		return spec, errors.New("release retention exceeds the subscription policy")
	}
	switch spec.FrameworkProfile {
	case "", types.PHPFrameworkPlain:
		spec.FrameworkProfile = types.PHPFrameworkPlain
		if spec.HealthPath == "" {
			spec.HealthPath = "/"
		}
	case types.PHPFrameworkLaravel:
		if spec.PublicPath == "" {
			spec.PublicPath = "public"
		}
		if len(spec.SharedPaths) == 0 {
			spec.SharedPaths = []string{"storage", "bootstrap/cache"}
		}
		if spec.HealthPath == "" {
			spec.HealthPath = "/up"
		}
	case types.PHPFrameworkSymfony:
		if spec.PublicPath == "" {
			spec.PublicPath = "public"
		}
		if len(spec.SharedPaths) == 0 {
			spec.SharedPaths = []string{"var"}
		}
		if spec.HealthPath == "" {
			spec.HealthPath = "/"
		}
	case types.PHPFrameworkCustom:
		if spec.HealthPath == "" {
			spec.HealthPath = "/"
		}
	default:
		return spec, errors.New("framework profile is invalid")
	}
	if err := validatePHPRelativePath(spec.PublicPath, true); err != nil {
		return spec, fmt.Errorf("public path: %w", err)
	}
	if !phpHealthPathRE.MatchString(spec.HealthPath) || strings.Contains(spec.HealthPath, "..") || strings.ContainsAny(spec.HealthPath, "\x00\r\n") {
		return spec, errors.New("health path is invalid")
	}
	if len(spec.SharedPaths) > 16 {
		return spec, errors.New("at most 16 shared paths are supported")
	}
	seen := make(map[string]struct{}, len(spec.SharedPaths))
	for index, value := range spec.SharedPaths {
		if err := validatePHPRelativePath(value, false); err != nil {
			return spec, fmt.Errorf("shared path %d: %w", index+1, err)
		}
		clean := path.Clean(value)
		if _, exists := seen[clean]; exists {
			return spec, errors.New("shared paths must be unique")
		}
		for existing := range seen {
			if strings.HasPrefix(clean, existing+"/") || strings.HasPrefix(existing, clean+"/") {
				return spec, errors.New("shared paths must not overlap")
			}
		}
		if clean == spec.PublicPath || (spec.PublicPath != "" && strings.HasPrefix(spec.PublicPath, clean+"/")) {
			return spec, errors.New("the managed public root cannot be contained by writable shared storage")
		}
		seen[clean] = struct{}{}
		spec.SharedPaths[index] = clean
	}
	if spec.PublicPath != "" {
		spec.PublicPath = path.Clean(spec.PublicPath)
	}
	return spec, nil
}

func containsExact(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validatePHPRelativePath(value string, emptyAllowed bool) error {
	if value == "" && emptyAllowed {
		return nil
	}
	if value == "" || len(value) > 240 || strings.Contains(value, `\`) || strings.ContainsAny(value, "\x00\r\n") || path.IsAbs(value) {
		return errors.New("must be a safe relative path")
	}
	clean := path.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != value {
		return errors.New("must be a canonical relative path without traversal")
	}
	return nil
}

func phpComposerCommands(spec types.PHPApplicationSpec, release string) [][]string {
	commands := [][]string{
		{"validate", "--no-interaction", "--working-dir=" + release},
		{"install", "--no-dev", "--prefer-dist", "--optimize-autoloader", "--no-interaction", "--working-dir=" + release},
		{"check-platform-reqs", "--no-dev", "--no-interaction", "--working-dir=" + release},
		{"audit", "--locked", "--no-dev", "--format=json", "--no-interaction", "--working-dir=" + release},
	}
	if !spec.Policy.Permissions.ComposerCodeExecution || !spec.Composer.AllowScripts || !spec.Composer.AllowPlugins {
		commands[1] = append(commands[1], "--no-scripts", "--no-plugins")
	}
	return commands
}

type composerAuditReport struct {
	summary    string
	advisories int
	abandoned  int
}

func parseComposerAudit(data []byte) (string, error) {
	report, err := parseComposerAuditReport(data)
	return report.summary, err
}

func parseComposerAuditReport(data []byte) (composerAuditReport, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return composerAuditReport{}, errors.New("Composer audit returned malformed JSON")
	}
	raw, exists := document["advisories"]
	if !exists {
		return composerAuditReport{}, errors.New("Composer audit response is incomplete")
	}
	var advisories map[string][]map[string]any
	if err := json.Unmarshal(raw, &advisories); err != nil {
		return composerAuditReport{}, errors.New("Composer audit advisories are malformed")
	}
	counts := make(map[string]int)
	totalAdvisories := 0
	for _, packageAdvisories := range advisories {
		for _, advisory := range packageAdvisories {
			totalAdvisories++
			severity, _ := advisory["severity"].(string)
			severity = strings.ToLower(strings.TrimSpace(severity))
			if severity == "" {
				severity = "unknown"
			}
			counts[severity]++
			encoded, _ := json.Marshal(advisory)
			if severity == "high" || severity == "critical" || strings.Contains(strings.ToLower(string(encoded)), "malware") {
				return composerAuditReport{}, errors.New("Composer audit found a blocking security advisory")
			}
		}
	}
	abandoned := 0
	if rawAbandoned, ok := document["abandoned"]; ok {
		var list []any
		if json.Unmarshal(rawAbandoned, &list) == nil {
			abandoned = len(list)
		} else {
			var object map[string]any
			if json.Unmarshal(rawAbandoned, &object) == nil {
				abandoned = len(object)
			}
		}
	}
	keys := make([]string, 0, len(counts))
	for severity := range counts {
		keys = append(keys, severity)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)+1)
	for _, severity := range keys {
		parts = append(parts, severity+"="+strconv.Itoa(counts[severity]))
	}
	if abandoned > 0 {
		parts = append(parts, "abandoned="+strconv.Itoa(abandoned))
	}
	if len(parts) == 0 {
		return composerAuditReport{summary: "clean"}, nil
	}
	return composerAuditReport{summary: strings.Join(parts, ", "), advisories: totalAdvisories, abandoned: abandoned}, nil
}

func evaluateComposerAudit(data []byte, executionErr error) (string, error) {
	// Composer 2.8 emits no JSON when the lock contains no packages. An empty
	// successful result is therefore clean; any empty non-zero result remains a
	// hard failure below because there is no report explaining the exit status.
	if len(bytes.TrimSpace(data)) == 0 && executionErr == nil {
		return "clean", nil
	}
	report, err := parseComposerAuditReport(data)
	if err != nil {
		return "", err
	}
	if executionErr == nil {
		return report.summary, nil
	}
	type exitCoder interface{ ExitCode() int }
	var coder exitCoder
	if !errors.As(executionErr, &coder) {
		return "", errors.New("Composer audit execution failed")
	}
	expected := 0
	if report.advisories > 0 {
		expected |= 1
	}
	if report.abandoned > 0 {
		expected |= 2
	}
	if code := coder.ExitCode(); code < 1 || code > 3 || code != expected {
		return "", errors.New("Composer audit execution failed with an unexplained status")
	}
	return report.summary, nil
}

func renderPHPEnvironmentFile(environment []types.PHPEnvironmentPayload) (string, error) {
	if len(environment) > 128 {
		return "", errors.New("at most 128 PHP environment bindings are permitted")
	}
	seen := make(map[string]struct{}, len(environment))
	totalBytes := 0
	var builder strings.Builder
	for _, entry := range environment {
		if !environmentKeyRE.MatchString(entry.Name) || len(entry.Value) > 65536 || len(entry.Secret) > 65536 ||
			strings.ContainsRune(entry.Value, '\x00') || strings.ContainsRune(entry.Secret, '\x00') || (entry.Value != "" && entry.Secret != "") {
			return "", fmt.Errorf("invalid PHP environment binding %q", entry.Name)
		}
		if _, exists := seen[entry.Name]; exists {
			return "", fmt.Errorf("duplicate PHP environment binding %q", entry.Name)
		}
		seen[entry.Name] = struct{}{}
		value := entry.Value
		if entry.Secret != "" {
			value = entry.Secret
		}
		totalBytes += len(entry.Name) + len(value) + 4
		if totalBytes > 256<<10 {
			return "", errors.New("PHP environment exceeds the 256 KiB agent limit")
		}
		value = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`).Replace(value)
		fmt.Fprintf(&builder, "%s=\"%s\"\n", entry.Name, value)
	}
	return builder.String(), nil
}

func renderPHPWorkerUnit(spec types.PHPApplicationSpec, worker types.PHPWorker, release, environmentFile string) (string, error) {
	if worker.ID <= 0 || worker.ApplicationID != spec.ApplicationID || worker.SubscriptionID != spec.SubscriptionID ||
		!phpWorkerNameRE.MatchString(worker.Name) || worker.Processes < 1 || worker.Processes > 64 ||
		(worker.DesiredState != "running" && worker.DesiredState != "stopped") {
		return "", errors.New("invalid PHP worker specification")
	}
	if !spec.Policy.Permissions.PHPWorkers ||
		(spec.Policy.Resources.MaxPHPWorkers >= 0 && worker.Processes > spec.Policy.Resources.MaxPHPWorkers) {
		return "", errors.New("PHP worker exceeds the subscription policy")
	}
	if err := validatePHPRelativePath(worker.Script, false); err != nil {
		return "", fmt.Errorf("worker script: %w", err)
	}
	if len(worker.Arguments) > 64 {
		return "", errors.New("at most 64 PHP worker arguments are permitted")
	}
	executable := "/usr/bin/php" + spec.PHPVersion
	arguments := []string{executable, filepath.Join(release, filepath.FromSlash(worker.Script))}
	argumentBytes := 0
	for _, argument := range worker.Arguments {
		if len(argument) > 4096 || strings.ContainsAny(argument, "\x00\r\n") {
			return "", errors.New("worker argument contains an unsafe control character")
		}
		argumentBytes += len(argument)
		if argumentBytes > 32<<10 {
			return "", errors.New("PHP worker arguments exceed the 32 KiB agent limit")
		}
		arguments = append(arguments, argument)
	}
	for index := range arguments {
		arguments[index] = systemdQuoteArgument(arguments[index])
	}
	return fmt.Sprintf(`[Unit]
Description=Nakpanel PHP worker %d for site %d
After=network.target nakpanel-php-fpm@%d.service

[Service]
Type=simple
Slice=%s
User=%s
Group=%s
WorkingDirectory=%s
EnvironmentFile=%s
ExecStart=%s
Restart=on-failure
RestartSec=3s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
`, worker.ID, spec.SiteID, spec.SiteID, phpApplicationSliceName(spec.ApplicationID), spec.Username, spec.Username, release, environmentFile,
		strings.Join(arguments, " "), filepath.Join(filepath.Dir(filepath.Dir(release)), "shared")), nil
}

func phpApplicationSliceName(applicationID int64) string {
	return fmt.Sprintf("nakpanel-php-app-%d.slice", applicationID)
}

func renderPHPApplicationSlice(spec types.PHPApplicationSpec) string {
	memory := spec.Policy.Resources.MemoryMB
	if memory <= 0 {
		memory = 512
	}
	tasks := spec.Policy.Resources.MaxTasks
	if tasks <= 0 {
		tasks = 128
	}
	return fmt.Sprintf(`[Unit]
Description=Nakpanel aggregate PHP runtime limits for application %d

[Slice]
MemoryMax=%dM
CPUQuota=%d%%
TasksMax=%d
`, spec.ApplicationID, memory, effectivePHPCPUPercent(spec.Policy.Resources.CPUPercent), tasks)
}

func systemdQuoteArgument(value string) string {
	value = strings.ReplaceAll(value, "%", "%%")
	if value != "" && !strings.ContainsAny(value, " \t\"'\\") {
		return value
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func exportGitRevision(ctx context.Context, runner CommandRunner, repository, revision, target string) error {
	return exportGitRevisionWith(ctx, repository, revision, target, nil, func(ctx context.Context, args ...string) ([]byte, error) {
		return runner.Run(ctx, "git", args...)
	})
}

func exportGitRevisionAsUser(ctx context.Context, runner CommandRunner, username, repository, revision, target string) error {
	if site.ValidateUsername(username) != nil {
		return errors.New("validated Git build identity is required")
	}
	prepareArchive := func(archivePath string) error {
		output, err := runner.Run(ctx, "chown", username+":"+username, archivePath)
		if err != nil {
			return fmt.Errorf("prepare user-scoped Git archive: %w: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	}
	return exportGitRevisionWith(ctx, repository, revision, target, prepareArchive, func(ctx context.Context, args ...string) ([]byte, error) {
		return runner.Run(ctx, "runuser", append([]string{"-u", username, "--", "git"}, args...)...)
	})
}

func exportGitRevisionWith(ctx context.Context, repository, revision, target string, prepareArchive func(string) error, runGit func(context.Context, ...string) ([]byte, error)) error {
	if !phpResolvedRefRE.MatchString(revision) {
		return errors.New("Git revision must be an immutable 40 or 64 character object ID")
	}
	info, err := os.Lstat(repository)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("managed Git repository is missing or unsafe")
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o710); err != nil {
		return err
	}
	tarFile, err := os.CreateTemp(filepath.Dir(target), ".php-release-*.tar")
	if err != nil {
		return err
	}
	tarPath := tarFile.Name()
	if err := tarFile.Close(); err != nil {
		return err
	}
	defer os.Remove(tarPath)
	if prepareArchive != nil {
		if err := prepareArchive(tarPath); err != nil {
			return err
		}
	}
	output, err := runGit(ctx, "--git-dir", repository, "archive", "--format=tar", "--output="+tarPath, revision)
	if err != nil {
		return fmt.Errorf("export immutable Git revision: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := extractPHPReleaseTar(tarPath, target); err != nil {
		return fmt.Errorf("extract immutable Git revision: %w", err)
	}
	return nil
}

func extractPHPReleaseTar(archivePath, target string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := os.Mkdir(target, 0o750); err != nil {
		return err
	}
	reader := tar.NewReader(io.LimitReader(file, 1<<30))
	entries := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		entries++
		if entries > 100000 || header.Size < 0 || header.Size > 256<<20 {
			return errors.New("Git archive exceeds release extraction limits")
		}
		name := filepath.Clean(filepath.FromSlash(header.Name))
		destination := filepath.Join(target, name)
		if name == "." || filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) || !site.PathWithinDir(target, destination) {
			return errors.New("Git archive contains an unsafe path")
		}
		switch header.Typeflag {
		case tar.TypeXHeader, tar.TypeXGlobalHeader:
			continue
		case tar.TypeDir:
			if err := os.MkdirAll(destination, 0o750); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
				return err
			}
			output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(output, io.LimitReader(reader, header.Size+1))
			closeErr := output.Close()
			if copyErr != nil || closeErr != nil {
				return errors.Join(copyErr, closeErr)
			}
		default:
			return errors.New("Git archive contains a link or special file")
		}
	}
}

func (p *PHPApplicationProvisioner) DeployPHPRelease(ctx context.Context, req types.DeployPHPReleaseReq) (result types.DeployPHPReleaseResult, err error) {
	spec, err := validatePHPApplicationSpec(req.Application)
	if err != nil {
		return result, err
	}
	if req.Deployment.ID <= 0 || req.Deployment.ApplicationID != spec.ApplicationID || req.Deployment.SubscriptionID != spec.SubscriptionID ||
		strings.TrimSpace(req.Deployment.RequestedRevision) == "" {
		return result, errors.New("validated PHP deployment identity is required")
	}
	if err := validatePHPEnvironment(req.Environment); err != nil {
		return result, err
	}
	if err := p.runtimeReady(ctx, spec.PHPVersion); err != nil {
		return result, err
	}
	unlock := lockToolkitMutation(&p.locks, spec.ApplicationID)
	defer unlock()

	paths, err := p.pathsFor(spec, req.Deployment.ID)
	if err != nil {
		return result, err
	}
	resolved, err := p.resolveGitRevision(ctx, spec.Username, paths.repository, spec.RepositoryRef, req.Environment)
	if err != nil {
		return result, err
	}
	if err := p.resetCandidateArtifacts(ctx, spec, req.Deployment.ID, req.Environment); err != nil {
		return result, err
	}
	if existing, markerErr := p.readMarker(spec.ApplicationID); markerErr == nil &&
		existing.ActiveDeploymentID == req.Deployment.ID && existing.ResolvedRevision == resolved && existing.DesiredRevision == spec.DesiredRevision {
		return types.DeployPHPReleaseResult{
			DeploymentID: req.Deployment.ID, ResolvedRevision: resolved, ReleasePath: existing.ReleasePath,
			PreviousDeploymentID: existing.PreviousDeploymentID, HealthMessage: "already active", Changed: false,
		}, nil
	}
	_ = os.RemoveAll(paths.candidateRelease)
	if err := os.MkdirAll(paths.releaseRoot, 0o710); err != nil {
		return result, err
	}
	if err := p.prepareReleaseRoot(ctx, spec, paths.releaseRoot, req.Environment); err != nil {
		return result, err
	}
	defer func() {
		if err != nil {
			if _, markerErr := p.readMarker(spec.ApplicationID); markerErr != nil {
				_ = p.revokeManagedWebAccess(context.Background(), spec, req.Environment)
			}
		}
	}()
	defer func() {
		cleanupErr := p.resetCandidateArtifacts(context.Background(), spec, req.Deployment.ID, req.Environment)
		if cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("clean PHP release candidate: %w", cleanupErr))
			return
		}
		if removeErr := os.RemoveAll(paths.candidateRelease); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("remove PHP release candidate: %w", removeErr))
		}
	}()
	if err := p.exporter.Export(ctx, p.runner, spec.Username, paths.repository, resolved, paths.candidateRelease); err != nil {
		return result, redactPHPError(err, req.Environment)
	}
	if err := p.prepareCandidateOwnership(ctx, spec, paths.candidateRelease, paths.domainRoot, req.Environment); err != nil {
		return result, err
	}
	if err := p.prepareSharedPaths(ctx, spec, paths.candidateRelease, paths.sharedRoot, req.Environment); err != nil {
		return result, err
	}
	if err := p.scanReleaseForMalware(ctx, spec, paths.candidateRelease, req.Environment); err != nil {
		return result, err
	}
	auditSummary, err := p.runComposer(ctx, spec, paths.candidateRelease, paths.domainRoot, req.Environment)
	if err != nil {
		return result, err
	}
	// Composer can materialize new executable PHP after the source scan, so the
	// completed dependency tree must pass the same fail-closed malware gate.
	if err := p.scanReleaseForMalware(ctx, spec, paths.candidateRelease, req.Environment); err != nil {
		return result, err
	}
	if err := p.makeReleaseImmutable(ctx, spec, paths.candidateRelease, req.Environment); err != nil {
		return result, err
	}
	environmentPath, err := p.writeEnvironment(spec, req.Deployment.ID, req.Environment)
	if err != nil {
		return result, err
	}
	defer func() {
		if err == nil {
			return
		}
		active, markerErr := p.readMarker(spec.ApplicationID)
		if markerErr != nil || active.EnvironmentPath != environmentPath {
			_ = os.Remove(environmentPath)
		}
	}()
	port, releasePort, err := p.reserveCandidatePort(req.Deployment.ID)
	if err != nil {
		return result, err
	}
	defer releasePort()
	if err := p.startCandidate(ctx, spec, req.Deployment.ID, resolved, paths.candidateRelease, environmentPath, port, req.Environment); err != nil {
		return result, err
	}
	if _, statErr := os.Lstat(paths.release); statErr == nil {
		return result, errors.New("deployment release already exists but is not the active immutable revision")
	} else if !os.IsNotExist(statErr) {
		return result, statErr
	}
	if err := os.Rename(paths.candidateRelease, paths.release); err != nil {
		return result, fmt.Errorf("activate immutable release directory: %w", err)
	}
	keepFailedRelease := false
	defer func() {
		if err != nil && !keepFailedRelease {
			_ = os.RemoveAll(paths.release)
		}
	}()
	marker := phpObservedMarker{
		ApplicationID: spec.ApplicationID, SiteID: spec.SiteID, DesiredRevision: spec.DesiredRevision,
		ActiveDeploymentID: req.Deployment.ID, PreviousDeploymentID: req.Deployment.PreviousDeploymentID,
		ResolvedRevision: resolved, ReleasePath: paths.release, EnvironmentPath: environmentPath,
	}
	if err := p.activateRelease(ctx, spec, marker, environmentPath, req.Environment); err != nil {
		return result, err
	}
	keepFailedRelease = true
	if err := p.reconcileWorkersForActive(ctx, spec, spec.Workers, req.Environment, environmentPath, paths.release); err != nil {
		return result, err
	}
	if err := p.pruneReleases(paths.releaseRoot, spec.ReleaseRetention, marker.ActiveDeploymentID, marker.PreviousDeploymentID); err != nil {
		return result, err
	}
	if err := p.pruneEnvironments(spec.ApplicationID, marker.ActiveDeploymentID, marker.PreviousDeploymentID); err != nil {
		return result, err
	}
	return types.DeployPHPReleaseResult{
		DeploymentID: req.Deployment.ID, ResolvedRevision: resolved, ReleasePath: paths.release,
		PreviousDeploymentID: req.Deployment.PreviousDeploymentID, HealthMessage: "healthy",
		ComposerAudit: auditSummary, Changed: true,
	}, nil
}

type phpApplicationPaths struct {
	domainRoot       string
	repository       string
	releaseRoot      string
	sharedRoot       string
	candidateRelease string
	release          string
}

func (p *PHPApplicationProvisioner) pathsFor(spec types.PHPApplicationSpec, deploymentID int64) (phpApplicationPaths, error) {
	if deploymentID <= 0 {
		return phpApplicationPaths{}, errors.New("deployment id is required")
	}
	home, err := filepath.EvalSymlinks(p.homeRoot)
	if err != nil {
		return phpApplicationPaths{}, errors.New("hosting home root is unavailable")
	}
	domainRoot := filepath.Join(home, spec.Username, "domains", spec.Domain)
	resolvedDomain, err := filepath.EvalSymlinks(domainRoot)
	if err != nil || filepath.Clean(resolvedDomain) != filepath.Clean(domainRoot) || !site.PathWithinDir(home, resolvedDomain) {
		return phpApplicationPaths{}, errors.New("domain root is missing or contains an unsafe symlink")
	}
	repositoryRoot := filepath.Join(p.gitRoot, "site-"+strconv.FormatInt(spec.SiteID, 10))
	resolvedGitRoot, err := filepath.EvalSymlinks(p.gitRoot)
	if err != nil {
		return phpApplicationPaths{}, errors.New("managed Git root is unavailable")
	}
	resolvedRepositoryRoot, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil || !site.PathWithinDir(resolvedGitRoot, resolvedRepositoryRoot) {
		return phpApplicationPaths{}, errors.New("managed Git repository root is missing or unsafe")
	}
	mappingRoot := filepath.Join(p.stateRoot, "repositories")
	if err := os.MkdirAll(mappingRoot, 0o700); err != nil {
		return phpApplicationPaths{}, err
	}
	mappingPath := filepath.Join(mappingRoot, strconv.FormatInt(spec.RepositoryID, 10)+".site")
	if raw, readErr := os.ReadFile(mappingPath); readErr == nil {
		if strings.TrimSpace(string(raw)) != strconv.FormatInt(spec.SiteID, 10) {
			return phpApplicationPaths{}, errors.New("managed Git repository identity does not match the application")
		}
	} else if os.IsNotExist(readErr) {
		if err := writeFileAtomic(mappingPath, []byte(strconv.FormatInt(spec.SiteID, 10)+"\n"), 0o600); err != nil {
			return phpApplicationPaths{}, err
		}
	} else {
		return phpApplicationPaths{}, readErr
	}
	repository := filepath.Join(resolvedRepositoryRoot, "repository.git")
	if _, err := os.Stat(filepath.Join(repository, "HEAD")); os.IsNotExist(err) {
		repository = filepath.Join(resolvedRepositoryRoot, "remote.git")
	}
	info, err := os.Lstat(repository)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return phpApplicationPaths{}, errors.New("managed Git repository is missing or unsafe")
	}
	applicationRoot := filepath.Join(resolvedDomain, ".nakpanel")
	releaseRoot := filepath.Join(applicationRoot, "releases")
	sharedRoot := filepath.Join(applicationRoot, "shared")
	for _, directory := range []string{applicationRoot, releaseRoot, sharedRoot} {
		if err := validateManagedDirectoryPath(resolvedDomain, directory); err != nil {
			return phpApplicationPaths{}, err
		}
	}
	return phpApplicationPaths{
		domainRoot: resolvedDomain, repository: repository, releaseRoot: releaseRoot,
		sharedRoot:       sharedRoot,
		candidateRelease: filepath.Join(releaseRoot, "."+strconv.FormatInt(deploymentID, 10)+".candidate"),
		release:          filepath.Join(releaseRoot, strconv.FormatInt(deploymentID, 10)),
	}, nil
}

func (p *PHPApplicationProvisioner) resolveGitRevision(ctx context.Context, username, repository, ref string, environment []types.PHPEnvironmentPayload) (string, error) {
	output, err := p.runner.Run(ctx, "runuser", "-u", username, "--", "git", "--git-dir", repository, "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return "", redactPHPError(fmt.Errorf("resolve immutable Git revision: %w: %s", err, strings.TrimSpace(string(output))), environment)
	}
	revision := strings.TrimSpace(string(output))
	if !phpResolvedRefRE.MatchString(revision) {
		return "", errors.New("managed Git repository returned an invalid immutable revision")
	}
	return revision, nil
}

func validatePHPEnvironment(environment []types.PHPEnvironmentPayload) error {
	_, err := renderPHPEnvironmentFile(environment)
	return err
}

func redactPHPError(err error, environment []types.PHPEnvironmentPayload) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	for _, entry := range environment {
		for _, secret := range []string{entry.Secret, entry.Value} {
			if secret != "" {
				message = strings.ReplaceAll(message, secret, "[redacted]")
			}
		}
	}
	return errors.New(message)
}

func (p *PHPApplicationProvisioner) prepareSharedPaths(ctx context.Context, spec types.PHPApplicationSpec, release, sharedRoot string, environment []types.PHPEnvironmentPayload) error {
	domainRoot := filepath.Dir(filepath.Dir(sharedRoot))
	if err := validateManagedDirectoryPath(domainRoot, sharedRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(sharedRoot, 0o750); err != nil {
		return err
	}
	if err := validateManagedDirectoryPath(domainRoot, sharedRoot); err != nil {
		return err
	}
	for _, relative := range spec.SharedPaths {
		shared := filepath.Join(sharedRoot, filepath.FromSlash(relative))
		releasePath := filepath.Join(release, filepath.FromSlash(relative))
		if !site.PathWithinDir(sharedRoot, shared) || !site.PathWithinDir(release, releasePath) {
			return errors.New("shared path escaped its managed root")
		}
		if err := validateManagedDirectoryPath(sharedRoot, shared); err != nil {
			return err
		}
		if err := os.MkdirAll(shared, 0o750); err != nil {
			return err
		}
		if err := validateManagedDirectoryPath(sharedRoot, shared); err != nil {
			return err
		}
		if err := os.RemoveAll(releasePath); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(releasePath), 0o750); err != nil {
			return err
		}
		if err := os.Symlink(shared, releasePath); err != nil {
			return err
		}
	}
	output, err := p.runner.Run(ctx, "chown", "-h", "-R", spec.Username+":"+spec.Username, sharedRoot)
	if err != nil {
		return redactPHPError(fmt.Errorf("set shared path ownership: %w: %s", err, strings.TrimSpace(string(output))), environment)
	}
	return p.grantSharedWebAccess(ctx, spec, sharedRoot, environment)
}

func (p *PHPApplicationProvisioner) grantSharedWebAccess(ctx context.Context, spec types.PHPApplicationSpec, sharedRoot string, environment []types.PHPEnvironmentPayload) error {
	for _, relative := range spec.SharedPaths {
		if !phpSharedPathIsPublic(spec.PublicPath, relative) {
			continue
		}
		shared := filepath.Join(sharedRoot, filepath.FromSlash(relative))
		if !site.PathWithinDir(sharedRoot, shared) {
			return errors.New("shared web path escaped its server-derived root")
		}
		if err := validateManagedDirectoryPath(sharedRoot, shared); err != nil {
			return err
		}
		info, err := os.Lstat(shared)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("shared web path is missing or unsafe")
		}
		ancestors := []string{sharedRoot}
		for parent := filepath.Dir(shared); parent != sharedRoot; parent = filepath.Dir(parent) {
			ancestors = append(ancestors, parent)
		}
		sort.Strings(ancestors)
		if output, err := p.runner.Run(ctx, "setfacl", append([]string{"-m", "u:www-data:--x"}, ancestors...)...); err != nil {
			return redactPHPError(fmt.Errorf("grant nginx shared path traversal: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
		if output, err := p.runner.Run(ctx, "setfacl", "-R", "-m", "u:www-data:r-X", shared); err != nil {
			return redactPHPError(fmt.Errorf("grant nginx shared content access: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
		if output, err := p.runner.Run(ctx, "setfacl", "-m", "d:u:www-data:r-X", shared); err != nil {
			return redactPHPError(fmt.Errorf("grant nginx inherited shared content access: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
	}
	return nil
}

func phpSharedPathIsPublic(publicPath, sharedPath string) bool {
	return publicPath == "" || sharedPath == publicPath || strings.HasPrefix(sharedPath, publicPath+"/")
}

func (p *PHPApplicationProvisioner) prepareReleaseRoot(ctx context.Context, spec types.PHPApplicationSpec, releaseRoot string, environment []types.PHPEnvironmentPayload) error {
	managedRoot := filepath.Dir(releaseRoot)
	domainRoot := filepath.Dir(managedRoot)
	for _, directory := range []string{managedRoot, releaseRoot} {
		if err := validateManagedDirectoryPath(domainRoot, directory); err != nil {
			return err
		}
		if err := os.Chmod(directory, 0o710); err != nil {
			return err
		}
	}
	output, err := p.runner.Run(ctx, "chown", "root:"+spec.Username, managedRoot, releaseRoot)
	if err != nil {
		return redactPHPError(fmt.Errorf("prepare PHP release management roots: %w: %s", err, strings.TrimSpace(string(output))), environment)
	}
	output, err = p.runner.Run(ctx, "setfacl", "-m", "u:www-data:--x", managedRoot, releaseRoot)
	if err != nil {
		return redactPHPError(fmt.Errorf("grant nginx managed release traversal: %w: %s", err, strings.TrimSpace(string(output))), environment)
	}
	return nil
}

func validateManagedDirectoryPath(base, target string) error {
	base = filepath.Clean(base)
	target = filepath.Clean(target)
	if !site.PathWithinDir(base, target) {
		return errors.New("managed directory escaped its server-derived root")
	}
	relative, err := filepath.Rel(base, target)
	if err != nil {
		return err
	}
	current := base
	if relative == "." {
		return nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("managed directory contains a symlink or non-directory component")
		}
	}
	return nil
}

func (p *PHPApplicationProvisioner) prepareCandidateOwnership(ctx context.Context, spec types.PHPApplicationSpec, release, domainRoot string, environment []types.PHPEnvironmentPayload) error {
	managedRoot := filepath.Join(domainRoot, ".nakpanel")
	if err := os.Chmod(managedRoot, 0o710); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		info, err := os.Stat(domainRoot)
		if err != nil {
			return err
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
			return errors.New("domain root must remain a root-owned managed boundary")
		}
	}
	output, err := p.runner.Run(ctx, "chown", "-h", "-R", spec.Username+":"+spec.Username, release)
	if err != nil {
		return redactPHPError(fmt.Errorf("prepare release build ownership: %w: %s", err, strings.TrimSpace(string(output))), environment)
	}
	return nil
}

func (p *PHPApplicationProvisioner) scanReleaseForMalware(ctx context.Context, spec types.PHPApplicationSpec, release string, environment []types.PHPEnvironmentPayload) error {
	args := []string{"--quiet", "--wait", "--collect", "--pipe", "--uid=" + spec.Username, "--gid=" + spec.Username,
		"--property=NoNewPrivileges=yes", "--property=PrivateTmp=yes", "--property=ProtectSystem=strict",
		"--property=ProtectHome=read-only", "--property=MemoryMax=1G", "--property=MemorySwapMax=0", "--property=TasksMax=32", "--property=RuntimeMaxSec=300",
		p.malwareScanner, "--recursive", "--infected", "--no-summary", "--", release}
	output, err := p.runner.Run(ctx, "systemd-run", args...)
	if err != nil {
		return redactPHPError(fmt.Errorf("release malware scan failed or was unavailable: %w: %s", err, strings.TrimSpace(string(output))), environment)
	}
	if strings.TrimSpace(string(output)) != "" {
		return errors.New("release malware scan reported infected content")
	}
	return nil
}

func (p *PHPApplicationProvisioner) runComposer(ctx context.Context, spec types.PHPApplicationSpec, release, domainRoot string, environment []types.PHPEnvironmentPayload) (string, error) {
	if _, err := os.Stat(filepath.Join(release, "composer.json")); os.IsNotExist(err) {
		return "not required", nil
	} else if err != nil {
		return "", err
	}
	if !spec.Composer.Install || !spec.Policy.Permissions.Composer {
		return "", errors.New("Composer is required by the release but disabled by policy")
	}
	if _, err := os.Stat(filepath.Join(release, "composer.lock")); err != nil {
		return "", errors.New("composer.lock is required for managed deployments")
	}
	cache := filepath.Join(domainRoot, ".nakpanel", "composer-cache")
	tmp := filepath.Join(domainRoot, ".nakpanel", "tmp")
	if err := os.MkdirAll(cache, 0o750); err != nil {
		return "", err
	}
	if err := os.MkdirAll(tmp, 0o750); err != nil {
		return "", err
	}
	if output, err := p.runner.Run(ctx, "chown", "-h", "-R", spec.Username+":"+spec.Username, cache, tmp); err != nil {
		return "", redactPHPError(fmt.Errorf("prepare Composer build directories: %w: %s", err, strings.TrimSpace(string(output))), environment)
	}
	commands := phpComposerCommands(spec, release)
	for index, command := range commands {
		args := []string{"--quiet", "--wait", "--collect", "--pipe", "--uid=" + spec.Username, "--gid=" + spec.Username,
			"--property=NoNewPrivileges=yes", "--property=PrivateTmp=yes", "--property=ProtectSystem=strict",
			"--property=ProtectHome=read-only", "--property=MemoryMax=1G", "--property=TasksMax=128", "--property=RuntimeMaxSec=900",
			"--property=ReadWritePaths=" + release + " " + cache + " " + tmp,
			"--setenv=HOME=" + filepath.Join(p.homeRoot, spec.Username), "--setenv=COMPOSER_CACHE_DIR=" + cache, "--setenv=TMPDIR=" + tmp,
			"--working-directory=" + release, "/usr/bin/php" + spec.PHPVersion, p.composerBinary}
		args = append(args, command...)
		output, err := p.runner.Run(ctx, "systemd-run", args...)
		if index == len(commands)-1 {
			summary, auditErr := evaluateComposerAudit(output, err)
			if auditErr != nil {
				return "", auditErr
			}
			return summary, nil
		}
		if err != nil {
			return "", redactPHPError(fmt.Errorf("Composer validation step %d failed: %w: %s", index+1, err, strings.TrimSpace(string(output))), environment)
		}
	}
	return "clean", nil
}

func (p *PHPApplicationProvisioner) makeReleaseImmutable(ctx context.Context, spec types.PHPApplicationSpec, release string, environment []types.PHPEnvironmentPayload) error {
	if err := filepath.WalkDir(release, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := filepath.EvalSymlinks(path)
			if err != nil || !site.PathWithinDir(filepath.Join(filepath.Dir(filepath.Dir(release)), "shared"), target) {
				return errors.New("release contains a symlink outside the managed shared root")
			}
			return nil
		}
		mode := os.FileMode(0o440)
		if entry.IsDir() {
			mode = 0o550
		}
		return os.Chmod(path, mode)
	}); err != nil {
		return err
	}
	output, err := p.runner.Run(ctx, "chown", "-h", "-R", "root:"+spec.Username, release)
	if err != nil {
		return redactPHPError(fmt.Errorf("secure immutable release ownership: %w: %s", err, strings.TrimSpace(string(output))), environment)
	}
	output, err = p.runner.Run(ctx, "setfacl", "-R", "-m", "u:www-data:r-X", release)
	if err != nil {
		return redactPHPError(fmt.Errorf("grant nginx immutable release access: %w: %s", err, strings.TrimSpace(string(output))), environment)
	}
	return nil
}

func (p *PHPApplicationProvisioner) environmentPath(applicationID, deploymentID, desiredRevision int64) string {
	return filepath.Join(p.stateRoot, "app-"+strconv.FormatInt(applicationID, 10), "environments",
		fmt.Sprintf("deployment-%d-revision-%d.env", deploymentID, desiredRevision))
}

func (p *PHPApplicationProvisioner) writeEnvironment(spec types.PHPApplicationSpec, deploymentID int64, environment []types.PHPEnvironmentPayload) (string, error) {
	if spec.ApplicationID <= 0 || deploymentID <= 0 || spec.DesiredRevision <= 0 {
		return "", errors.New("PHP environment generation identity is required")
	}
	data, err := renderPHPEnvironmentFile(environment)
	if err != nil {
		return "", err
	}
	path := p.environmentPath(spec.ApplicationID, deploymentID, spec.DesiredRevision)
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", err
	}
	if existing, readErr := os.ReadFile(path); readErr == nil {
		if string(existing) != data {
			return "", errors.New("PHP environment generation is immutable")
		}
		return path, nil
	} else if !os.IsNotExist(readErr) {
		return "", readErr
	}
	if err := writeFileAtomic(path, []byte(data), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (p *PHPApplicationProvisioner) pruneEnvironments(applicationID int64, protectedDeployments ...int64) error {
	directory := filepath.Dir(p.environmentPath(applicationID, 1, 1))
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	protected := make(map[int64]struct{}, len(protectedDeployments))
	for _, deploymentID := range protectedDeployments {
		if deploymentID > 0 {
			protected[deploymentID] = struct{}{}
		}
	}
	pattern := regexp.MustCompile(`^deployment-([1-9][0-9]*)-revision-[1-9][0-9]*\.env$`)
	for _, entry := range entries {
		match := pattern.FindStringSubmatch(entry.Name())
		if entry.IsDir() || len(match) != 2 {
			continue
		}
		deploymentID, _ := strconv.ParseInt(match[1], 10, 64)
		if _, keep := protected[deploymentID]; keep {
			continue
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (p *PHPApplicationProvisioner) validEnvironmentPath(spec types.PHPApplicationSpec, deploymentID int64, environmentPath string) bool {
	directory := filepath.Dir(p.environmentPath(spec.ApplicationID, 1, 1))
	if !site.PathWithinDir(directory, environmentPath) {
		return false
	}
	pattern := regexp.MustCompile(fmt.Sprintf(`^deployment-%d-revision-[1-9][0-9]*\.env$`, deploymentID))
	if !pattern.MatchString(filepath.Base(environmentPath)) {
		return false
	}
	info, err := os.Lstat(environmentPath)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o600
}

func phpCandidatePort(deploymentID int64) int {
	return 31000 + int(deploymentID%1000)
}

func (p *PHPApplicationProvisioner) reserveCandidatePort(deploymentID int64) (int, func(), error) {
	p.portMu.Lock()
	defer p.portMu.Unlock()
	start := phpCandidatePort(deploymentID)
	for offset := 0; offset < 1000; offset++ {
		port := 31000 + ((start - 31000 + offset) % 1000)
		if _, exists := p.reservedPorts[port]; exists {
			continue
		}
		p.reservedPorts[port] = struct{}{}
		return port, func() {
			p.portMu.Lock()
			delete(p.reservedPorts, port)
			p.portMu.Unlock()
		}, nil
	}
	return 0, nil, errors.New("no managed PHP candidate ports are available")
}

func (p *PHPApplicationProvisioner) candidateMarkerPath(applicationID, deploymentID int64) string {
	return filepath.Join(p.stateRoot, "app-"+strconv.FormatInt(applicationID, 10),
		"candidate-"+strconv.FormatInt(deploymentID, 10), "candidate.json")
}

func (p *PHPApplicationProvisioner) readCandidateMarker(applicationID, deploymentID int64) (phpCandidateMarker, error) {
	var marker phpCandidateMarker
	data, err := os.ReadFile(p.candidateMarkerPath(applicationID, deploymentID))
	if err != nil {
		return marker, err
	}
	if err := json.Unmarshal(data, &marker); err != nil {
		return marker, err
	}
	return marker, nil
}

type phpCandidateUnitState struct {
	LoadState   string
	ActiveState string
}

func (s phpCandidateUnitState) inactive() bool {
	return s.ActiveState == "inactive" || s.ActiveState == "failed"
}

func (p *PHPApplicationProvisioner) candidateUnitState(ctx context.Context, unitName string, environment []types.PHPEnvironmentPayload) (phpCandidateUnitState, error) {
	output, err := p.runner.Run(ctx, "systemctl", "show", "--property=LoadState", "--property=ActiveState", "--no-pager", unitName)
	if err != nil {
		return phpCandidateUnitState{}, redactPHPError(fmt.Errorf("inspect PHP release candidate: %w: %s", err, strings.TrimSpace(string(output))), environment)
	}
	state := phpCandidateUnitState{}
	for _, line := range strings.Split(string(output), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "LoadState":
			state.LoadState = value
		case "ActiveState":
			state.ActiveState = value
		}
	}
	if state.LoadState == "" || state.ActiveState == "" {
		return phpCandidateUnitState{}, errors.New("systemd returned an incomplete PHP candidate state")
	}
	return state, nil
}

func (p *PHPApplicationProvisioner) stopCandidateUnit(ctx context.Context, unitName string, environment []types.PHPEnvironmentPayload) (bool, error) {
	state, err := p.candidateUnitState(ctx, unitName, environment)
	if err != nil {
		return false, err
	}
	if state.LoadState == "not-found" && state.inactive() {
		return false, nil
	}
	output, err := p.runner.Run(ctx, "systemctl", "stop", unitName)
	if err != nil {
		return false, redactPHPError(fmt.Errorf("stop stale PHP release candidate: %w: %s", err, strings.TrimSpace(string(output))), environment)
	}
	state, err = p.candidateUnitState(ctx, unitName, environment)
	if err != nil {
		return false, err
	}
	if !state.inactive() {
		return false, fmt.Errorf("PHP release candidate remained %s after stop", state.ActiveState)
	}
	return true, nil
}

func (p *PHPApplicationProvisioner) resetCandidateArtifacts(ctx context.Context, spec types.PHPApplicationSpec, deploymentID int64, environment []types.PHPEnvironmentPayload) error {
	siteConfigMutationMu.Lock()
	defer siteConfigMutationMu.Unlock()
	unitName := fmt.Sprintf("nakpanel-php-fpm-candidate@%d-%d.service", spec.SiteID, deploymentID)
	unitPath := filepath.Join(p.systemdUnitDir, unitName)
	nginxPath := filepath.Join(p.nginxCandidateDir, fmt.Sprintf("90-nakpanel-php-candidate-%d-%d.conf", spec.SiteID, deploymentID))
	_, unitErr := os.Lstat(unitPath)
	unitExists := unitErr == nil
	if unitErr != nil && !os.IsNotExist(unitErr) {
		return unitErr
	}
	_, nginxErr := os.Lstat(nginxPath)
	nginxExists := nginxErr == nil
	if nginxErr != nil && !os.IsNotExist(nginxErr) {
		return nginxErr
	}
	unitLoaded, err := p.stopCandidateUnit(ctx, unitName, environment)
	if err != nil {
		return err
	}
	for _, path := range []string{unitPath, nginxPath, filepath.Join(p.phpRunDir, fmt.Sprintf("candidate-%d-%d.sock", spec.SiteID, deploymentID))} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.RemoveAll(filepath.Dir(p.candidateMarkerPath(spec.ApplicationID, deploymentID))); err != nil {
		return err
	}
	if unitExists || unitLoaded {
		if output, err := p.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return redactPHPError(fmt.Errorf("reload units after stale PHP candidate cleanup: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
	}
	if nginxExists {
		if output, err := p.runner.Run(ctx, "nginx", "-t"); err != nil {
			return redactPHPError(fmt.Errorf("validate nginx after stale PHP candidate cleanup: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
		if output, err := p.runner.Run(ctx, "systemctl", "reload", "nginx"); err != nil {
			return redactPHPError(fmt.Errorf("reload nginx after stale PHP candidate cleanup: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
	}
	return nil
}

func (p *PHPApplicationProvisioner) startCandidate(ctx context.Context, spec types.PHPApplicationSpec, deploymentID int64, resolvedRevision, release, environmentPath string, port int, environment []types.PHPEnvironmentPayload) error {
	siteConfigMutationMu.Lock()
	defer siteConfigMutationMu.Unlock()
	if port < 31000 || port > 31999 {
		return errors.New("candidate port is outside the managed loopback range")
	}
	candidateRoot := filepath.Join(p.stateRoot, "app-"+strconv.FormatInt(spec.ApplicationID, 10), "candidate-"+strconv.FormatInt(deploymentID, 10))
	if err := os.MkdirAll(candidateRoot, 0o700); err != nil {
		return err
	}
	socket := filepath.Join(p.phpRunDir, fmt.Sprintf("candidate-%d-%d.sock", spec.SiteID, deploymentID))
	fpmConfig := filepath.Join(candidateRoot, "fpm.conf")
	unitName := fmt.Sprintf("nakpanel-php-fpm-candidate@%d-%d.service", spec.SiteID, deploymentID)
	unitPath := filepath.Join(p.systemdUnitDir, unitName)
	nginxPath := filepath.Join(p.nginxCandidateDir, fmt.Sprintf("90-nakpanel-php-candidate-%d-%d.conf", spec.SiteID, deploymentID))
	documentRoot := phpDocumentRoot(release, spec.PublicPath)
	marker := phpCandidateMarker{
		ApplicationID: spec.ApplicationID, SiteID: spec.SiteID, DeploymentID: deploymentID,
		DesiredRevision: spec.DesiredRevision, ResolvedRevision: resolvedRevision,
	}
	markerData, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(p.candidateMarkerPath(spec.ApplicationID, deploymentID), append(markerData, '\n'), 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(fpmConfig, []byte(renderManagedFPMConfig(spec, documentRoot, socket)), 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(unitPath, []byte(renderManagedFPMUnit(spec, fpmConfig, environmentPath, release, socket, true)), 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(nginxPath, []byte(renderCandidatePHPNginx(spec, documentRoot, socket, port)), 0o600); err != nil {
		return err
	}
	commands := [][]string{
		{"php-fpm" + spec.PHPVersion, "-t", "-y", fpmConfig},
		{"systemctl", "daemon-reload"},
		{"systemctl", "restart", unitName},
		{"nginx", "-t"},
		{"systemctl", "reload", "nginx"},
	}
	for _, command := range commands {
		output, err := p.runner.Run(ctx, command[0], command[1:]...)
		if err != nil {
			return redactPHPError(fmt.Errorf("start PHP release candidate: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
	}
	state, err := p.candidateUnitState(ctx, unitName, environment)
	if err != nil {
		return err
	}
	if state.LoadState != "loaded" || state.ActiveState != "active" {
		return fmt.Errorf("new PHP release candidate did not become active (load=%s active=%s)", state.LoadState, state.ActiveState)
	}
	if err := p.probeThree(ctx, fmt.Sprintf("http://127.0.0.1:%d%s", port, spec.HealthPath), spec.Domain); err != nil {
		return fmt.Errorf("PHP release candidate failed readiness: %w", err)
	}
	observed, err := p.readCandidateMarker(spec.ApplicationID, deploymentID)
	if err != nil || observed != marker {
		return errors.New("PHP release candidate generation marker changed during readiness checks")
	}
	return nil
}

func (p *PHPApplicationProvisioner) stopPHPCandidates(ctx context.Context, spec types.PHPApplicationSpec, environment []types.PHPEnvironmentPayload) error {
	siteConfigMutationMu.Lock()
	defer siteConfigMutationMu.Unlock()

	changedUnits := false
	units, _ := filepath.Glob(filepath.Join(p.systemdUnitDir, fmt.Sprintf("nakpanel-php-fpm-candidate@%d-*.service", spec.SiteID)))
	for _, unitPath := range units {
		unitName := filepath.Base(unitPath)
		output, err := p.runner.Run(ctx, "systemctl", "disable", "--now", unitName)
		if err != nil {
			return redactPHPError(fmt.Errorf("stop PHP release candidate: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
		if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		changedUnits = true
	}

	changedNginx := false
	configs, _ := filepath.Glob(filepath.Join(p.nginxCandidateDir, fmt.Sprintf("90-nakpanel-php-candidate-%d-*.conf", spec.SiteID)))
	for _, configPath := range configs {
		if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		changedNginx = true
	}
	sockets, _ := filepath.Glob(filepath.Join(p.phpRunDir, fmt.Sprintf("candidate-%d-*.sock", spec.SiteID)))
	for _, socketPath := range sockets {
		if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	candidateStates, _ := filepath.Glob(filepath.Join(p.stateRoot, "app-"+strconv.FormatInt(spec.ApplicationID, 10), "candidate-*"))
	for _, statePath := range candidateStates {
		if err := os.RemoveAll(statePath); err != nil {
			return err
		}
	}
	if changedUnits {
		if output, err := p.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return redactPHPError(fmt.Errorf("reload PHP release candidate units: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
	}
	if changedNginx {
		if output, err := p.runner.Run(ctx, "nginx", "-t"); err != nil {
			return redactPHPError(fmt.Errorf("validate nginx after stopping PHP candidates: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
		if output, err := p.runner.Run(ctx, "systemctl", "reload", "nginx"); err != nil {
			return redactPHPError(fmt.Errorf("reload nginx after stopping PHP candidates: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
	}
	return nil
}

func (p *PHPApplicationProvisioner) activateRelease(ctx context.Context, spec types.PHPApplicationSpec, marker phpObservedMarker, environmentPath string, environment []types.PHPEnvironmentPayload) (err error) {
	siteConfigMutationMu.Lock()
	defer siteConfigMutationMu.Unlock()
	resolvedHome, homeErr := filepath.EvalSymlinks(p.homeRoot)
	if marker.ApplicationID != spec.ApplicationID || marker.SiteID != spec.SiteID || marker.ActiveDeploymentID <= 0 ||
		homeErr != nil || !phpResolvedRefRE.MatchString(marker.ResolvedRevision) ||
		!site.PathWithinDir(filepath.Join(resolvedHome, spec.Username, "domains", spec.Domain, ".nakpanel", "releases"), marker.ReleasePath) ||
		marker.EnvironmentPath != environmentPath || !p.validEnvironmentPath(spec, marker.ActiveDeploymentID, environmentPath) {
		return errors.New("active PHP release marker is invalid")
	}
	info, err := os.Lstat(marker.ReleasePath)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("active PHP release is missing or unsafe")
	}
	documentRoot := phpDocumentRoot(marker.ReleasePath, spec.PublicPath)
	if info, err := os.Stat(documentRoot); err != nil || !info.IsDir() {
		return errors.New("managed PHP public directory is missing")
	}
	fpmConfig := filepath.Join(p.phpConfigDir, strconv.FormatInt(spec.SiteID, 10)+".conf")
	unitName := fmt.Sprintf("nakpanel-php-fpm@%d.service", spec.SiteID)
	unitPath := filepath.Join(p.systemdUnitDir, unitName)
	slicePath := filepath.Join(p.systemdUnitDir, phpApplicationSliceName(spec.ApplicationID))
	nginxPath := filepath.Join(p.nginxAvailableDir, spec.Domain+".conf")
	paths := []string{fpmConfig, unitPath, slicePath, nginxPath, p.markerPath(spec.ApplicationID)}
	snapshots, err := snapshotFiles(paths)
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		var rollbackErrors []error
		rollbackErrors = append(rollbackErrors, cause)
		if restoreErr := restoreSnapshots(snapshots); restoreErr != nil {
			rollbackErrors = append(rollbackErrors, restoreErr)
		}
		for _, command := range [][]string{
			{"systemctl", "daemon-reload"},
			{"systemctl", "restart", unitName},
			{"nginx", "-t"},
			{"systemctl", "reload", "nginx"},
		} {
			output, commandErr := p.runner.Run(context.Background(), command[0], command[1:]...)
			if commandErr != nil {
				rollbackErrors = append(rollbackErrors, redactPHPError(fmt.Errorf("restore previous PHP runtime: %w: %s", commandErr, strings.TrimSpace(string(output))), environment))
			}
		}
		return errors.Join(rollbackErrors...)
	}
	currentNginx, err := os.ReadFile(nginxPath)
	if err != nil {
		return errors.New("existing Nakpanel nginx site configuration is required before managed activation")
	}
	managedNginx, err := replaceManagedNginxRuntime(currentNginx, documentRoot, filepath.Join(p.phpRunDir, fmt.Sprintf("site-%d.sock", spec.SiteID)))
	if err != nil {
		return err
	}
	if err := writeFileAtomic(fpmConfig, []byte(renderManagedFPMConfig(spec, documentRoot, filepath.Join(p.phpRunDir, fmt.Sprintf("site-%d.sock", spec.SiteID)))), 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(slicePath, []byte(renderPHPApplicationSlice(spec)), 0o644); err != nil {
		return rollback(err)
	}
	if err := writeFileAtomic(unitPath, []byte(renderManagedFPMUnit(spec, fpmConfig, environmentPath, marker.ReleasePath, filepath.Join(p.phpRunDir, fmt.Sprintf("site-%d.sock", spec.SiteID)), false)), 0o644); err != nil {
		return rollback(err)
	}
	if err := writeFileAtomic(nginxPath, managedNginx, 0o644); err != nil {
		return rollback(err)
	}
	for _, command := range [][]string{
		{"php-fpm" + spec.PHPVersion, "-t", "-y", fpmConfig},
		{"systemctl", "daemon-reload"},
		{"systemctl", "restart", unitName},
		{"nginx", "-t"},
		{"systemctl", "reload", "nginx"},
	} {
		output, runErr := p.runner.Run(ctx, command[0], command[1:]...)
		if runErr != nil {
			return rollback(redactPHPError(fmt.Errorf("activate managed PHP release: %w: %s", runErr, strings.TrimSpace(string(output))), environment))
		}
	}
	if err := p.probeThree(ctx, "http://127.0.0.1"+spec.HealthPath, spec.Domain); err != nil {
		return rollback(fmt.Errorf("live managed PHP release failed readiness: %w", err))
	}
	if err := p.writeMarker(marker); err != nil {
		return rollback(err)
	}
	return nil
}

func phpDocumentRoot(release, publicPath string) string {
	if publicPath == "" {
		return release
	}
	return filepath.Join(release, filepath.FromSlash(publicPath))
}

func renderManagedFPMConfig(spec types.PHPApplicationSpec, documentRoot, socket string) string {
	maxChildren := spec.Policy.PHP.FPMMaxChildren
	if maxChildren <= 0 {
		maxChildren = 8
	}
	maxRequests := spec.Policy.PHP.FPMMaxRequests
	if maxRequests <= 0 {
		maxRequests = 500
	}
	memory := spec.Policy.PHP.MemoryLimitMB
	if memory <= 0 {
		memory = 128
	}
	releaseRoot := documentRoot
	if spec.PublicPath != "" {
		for range strings.Split(spec.PublicPath, "/") {
			releaseRoot = filepath.Dir(releaseRoot)
		}
	}
	sharedRoot := filepath.Join(filepath.Dir(filepath.Dir(releaseRoot)), "shared")
	return fmt.Sprintf(`[global]
pid = %s
error_log = /var/log/php-fpm/%s-%s.error.log
daemonize = no

[www]
user = %s
group = %s
listen = %s
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = %d
pm.max_requests = %d
pm.process_idle_timeout = 10s
clear_env = no
catch_workers_output = yes
security.limit_extensions = .php
php_admin_value[open_basedir] = %s:%s:/tmp
php_admin_value[memory_limit] = %dM
php_admin_flag[log_errors] = on
	`, strings.TrimSuffix(socket, ".sock")+".pid", spec.Username, strings.ReplaceAll(spec.Domain, ".", "-"), spec.Username, spec.Username,
		socket, maxChildren, maxRequests, releaseRoot, sharedRoot, memory)
}

func renderManagedFPMUnit(spec types.PHPApplicationSpec, fpmConfig, environmentFile, release, socket string, candidate bool) string {
	memory := spec.Policy.Resources.MemoryMB
	if memory <= 0 {
		memory = 512
	}
	tasks := spec.Policy.Resources.MaxTasks
	if tasks <= 0 {
		tasks = 128
	}
	description := fmt.Sprintf("Nakpanel managed PHP-FPM for site %d", spec.SiteID)
	slice := ""
	if candidate {
		description += " candidate"
	} else {
		slice = "Slice=" + phpApplicationSliceName(spec.ApplicationID) + "\n"
	}
	return fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
Type=simple
%sEnvironmentFile=%s
ExecStartPre=/usr/sbin/php-fpm%s -t -y %s
ExecStart=/usr/sbin/php-fpm%s --nodaemonize -y %s
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s %s %s %s
RuntimeDirectory=nakpanel-php
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
MemoryMax=%dM
CPUQuota=%d%%
TasksMax=%d

[Install]
WantedBy=multi-user.target
`, description, slice, environmentFile, spec.PHPVersion, fpmConfig, spec.PHPVersion, fpmConfig,
		filepath.Join(filepath.Dir(filepath.Dir(release)), "shared"), "/var/log/php-fpm", filepath.Dir(socket), phpSessionDirectory, memory,
		effectivePHPCPUPercent(spec.Policy.Resources.CPUPercent), tasks)
}

func effectivePHPCPUPercent(value int) int {
	if value <= 0 {
		return 100
	}
	return value
}

func renderCandidatePHPNginx(spec types.PHPApplicationSpec, documentRoot, socket string, port int) string {
	return fmt.Sprintf(`server {
    listen 127.0.0.1:%d;
    server_name _;
    root %s;
    index index.php index.html;
    access_log off;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:%s;
    }
    location ~ /\. { deny all; }
}
`, port, documentRoot, socket)
}

func replaceManagedNginxRuntime(config []byte, documentRoot, socket string) ([]byte, error) {
	lines := strings.Split(string(config), "\n")
	rootCount, socketCount := 0, 0
	rootRE := regexp.MustCompile(`^(\s*)root\s+[^;]+;\s*$`)
	socketRE := regexp.MustCompile(`^(\s*)fastcgi_pass\s+unix:[^;]+;\s*$`)
	for index, line := range lines {
		if match := rootRE.FindStringSubmatch(line); len(match) == 2 {
			lines[index] = match[1] + "root " + documentRoot + ";"
			rootCount++
		}
		if match := socketRE.FindStringSubmatch(line); len(match) == 2 {
			lines[index] = match[1] + "fastcgi_pass unix:" + socket + ";"
			socketCount++
		}
	}
	if rootCount == 0 || socketCount == 0 {
		return nil, errors.New("existing nginx site configuration is not a recognized Nakpanel PHP vhost")
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func (p *PHPApplicationProvisioner) probeThree(ctx context.Context, address, host string) error {
	for attempt := 0; attempt < 3; attempt++ {
		if err := p.probe(ctx, address, host); err != nil {
			return err
		}
	}
	return nil
}

func probePHPHTTP(ctx context.Context, address, host string) error {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	request.Host = host
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode > 399 {
		return fmt.Errorf("HTTP health probe returned %d", response.StatusCode)
	}
	return nil
}

func (p *PHPApplicationProvisioner) markerPath(applicationID int64) string {
	return filepath.Join(p.stateRoot, "app-"+strconv.FormatInt(applicationID, 10), "observed.json")
}

func (p *PHPApplicationProvisioner) writeMarker(marker phpObservedMarker) error {
	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	return writeFileAtomic(p.markerPath(marker.ApplicationID), append(data, '\n'), 0o600)
}

func (p *PHPApplicationProvisioner) readMarker(applicationID int64) (phpObservedMarker, error) {
	var marker phpObservedMarker
	data, err := os.ReadFile(p.markerPath(applicationID))
	if err != nil {
		return marker, err
	}
	if err := json.Unmarshal(data, &marker); err != nil {
		return marker, err
	}
	return marker, nil
}

func (p *PHPApplicationProvisioner) pruneReleases(root string, retention int, protected ...int64) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	keep := make(map[int64]struct{}, len(protected))
	for _, id := range protected {
		if id > 0 {
			keep[id] = struct{}{}
		}
	}
	type item struct {
		id   int64
		path string
	}
	var releases []item
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		id, err := strconv.ParseInt(entry.Name(), 10, 64)
		if err == nil && id > 0 {
			releases = append(releases, item{id: id, path: filepath.Join(root, entry.Name())})
		}
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].id > releases[j].id })
	retention = max(retention, len(keep))
	remaining := retention - len(keep)
	for _, release := range releases {
		_, protected := keep[release.id]
		if protected {
			continue
		}
		if remaining > 0 {
			remaining--
			continue
		}
		if err := os.RemoveAll(release.path); err != nil {
			return err
		}
	}
	return nil
}

func (p *PHPApplicationProvisioner) RollbackPHPRelease(ctx context.Context, req types.RollbackPHPReleaseReq) (types.RollbackPHPReleaseResult, error) {
	spec, err := validatePHPApplicationSpec(req.Application)
	if err != nil {
		return types.RollbackPHPReleaseResult{}, err
	}
	if req.DeploymentID <= 0 || req.TargetDeployment.ID <= 0 || req.TargetDeployment.ApplicationID != spec.ApplicationID ||
		req.TargetDeployment.SubscriptionID != spec.SubscriptionID || !phpResolvedRefRE.MatchString(req.TargetDeployment.ResolvedRevision) {
		return types.RollbackPHPReleaseResult{}, errors.New("rollback target does not belong to the PHP application")
	}
	if err := validatePHPEnvironment(req.Environment); err != nil {
		return types.RollbackPHPReleaseResult{}, err
	}
	if err := p.runtimeReady(ctx, spec.PHPVersion); err != nil {
		return types.RollbackPHPReleaseResult{}, err
	}
	unlock := lockToolkitMutation(&p.locks, spec.ApplicationID)
	defer unlock()
	paths, err := p.pathsFor(spec, req.TargetDeployment.ID)
	if err != nil {
		return types.RollbackPHPReleaseResult{}, err
	}
	info, err := os.Lstat(paths.release)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return types.RollbackPHPReleaseResult{}, errors.New("rollback release is missing or unsafe")
	}
	if err := p.prepareReleaseRoot(ctx, spec, paths.releaseRoot, req.Environment); err != nil {
		return types.RollbackPHPReleaseResult{}, err
	}
	if err := p.grantSharedWebAccess(ctx, spec, paths.sharedRoot, req.Environment); err != nil {
		return types.RollbackPHPReleaseResult{}, err
	}
	if err := p.makeReleaseImmutable(ctx, spec, paths.release, req.Environment); err != nil {
		return types.RollbackPHPReleaseResult{}, err
	}
	current, _ := p.readMarker(spec.ApplicationID)
	environmentPath, err := p.writeEnvironment(spec, req.TargetDeployment.ID, req.Environment)
	if err != nil {
		return types.RollbackPHPReleaseResult{}, err
	}
	marker := phpObservedMarker{
		ApplicationID: spec.ApplicationID, SiteID: spec.SiteID, DesiredRevision: spec.DesiredRevision,
		ActiveDeploymentID: req.TargetDeployment.ID, PreviousDeploymentID: current.ActiveDeploymentID,
		ResolvedRevision: req.TargetDeployment.ResolvedRevision, ReleasePath: paths.release, EnvironmentPath: environmentPath,
	}
	if current.ActiveDeploymentID == marker.ActiveDeploymentID && current.DesiredRevision == marker.DesiredRevision {
		return types.RollbackPHPReleaseResult{DeploymentID: req.DeploymentID, ActiveDeploymentID: marker.ActiveDeploymentID, ResolvedRevision: marker.ResolvedRevision, HealthMessage: "already active"}, nil
	}
	if err := p.activateRelease(ctx, spec, marker, environmentPath, req.Environment); err != nil {
		return types.RollbackPHPReleaseResult{}, err
	}
	if err := p.reconcileWorkersForActive(ctx, spec, spec.Workers, req.Environment, environmentPath, paths.release); err != nil {
		return types.RollbackPHPReleaseResult{}, err
	}
	return types.RollbackPHPReleaseResult{DeploymentID: req.DeploymentID, ActiveDeploymentID: marker.ActiveDeploymentID, ResolvedRevision: marker.ResolvedRevision, HealthMessage: "healthy", Changed: true}, nil
}

func (p *PHPApplicationProvisioner) ReconcilePHPApplication(ctx context.Context, req types.ReconcilePHPApplicationReq) (types.ReconcilePHPApplicationResult, error) {
	spec := req.Application
	if spec.ApplicationID <= 0 || spec.SubscriptionID <= 0 || spec.SiteID <= 0 || site.ValidateUsername(spec.Username) != nil || site.ValidateDomain(spec.Domain) != nil {
		return types.ReconcilePHPApplicationResult{}, errors.New("validated PHP application identity is required")
	}
	if err := validatePHPEnvironment(req.Environment); err != nil {
		return types.ReconcilePHPApplicationResult{}, err
	}
	unlock := lockToolkitMutation(&p.locks, spec.ApplicationID)
	defer unlock()
	if spec.HostingMode == types.PHPHostingModeClassic {
		if err := p.stopApplicationWorkers(ctx, spec.ApplicationID, nil, req.Environment); err != nil {
			return types.ReconcilePHPApplicationResult{}, err
		}
		if err := p.revokeManagedWebAccess(ctx, spec, req.Environment); err != nil {
			return types.ReconcilePHPApplicationResult{}, err
		}
		return types.ReconcilePHPApplicationResult{ApplicationID: spec.ApplicationID, ObservedState: "classic", Message: "Classic Hosting remains active"}, nil
	}
	if spec.DesiredState == "suspended" {
		if err := p.stopPHPCandidates(ctx, spec, req.Environment); err != nil {
			return types.ReconcilePHPApplicationResult{}, err
		}
		output, err := p.runner.Run(ctx, "systemctl", "stop", fmt.Sprintf("nakpanel-php-fpm@%d.service", spec.SiteID))
		if err != nil {
			return types.ReconcilePHPApplicationResult{}, redactPHPError(fmt.Errorf("stop managed PHP-FPM: %w: %s", err, strings.TrimSpace(string(output))), req.Environment)
		}
		if err := p.stopApplicationWorkers(ctx, spec.ApplicationID, nil, req.Environment); err != nil {
			return types.ReconcilePHPApplicationResult{}, err
		}
		if err := p.revokeManagedWebAccess(ctx, spec, req.Environment); err != nil {
			return types.ReconcilePHPApplicationResult{}, err
		}
		return types.ReconcilePHPApplicationResult{ApplicationID: spec.ApplicationID, ObservedState: "suspended", Changed: true}, nil
	}
	normalized, err := validatePHPApplicationSpec(spec)
	if err != nil {
		return types.ReconcilePHPApplicationResult{}, err
	}
	if err := p.runtimeReady(ctx, normalized.PHPVersion); err != nil {
		return types.ReconcilePHPApplicationResult{}, err
	}
	if req.ActiveDeployment == nil {
		marker, markerErr := p.readMarker(spec.ApplicationID)
		if markerErr == nil {
			if marker.ApplicationID != spec.ApplicationID || marker.SiteID != spec.SiteID || marker.ActiveDeploymentID <= 0 ||
				!phpResolvedRefRE.MatchString(marker.ResolvedRevision) {
				return types.ReconcilePHPApplicationResult{}, errors.New("observed PHP release marker is invalid")
			}
			paths, pathErr := p.pathsFor(normalized, marker.ActiveDeploymentID)
			if pathErr != nil {
				return types.ReconcilePHPApplicationResult{}, pathErr
			}
			if filepath.Clean(marker.ReleasePath) != filepath.Clean(paths.release) {
				return types.ReconcilePHPApplicationResult{}, errors.New("observed PHP release marker path is invalid")
			}
			if info, statErr := os.Stat(paths.release); statErr != nil || !info.IsDir() {
				if statErr != nil {
					return types.ReconcilePHPApplicationResult{}, fmt.Errorf("inspect observed PHP release: %w", statErr)
				}
				return types.ReconcilePHPApplicationResult{}, errors.New("observed PHP release is not a directory")
			}
			return types.ReconcilePHPApplicationResult{
				ApplicationID: spec.ApplicationID, ActiveDeploymentID: marker.ActiveDeploymentID,
				PreviousDeploymentID: marker.PreviousDeploymentID, ResolvedRevision: marker.ResolvedRevision,
				ObservedState: "healthy", Message: "recovered active release from the observed-state marker",
			}, nil
		}
		if !errors.Is(markerErr, os.ErrNotExist) {
			return types.ReconcilePHPApplicationResult{}, fmt.Errorf("read observed PHP release marker: %w", markerErr)
		}
		return types.ReconcilePHPApplicationResult{ApplicationID: spec.ApplicationID, ObservedState: "pending", Message: "waiting for the first healthy managed release"}, nil
	}
	deployment := req.ActiveDeployment
	if deployment.ApplicationID != spec.ApplicationID || deployment.SubscriptionID != spec.SubscriptionID || !phpResolvedRefRE.MatchString(deployment.ResolvedRevision) {
		return types.ReconcilePHPApplicationResult{}, errors.New("active PHP deployment does not belong to the application")
	}
	paths, err := p.pathsFor(normalized, deployment.ID)
	if err != nil {
		return types.ReconcilePHPApplicationResult{}, err
	}
	if err := p.prepareReleaseRoot(ctx, normalized, paths.releaseRoot, req.Environment); err != nil {
		return types.ReconcilePHPApplicationResult{}, err
	}
	if err := p.grantSharedWebAccess(ctx, normalized, paths.sharedRoot, req.Environment); err != nil {
		return types.ReconcilePHPApplicationResult{}, err
	}
	if err := p.makeReleaseImmutable(ctx, normalized, paths.release, req.Environment); err != nil {
		return types.ReconcilePHPApplicationResult{}, err
	}
	environmentPath, err := p.writeEnvironment(normalized, deployment.ID, req.Environment)
	if err != nil {
		return types.ReconcilePHPApplicationResult{}, err
	}
	previousID := int64(0)
	if req.PreviousDeployment != nil && req.PreviousDeployment.ApplicationID == spec.ApplicationID {
		previousID = req.PreviousDeployment.ID
	}
	marker := phpObservedMarker{
		ApplicationID: spec.ApplicationID, SiteID: spec.SiteID, DesiredRevision: spec.DesiredRevision,
		ActiveDeploymentID: deployment.ID, PreviousDeploymentID: previousID,
		ResolvedRevision: deployment.ResolvedRevision, ReleasePath: paths.release, EnvironmentPath: environmentPath,
	}
	current, markerErr := p.readMarker(spec.ApplicationID)
	changed := markerErr != nil || current != marker
	if err := p.activateRelease(ctx, normalized, marker, environmentPath, req.Environment); err != nil {
		return types.ReconcilePHPApplicationResult{}, err
	}
	return types.ReconcilePHPApplicationResult{ApplicationID: spec.ApplicationID, ActiveDeploymentID: deployment.ID,
		PreviousDeploymentID: previousID, ResolvedRevision: deployment.ResolvedRevision,
		ObservedState: "healthy", Message: "managed PHP release converged", Changed: changed}, nil
}

func (p *PHPApplicationProvisioner) revokeManagedWebAccess(ctx context.Context, spec types.PHPApplicationSpec, environment []types.PHPEnvironmentPayload) error {
	marker, markerErr := p.readMarker(spec.ApplicationID)
	if markerErr == nil && marker.ReleasePath != "" {
		if output, err := p.runner.Run(ctx, "setfacl", "-R", "-x", "u:www-data", marker.ReleasePath); err != nil {
			return redactPHPError(fmt.Errorf("revoke nginx release access: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
	}
	resolvedHome, err := filepath.EvalSymlinks(p.homeRoot)
	if err != nil {
		return err
	}
	domainRoot := filepath.Join(resolvedHome, spec.Username, "domains", spec.Domain)
	managedRoot := filepath.Join(domainRoot, ".nakpanel")
	releaseRoot := filepath.Join(managedRoot, "releases")
	sharedRoot := filepath.Join(managedRoot, "shared")
	if _, err := os.Lstat(managedRoot); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, relative := range spec.SharedPaths {
		if !phpSharedPathIsPublic(spec.PublicPath, relative) {
			continue
		}
		shared := filepath.Join(sharedRoot, filepath.FromSlash(relative))
		if _, err := os.Lstat(shared); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if output, err := p.runner.Run(ctx, "setfacl", "-R", "-x", "u:www-data", shared); err != nil {
			return redactPHPError(fmt.Errorf("revoke nginx shared content access: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
		if output, err := p.runner.Run(ctx, "setfacl", "-x", "d:u:www-data", shared); err != nil {
			return redactPHPError(fmt.Errorf("revoke nginx inherited shared access: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
		var ancestors []string
		for parent := filepath.Dir(shared); parent != sharedRoot; parent = filepath.Dir(parent) {
			ancestors = append(ancestors, parent)
		}
		if len(ancestors) > 0 {
			sort.Strings(ancestors)
			if output, err := p.runner.Run(ctx, "setfacl", append([]string{"-x", "u:www-data"}, ancestors...)...); err != nil {
				return redactPHPError(fmt.Errorf("revoke nginx shared path traversal: %w: %s", err, strings.TrimSpace(string(output))), environment)
			}
		}
	}
	if _, err := os.Lstat(releaseRoot); err == nil {
		if output, err := p.runner.Run(ctx, "setfacl", "-x", "u:www-data", managedRoot, releaseRoot); err != nil {
			return redactPHPError(fmt.Errorf("revoke nginx managed release traversal: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
	}
	if _, err := os.Lstat(sharedRoot); err == nil {
		if output, err := p.runner.Run(ctx, "setfacl", "-x", "u:www-data", sharedRoot); err != nil {
			return redactPHPError(fmt.Errorf("revoke nginx shared root traversal: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
	}
	return nil
}

func (p *PHPApplicationProvisioner) ReconcilePHPWorkers(ctx context.Context, req types.ReconcilePHPWorkersReq) (types.ReconcilePHPWorkersResult, error) {
	spec := req.Application
	if spec.ApplicationID <= 0 || spec.SubscriptionID <= 0 || spec.SiteID <= 0 || site.ValidateUsername(spec.Username) != nil || site.ValidateDomain(spec.Domain) != nil {
		return types.ReconcilePHPWorkersResult{}, errors.New("validated PHP application identity is required")
	}
	if err := validatePHPEnvironment(req.Environment); err != nil {
		return types.ReconcilePHPWorkersResult{}, err
	}
	unlock := lockToolkitMutation(&p.locks, spec.ApplicationID)
	defer unlock()
	if spec.HostingMode != types.PHPHostingModeManaged || spec.DesiredState != "active" {
		if err := p.stopApplicationWorkers(ctx, spec.ApplicationID, nil, req.Environment); err != nil {
			return types.ReconcilePHPWorkersResult{}, err
		}
		return types.ReconcilePHPWorkersResult{ApplicationID: spec.ApplicationID, Changed: true}, nil
	}
	normalized, err := validatePHPApplicationSpec(spec)
	if err != nil {
		return types.ReconcilePHPWorkersResult{}, err
	}
	marker, err := p.readMarker(spec.ApplicationID)
	if err != nil || marker.ActiveDeploymentID <= 0 {
		return types.ReconcilePHPWorkersResult{}, errors.New("PHP workers require a healthy active release")
	}
	environmentPath := marker.EnvironmentPath
	if !p.validEnvironmentPath(normalized, marker.ActiveDeploymentID, environmentPath) {
		return types.ReconcilePHPWorkersResult{}, errors.New("active PHP environment generation is missing or unsafe")
	}
	return p.reconcileWorkerRecords(ctx, normalized, req.Workers, req.Environment, environmentPath, marker.ReleasePath)
}

func (p *PHPApplicationProvisioner) reconcileWorkersForActive(ctx context.Context, spec types.PHPApplicationSpec, workers []types.PHPWorkerSpec, environment []types.PHPEnvironmentPayload, environmentPath, release string) error {
	if len(workers) == 0 {
		return p.stopApplicationWorkers(ctx, spec.ApplicationID, nil, environment)
	}
	converted := make([]types.PHPWorker, 0, len(workers))
	for _, worker := range workers {
		converted = append(converted, types.PHPWorker{
			ID: worker.WorkerID, SubscriptionID: spec.SubscriptionID, ApplicationID: spec.ApplicationID,
			Name: worker.Name, Script: worker.Script, Arguments: worker.Arguments, Processes: worker.Processes, DesiredState: worker.DesiredState,
		})
	}
	_, err := p.reconcileWorkerRecords(ctx, spec, converted, environment, environmentPath, release)
	return err
}

func (p *PHPApplicationProvisioner) reconcileWorkerRecords(ctx context.Context, spec types.PHPApplicationSpec, workers []types.PHPWorker, environment []types.PHPEnvironmentPayload, environmentPath, release string) (types.ReconcilePHPWorkersResult, error) {
	result := types.ReconcilePHPWorkersResult{ApplicationID: spec.ApplicationID}
	if len(workers) > 64 {
		return result, errors.New("at most 64 PHP worker definitions are permitted")
	}
	total := 0
	requested := make(map[int64]struct{}, len(workers))
	for _, worker := range workers {
		if worker.ID <= 0 {
			return result, errors.New("PHP worker id is required")
		}
		if worker.Processes < 1 || worker.Processes > 64 {
			return result, errors.New("PHP worker process count must be between 1 and 64")
		}
		if total > 4096-worker.Processes {
			return result, errors.New("PHP worker process count exceeds the agent safety limit")
		}
		total += worker.Processes
		if _, exists := requested[worker.ID]; exists {
			return result, errors.New("PHP worker ids must be unique")
		}
		requested[worker.ID] = struct{}{}
	}
	if !spec.Policy.Permissions.PHPWorkers || (spec.Policy.Resources.MaxPHPWorkers >= 0 && total > spec.Policy.Resources.MaxPHPWorkers) {
		return result, errors.New("PHP worker process count exceeds the subscription policy")
	}
	slicePath := filepath.Join(p.systemdUnitDir, phpApplicationSliceName(spec.ApplicationID))
	if err := writeFileAtomic(slicePath, []byte(renderPHPApplicationSlice(spec)), 0o644); err != nil {
		return result, err
	}
	type desiredWorkerUnit struct {
		name  string
		state string
	}
	var desired []desiredWorkerUnit
	for _, worker := range workers {
		scriptPath := filepath.Join(release, filepath.FromSlash(worker.Script))
		resolvedScript, resolveErr := filepath.EvalSymlinks(scriptPath)
		if resolveErr != nil || !site.PathWithinDir(release, resolvedScript) {
			return result, errors.New("PHP worker script is missing or escaped the active release")
		}
		if info, statErr := os.Stat(resolvedScript); statErr != nil || !info.Mode().IsRegular() {
			return result, errors.New("PHP worker script must be a regular file")
		}
		unit, err := renderPHPWorkerUnit(spec, worker, release, environmentPath)
		if err != nil {
			return result, err
		}
		desiredUnits := make(map[string]struct{}, worker.Processes)
		for process := 1; process <= worker.Processes; process++ {
			unitName := phpWorkerUnitName(worker.ID, process)
			desiredUnits[unitName] = struct{}{}
			unitPath := filepath.Join(p.systemdUnitDir, unitName)
			if err := writeFileAtomic(unitPath, []byte(unit), 0o644); err != nil {
				return result, err
			}
			desired = append(desired, desiredWorkerUnit{name: unitName, state: worker.DesiredState})
		}
		matches, err := p.exactWorkerUnitPaths(worker.ID)
		if err != nil {
			return result, err
		}
		for _, match := range matches {
			if _, keep := desiredUnits[filepath.Base(match)]; keep {
				continue
			}
			stale := filepath.Base(match)
			output, err := p.runner.Run(ctx, "systemctl", "disable", "--now", stale)
			if err != nil {
				return result, redactPHPError(fmt.Errorf("stop stale PHP worker unit: %w: %s", err, strings.TrimSpace(string(output))), environment)
			}
			if err := os.Remove(match); err != nil && !os.IsNotExist(err) {
				return result, err
			}
		}
		result.Reconciled = append(result.Reconciled, worker.ID)
		result.Changed = true
	}
	previous, _ := p.readWorkerState(spec.ApplicationID)
	for _, id := range previous {
		if _, exists := requested[id]; !exists {
			if _, err := p.removeExactWorkerUnits(ctx, id, environment); err != nil {
				return result, err
			}
			result.Removed = append(result.Removed, id)
		}
	}
	if output, err := p.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return result, redactPHPError(fmt.Errorf("reload PHP worker units: %w: %s", err, strings.TrimSpace(string(output))), environment)
	}
	for _, unit := range desired {
		if unit.state == "stopped" {
			output, err := p.runner.Run(ctx, "systemctl", "disable", "--now", unit.name)
			if err != nil {
				return result, redactPHPError(fmt.Errorf("stop desired-inactive PHP worker: %w: %s", err, strings.TrimSpace(string(output))), environment)
			}
			continue
		}
		if output, err := p.runner.Run(ctx, "systemctl", "enable", unit.name); err != nil {
			return result, redactPHPError(fmt.Errorf("enable PHP worker: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
		if output, err := p.runner.Run(ctx, "systemctl", "restart", unit.name); err != nil {
			return result, redactPHPError(fmt.Errorf("restart PHP worker onto active release: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
	}
	if err := p.writeWorkerState(spec.ApplicationID, requested); err != nil {
		return result, err
	}
	return result, nil
}

func (p *PHPApplicationProvisioner) workerStatePath(applicationID int64) string {
	return filepath.Join(p.stateRoot, "app-"+strconv.FormatInt(applicationID, 10), "workers.json")
}

func (p *PHPApplicationProvisioner) readWorkerState(applicationID int64) ([]int64, error) {
	var ids []int64
	data, err := os.ReadFile(p.workerStatePath(applicationID))
	if err != nil {
		return nil, err
	}
	return ids, json.Unmarshal(data, &ids)
}

func (p *PHPApplicationProvisioner) writeWorkerState(applicationID int64, requested map[int64]struct{}) error {
	ids := make([]int64, 0, len(requested))
	for id := range requested {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	data, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.workerStatePath(applicationID)), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(p.workerStatePath(applicationID), append(data, '\n'), 0o600)
}

func (p *PHPApplicationProvisioner) stopApplicationWorkers(ctx context.Context, applicationID int64, keep map[int64]struct{}, environment []types.PHPEnvironmentPayload) error {
	ids, err := p.readWorkerState(applicationID)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	changed := false
	for _, id := range ids {
		if _, exists := keep[id]; exists {
			continue
		}
		removed, err := p.removeExactWorkerUnits(ctx, id, environment)
		if err != nil {
			return err
		}
		changed = changed || removed
	}
	if changed {
		if output, err := p.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return redactPHPError(fmt.Errorf("reload units after PHP worker cleanup: %w: %s", err, strings.TrimSpace(string(output))), environment)
		}
	}
	return nil
}

var phpWorkerUnitFileRE = regexp.MustCompile(`^nakpanel-php-worker@([1-9][0-9]*)(?:-([2-9]|[1-9][0-9]*))?\.service$`)

func (p *PHPApplicationProvisioner) exactWorkerUnitPaths(workerID int64) ([]string, error) {
	entries, err := os.ReadDir(p.systemdUnitDir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		match := phpWorkerUnitFileRE.FindStringSubmatch(entry.Name())
		if len(match) != 3 {
			continue
		}
		id, err := strconv.ParseInt(match[1], 10, 64)
		if err == nil && id == workerID {
			paths = append(paths, filepath.Join(p.systemdUnitDir, entry.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func (p *PHPApplicationProvisioner) removeExactWorkerUnits(ctx context.Context, workerID int64, environment []types.PHPEnvironmentPayload) (bool, error) {
	paths, err := p.exactWorkerUnitPaths(workerID)
	if err != nil {
		return false, err
	}
	for _, path := range paths {
		unitName := filepath.Base(path)
		output, runErr := p.runner.Run(ctx, "systemctl", "disable", "--now", unitName)
		if runErr != nil {
			return false, redactPHPError(fmt.Errorf("stop exact PHP worker unit: %w: %s", runErr, strings.TrimSpace(string(output))), environment)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return false, err
		}
	}
	return len(paths) > 0, nil
}

func phpWorkerUnitName(workerID int64, process int) string {
	if process <= 1 {
		return fmt.Sprintf("nakpanel-php-worker@%d.service", workerID)
	}
	return fmt.Sprintf("nakpanel-php-worker@%d-%d.service", workerID, process)
}
