package ops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	digestImageRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{1,447}@sha256:[a-f0-9]{64}$`)
	routePathRE   = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$`)
	volumeNameRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

func (p *PodmanProvisioner) DeployApplicationGeneration(ctx context.Context, req types.EnsureApplicationReq) (types.DeployApplicationGenerationResult, error) {
	now := time.Now().UTC()
	if err := p.validateGenerationRequest(req); err != nil {
		return types.DeployApplicationGenerationResult{}, err
	}
	if req.Remove || req.DesiredState == "stopped" {
		if err := p.stopApplicationGenerations(ctx, req); err != nil {
			return types.DeployApplicationGenerationResult{}, err
		}
		return types.DeployApplicationGenerationResult{ApplicationObservedState: types.ApplicationObservedState{
			ApplicationID: req.ApplicationID, DesiredState: req.DesiredState, ObservedState: "stopped",
			EndpointPort: req.Endpoint.HostPort, ObservedAt: now,
		}, Changed: true}, nil
	}
	if req.Runtime != "oci" {
		return types.DeployApplicationGenerationResult{}, fmt.Errorf("runtime %q is not operational; Phase 28 supports OCI containers only", req.Runtime)
	}
	if !imageAllowed(req.ImageRef, req.Policy) {
		return types.DeployApplicationGenerationResult{}, errors.New("application image is not allowed by the subscription policy")
	}

	identity, err := p.prepareRootlessIdentity(req, true)
	if err != nil {
		return types.DeployApplicationGenerationResult{}, err
	}
	activePort := req.Endpoint.HostPort
	candidatePort := alternateApplicationPort(activePort)
	generation := req.DesiredRevision
	if generation <= 0 {
		generation = 1
	}
	container := fmt.Sprintf("nakpanel-app-%d-g%d", req.ApplicationID, generation)
	unit := container + ".service"
	unitPath := filepath.Join(p.systemdUnitDir, unit)
	run := p.rootlessRunner(req.Username, identity)

	// A reconciliation may redeploy the same immutable revision after a reboot
	// or observed-state failure. Stop its supervisor before replacing the
	// container so systemd cannot race the candidate rollout with an automatic
	// restart of the old generation.
	_, _ = p.runner.Run(context.Background(), "systemctl", "disable", "--now", unit)
	_, _ = run(ctx, "rm", "--force", "--ignore", container)
	args := []string{
		"create", "--name", container,
		"--label", "io.nakpanel.application-id=" + strconv.FormatInt(req.ApplicationID, 10),
		"--label", "io.nakpanel.desired-revision=" + strconv.FormatInt(generation, 10),
		"--userns=keep-id", "--pull=never", "--read-only",
		"--cap-drop=all", "--security-opt=no-new-privileges",
		"--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
		"--pids-limit", positiveLimit(req.Policy.Resources.MaxTasks, 128),
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
		"--tmpfs", "/run:rw,nosuid,nodev,size=16m,mode=1777",
		"--tmpfs", "/var/cache/nginx:rw,nosuid,nodev,size=64m,mode=1777",
		"--publish", fmt.Sprintf("127.0.0.1:%d:%d/tcp", candidatePort, req.Endpoint.ContainerPort),
		"--volume", identity.siteRoot + ":/workspace:rw,Z",
		"--workdir", "/workspace",
		"--env", "NAKPANEL_SITE_DOMAIN=" + req.Domain,
	}
	volumeArgs, err := p.prepareApplicationVolumes(req, identity)
	if err != nil {
		return types.DeployApplicationGenerationResult{}, err
	}
	args = append(args, volumeArgs...)
	networkMode := "slirp4netns:allow_host_loopback=false,cidr=" + applicationNetworkCIDR(req.SubscriptionID)
	if !req.Policy.Permissions.ApplicationEgress || !req.Policy.Applications.EgressEnabled {
		networkMode += ",outbound_addr=lo"
	}
	args = append(args, "--network", networkMode)
	if req.Policy.Resources.MemoryMB > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dm", req.Policy.Resources.MemoryMB))
	}
	if req.Policy.Resources.CPUPercent > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%.2f", float64(req.Policy.Resources.CPUPercent)/100))
	}
	for key, value := range req.Environment {
		if !environmentKeyRE.MatchString(key) || strings.ContainsRune(value, '\x00') || len(value) > 8192 {
			return types.DeployApplicationGenerationResult{}, fmt.Errorf("invalid application environment entry %q", key)
		}
		args = append(args, "--env", key+"="+value)
	}
	secretDir, err := p.writeApplicationSecrets(req, identity)
	if err != nil {
		return types.DeployApplicationGenerationResult{}, err
	}
	candidateGenerationRoot := filepath.Dir(secretDir)
	cleanupCandidateSecrets := func() {
		_ = os.RemoveAll(candidateGenerationRoot)
	}
	for key := range req.Secrets {
		args = append(args, "--mount", fmt.Sprintf("type=bind,src=%s,dst=/run/secrets/%s,ro=true", filepath.Join(secretDir, key), key))
	}
	args = append(args, req.ImageRef)
	if output, err := run(ctx, args...); err != nil {
		cleanupCandidateSecrets()
		return types.DeployApplicationGenerationResult{}, fmt.Errorf("create application candidate: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := writeFileAtomic(unitPath, []byte(renderApplicationUnit(req, identity, container)), 0o600); err != nil {
		_, _ = run(context.Background(), "rm", "--force", "--ignore", container)
		cleanupCandidateSecrets()
		return types.DeployApplicationGenerationResult{}, err
	}
	rollbackCandidate := func(cause error) (types.DeployApplicationGenerationResult, error) {
		_, _ = p.runner.Run(context.Background(), "systemctl", "disable", "--now", unit)
		_, _ = run(context.Background(), "rm", "--force", "--ignore", container)
		_ = os.Remove(unitPath)
		_, _ = p.runner.Run(context.Background(), "systemctl", "daemon-reload")
		cleanupCandidateSecrets()
		return types.DeployApplicationGenerationResult{}, cause
	}
	if _, err := p.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return rollbackCandidate(err)
	}
	if output, err := p.runner.Run(ctx, "systemctl", "enable", "--now", unit); err != nil {
		return rollbackCandidate(fmt.Errorf("start application candidate unit: %w: %s", err, strings.TrimSpace(string(output))))
	}
	if err := waitForApplicationHealth(ctx, candidatePort, req.Health); err != nil {
		return rollbackCandidate(fmt.Errorf("application candidate failed readiness: %w", err))
	}

	configPath := filepath.Join(p.nginxConfigDir, "site-"+strconv.FormatInt(req.SiteID, 10)+".conf")
	fragmentDir := filepath.Join(p.nginxConfigDir, "site-"+strconv.FormatInt(req.SiteID, 10)+".d")
	fragmentPath := filepath.Join(fragmentDir, "app-"+strconv.FormatInt(req.ApplicationID, 10)+".conf")
	markerPath := filepath.Join(p.nginxConfigDir, "site-"+strconv.FormatInt(req.SiteID, 10)+".domain")
	if err := os.MkdirAll(fragmentDir, 0o700); err != nil {
		return rollbackCandidate(err)
	}
	previous, previousErr := os.ReadFile(configPath)
	previousFragment, previousFragmentErr := os.ReadFile(fragmentPath)
	previousMarker, previousMarkerErr := os.ReadFile(markerPath)
	if err := writeFileAtomic(fragmentPath, []byte(renderApplicationNginx(req, candidatePort)), 0o600); err != nil {
		return rollbackCandidate(err)
	}
	if req.Endpoint.RouteMode == types.ApplicationRouteDomain {
		if err := writeFileAtomic(markerPath, []byte(strconv.FormatInt(req.ApplicationID, 10)+"\n"), 0o600); err != nil {
			return rollbackCandidate(err)
		}
	}
	if err := p.rebuildApplicationNginx(req.SiteID); err != nil {
		return rollbackCandidate(err)
	}
	restoreNginx := func(cause error) (types.DeployApplicationGenerationResult, error) {
		if previousFragmentErr == nil {
			_ = writeFileAtomic(fragmentPath, previousFragment, 0o600)
		} else {
			_ = os.Remove(fragmentPath)
		}
		if previousMarkerErr == nil {
			_ = writeFileAtomic(markerPath, previousMarker, 0o600)
		} else {
			_ = os.Remove(markerPath)
		}
		if previousErr == nil {
			_ = writeFileAtomic(configPath, previous, 0o600)
		} else {
			_ = os.Remove(configPath)
		}
		_, _ = p.runner.Run(context.Background(), "systemctl", "reload", "nginx")
		return rollbackCandidate(cause)
	}
	if output, err := p.runner.Run(ctx, "nginx", "-t"); err != nil {
		return restoreNginx(fmt.Errorf("validate application route: %w: %s", err, strings.TrimSpace(string(output))))
	}
	if output, err := p.runner.Run(ctx, "systemctl", "reload", "nginx"); err != nil {
		return restoreNginx(fmt.Errorf("reload application route: %w: %s", err, strings.TrimSpace(string(output))))
	}

	if err := p.retireOtherGenerations(ctx, req, identity, container); err != nil {
		return types.DeployApplicationGenerationResult{}, err
	}
	return types.DeployApplicationGenerationResult{ApplicationObservedState: types.ApplicationObservedState{
		ApplicationID: req.ApplicationID, DesiredState: "running", ObservedState: "healthy",
		ActiveRevision: generation, EndpointPort: candidatePort, UnitName: unit,
		ContainerName: container, ObservedAt: time.Now().UTC(),
	}, Changed: true}, nil
}

func (p *PodmanProvisioner) validateGenerationRequest(req types.EnsureApplicationReq) error {
	if req.ApplicationID <= 0 || req.SubscriptionID <= 0 || req.SiteID <= 0 || req.DesiredRevision <= 0 {
		return errors.New("application, subscription, site, and revision are required")
	}
	if !accountUsernameRE.MatchString(req.Username) || !applicationNameRE.MatchString(req.Name) || site.ValidateDomain(req.Domain) != nil {
		return errors.New("validated application identity is required")
	}
	if req.DesiredState != "running" && req.DesiredState != "stopped" {
		return errors.New("application desired state is invalid")
	}
	if req.DesiredState == "running" && !digestImageRE.MatchString(req.ImageRef) {
		return errors.New("application image must use an immutable sha256 digest")
	}
	if req.Endpoint.HostPort < 20000 || req.Endpoint.HostPort > 29999 ||
		req.Endpoint.ContainerPort < 1 || req.Endpoint.ContainerPort > 65535 {
		return errors.New("application endpoint is outside the managed range")
	}
	if req.Endpoint.RouteMode != types.ApplicationRouteDomain && req.Endpoint.RouteMode != types.ApplicationRoutePrefix {
		return errors.New("application route mode is invalid")
	}
	cleanRoute := path.Clean(req.Endpoint.RoutePrefix)
	if !routePathRE.MatchString(req.Endpoint.RoutePrefix) || strings.Contains(req.Endpoint.RoutePrefix, "..") || cleanRoute == "." {
		return errors.New("application route prefix is invalid")
	}
	if req.Health.Kind != types.ApplicationHealthHTTP && req.Health.Kind != types.ApplicationHealthTCP {
		return errors.New("application health check is invalid")
	}
	if req.Health.Kind == types.ApplicationHealthHTTP && (!routePathRE.MatchString(req.Health.Path) || strings.Contains(req.Health.Path, "..")) {
		return errors.New("application health path is invalid")
	}
	if req.Health.TimeoutSeconds < 1 || req.Health.TimeoutSeconds > 300 {
		return errors.New("application health timeout is invalid")
	}
	return nil
}

type applicationIdentity struct {
	uid         int
	gid         int
	stateHome   string
	dataHome    string
	configHome  string
	runtimeHome string
	siteRoot    string
}

func (p *PodmanProvisioner) prepareRootlessIdentity(req types.EnsureApplicationReq, requireSiteRoot bool) (applicationIdentity, error) {
	account, err := user.Lookup(req.Username)
	if err != nil {
		return applicationIdentity{}, err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return applicationIdentity{}, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return applicationIdentity{}, err
	}
	for _, file := range []string{p.subUIDPath, p.subGIDPath} {
		ok, readErr := subordinateIDRangeReady(file, req.Username, 65536)
		if readErr != nil || !ok {
			return applicationIdentity{}, fmt.Errorf("rootless Podman identity for %q is incomplete", req.Username)
		}
	}
	base := filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10))
	identity := applicationIdentity{
		uid: uid, gid: gid, stateHome: filepath.Join(base, "home"),
		dataHome: filepath.Join(base, "data"), configHome: filepath.Join(base, "config"),
		runtimeHome: filepath.Join(p.runtimeRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10)),
		siteRoot:    filepath.Join(p.homeRoot, req.Username, "domains", req.Domain, "public_html"),
	}
	if requireSiteRoot {
		resolved, err := filepath.EvalSymlinks(identity.siteRoot)
		if err != nil || filepath.Clean(resolved) != filepath.Clean(identity.siteRoot) {
			return applicationIdentity{}, errors.New("application document root is missing or unsafe")
		}
	}
	for _, dir := range []string{identity.stateHome, identity.dataHome, identity.configHome, identity.runtimeHome} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return applicationIdentity{}, err
		}
		if os.Geteuid() == 0 {
			if err := os.Chown(dir, uid, gid); err != nil {
				return applicationIdentity{}, err
			}
		}
	}
	if err := p.writeRootlessPodmanConfig(identity); err != nil {
		return applicationIdentity{}, err
	}
	return identity, nil
}

func (p *PodmanProvisioner) writeRootlessPodmanConfig(identity applicationIdentity) error {
	networkCommandPath := filepath.Clean(p.networkCommandPath)
	if !filepath.IsAbs(networkCommandPath) || strings.ContainsAny(networkCommandPath, "\"'\r\n\t ") {
		return errors.New("rootless Podman network command path is invalid")
	}
	configDir := filepath.Join(identity.configHome, "containers")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(configDir, identity.uid, identity.gid); err != nil {
			return err
		}
	}
	configPath := filepath.Join(configDir, "containers.conf")
	content := []byte("[engine]\nnetwork_cmd_path=\"" + networkCommandPath + "\"\n")
	if err := writeFileAtomic(configPath, content, 0o600); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(configPath, identity.uid, identity.gid); err != nil {
			return err
		}
	}
	return nil
}

func (p *PodmanProvisioner) writeApplicationSecrets(req types.EnsureApplicationReq, identity applicationIdentity) (string, error) {
	subscriptionRoot := filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10))
	dir := filepath.Join(subscriptionRoot, "apps",
		strconv.FormatInt(req.ApplicationID, 10), "generations", strconv.FormatInt(req.DesiredRevision, 10), "secrets")
	if err := prepareApplicationOwnedLeaf(subscriptionRoot, dir, identity.uid, identity.gid); err != nil {
		return "", err
	}
	for key, value := range req.Secrets {
		if !environmentKeyRE.MatchString(key) || strings.ContainsRune(value, '\x00') || len(value) > 65536 {
			return "", fmt.Errorf("invalid application secret %q", key)
		}
		target := filepath.Join(dir, key)
		if err := writeFileAtomic(target, []byte(value), 0o600); err != nil {
			return "", err
		}
		if os.Geteuid() == 0 {
			if err := os.Chown(target, identity.uid, identity.gid); err != nil {
				return "", err
			}
		}
	}
	return dir, nil
}

func (p *PodmanProvisioner) prepareApplicationVolumes(req types.EnsureApplicationReq, identity applicationIdentity) ([]string, error) {
	if len(req.Volumes) > 16 {
		return nil, errors.New("application declares too many volume slots")
	}
	var declaredMB int
	seen := make(map[string]bool, len(req.Volumes))
	var args []string
	for _, volume := range req.Volumes {
		target := path.Clean(volume.Target)
		if !volumeNameRE.MatchString(volume.Name) || seen[volume.Name] || !strings.HasPrefix(target, "/") ||
			target == "/" || strings.HasPrefix(target, "/run/secrets") || strings.ContainsAny(target, "\x00\r\n") ||
			volume.SizeMB <= 0 {
			return nil, errors.New("application volume manifest is invalid")
		}
		seen[volume.Name] = true
		declaredMB += volume.SizeMB
		subscriptionRoot := filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10))
		hostPath := filepath.Join(subscriptionRoot, "apps",
			strconv.FormatInt(req.ApplicationID, 10), "volumes", volume.Name)
		if err := prepareApplicationOwnedLeaf(subscriptionRoot, hostPath, identity.uid, identity.gid); err != nil {
			return nil, err
		}
		mode := "rw"
		if volume.ReadOnly {
			mode = "ro"
		}
		args = append(args, "--volume", hostPath+":"+target+":"+mode+",Z")
	}
	if req.Policy.Resources.ContainerStorageMB >= 0 && declaredMB > req.Policy.Resources.ContainerStorageMB {
		return nil, errors.New("application volume allocation exceeds the subscription container storage limit")
	}
	return args, nil
}

// prepareApplicationOwnedLeaf keeps the namespace above an application-owned
// directory root-owned and non-writable while allowing the rootless runtime to
// traverse it. The final leaf belongs to the subscription account.
func prepareApplicationOwnedLeaf(subscriptionRoot, leaf string, uid, gid int) error {
	relative, err := filepath.Rel(subscriptionRoot, leaf)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("application storage path escapes the subscription root")
	}
	if err := os.Mkdir(subscriptionRoot, 0o711); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	rootInfo, err := os.Lstat(subscriptionRoot)
	if err != nil {
		return err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("application subscription storage is not a managed directory")
	}
	if err := os.Chmod(subscriptionRoot, 0o711); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(subscriptionRoot, 0, 0); err != nil {
			return err
		}
	}
	parent := filepath.Dir(leaf)
	current := filepath.Clean(subscriptionRoot)
	for _, component := range strings.Split(filepath.Clean(filepath.Dir(relative)), string(filepath.Separator)) {
		if component == "." || component == "" {
			continue
		}
		current = filepath.Join(current, component)
		if err := os.Mkdir(current, 0o711); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("application storage parent is not a managed directory")
		}
		if err := os.Chmod(current, 0o711); err != nil {
			return err
		}
		if os.Geteuid() == 0 {
			if err := os.Chown(current, 0, 0); err != nil {
				return err
			}
		}
	}
	if filepath.Clean(current) != filepath.Clean(parent) {
		return errors.New("application storage parent could not be prepared")
	}
	if err := os.Mkdir(leaf, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(leaf)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("application storage leaf is not a managed directory")
	}
	if err := os.Chmod(leaf, 0o700); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(leaf, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func (p *PodmanProvisioner) rootlessRunner(username string, identity applicationIdentity) func(context.Context, ...string) ([]byte, error) {
	return func(ctx context.Context, args ...string) ([]byte, error) {
		env := []string{
			"-u", username, "--", "env",
			"HOME=" + identity.stateHome,
			"XDG_DATA_HOME=" + identity.dataHome,
			"XDG_CONFIG_HOME=" + identity.configHome,
			"XDG_RUNTIME_DIR=" + identity.runtimeHome,
			"TMPDIR=" + identity.runtimeHome,
			p.binary,
		}
		return p.runner.Run(ctx, "runuser", append(env, args...)...)
	}
}

func waitForApplicationHealth(ctx context.Context, port int, health types.ApplicationHealthSpec) error {
	timeout := time.Duration(health.TimeoutSeconds) * time.Second
	deadline := time.Now().Add(timeout)
	for {
		var err error
		if health.Kind == types.ApplicationHealthTCP {
			var conn net.Conn
			conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if err == nil {
				_ = conn.Close()
				return nil
			}
		} else {
			request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet,
				fmt.Sprintf("http://127.0.0.1:%d%s", port, health.Path), nil)
			if requestErr != nil {
				return requestErr
			}
			response, requestErr := (&http.Client{Timeout: 2 * time.Second}).Do(request)
			err = requestErr
			if requestErr == nil {
				_ = response.Body.Close()
				if response.StatusCode >= 200 && response.StatusCode < 400 {
					return nil
				}
				err = fmt.Errorf("health returned HTTP %d", response.StatusCode)
			}
		}
		if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func renderApplicationNginx(req types.EnsureApplicationReq, port int) string {
	proxyHeaders := `proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";`
	if req.Endpoint.RouteMode == types.ApplicationRouteDomain {
		proxy := fmt.Sprintf("%s\n        proxy_pass http://127.0.0.1:%d;", proxyHeaders, port)
		return "# Managed by Nakpanel.\nlocation @nakpanel_application {\n        " + proxy + "\n}\n"
	}
	prefix := req.Endpoint.RoutePrefix
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	proxy := fmt.Sprintf("%s\n        proxy_pass http://127.0.0.1:%d/;", proxyHeaders, port)
	return fmt.Sprintf("# Managed by Nakpanel.\nlocation ^~ %s {\n        %s\n}\n", prefix, proxy)
}

func (p *PodmanProvisioner) rebuildApplicationNginx(siteID int64) error {
	fragmentDir := filepath.Join(p.nginxConfigDir, "site-"+strconv.FormatInt(siteID, 10)+".d")
	entries, err := os.ReadDir(fragmentDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var builder strings.Builder
	builder.WriteString("# Managed by Nakpanel. Per-container routes follow.\n")
	builder.WriteString("error_page 418 = @nakpanel_application;\n")
	if _, markerErr := os.Stat(filepath.Join(p.nginxConfigDir, "site-"+strconv.FormatInt(siteID, 10)+".domain")); os.IsNotExist(markerErr) {
		builder.WriteString("location @nakpanel_application { return 404; }\n")
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		fragment, readErr := os.ReadFile(filepath.Join(fragmentDir, entry.Name()))
		if readErr != nil {
			return readErr
		}
		builder.Write(fragment)
		if len(fragment) > 0 && fragment[len(fragment)-1] != '\n' {
			builder.WriteByte('\n')
		}
	}
	return writeFileAtomic(filepath.Join(p.nginxConfigDir, "site-"+strconv.FormatInt(siteID, 10)+".conf"), []byte(builder.String()), 0o600)
}

func renderApplicationUnit(req types.EnsureApplicationReq, identity applicationIdentity, container string) string {
	return fmt.Sprintf(`[Unit]
Description=Nakpanel application %d generation %d
After=network-online.target

[Service]
User=%s
Group=%s
Environment=HOME=%s
Environment=XDG_DATA_HOME=%s
Environment=XDG_CONFIG_HOME=%s
Environment=XDG_RUNTIME_DIR=%s
Environment=TMPDIR=%s
RuntimeDirectory=nakpanel-containers/sub-%d
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
ExecStart=%s start --attach %s
ExecStop=%s stop --time 20 %s
Restart=on-failure
RestartSec=3
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
`, req.ApplicationID, req.DesiredRevision, req.Username, req.Username,
		identity.stateHome, identity.dataHome, identity.configHome, identity.runtimeHome, identity.runtimeHome,
		req.SubscriptionID,
		"/usr/bin/podman", container, "/usr/bin/podman", container)
}

func (p *PodmanProvisioner) retireOtherGenerations(ctx context.Context, req types.EnsureApplicationReq, identity applicationIdentity, active string) error {
	run := p.rootlessRunner(req.Username, identity)
	output, err := run(ctx, "ps", "-a", "--filter", "label=io.nakpanel.application-id="+strconv.FormatInt(req.ApplicationID, 10), "--format", "{{.Names}}")
	if err != nil {
		return err
	}
	removedUnit := false
	for _, name := range applicationContainerNames(output, req.ApplicationID) {
		if name == active {
			continue
		}
		unit := name + ".service"
		if output, err := p.runner.Run(ctx, "systemctl", "disable", "--now", unit); err != nil {
			return fmt.Errorf("disable retired application generation %q: %w: %s", name, err, strings.TrimSpace(string(output)))
		}
		if output, err := run(ctx, "rm", "--force", "--ignore", name); err != nil {
			return fmt.Errorf("remove retired application generation %q: %w: %s", name, err, strings.TrimSpace(string(output)))
		}
		unitPath := filepath.Join(p.systemdUnitDir, unit)
		if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove retired application unit %q: %w", unit, err)
		}
		removedUnit = true
		revision, err := applicationContainerRevision(name, req.ApplicationID)
		if err != nil {
			return err
		}
		generationRoot := filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10),
			"apps", strconv.FormatInt(req.ApplicationID, 10), "generations", strconv.FormatInt(revision, 10))
		if err := os.RemoveAll(generationRoot); err != nil {
			return fmt.Errorf("remove retired application secrets for generation %d: %w", revision, err)
		}
	}
	if removedUnit {
		if output, err := p.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("reload systemd after retiring application generations: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func (p *PodmanProvisioner) stopApplicationGenerations(ctx context.Context, req types.EnsureApplicationReq) error {
	identity, err := p.prepareRootlessIdentity(req, false)
	if err != nil {
		return err
	}
	run := p.rootlessRunner(req.Username, identity)
	output, err := run(ctx, "ps", "-a", "--filter", "label=io.nakpanel.application-id="+strconv.FormatInt(req.ApplicationID, 10), "--format", "{{.Names}}")
	if err != nil {
		return err
	}
	for _, name := range applicationContainerNames(output, req.ApplicationID) {
		_, _ = p.runner.Run(ctx, "systemctl", "disable", "--now", name+".service")
		if req.Remove {
			var removeErr error
			var output []byte
			for attempt := 0; attempt < 3; attempt++ {
				output, removeErr = run(ctx, "rm", "--force", "--ignore", name)
				if removeErr == nil {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if removeErr != nil {
				return fmt.Errorf("remove application container %q: %w: %s", name, removeErr, strings.TrimSpace(string(output)))
			}
		} else if _, err := run(ctx, "stop", "--ignore", name); err != nil {
			return err
		}
	}
	if req.SiteID > 0 {
		fragmentDir := filepath.Join(p.nginxConfigDir, "site-"+strconv.FormatInt(req.SiteID, 10)+".d")
		_ = os.Remove(filepath.Join(fragmentDir, "app-"+strconv.FormatInt(req.ApplicationID, 10)+".conf"))
		markerPath := filepath.Join(p.nginxConfigDir, "site-"+strconv.FormatInt(req.SiteID, 10)+".domain")
		if owner, readErr := os.ReadFile(markerPath); readErr == nil &&
			strings.TrimSpace(string(owner)) == strconv.FormatInt(req.ApplicationID, 10) {
			_ = os.Remove(markerPath)
		}
		if err := p.rebuildApplicationNginx(req.SiteID); err != nil {
			return err
		}
		if output, err := p.runner.Run(ctx, "nginx", "-t"); err != nil {
			return fmt.Errorf("validate application route removal: %w: %s", err, strings.TrimSpace(string(output)))
		}
		_, _ = p.runner.Run(ctx, "systemctl", "reload", "nginx")
	}
	if req.Remove {
		unitPattern := filepath.Join(p.systemdUnitDir,
			"nakpanel-app-"+strconv.FormatInt(req.ApplicationID, 10)+"-g*.service")
		units, globErr := filepath.Glob(unitPattern)
		if globErr != nil {
			return globErr
		}
		for _, unitPath := range units {
			if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if _, err := p.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		appRoot := filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10),
			"apps", strconv.FormatInt(req.ApplicationID, 10))
		if err := os.RemoveAll(appRoot); err != nil {
			return err
		}
	}
	return nil
}

func (p *PodmanProvisioner) ApplicationStatus(ctx context.Context, req types.ApplicationControlReq) (types.ApplicationObservedState, error) {
	identity := applicationIdentity{
		stateHome:   filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10), "home"),
		dataHome:    filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10), "data"),
		configHome:  filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10), "config"),
		runtimeHome: filepath.Join(p.runtimeRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10)),
	}
	output, err := p.rootlessRunner(req.Username, identity)(ctx, "ps", "-a",
		"--filter", "label=io.nakpanel.application-id="+strconv.FormatInt(req.ApplicationID, 10),
		"--format", "{{.Names}}|{{.State}}|{{.Ports}}")
	if err != nil {
		return types.ApplicationObservedState{}, err
	}
	state := types.ApplicationObservedState{ApplicationID: req.ApplicationID, ObservedState: "missing", ObservedAt: time.Now().UTC()}
	var selectedRevision int64 = -1
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(applicationContainerNames([]byte(parts[0]+"\n"), req.ApplicationID)) != 1 {
			continue
		}
		revision, parseErr := strconv.ParseInt(strings.TrimPrefix(parts[0],
			"nakpanel-app-"+strconv.FormatInt(req.ApplicationID, 10)+"-g"), 10, 64)
		if parseErr != nil || (req.ActiveRevision > 0 && revision != req.ActiveRevision) ||
			(req.ActiveRevision == 0 && revision < selectedRevision) {
			continue
		}
		selectedRevision = revision
		state.ContainerName = parts[0]
		state.ActiveRevision = revision
		if len(parts) > 1 && parts[1] == "running" {
			state.ObservedState = "healthy"
			if req.Endpoint.HostPort >= 20000 && req.Health.TimeoutSeconds > 0 {
				if healthErr := waitForApplicationHealth(ctx, req.Endpoint.HostPort, req.Health); healthErr != nil {
					state.ObservedState = "unhealthy"
					state.Message = healthErr.Error()
				}
			}
		} else {
			state.ObservedState = "stopped"
		}
	}
	return state, nil
}

func applicationContainerNames(output []byte, applicationID int64) []string {
	prefix := "nakpanel-app-" + strconv.FormatInt(applicationID, 10) + "-g"
	var names []string
	for _, line := range strings.Split(string(output), "\n") {
		name := strings.TrimSpace(line)
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		generation := strings.TrimPrefix(name, prefix)
		if generation == "" || strings.IndexFunc(generation, func(r rune) bool {
			return r < '0' || r > '9'
		}) >= 0 {
			continue
		}
		names = append(names, name)
	}
	return names
}

func applicationContainerRevision(name string, applicationID int64) (int64, error) {
	prefix := "nakpanel-app-" + strconv.FormatInt(applicationID, 10) + "-g"
	if !strings.HasPrefix(name, prefix) {
		return 0, fmt.Errorf("application container %q does not belong to application %d", name, applicationID)
	}
	revision, err := strconv.ParseInt(strings.TrimPrefix(name, prefix), 10, 64)
	if err != nil || revision <= 0 {
		return 0, fmt.Errorf("application container %q has an invalid generation", name)
	}
	return revision, nil
}

func (p *PodmanProvisioner) ControlApplication(ctx context.Context, req types.ApplicationControlReq) (types.ApplicationObservedState, error) {
	if req.Action != "start" && req.Action != "stop" && req.Action != "restart" {
		return types.ApplicationObservedState{}, errors.New("unsupported application action")
	}
	status, err := p.ApplicationStatus(ctx, req)
	if err != nil || status.ContainerName == "" {
		return status, err
	}
	identity := applicationIdentity{
		stateHome:   filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10), "home"),
		dataHome:    filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10), "data"),
		configHome:  filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10), "config"),
		runtimeHome: filepath.Join(p.runtimeRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10)),
	}
	if _, err := p.rootlessRunner(req.Username, identity)(ctx, req.Action, status.ContainerName); err != nil {
		return types.ApplicationObservedState{}, err
	}
	return p.ApplicationStatus(ctx, req)
}

func (p *PodmanProvisioner) ReadApplicationLog(ctx context.Context, req types.ApplicationLogReq) (types.ApplicationLogResult, error) {
	if req.Lines < 1 || req.Lines > 1000 {
		req.Lines = 200
	}
	if req.Bytes < 1 || req.Bytes > 1024*1024 {
		req.Bytes = 256 * 1024
	}
	status, err := p.ApplicationStatus(ctx, types.ApplicationControlReq{
		ApplicationID: req.ApplicationID, SubscriptionID: req.SubscriptionID, Username: req.Username,
	})
	if err != nil || status.ContainerName == "" {
		return types.ApplicationLogResult{}, err
	}
	identity := applicationIdentity{
		stateHome:   filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10), "home"),
		dataHome:    filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10), "data"),
		configHome:  filepath.Join(p.stateRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10), "config"),
		runtimeHome: filepath.Join(p.runtimeRoot, "sub-"+strconv.FormatInt(req.SubscriptionID, 10)),
	}
	output, err := p.rootlessRunner(req.Username, identity)(ctx, "logs", "--tail", strconv.Itoa(req.Lines), status.ContainerName)
	if err != nil {
		return types.ApplicationLogResult{}, err
	}
	truncated := false
	if len(output) > req.Bytes {
		output = output[len(output)-req.Bytes:]
		truncated = true
		if newline := bytes.IndexByte(output, '\n'); newline >= 0 {
			output = output[newline+1:]
		}
	}
	lines := strings.Split(strings.TrimRight(string(output), "\r\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	return types.ApplicationLogResult{Lines: lines, Truncated: truncated}, nil
}

func alternateApplicationPort(active int) int {
	if active >= 25000 {
		return active - 5000
	}
	return active + 5000
}

func applicationNetworkCIDR(subscriptionID int64) string {
	second := 100 + (subscriptionID/250)%100
	third := subscriptionID % 250
	return fmt.Sprintf("10.%d.%d.0/24", second, third)
}

func positiveLimit(value, fallback int) string {
	if value <= 0 {
		value = fallback
	}
	return strconv.Itoa(value)
}
