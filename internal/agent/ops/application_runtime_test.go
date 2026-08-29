package ops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func validApplicationGenerationRequest() types.EnsureApplicationReq {
	return types.EnsureApplicationReq{
		ApplicationID: 4, SubscriptionID: 7, SiteID: 9, DesiredRevision: 3,
		Username: "np12345678", Domain: "app.example.test", Name: "demo-app",
		Runtime: "oci", ImageRef: "docker.io/library/nginx@sha256:" + strings.Repeat("a", 64),
		DesiredState: "running",
		Endpoint: types.ApplicationEndpointSpec{
			RouteMode: types.ApplicationRoutePrefix, RoutePrefix: "/demo/", HostPort: 20004, ContainerPort: 8080,
		},
		Health: types.ApplicationHealthSpec{Kind: types.ApplicationHealthHTTP, Path: "/healthz", TimeoutSeconds: 30},
	}
}

func TestApplicationGenerationRequiresImmutableImage(t *testing.T) {
	provisioner := NewPodmanProvisioner(PodmanProvisionerOptions{})
	request := validApplicationGenerationRequest()
	request.ImageRef = "docker.io/library/nginx:latest"
	if err := provisioner.validateGenerationRequest(request); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("validateGenerationRequest() error = %v, want immutable digest rejection", err)
	}
}

func TestApplicationGenerationRejectsUnsafeRoute(t *testing.T) {
	provisioner := NewPodmanProvisioner(PodmanProvisionerOptions{})
	request := validApplicationGenerationRequest()
	request.Endpoint.RoutePrefix = "/demo/../admin"
	if err := provisioner.validateGenerationRequest(request); err == nil || !strings.Contains(err.Error(), "route prefix") {
		t.Fatalf("validateGenerationRequest() error = %v, want route rejection", err)
	}
}

func TestApplicationNginxAggregateKeepsMultiplePrefixRoutes(t *testing.T) {
	root := t.TempDir()
	provisioner := NewPodmanProvisioner(PodmanProvisionerOptions{NginxConfigDir: root})
	fragmentDir := filepath.Join(root, "site-9.d")
	if err := os.MkdirAll(fragmentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, route := range map[string]string{"app-1.conf": "/one/", "app-2.conf": "/two/"} {
		request := validApplicationGenerationRequest()
		request.Endpoint.RoutePrefix = route
		if err := os.WriteFile(filepath.Join(fragmentDir, name), []byte(renderApplicationNginx(request, 20001)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := provisioner.rebuildApplicationNginx(9); err != nil {
		t.Fatal(err)
	}
	output, err := os.ReadFile(filepath.Join(root, "site-9.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"location ^~ /one/", "location ^~ /two/", "proxy_pass http://127.0.0.1:20001/;", "location @nakpanel_application { return 404; }"} {
		if !strings.Contains(string(output), marker) {
			t.Fatalf("aggregate nginx configuration is missing %q:\n%s", marker, output)
		}
	}
}

func TestApplicationSecretsAreWrittenMode0600(t *testing.T) {
	root := t.TempDir()
	provisioner := NewPodmanProvisioner(PodmanProvisionerOptions{StateRoot: root})
	request := validApplicationGenerationRequest()
	request.Secrets = map[string]string{"DATABASE_PASSWORD": "not-for-logs"}
	dir, err := provisioner.writeApplicationSecrets(request, applicationIdentity{uid: os.Getuid(), gid: os.Getgid()})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "DATABASE_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("secret mode = %o, want 600", got)
	}
	for _, parent := range []string{
		filepath.Join(root, "sub-7", "apps"),
		filepath.Join(root, "sub-7", "apps", "4"),
		filepath.Join(root, "sub-7", "apps", "4", "generations"),
		filepath.Join(root, "sub-7", "apps", "4", "generations", "3"),
	} {
		info, err := os.Stat(parent)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o711 {
			t.Fatalf("storage parent %s mode = %o, want 711", parent, got)
		}
	}
}

func TestApplicationUnitUsesDedicatedRootlessRuntime(t *testing.T) {
	request := validApplicationGenerationRequest()
	unit := renderApplicationUnit(request, applicationIdentity{
		stateHome: "/var/lib/nakpanel/containers/sub-7/home",
		dataHome:  "/var/lib/nakpanel/containers/sub-7/data", configHome: "/var/lib/nakpanel/containers/sub-7/config",
		runtimeHome: "/run/nakpanel-containers/sub-7",
	}, "nakpanel-app-4-g3")
	for _, marker := range []string{
		"User=np12345678", "Environment=HOME=/var/lib/nakpanel/containers/sub-7/home",
		"Environment=TMPDIR=/run/nakpanel-containers/sub-7",
		"RuntimeDirectory=nakpanel-containers/sub-7", "RuntimeDirectoryPreserve=yes",
		"ExecStart=/usr/bin/podman start --attach nakpanel-app-4-g3",
	} {
		if !strings.Contains(unit, marker) {
			t.Fatalf("systemd unit is missing %q:\n%s", marker, unit)
		}
	}
	if strings.Contains(unit, "NoNewPrivileges=true") {
		t.Fatalf("host unit must allow rootless Podman's setuid newuidmap helper:\n%s", unit)
	}
	if strings.Contains(unit, "PrivateTmp=true") {
		t.Fatalf("host unit must not hide /tmp from slirp4netns sandbox setup:\n%s", unit)
	}
}

func TestRootlessPodmanConfigUsesManagedNetworkCommand(t *testing.T) {
	configHome := t.TempDir()
	provisioner := NewPodmanProvisioner(PodmanProvisionerOptions{
		NetworkCommandPath: "/usr/lib/nakpanel/slirp4netns",
	})
	if err := provisioner.writeRootlessPodmanConfig(applicationIdentity{
		uid: os.Getuid(), gid: os.Getgid(), configHome: configHome,
	}); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configHome, "containers", "containers.conf")
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(config), "[engine]\nnetwork_cmd_path=\"/usr/lib/nakpanel/slirp4netns\"\n"; got != want {
		t.Fatalf("containers.conf = %q, want %q", got, want)
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("containers.conf mode = %o, want 600", got)
	}

	provisioner.networkCommandPath = "../slirp4netns"
	if err := provisioner.writeRootlessPodmanConfig(applicationIdentity{configHome: configHome}); err == nil {
		t.Fatal("relative network command path must be rejected")
	}
}

func TestApplicationCandidatePortAlternatesInsideManagedRange(t *testing.T) {
	if got := alternateApplicationPort(20017); got != 25017 {
		t.Fatalf("alternateApplicationPort(20017) = %d", got)
	}
	if got := alternateApplicationPort(25017); got != 20017 {
		t.Fatalf("alternateApplicationPort(25017) = %d", got)
	}
}

func TestApplicationNetworkCIDRIsStablePerSubscription(t *testing.T) {
	if got := applicationNetworkCIDR(7); got != "10.100.7.0/24" {
		t.Fatalf("applicationNetworkCIDR(7) = %q", got)
	}
	if applicationNetworkCIDR(7) == applicationNetworkCIDR(8) {
		t.Fatal("adjacent subscriptions must not share an application CIDR")
	}
}

func TestApplicationContainerNamesIgnoreRootlessWarnings(t *testing.T) {
	output := []byte(`time="2026-07-24T11:00:00-04:00" level=warning msg="Falling back to --cgroup-manager=cgroupfs"
nakpanel-app-42-g7
other-container
nakpanel-app-42-gbad
`)
	names := applicationContainerNames(output, 42)
	if len(names) != 1 || names[0] != "nakpanel-app-42-g7" {
		t.Fatalf("applicationContainerNames() = %#v", names)
	}
}

type applicationRuntimeTestRunner struct {
	calls     []string
	psOutput  string
	logOutput string
}

func (r *applicationRuntimeTestRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	switch {
	case strings.Contains(call, "/podman ps "):
		return []byte(r.psOutput), nil
	case strings.Contains(call, "/podman logs "):
		return []byte(r.logOutput), nil
	default:
		return nil, nil
	}
}

func TestRetireOtherApplicationGenerationsRemovesRuntimeArtifacts(t *testing.T) {
	stateRoot := t.TempDir()
	unitRoot := t.TempDir()
	runner := &applicationRuntimeTestRunner{psOutput: "nakpanel-app-4-g2\nnakpanel-app-4-g3\n"}
	provisioner := NewPodmanProvisioner(PodmanProvisionerOptions{
		StateRoot: stateRoot, SystemdUnitDir: unitRoot, Runner: runner,
	})
	oldUnit := filepath.Join(unitRoot, "nakpanel-app-4-g2.service")
	oldGeneration := filepath.Join(stateRoot, "sub-7", "apps", "4", "generations", "2")
	activeGeneration := filepath.Join(stateRoot, "sub-7", "apps", "4", "generations", "3")
	for _, dir := range []string{oldGeneration, activeGeneration} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(oldUnit, []byte("[Service]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	req := validApplicationGenerationRequest()
	if err := provisioner.retireOtherGenerations(context.Background(), req, applicationIdentity{}, "nakpanel-app-4-g3"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldUnit); !os.IsNotExist(err) {
		t.Fatalf("retired unit still exists: %v", err)
	}
	if _, err := os.Stat(oldGeneration); !os.IsNotExist(err) {
		t.Fatalf("retired secret generation still exists: %v", err)
	}
	if _, err := os.Stat(activeGeneration); err != nil {
		t.Fatalf("active generation was removed: %v", err)
	}
	calls := strings.Join(runner.calls, "\n")
	for _, marker := range []string{
		"systemctl disable --now nakpanel-app-4-g2.service",
		"podman rm --force --ignore nakpanel-app-4-g2",
		"systemctl daemon-reload",
	} {
		if !strings.Contains(calls, marker) {
			t.Fatalf("retirement did not run %q:\n%s", marker, calls)
		}
	}
	if strings.Contains(calls, "disable --now nakpanel-app-4-g3.service") {
		t.Fatalf("active generation was retired:\n%s", calls)
	}
}

func TestReadApplicationLogEnforcesByteLimit(t *testing.T) {
	runner := &applicationRuntimeTestRunner{
		psOutput:  "nakpanel-app-4-g3|running|127.0.0.1:20004->8080/tcp\n",
		logOutput: "old line that must be discarded\n" + strings.Repeat("x", 40) + "\n" + strings.Repeat("y", 40) + "\n",
	}
	provisioner := NewPodmanProvisioner(PodmanProvisionerOptions{Runner: runner})
	result, err := provisioner.ReadApplicationLog(context.Background(), types.ApplicationLogReq{
		ApplicationID: 4, SubscriptionID: 7, Username: "np12345678", Lines: 20, Bytes: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Truncated {
		t.Fatal("oversized application log was not marked truncated")
	}
	joined := strings.Join(result.Lines, "\n")
	if strings.Contains(joined, "old line") || len(joined) > 64 {
		t.Fatalf("bounded log result is invalid: %q", joined)
	}
	if !strings.Contains(joined, strings.Repeat("y", 40)) {
		t.Fatalf("bounded log did not retain the newest complete line: %q", joined)
	}
}
