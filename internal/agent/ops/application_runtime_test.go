package ops

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
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

func TestApplicationUnitEnforcesPolicyResourcesInParentCgroup(t *testing.T) {
	for _, tc := range []struct {
		name               string
		memory, cpu, tasks int
		want               []string
		absent             []string
	}{
		{name: "finite policy", memory: 256, cpu: 50, tasks: 128, want: []string{"MemoryMax=256M", "CPUQuota=50%", "TasksMax=128"}},
		{name: "larger policy", memory: 1024, cpu: 200, tasks: 256, want: []string{"MemoryMax=1024M", "CPUQuota=200%", "TasksMax=256"}},
		{name: "zero memory and CPU retain inherited defaults", want: []string{"TasksMax=128"}, absent: []string{"MemoryMax=", "CPUQuota="}},
		{name: "nonpositive task limit keeps safe default", tasks: -1, want: []string{"TasksMax=128"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := validApplicationGenerationRequest()
			req.Policy.Resources.MemoryMB = tc.memory
			req.Policy.Resources.CPUPercent = tc.cpu
			req.Policy.Resources.MaxTasks = tc.tasks
			unit := renderApplicationUnit(req, applicationIdentity{}, "nakpanel-app-4-g3")
			for _, want := range tc.want {
				if !strings.Contains(unit, "\n"+want+"\n") {
					t.Fatalf("parent unit lacks %q: %s", want, unit)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(unit, absent) {
					t.Fatalf("parent unit changed unconstrained policy with %q: %s", absent, unit)
				}
			}
		})
	}
}

type applicationResourceDeployRunner struct {
	unitDir     string
	calls       []string
	enabledUnit string
}

func (r *applicationResourceDeployRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name == "systemctl" && len(args) == 3 && args[0] == "enable" && args[1] == "--now" {
		contents, err := os.ReadFile(filepath.Join(r.unitDir, args[2]))
		if err != nil {
			return nil, err
		}
		r.enabledUnit = string(contents)
	}
	return nil, nil
}

func TestDeployApplicationEnablesResourceBoundSupervisorBeforeRouting(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if !accountUsernameRE.MatchString(account.Username) {
		t.Skip("current account does not match supported Linux application username policy")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	req := validApplicationGenerationRequest()
	req.Username = account.Username
	req.Policy.Permissions.Applications = true
	req.Policy.Applications.Rootless = true
	req.Policy.Applications.AllowedRegistries = []string{"docker.io"}
	req.Policy.Resources.MemoryMB = 256
	req.Policy.Resources.CPUPercent = 50
	req.Policy.Resources.MaxTasks = 128
	req.Health = types.ApplicationHealthSpec{Kind: types.ApplicationHealthTCP, TimeoutSeconds: 1}
	var listener net.Listener
	for port := 25000; port < 25100; port++ {
		listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			req.Endpoint.HostPort = port - 5000
			break
		}
	}
	if listener == nil {
		t.Fatal("no available local candidate test port")
	}
	defer listener.Close()
	siteRoot := filepath.Join(home, req.Username, "domains", req.Domain, "public_html")
	if err := os.MkdirAll(siteRoot, 0750); err != nil {
		t.Fatal(err)
	}
	subIDs := filepath.Join(root, "subids")
	if err := os.WriteFile(subIDs, []byte(req.Username+":100000:65536\n"), 0600); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(root, "systemd")
	runner := &applicationResourceDeployRunner{unitDir: unitDir}
	p := NewPodmanProvisioner(PodmanProvisionerOptions{HomeRoot: home, StateRoot: filepath.Join(root, "state"), RuntimeRoot: filepath.Join(root, "run"), SystemdUnitDir: unitDir, NginxConfigDir: filepath.Join(root, "nginx"), SubUIDPath: subIDs, SubGIDPath: subIDs, Runner: runner})
	result, err := p.DeployApplicationGeneration(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.ObservedState != "healthy" || result.UnitName != "nakpanel-app-4-g3.service" {
		t.Fatalf("deployment result=%+v", result)
	}
	for _, want := range []string{"MemoryMax=256M", "CPUQuota=50%", "TasksMax=128", "User=" + req.Username, "ExecStart=/usr/bin/podman start --attach nakpanel-app-4-g3"} {
		if !strings.Contains(runner.enabledUnit, "\n"+want+"\n") {
			t.Fatalf("enabled supervisor lacks %q: %s", want, runner.enabledUnit)
		}
	}
	calls := strings.Join(runner.calls, "\n")
	reloadAt := strings.Index(calls, "systemctl daemon-reload")
	startAt := strings.Index(calls, "systemctl enable --now nakpanel-app-4-g3.service")
	routeAt := strings.Index(calls, "systemctl reload nginx")
	if reloadAt < 0 || startAt < 0 || routeAt < 0 || reloadAt > startAt || routeAt < startAt {
		t.Fatalf("supervisor was not loaded before activation/routing: %s", calls)
	}
	for _, want := range []string{"--pids-limit 128", "--memory 256m", "--cpus 0.50", "--cap-drop=all", "--security-opt=no-new-privileges", "--read-only"} {
		if !strings.Contains(calls, want) {
			t.Fatalf("container creation lost %q: %s", want, calls)
		}
	}
}

func freshStoppedRootlessIdentityFixture(t *testing.T, runner CommandRunner) (*PodmanProvisioner, types.EnsureApplicationReq, string) {
	t.Helper()
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if !accountUsernameRE.MatchString(account.Username) {
		t.Skip("current account does not match supported application username policy")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateRoot, runtimeRoot := filepath.Join(root, "state"), filepath.Join(root, "run")
	unitRoot, nginxRoot := filepath.Join(root, "units"), filepath.Join(root, "nginx")
	for _, dir := range []string{stateRoot, runtimeRoot, unitRoot, nginxRoot} {
		if err := os.Mkdir(dir, 0o711); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o711); err != nil {
			t.Fatal(err)
		}
	}
	subIDs := filepath.Join(root, "subids")
	if err := os.WriteFile(subIDs, []byte(account.Username+":100000:65536\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := validApplicationGenerationRequest()
	req.Username, req.DesiredState = account.Username, "stopped"
	p := NewPodmanProvisioner(PodmanProvisionerOptions{
		HomeRoot: filepath.Join(root, "missing-home"), StateRoot: stateRoot, RuntimeRoot: runtimeRoot,
		SystemdUnitDir: unitRoot, NginxConfigDir: nginxRoot,
		SubUIDPath: subIDs, SubGIDPath: subIDs, Runner: runner,
	})
	return p, req, filepath.Join(stateRoot, "sub-7")
}

func TestPrepareRootlessIdentityFreshStoppedParentIsTraversable(t *testing.T) {
	p, req, parent := freshStoppedRootlessIdentityFixture(t, &applicationRuntimeTestRunner{})
	identity, err := p.prepareRootlessIdentity(req, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaf := range []string{identity.stateHome, identity.dataHome, identity.configHome, identity.runtimeHome} {
		info, err := os.Lstat(leaf)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || !ownedBy(info, identity.uid) {
			t.Errorf("private rootless leaf %s mode/type/owner = %v, want tenant-owned directory0700", filepath.Base(leaf), info.Mode())
		}
	}
	config := filepath.Join(identity.configHome, "containers", "containers.conf")
	info, err := os.Lstat(config)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ownedBy(info, identity.uid) {
		t.Errorf("private rootless config mode/type/owner = %v, want tenant-owned regular0600", info.Mode())
	}
	info, err = os.Lstat(parent)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fresh subscription parent=%04o; private leaves=0700; config=0600", info.Mode().Perm())
	if info.Mode().Perm() != 0o711 {
		t.Errorf("fresh rootless subscription parent mode = %04o, want 0711 before tenant Podman", info.Mode().Perm())
	}
}

type stoppedRootlessParentRunner struct {
	parent string
	calls  []string
	sawPS  bool
	mode   os.FileMode
}

func (r *stoppedRootlessParentRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if name == "runuser" && strings.Contains(call, "/podman ps ") {
		r.sawPS = true
		info, err := os.Lstat(r.parent)
		if err != nil {
			return nil, err
		}
		r.mode = info.Mode().Perm()
		if r.mode != 0o711 {
			return nil, fmt.Errorf("synthetic tenant traversal refusal: parent mode %04o, want 0711", r.mode)
		}
	}
	return nil, nil
}

func TestDeployStoppedApplicationPreparesTraversableRootlessParent(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprintf("remove=%v", remove), func(t *testing.T) {
			runner := &stoppedRootlessParentRunner{}
			p, req, parent := freshStoppedRootlessIdentityFixture(t, runner)
			runner.parent, req.Remove = parent, remove
			result, err := p.DeployApplicationGeneration(context.Background(), req)
			if !runner.sawPS {
				t.Fatal("stopped generation did not reach the actual first tenant Podman ps boundary")
			}
			if err != nil {
				t.Fatalf("fresh stopped generation parent=%04o: %v", runner.mode, err)
			}
			if result.ObservedState != "stopped" {
				t.Fatalf("observed state=%q, want stopped", result.ObservedState)
			}
			joined := strings.Join(runner.calls, "\n")
			for _, forbidden := range []string{"podman pull ", "podman create ", "podman start "} {
				if strings.Contains(joined, forbidden) {
					t.Fatalf("stopped generation reached provisioning command %q", forbidden)
				}
			}
		})
	}
}

func TestRootlessIdentityRepairsOnlyManagedParentAndPreservesPrivateState(t *testing.T) {
	for _, initial := range []os.FileMode{0o700, 0o711} {
		t.Run(fmt.Sprintf("parent=%04o", initial), func(t *testing.T) {
			p, req, parent := freshStoppedRootlessIdentityFixture(t, &applicationRuntimeTestRunner{})
			if err := os.Mkdir(parent, initial); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(parent, initial); err != nil {
				t.Fatal(err)
			}
			for pass := 0; pass < 2; pass++ {
				identity, err := p.prepareRootlessIdentity(req, false)
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(parent)
				if err != nil || info.Mode().Perm() != 0o711 || !ownedBy(info, os.Geteuid()) {
					t.Fatalf("managed parent not preserved/repaired: %v, %v", info, err)
				}
				private := filepath.Join(identity.dataHome, "unrelated-state")
				if pass == 0 {
					if err := os.WriteFile(private, []byte("private-state-sentinel"), 0o600); err != nil {
						t.Fatal(err)
					}
				} else {
					contents, err := os.ReadFile(private)
					if err != nil || string(contents) != "private-state-sentinel" {
						t.Fatalf("private state changed: %q, %v", contents, err)
					}
				}
				for _, leaf := range []string{identity.stateHome, identity.dataHome, identity.configHome, identity.runtimeHome} {
					info, err := os.Lstat(leaf)
					if err != nil || info.Mode().Perm() != 0o700 || !ownedBy(info, identity.uid) {
						t.Fatalf("private leaf changed: %v, %v", info, err)
					}
				}
			}
		})
	}
}

func TestRootlessIdentityConcurrentPreparationPreservesPrivateState(t *testing.T) {
	p, req, parent := freshStoppedRootlessIdentityFixture(t, &applicationRuntimeTestRunner{})
	start := make(chan struct{})
	results := make(chan error, 8)
	for worker := 0; worker < cap(results); worker++ {
		go func() {
			<-start
			_, err := p.prepareRootlessIdentity(req, false)
			results <- err
		}()
	}
	close(start)
	for worker := 0; worker < cap(results); worker++ {
		if err := <-results; err != nil {
			t.Errorf("concurrent preparation refused: %v", err)
		}
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".nakpanel-rootless-") {
			t.Errorf("temporary rootless staging directory remained: %q", entry.Name())
		}
	}
}

func TestRootlessIdentityRejectsUnsafePathsWithoutOutsideMutation(t *testing.T) {
	for _, kind := range []string{"state-root-symlink", "parent-symlink", "home-symlink", "data-symlink", "config-symlink", "runtime-root-symlink", "runtime-symlink", "containers-symlink", "config-file-symlink", "config-file-hardlink", "parent-file", "runtime-file", "containers-file"} {
		t.Run(kind, func(t *testing.T) {
			runner := &stoppedRootlessParentRunner{}
			p, req, parent := freshStoppedRootlessIdentityFixture(t, runner)
			runner.parent = parent
			outside, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"sentinel", "containers.conf"} {
				if err := os.WriteFile(filepath.Join(outside, name), []byte("outside-sentinel"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(parent, 0o711); err != nil {
				t.Fatal(err)
			}
			target := parent
			switch kind {
			case "state-root-symlink":
				if err := os.Remove(parent); err != nil {
					t.Fatal(err)
				}
				target = p.stateRoot
			case "home-symlink":
				target = filepath.Join(parent, "home")
			case "data-symlink":
				target = filepath.Join(parent, "data")
			case "config-symlink":
				target = filepath.Join(parent, "config")
			case "runtime-root-symlink":
				target = p.runtimeRoot
			case "runtime-symlink", "runtime-file":
				target = filepath.Join(p.runtimeRoot, "sub-7")
			case "containers-symlink", "containers-file", "config-file-symlink", "config-file-hardlink":
				config := filepath.Join(parent, "config")
				if err := os.Mkdir(config, 0o700); err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(config, "containers")
				if strings.HasPrefix(kind, "config-file-") {
					if err := os.Mkdir(target, 0o700); err != nil {
						t.Fatal(err)
					}
					target = filepath.Join(target, "containers.conf")
				}
			}
			if _, err := os.Lstat(target); err == nil {
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "config-file-hardlink" {
				if err := os.Link(filepath.Join(outside, "sentinel"), target); err != nil {
					t.Fatal(err)
				}
			} else if strings.HasSuffix(kind, "-file") {
				if err := os.WriteFile(target, []byte("managed-file-sentinel"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				link := outside
				if kind == "config-file-symlink" {
					link = filepath.Join(outside, "sentinel")
				}
				if err := os.Symlink(link, target); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := p.DeployApplicationGeneration(context.Background(), req); err == nil {
				t.Error("unsafe rootless path accepted")
			}
			if len(runner.calls) != 0 {
				t.Errorf("unsafe path reached tenant runner: %v", runner.calls)
			}
			entries, err := os.ReadDir(outside)
			if err != nil || len(entries) != 2 {
				t.Errorf("outside directory changed: %v, %v", entries, err)
			}
			for _, name := range []string{"sentinel", "containers.conf"} {
				contents, err := os.ReadFile(filepath.Join(outside, name))
				if err != nil || string(contents) != "outside-sentinel" {
					t.Errorf("outside file changed: %s: %q, %v", name, contents, err)
				}
			}
		})
	}
}

func TestRootlessIdentityRejectsWritableManagedNamespaces(t *testing.T) {
	for _, kind := range []string{"state-root", "parent", "runtime-root"} {
		t.Run(kind, func(t *testing.T) {
			runner := &stoppedRootlessParentRunner{}
			p, req, parent := freshStoppedRootlessIdentityFixture(t, runner)
			runner.parent = parent
			if err := os.Mkdir(parent, 0o711); err != nil {
				t.Fatal(err)
			}
			target := map[string]string{"state-root": p.stateRoot, "parent": parent, "runtime-root": p.runtimeRoot}[kind]
			if err := os.Chmod(target, 0o777); err != nil {
				t.Fatal(err)
			}
			if _, err := p.DeployApplicationGeneration(context.Background(), req); err == nil {
				t.Error("writable managed namespace accepted")
			}
			if len(runner.calls) != 0 {
				t.Errorf("writable namespace reached tenant runner: %v", runner.calls)
			}
			info, err := os.Lstat(target)
			if err != nil || info.Mode().Perm() != 0o777 {
				t.Errorf("untrusted namespace was changed/adopted: %v, %v", info, err)
			}
		})
	}
}

func TestRootlessConfigRejectsForeignIdentityWithoutAdoption(t *testing.T) {
	for _, kind := range []string{"uid", "gid"} {
		t.Run(kind, func(t *testing.T) {
			config := t.TempDir()
			identity := applicationIdentity{uid: os.Getuid(), gid: os.Getgid(), configHome: config}
			if kind == "uid" {
				identity.uid++
			} else {
				identity.gid++
			}
			p := NewPodmanProvisioner(PodmanProvisionerOptions{})
			if err := p.writeRootlessPodmanConfig(identity); err == nil {
				t.Error("foreign existing config owner accepted")
			}
			entries, err := os.ReadDir(config)
			if err != nil || len(entries) != 0 {
				t.Errorf("foreign identity caused config writes: %v, %v", entries, err)
			}
		})
	}
}
