package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type serviceTestRunner struct {
	calls   []string
	outputs [][]byte
}

func (r *serviceTestRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if len(r.outputs) == 0 {
		return nil, nil
	}
	out := r.outputs[0]
	r.outputs = r.outputs[1:]
	return out, nil
}

func TestPodmanProvisionerEnforcesRegistryAndEnvironment(t *testing.T) {
	policy := validAccountPolicy()
	policy.Permissions.Applications = true
	policy.Applications.Rootless = true
	policy.Applications.AllowedRegistries = []string{"registry.example.test"}
	homeRoot := applicationTestHome(t, "npaccount", "example.test")
	runner := &serviceTestRunner{}
	p := NewPodmanProvisioner(PodmanProvisionerOptions{HomeRoot: homeRoot, Runner: runner})
	valid := types.EnsureApplicationReq{ApplicationID: 1, SiteID: 2, Username: "npaccount", Domain: "example.test", Name: "web-app", Runtime: "oci", ImageRef: "registry.example.test/team/app:1", DesiredState: "running", Environment: map[string]string{"APP_ENV": "prod"}, Policy: policy}
	if err := p.EnsureApplication(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	if calls := strings.Join(runner.calls, "\n"); !strings.Contains(calls, "--network=none") || !strings.Contains(calls, ":/workspace:rw,Z") {
		t.Fatalf("application was not domain-confined with egress disabled:\n%s", calls)
	}
	invalid := valid
	invalid.ImageRef = "untrusted.test/app:latest"
	if err := p.EnsureApplication(context.Background(), invalid); err == nil {
		t.Fatal("untrusted registry was accepted")
	}
	invalid = valid
	invalid.Environment = map[string]string{"BAD-NAME": "x"}
	if err := p.EnsureApplication(context.Background(), invalid); err == nil {
		t.Fatal("unsafe environment key was accepted")
	}
}

func TestPodmanProvisionerEgressPolicyChangesRuntimeAndSpecHash(t *testing.T) {
	base := validAccountPolicy()
	base.Permissions.Applications = true
	base.Permissions.ApplicationEgress = true
	base.Applications.Rootless = true
	base.Applications.EgressEnabled = true
	base.Applications.AllowedRegistries = []string{"registry.example.test"}
	homeRoot := applicationTestHome(t, "npaccount", "example.test")
	request := types.EnsureApplicationReq{
		ApplicationID: 3, SiteID: 2, Username: "npaccount", Domain: "example.test",
		Name: "web-app", Runtime: "oci", ImageRef: "registry.example.test/team/app:1",
		DesiredState: "running", Policy: base,
	}
	allowedRunner := &serviceTestRunner{}
	if err := NewPodmanProvisioner(PodmanProvisionerOptions{HomeRoot: homeRoot, Runner: allowedRunner}).EnsureApplication(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	allowedCalls := strings.Join(allowedRunner.calls, "\n")
	if strings.Contains(allowedCalls, "--network=none") {
		t.Fatalf("explicitly allowed application egress was disabled:\n%s", allowedCalls)
	}

	request.Policy.Applications.EgressEnabled = false
	blockedRunner := &serviceTestRunner{}
	if err := NewPodmanProvisioner(PodmanProvisionerOptions{HomeRoot: homeRoot, Runner: blockedRunner}).EnsureApplication(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	blockedCalls := strings.Join(blockedRunner.calls, "\n")
	if !strings.Contains(blockedCalls, "--network=none") {
		t.Fatalf("disabled application egress was not enforced:\n%s", blockedCalls)
	}
	if applicationSpecLabel(allowedCalls) == applicationSpecLabel(blockedCalls) {
		t.Fatal("egress policy change did not change the application spec hash")
	}
}

func applicationSpecLabel(calls string) string {
	const prefix = "io.nakpanel.spec-sha256="
	index := strings.Index(calls, prefix)
	if index < 0 {
		return ""
	}
	value := calls[index+len(prefix):]
	if end := strings.IndexAny(value, " \n"); end >= 0 {
		value = value[:end]
	}
	return value
}

func TestPodmanProvisionerReplacesDriftedContainer(t *testing.T) {
	policy := validAccountPolicy()
	policy.Permissions.Applications = true
	policy.Applications.Rootless = true
	policy.Applications.AllowedRegistries = []string{"registry.example.test"}
	runner := &serviceTestRunner{outputs: [][]byte{[]byte("stale-hash"), nil, nil}}
	homeRoot := applicationTestHome(t, "npaccount", "example.test")
	p := NewPodmanProvisioner(PodmanProvisionerOptions{HomeRoot: homeRoot, Runner: runner})
	req := types.EnsureApplicationReq{ApplicationID: 9, SiteID: 2, Username: "npaccount", Domain: "example.test", Name: "web-app", Runtime: "oci", ImageRef: "registry.example.test/team/app:2", DesiredState: "running", Environment: map[string]string{"APP_ENV": "prod"}, Policy: policy}
	if err := p.EnsureApplication(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, "--name nakpanel-app-9-candidate") ||
		!strings.Contains(joined, " rename nakpanel-app-9 nakpanel-app-9-previous") ||
		!strings.Contains(joined, " rename nakpanel-app-9-candidate nakpanel-app-9") ||
		!strings.Contains(joined, "rm --force --ignore nakpanel-app-9-previous") ||
		!strings.Contains(joined, "rm --force --ignore nakpanel-9-web-app") ||
		!strings.Contains(joined, "io.nakpanel.spec-sha256=") {
		t.Fatalf("drifted application was not replaced with a labeled container:\n%s", joined)
	}
}

type replacementFailureRunner struct {
	calls []string
}

func (r *replacementFailureRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if strings.Contains(call, "container inspect") {
		return []byte("stale-hash"), nil
	}
	if strings.Contains(call, "run --detach --name nakpanel-app-9-candidate") {
		return []byte("image unavailable"), errors.New("image unavailable")
	}
	return nil, nil
}

func TestPodmanProvisionerKeepsCurrentContainerWhenReplacementFails(t *testing.T) {
	policy := validAccountPolicy()
	policy.Permissions.Applications = true
	policy.Applications.Rootless = true
	policy.Applications.AllowedRegistries = []string{"registry.example.test"}
	runner := &replacementFailureRunner{}
	homeRoot := applicationTestHome(t, "npaccount", "example.test")
	req := types.EnsureApplicationReq{
		ApplicationID: 9, SiteID: 2, Username: "npaccount", Domain: "example.test",
		Name: "web-app", Runtime: "oci", ImageRef: "registry.example.test/team/app:2",
		DesiredState: "running", Policy: policy,
	}
	err := NewPodmanProvisioner(PodmanProvisionerOptions{HomeRoot: homeRoot, Runner: runner}).EnsureApplication(context.Background(), req)
	if err == nil {
		t.Fatal("expected replacement start failure")
	}
	joined := strings.Join(runner.calls, "\n")
	if strings.Contains(joined, " rename nakpanel-app-9 ") ||
		strings.Contains(joined, " rm --force nakpanel-app-9") {
		t.Fatalf("failed replacement changed the last known-good container:\n%s", joined)
	}
}

func TestApplicationContainerIdentityDoesNotDependOnMutableName(t *testing.T) {
	if got := applicationContainerName(19); got != "nakpanel-app-19" {
		t.Fatalf("applicationContainerName(19) = %q", got)
	}
}

type replacementCleanupRetryRunner struct {
	calls            []string
	specHash         string
	inspectMissing   bool
	failPreviousOnce bool
}

func (r *replacementCleanupRetryRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if strings.Contains(call, "container inspect") {
		if r.inspectMissing {
			return nil, errors.New("container missing")
		}
		return []byte(r.specHash), nil
	}
	if strings.Contains(call, "run --detach") {
		r.specHash = applicationSpecLabel(call)
	}
	if r.failPreviousOnce && strings.Contains(call, "rm --force --ignore nakpanel-app-9-previous") {
		r.failPreviousOnce = false
		return nil, errors.New("temporary remove failure")
	}
	return nil, nil
}

func TestPodmanProvisionerRetriesPriorContainerCleanup(t *testing.T) {
	policy := validAccountPolicy()
	policy.Permissions.Applications = true
	policy.Applications.Rootless = true
	policy.Applications.AllowedRegistries = []string{"registry.example.test"}
	homeRoot := applicationTestHome(t, "npaccount", "example.test")
	req := types.EnsureApplicationReq{
		ApplicationID: 9, SiteID: 2, Username: "npaccount", Domain: "example.test",
		Name: "web-app", Runtime: "oci", ImageRef: "registry.example.test/team/app:2",
		DesiredState: "running", Policy: policy,
	}
	runner := &replacementCleanupRetryRunner{inspectMissing: true}
	provisioner := NewPodmanProvisioner(PodmanProvisionerOptions{HomeRoot: homeRoot, Runner: runner})
	if err := provisioner.EnsureApplication(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	runner.inspectMissing = false
	runner.failPreviousOnce = true
	if err := provisioner.EnsureApplication(context.Background(), req); err == nil {
		t.Fatal("expected transient prior-container cleanup failure")
	}
	if err := provisioner.EnsureApplication(context.Background(), req); err != nil {
		t.Fatalf("cleanup retry failed: %v", err)
	}
	if count := strings.Count(strings.Join(runner.calls, "\n"), "rm --force --ignore nakpanel-app-9-previous"); count < 3 {
		t.Fatalf("previous container cleanup attempts = %d; want initial plus two retries", count)
	}
}

func applicationTestHome(t *testing.T, username, domain string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, username, "domains", domain, "public_html"), 0o750); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestPodmanProvisionerRemovesTrackedContainerWithoutPullingImage(t *testing.T) {
	runner := &serviceTestRunner{}
	p := NewPodmanProvisioner(PodmanProvisionerOptions{Runner: runner})
	req := types.EnsureApplicationReq{ApplicationID: 9, Username: "npaccount", Name: "web-app", Runtime: "oci", DesiredState: "stopped", Remove: true}
	if err := p.EnsureApplication(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, "rm --force --ignore nakpanel-app-9") ||
		!strings.Contains(joined, "rm --force --ignore nakpanel-app-9-candidate") ||
		!strings.Contains(joined, "rm --force --ignore nakpanel-app-9-previous") ||
		!strings.Contains(joined, "rm --force --ignore nakpanel-9-web-app") ||
		strings.Contains(joined, " inspect ") || strings.Contains(joined, " pull ") {
		t.Fatalf("application removal calls were unsafe:\n%s", joined)
	}
}

func TestPodmanProvisionerStopsApplicationAfterEntitlementRevocation(t *testing.T) {
	runner := &serviceTestRunner{}
	p := NewPodmanProvisioner(PodmanProvisionerOptions{Runner: runner})
	req := types.EnsureApplicationReq{
		ApplicationID: 9, Username: "npaccount", Name: "web-app",
		Runtime: "oci", DesiredState: "stopped",
		// Site, image, and policy are intentionally absent: stopping a tracked
		// container must remain possible after its entitlement is withdrawn.
	}
	if err := p.EnsureApplication(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls, "\n")
	for _, name := range []string{"nakpanel-app-9", "nakpanel-app-9-candidate", "nakpanel-app-9-previous", "nakpanel-9-web-app"} {
		if !strings.Contains(joined, "stop --ignore "+name) {
			t.Fatalf("revoked application did not stop %s:\n%s", name, joined)
		}
	}
	if strings.Contains(joined, " inspect ") || strings.Contains(joined, " pull ") || strings.Contains(joined, " run --detach ") {
		t.Fatalf("revoked application stop performed provisioning work:\n%s", joined)
	}
}
