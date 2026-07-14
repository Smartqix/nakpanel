package ops

import (
	"context"
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
	p := NewPodmanProvisioner(PodmanProvisionerOptions{Runner: &serviceTestRunner{}})
	valid := types.EnsureApplicationReq{ApplicationID: 1, Username: "npaccount", Name: "web-app", Runtime: "oci", ImageRef: "registry.example.test/team/app:1", DesiredState: "running", Environment: map[string]string{"APP_ENV": "prod"}, Policy: policy}
	if err := p.EnsureApplication(context.Background(), valid); err != nil {
		t.Fatal(err)
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

func TestPodmanProvisionerReplacesDriftedContainer(t *testing.T) {
	policy := validAccountPolicy()
	policy.Permissions.Applications = true
	policy.Applications.Rootless = true
	policy.Applications.AllowedRegistries = []string{"registry.example.test"}
	runner := &serviceTestRunner{outputs: [][]byte{[]byte("stale-hash"), nil, nil}}
	p := NewPodmanProvisioner(PodmanProvisionerOptions{Runner: runner})
	req := types.EnsureApplicationReq{ApplicationID: 9, Username: "npaccount", Name: "web-app", Runtime: "oci", ImageRef: "registry.example.test/team/app:2", DesiredState: "running", Environment: map[string]string{"APP_ENV": "prod"}, Policy: policy}
	if err := p.EnsureApplication(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, " rm --force nakpanel-9-web-app") || !strings.Contains(joined, "io.nakpanel.spec-sha256=") {
		t.Fatalf("drifted application was not replaced with a labeled container:\n%s", joined)
	}
}

func TestPodmanProvisionerRemovesTrackedContainerWithoutPullingImage(t *testing.T) {
	runner := &serviceTestRunner{}
	p := NewPodmanProvisioner(PodmanProvisionerOptions{Runner: runner})
	req := types.EnsureApplicationReq{ApplicationID: 9, Username: "npaccount", Name: "web-app", Runtime: "oci", DesiredState: "stopped", Remove: true}
	if err := p.EnsureApplication(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, "rm --force --ignore nakpanel-9-web-app") || strings.Contains(joined, " inspect ") || strings.Contains(joined, " pull ") {
		t.Fatalf("application removal calls were unsafe:\n%s", joined)
	}
}
