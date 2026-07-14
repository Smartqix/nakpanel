package ops

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeRunner struct {
	name string
	args []string
	err  error
	out  []byte
}

func (r *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.name = name
	r.args = append([]string(nil), args...)
	return r.out, r.err
}

func TestSystemdReloaderReloadsAllowedServiceWithoutShell(t *testing.T) {
	runner := &fakeRunner{}
	reloader := NewSystemdReloader(SystemdReloaderOptions{
		AllowedServices: []string{"nginx"},
		Runner:          runner,
	})

	if err := reloader.ReloadService(context.Background(), "nginx"); err != nil {
		t.Fatalf("ReloadService returned error: %v", err)
	}
	if runner.name != "systemctl" {
		t.Fatalf("runner name = %q, want systemctl", runner.name)
	}
	wantArgs := []string{"reload-or-restart", "nginx"}
	if len(runner.args) != len(wantArgs) {
		t.Fatalf("runner args = %#v, want %#v", runner.args, wantArgs)
	}
	for i := range wantArgs {
		if runner.args[i] != wantArgs[i] {
			t.Fatalf("runner args = %#v, want %#v", runner.args, wantArgs)
		}
	}
}

func TestSystemdReloaderRejectsDisallowedService(t *testing.T) {
	runner := &fakeRunner{}
	reloader := NewSystemdReloader(SystemdReloaderOptions{
		AllowedServices: []string{"nginx"},
		Runner:          runner,
	})

	err := reloader.ReloadService(context.Background(), "postgresql")
	if !errors.Is(err, ErrServiceNotAllowed) {
		t.Fatalf("ReloadService error = %v, want ErrServiceNotAllowed", err)
	}
	if runner.name != "" {
		t.Fatalf("runner was called for disallowed service: %q %#v", runner.name, runner.args)
	}
}

func TestSystemdReloaderIncludesCommandOutputOnFailure(t *testing.T) {
	reloader := NewSystemdReloader(SystemdReloaderOptions{
		AllowedServices: []string{"nginx"},
		Runner: &fakeRunner{
			err: errors.New("exit status 1"),
			out: []byte("reload failed"),
		},
	})

	err := reloader.ReloadService(context.Background(), "nginx")
	if err == nil {
		t.Fatal("ReloadService returned nil error")
	}
	if !strings.Contains(err.Error(), "reload failed") {
		t.Fatalf("error = %q, want command output", err.Error())
	}
}
