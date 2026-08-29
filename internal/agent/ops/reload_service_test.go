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

type callRunner struct {
	calls [][]string
}

func (r *callRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return nil, nil
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

func TestSystemdReloaderPersistsDedicatedPHPDesiredState(t *testing.T) {
	runner := &callRunner{}
	reloader := NewSystemdReloader(SystemdReloaderOptions{Runner: runner})
	const service = "nakpanel-php-fpm@42.service"
	if err := reloader.ReloadService(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	if err := reloader.StopService(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", service},
		{"systemctl", "reset-failed", service},
		{"systemctl", "reload-or-restart", service},
		{"systemctl", "disable", "--now", service},
	}
	if len(runner.calls) != len(want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
	for index := range want {
		if strings.Join(runner.calls[index], "\x00") != strings.Join(want[index], "\x00") {
			t.Fatalf("call %d = %#v, want %#v", index, runner.calls[index], want[index])
		}
	}
}
