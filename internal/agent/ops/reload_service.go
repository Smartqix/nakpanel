package ops

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

var ErrServiceNotAllowed = errors.New("service is not allowed")

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type SystemdReloaderOptions struct {
	AllowedServices []string
	Runner          CommandRunner
}

type SystemdReloader struct {
	allowed map[string]struct{}
	runner  CommandRunner
}

func NewSystemdReloader(opts SystemdReloaderOptions) *SystemdReloader {
	allowed := make(map[string]struct{}, len(opts.AllowedServices))
	for _, service := range opts.AllowedServices {
		allowed[service] = struct{}{}
	}
	if len(allowed) == 0 {
		for _, service := range []string{"nginx", "php8.3-fpm", "php8.2-fpm"} {
			allowed[service] = struct{}{}
		}
	}

	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}

	return &SystemdReloader{
		allowed: allowed,
		runner:  runner,
	}
}

func (r *SystemdReloader) ReloadService(ctx context.Context, name string) error {
	if _, ok := r.allowed[name]; !ok {
		return ErrServiceNotAllowed
	}

	output, err := r.runner.Run(ctx, "systemctl", "reload", name)
	if err != nil {
		return fmt.Errorf("reload service %q: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}
