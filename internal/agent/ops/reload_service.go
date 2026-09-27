package ops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

var ErrServiceNotAllowed = errors.New("service is not allowed")
var sitePHPServiceRE = regexp.MustCompile(`^nakpanel-php-fpm@[1-9][0-9]*\.service$`)

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type InputCommandRunner interface {
	RunInput(ctx context.Context, input []byte, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (ExecRunner) RunInput(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = bytes.NewReader(input)
	return command.CombinedOutput()
}

type SystemdReloaderOptions struct {
	AllowedServices []string
	Runner          CommandRunner
}

type SystemdReloader struct {
	allowed map[string]struct{}
	runner  CommandRunner
}

type NginxConfigTester interface {
	TestNginxConfig(ctx context.Context) error
}

type CommandNginxConfigTester struct {
	runner CommandRunner
}

type CommandPHPConfigTester struct{ runner CommandRunner }

func NewCommandPHPConfigTester(runner CommandRunner) *CommandPHPConfigTester {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &CommandPHPConfigTester{runner: runner}
}

func (t *CommandPHPConfigTester) TestPHPConfig(ctx context.Context, version, configPath string) error {
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version) {
		return fmt.Errorf("invalid PHP version %q", version)
	}
	output, err := t.runner.Run(ctx, "php-fpm"+version, "-t", "-y", configPath)
	if err != nil {
		return fmt.Errorf("test PHP-FPM configuration: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func NewCommandNginxConfigTester(runner CommandRunner) *CommandNginxConfigTester {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &CommandNginxConfigTester{runner: runner}
}

func (t *CommandNginxConfigTester) TestNginxConfig(ctx context.Context) error {
	output, err := t.runner.Run(ctx, "nginx", "-t")
	if err != nil {
		return fmt.Errorf("test nginx configuration: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
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
	if _, ok := r.allowed[name]; !ok && !sitePHPServiceRE.MatchString(name) {
		return ErrServiceNotAllowed
	}
	if sitePHPServiceRE.MatchString(name) {
		if output, err := r.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("reload systemd units: %w: %s", err, strings.TrimSpace(string(output)))
		}
		if output, err := r.runner.Run(ctx, "systemctl", "enable", name); err != nil {
			return fmt.Errorf("enable dedicated PHP service: %w: %s", err, strings.TrimSpace(string(output)))
		}
		if output, err := r.runner.Run(ctx, "systemctl", "reset-failed", name); err != nil {
			return fmt.Errorf("reset dedicated PHP service state: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}

	output, err := r.runner.Run(ctx, "systemctl", "reload-or-restart", name)
	if err != nil {
		return fmt.Errorf("reload or restart service %q: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (r *SystemdReloader) StopService(ctx context.Context, name string) error {
	if !sitePHPServiceRE.MatchString(name) {
		return ErrServiceNotAllowed
	}
	output, err := r.runner.Run(ctx, "systemctl", "disable", "--now", name)
	if err != nil {
		return fmt.Errorf("disable service %q: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}
