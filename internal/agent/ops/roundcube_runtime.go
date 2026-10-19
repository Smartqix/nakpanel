package ops

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

// CheckRoundcubeMySQLRuntime uses the same trusted descriptor and isolated FPM
// readiness probe as hosting, plus Roundcube's PDO MySQL requirement in both
// SAPIs. Environment-based PHP/loader overrides cannot satisfy this check.
func CheckRoundcubeMySQLRuntime(ctx context.Context, version string) error {
	return checkRoundcubeMySQLRuntime(ctx, version, roundcubeRuntimeProbe{}, nil)
}
func checkRoundcubeMySQLRuntime(ctx context.Context, version string, probe RuntimeCapabilityProbe, resolver PHPRuntimeResolver) error {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	capability, installed := probePHPRuntimeWithResolver(bounded, probe, resolver, version, types.PHPSupportActive)
	if !installed || !capability.Ready || !containsFold(capability.Extensions, "pdo_mysql") {
		return errors.New("trusted internal PHP CLI/FPM runtime with PDO MySQL is unavailable")
	}
	descriptor, err := resolvePHPRuntime(resolver, version)
	if err != nil {
		return errors.New("trusted internal PHP runtime descriptor is unavailable")
	}
	output, err := (descriptorRuntimeProbe{RuntimeCapabilityProbe: probe, runtime: descriptor}).Run(bounded, descriptor.FPMPath, "-i")
	if err != nil || !containsFold(strings.Split(strings.ReplaceAll(string(output), "\r", ""), "\n"), "pdo_mysql") {
		return errors.New("trusted internal PHP FPM PDO MySQL extension is unavailable")
	}
	return nil
}

type roundcubeRuntimeProbe struct{ systemRuntimeCapabilityProbe }

func roundcubeRuntimeEnvironment() []string {
	clean := make([]string, 0)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name != "PHPRC" && name != "PHP_INI_SCAN_DIR" && !strings.HasPrefix(name, "LD_") && !strings.HasPrefix(name, "DYLD_") {
			clean = append(clean, entry)
		}
	}
	return clean
}
func (roundcubeRuntimeProbe) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = roundcubeRuntimeEnvironment()
	return cmd.CombinedOutput()
}
func (roundcubeRuntimeProbe) Start(ctx context.Context, name string, args ...string) (RuntimeCapabilityProcess, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = roundcubeRuntimeEnvironment()
	process := &execRuntimeCapabilityProcess{command: command}
	command.Stdout = &process.output
	command.Stderr = &process.output
	if err := command.Start(); err != nil {
		return nil, err
	}
	return process, nil
}
