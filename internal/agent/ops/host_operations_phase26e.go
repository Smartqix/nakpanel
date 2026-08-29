package ops

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

// ControlHostPower maps closed registry actions to a fixed transient timer.
// The short delay gives the panel time to commit the accepted operation and its
// audit record before systemd terminates panel processes.
func (m *ManagedOperations) ControlHostPower(ctx context.Context, req types.HostPowerReq) (types.HostPowerResult, error) {
	if !operationIDRE.MatchString(req.OperationID) {
		return types.HostPowerResult{}, errors.New("a valid operation id is required")
	}
	var verb string
	switch req.Action {
	case types.HostPowerReboot:
		verb = "reboot"
	case types.HostPowerShutdown:
		verb = "poweroff"
	default:
		return types.HostPowerResult{}, errors.New("host power action is not allowed")
	}

	runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	output, err := m.runner.Run(runCtx, "systemd-run",
		"--quiet",
		"--collect",
		"--unit=nakpanel-power-"+req.OperationID,
		"--on-active=10s",
		"/usr/bin/systemctl",
		verb,
		"--no-block",
	)
	cancel()
	if err != nil {
		return types.HostPowerResult{}, fmt.Errorf("%s host: %w: %s", req.Action, err, boundedText(output, 4096))
	}
	return types.HostPowerResult{Action: req.Action, Accepted: true}, nil
}
