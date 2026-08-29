package ops

import (
	"context"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestControlHostPowerUsesOnlyFixedSystemdActions(t *testing.T) {
	for _, test := range []struct {
		action string
		verb   string
	}{
		{types.HostPowerReboot, "reboot"},
		{types.HostPowerShutdown, "poweroff"},
	} {
		runner := &recordingCommandRunner{}
		operations := NewManagedOperations(ManagedOperationsOptions{Runner: runner})
		result, err := operations.ControlHostPower(context.Background(), types.HostPowerReq{
			Action: test.action, OperationID: "op_12345678901234567890",
		})
		if err != nil {
			t.Fatalf("%s: %v", test.action, err)
		}
		if !result.Accepted || len(runner.calls) != 1 || runner.calls[0].name != "systemd-run" ||
			strings.Join(runner.calls[0].args, " ") !=
				"--quiet --collect --unit=nakpanel-power-op_12345678901234567890 --on-active=10s /usr/bin/systemctl "+test.verb+" --no-block" {
			t.Fatalf("%s result=%#v commands=%#v", test.action, result, runner.calls)
		}
	}
}

func TestControlHostPowerRejectsUnregisteredAction(t *testing.T) {
	runner := &recordingCommandRunner{}
	operations := NewManagedOperations(ManagedOperationsOptions{Runner: runner})
	_, err := operations.ControlHostPower(context.Background(), types.HostPowerReq{
		Action: "reboot;id", OperationID: "op_12345678901234567890",
	})
	if err == nil || len(runner.calls) != 0 {
		t.Fatalf("unsafe host action err=%v commands=%#v", err, runner.calls)
	}
}
