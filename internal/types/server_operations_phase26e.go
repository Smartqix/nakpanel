package types

import "time"

const OpControlHostPower = "control_host_power"

const (
	HostPowerReboot   = "reboot"
	HostPowerShutdown = "shutdown"
)

// HostPowerReq deliberately carries only a registry action. The agent maps the
// action to a fixed systemd invocation and never accepts commands or arguments.
type HostPowerReq struct {
	Action      string `json:"action"`
	OperationID string `json:"operation_id"`
	ActorUserID int64  `json:"-"`
}

type HostPowerResult struct {
	Action   string `json:"action"`
	Accepted bool   `json:"accepted"`
}

type ApplicationCatalogInventory struct {
	Slug               string    `json:"slug"`
	Runtime            string    `json:"runtime"`
	Instances          int       `json:"instances"`
	Running            int       `json:"running"`
	Stopped            int       `json:"stopped"`
	Failed             int       `json:"failed"`
	PendingConvergence int       `json:"pending_convergence"`
	LastChangedAt      time.Time `json:"last_changed_at,omitempty"`
}
