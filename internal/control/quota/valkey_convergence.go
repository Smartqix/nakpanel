package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

func valkeyDisabledByPolicy(policy types.HostingPolicy) bool {
	return !policy.Permissions.Valkey || !policy.Valkey.Enabled ||
		policy.Resources.ValkeyMemoryMB == 0 || policy.Valkey.MemoryMB == 0 ||
		policy.Valkey.MaxClients == 0 || policy.Valkey.CPUPercent == 0 || policy.Valkey.ProcessLimit == 0 ||
		policy.Resources.CPUPercent == 0 || policy.Resources.MaxTasks == 0
}

type valkeyConvergenceAgent interface {
	EnsureValkey(context.Context, types.EnsureValkeyReq) (types.EnsureValkeyResult, error)
}

func convergeValkeyAllocation(ctx context.Context, db *sql.DB, agent valkeyConvergenceAgent, req types.EnsureValkeyReq, revision int64, allocationErr error) error {
	result, convergenceErr := applyValkeyConvergence(ctx, agent, req)
	convergenceErr = errors.Join(convergenceErr, allocationErr)
	acknowledged, ackErr := acknowledgeValkeyConvergence(ctx, db, req, revision, result, convergenceErr)
	convergenceErr = errors.Join(convergenceErr, ackErr)
	if !acknowledged && convergenceErr == nil {
		return errors.New("Valkey convergence revision advanced before acknowledgement")
	}
	return convergenceErr
}

func applyValkeyConvergence(ctx context.Context, agent valkeyConvergenceAgent, req types.EnsureValkeyReq) (types.EnsureValkeyResult, error) {
	result, err := agent.EnsureValkey(ctx, req)
	if err == nil && result.Running != (req.State == "enabled") {
		err = errors.New("Valkey running state was not acknowledged by the agent")
	}
	if err == nil && req.State == "enabled" && req.Flush && !result.Flushed {
		err = errors.New("Valkey flush was not acknowledged by the agent")
	}
	if err == nil {
		return result, nil
	}
	// Agent rollback can restore an older over-ceiling allocation. An
	// unsuccessful update must therefore be followed by an explicit stop.
	stopped := req
	stopped.State, stopped.Flush = "disabled", false
	stopResult, stopErr := agent.EnsureValkey(ctx, stopped)
	if stopErr == nil && !stopResult.Running {
		return stopResult, err
	}
	if stopErr == nil {
		stopErr = errors.New("agent did not stop Valkey after failed allocation update")
	}
	result.Running = true // Runtime is unknown; do not acknowledge it as stopped.
	return result, errors.Join(err, stopErr)
}

func boundedValkeyRequest(accountState string, stored types.EnsureValkeyReq, policy types.HostingPolicy, providerMemoryHeadroom int) (types.EnsureValkeyReq, error) {
	req := stored
	req.State = effectiveValkeyState(accountState, stored.State, policy)
	// Even stop requests must satisfy the agent's configuration validator.
	stop := func() types.EnsureValkeyReq {
		stopped := stored
		stopped.State, stopped.Flush = req.State, false
		stopped.MemoryMB = max(stopped.MemoryMB, 16)
		stopped.MaxClients = max(stopped.MaxClients, 1)
		stopped.CPUPercent = max(stopped.CPUPercent, 1)
		stopped.ProcessLimit = max(stopped.ProcessLimit, 8)
		stopped.IdleTimeout = max(stopped.IdleTimeout, 0)
		return stopped
	}
	if req.State != "enabled" {
		return stop(), nil
	}
	capValue := func(value int, ceilings ...int) int {
		for _, ceiling := range ceilings {
			if ceiling >= 0 {
				value = min(value, ceiling)
			}
		}
		return value
	}
	req.MemoryMB = capValue(req.MemoryMB, policy.Resources.ValkeyMemoryMB, policy.Valkey.MemoryMB, providerMemoryHeadroom)
	req.MaxClients = capValue(req.MaxClients, policy.Valkey.MaxClients)
	req.CPUPercent = capValue(req.CPUPercent, policy.Valkey.CPUPercent, policy.Resources.CPUPercent)
	req.ProcessLimit = capValue(req.ProcessLimit, policy.Valkey.ProcessLimit, policy.Resources.MaxTasks)
	// Zero timeout means no idle expiry, not a tighter finite timeout.
	if policy.Valkey.IdleTimeoutSeconds > 0 && (req.IdleTimeout == 0 || req.IdleTimeout > policy.Valkey.IdleTimeoutSeconds) {
		req.IdleTimeout = policy.Valkey.IdleTimeoutSeconds
	}
	if req.MemoryMB < 16 || req.MaxClients < 1 || req.CPUPercent < 1 || req.ProcessLimit < 8 || req.IdleTimeout < 0 {
		req.State = "disabled"
		return stop(), fmt.Errorf("Valkey allocation cannot fit current ceilings (memory=%d MB, clients=%d, CPU=%d%%, processes=%d); service stopped", req.MemoryMB, req.MaxClients, req.CPUPercent, req.ProcessLimit)
	}
	return req, nil
}

func acknowledgeValkeyConvergence(ctx context.Context, db *sql.DB, req types.EnsureValkeyReq, revision int64, result types.EnsureValkeyResult, convergenceErr error) (bool, error) {
	status, message := "in_sync", ""
	applied := "stopped"
	if convergenceErr != nil {
		status, message = "failed", convergenceErr.Error()
	}
	if result.Running {
		applied = "running"
		if convergenceErr != nil {
			applied = "failed"
		}
	}
	if convergenceErr == nil && result.Running != (req.State == "enabled") {
		return false, errors.New("Valkey running state was not acknowledged by the agent")
	}
	if req.State == "enabled" && req.Flush && convergenceErr == nil && !result.Flushed {
		return false, errors.New("Valkey flush was not acknowledged by the agent")
	}
	// The schema has one allocation. Normalize it only after that exact
	// revision was applied successfully; stopped instances retain user intent.
	updated, err := db.ExecContext(ctx, `UPDATE valkey_instances instance SET applied_state=$3,socket_path=$4,
flush_requested=CASE WHEN $5 THEN false ELSE flush_requested END,
memory_mb=CASE WHEN $3='running' THEN $6 ELSE memory_mb END,
max_clients=CASE WHEN $3='running' THEN $7 ELSE max_clients END,
idle_timeout_seconds=CASE WHEN $3='running' THEN $8 ELSE idle_timeout_seconds END,
cpu_percent=CASE WHEN $3='running' THEN $9 ELSE cpu_percent END,
process_limit=CASE WHEN $3='running' THEN $10 ELSE process_limit END,
convergence_status=$11,last_error=$12,updated_at=now()
WHERE instance.subscription_id=$1 AND EXISTS (
SELECT 1 FROM subscription_system_accounts account WHERE account.subscription_id=instance.subscription_id AND account.desired_revision=$2)`,
		req.SubscriptionID, revision, applied, result.SocketPath, result.Flushed && convergenceErr == nil,
		req.MemoryMB, req.MaxClients, req.IdleTimeout, req.CPUPercent, req.ProcessLimit, status, strings.TrimSpace(message))
	if err != nil {
		return false, err
	}
	rows, err := updated.RowsAffected()
	return rows == 1, err
}
