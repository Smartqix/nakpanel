package serveradmin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type updateAgent interface {
	InspectUpdates(context.Context) (types.UpdateState, error)
	ApplyUpdates(context.Context, types.ApplyUpdatesReq) (types.UpdateState, error)
}

type hostPowerAgent interface {
	ControlHostPower(context.Context, types.HostPowerReq) (types.HostPowerResult, error)
}

type ApplyUpdatesArgs struct {
	OperationID string `json:"operation_id" river:"unique"`
}

func (ApplyUpdatesArgs) Kind() string { return "system_apply_updates" }

func (ApplyUpdatesArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       SystemQueue,
		MaxAttempts: 1,
		UniqueOpts: river.UniqueOpts{
			ByArgs:  true,
			ByState: activeJobStates,
		},
	}
}

type HostPowerArgs struct {
	OperationID string `json:"operation_id" river:"unique"`
}

func (HostPowerArgs) Kind() string { return "system_host_power" }

func (HostPowerArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       SystemQueue,
		MaxAttempts: 1,
		UniqueOpts: river.UniqueOpts{
			ByArgs:  true,
			ByState: activeJobStates,
		},
	}
}

func (m *Manager) InspectUpdates(ctx context.Context) (types.UpdateState, error) {
	if m == nil {
		return types.UpdateState{}, errors.New("managed update agent is not configured")
	}
	agent, ok := any(m.agent).(updateAgent)
	if !ok {
		return types.UpdateState{}, errors.New("managed update agent is not configured")
	}
	return agent.InspectUpdates(ctx)
}

func (m *Manager) ApplyUpdates(ctx context.Context, req types.ApplyUpdatesReq, actorUserID int64) error {
	if m == nil || m.store == nil || m.river == nil {
		return errors.New("managed update queue is not configured")
	}
	if actorUserID <= 0 {
		return errors.New("managed update actor is required")
	}
	if _, ok := any(m.agent).(updateAgent); !ok {
		return errors.New("managed update agent is not configured")
	}
	action := "install_updates"
	if req.DryRun {
		action = "preview_updates"
	}
	return m.queueOperation(ctx, CreateOperationParams{
		OperationID:    req.OperationID,
		Category:       CategoryServerManagement,
		Action:         action,
		TargetType:     "server_updates",
		TargetKey:      "selected_packages",
		IdempotencyKey: req.OperationID,
		ActorUserID:    actorUserID,
	}, req, ApplyUpdatesArgs{OperationID: req.OperationID})
}

func (m *Manager) ControlHostPower(ctx context.Context, req types.HostPowerReq) error {
	if m == nil || m.store == nil || m.river == nil {
		return errors.New("host power queue is not configured")
	}
	if req.ActorUserID <= 0 {
		return errors.New("host power actor is required")
	}
	if req.Action != types.HostPowerReboot && req.Action != types.HostPowerShutdown {
		return errors.New("host power action is not allowed")
	}
	if _, ok := any(m.agent).(hostPowerAgent); !ok {
		return errors.New("host power agent is not configured")
	}
	return m.queueOperation(ctx, CreateOperationParams{
		OperationID:    req.OperationID,
		Category:       CategoryServerManagement,
		Action:         req.Action,
		TargetType:     "server_host",
		TargetKey:      "host",
		IdempotencyKey: req.OperationID,
		ActorUserID:    req.ActorUserID,
	}, req, HostPowerArgs{OperationID: req.OperationID})
}

func (m *Manager) queueOperation(ctx context.Context, params CreateOperationParams, request any, args river.JobArgs) error {
	payload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode server operation: %w", err)
	}
	params.Request = payload
	tx, err := m.store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin server operation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := m.store.CreateOperationTx(ctx, tx, params); err != nil {
		return fmt.Errorf("persist server operation: %w", err)
	}
	auditAction := "server." + strings.ReplaceAll(params.Action, "_", ".") + "_requested"
	if params.TargetType == "server_updates" {
		auditAction = "server.updates_requested"
	} else if params.TargetType == "server_host" {
		auditAction = "server.host_" + params.Action + "_requested"
	}
	if err := m.store.RecordOperationRequestTx(ctx, tx, params.ActorUserID, auditAction, params.TargetType,
		mustJSONObject(map[string]any{"operation_id": params.OperationID, "action": params.Action})); err != nil {
		return fmt.Errorf("record server operation request: %w", err)
	}
	if _, err := m.river.InsertTx(ctx, tx, args, nil); err != nil {
		return fmt.Errorf("queue server operation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit server operation: %w", err)
	}
	return nil
}

func (m *Manager) ApplicationCatalogInventory(ctx context.Context) ([]types.ApplicationCatalogInventory, error) {
	if m == nil || m.store == nil {
		return nil, errors.New("application catalog inventory is unavailable")
	}
	rows, err := m.store.db.QueryContext(ctx, `
SELECT COALESCE(NULLIF(catalog_slug,''),'custom') AS slug,runtime,
       count(*)::integer,
       count(*) FILTER (WHERE applied_state='running')::integer,
       count(*) FILTER (WHERE applied_state='stopped')::integer,
       count(*) FILTER (WHERE applied_state='failed')::integer,
       count(*) FILTER (WHERE convergence_status='pending')::integer,
       max(updated_at)
FROM application_instances
WHERE NOT delete_requested
GROUP BY COALESCE(NULLIF(catalog_slug,''),'custom'),runtime
ORDER BY slug,runtime`)
	if err != nil {
		return nil, fmt.Errorf("list application catalog inventory: %w", err)
	}
	defer rows.Close()
	var inventory []types.ApplicationCatalogInventory
	for rows.Next() {
		var item types.ApplicationCatalogInventory
		if err := rows.Scan(
			&item.Slug, &item.Runtime, &item.Instances, &item.Running,
			&item.Stopped, &item.Failed, &item.PendingConvergence, &item.LastChangedAt,
		); err != nil {
			return nil, fmt.Errorf("scan application catalog inventory: %w", err)
		}
		inventory = append(inventory, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list application catalog inventory rows: %w", err)
	}
	return inventory, nil
}

func (m *Manager) OperationStatus(ctx context.Context, operationID string) (Operation, error) {
	if m == nil || m.store == nil {
		return Operation{}, errors.New("server operation status is unavailable")
	}
	return m.store.GetOperation(ctx, operationID)
}

type ApplyUpdatesWorker struct {
	river.WorkerDefaults[ApplyUpdatesArgs]
	manager *Manager
}

func NewApplyUpdatesWorker(manager *Manager) *ApplyUpdatesWorker {
	return &ApplyUpdatesWorker{manager: manager}
}

func (w *ApplyUpdatesWorker) Work(ctx context.Context, job *river.Job[ApplyUpdatesArgs]) error {
	if w.manager == nil || w.manager.store == nil {
		return errors.New("managed update worker is not configured")
	}
	agent, ok := any(w.manager.agent).(updateAgent)
	if !ok {
		return errors.New("managed update worker is not configured")
	}
	operation, err := w.manager.beginOperation(ctx, job.Args.OperationID)
	if err != nil || operation.Status == OperationSucceeded || operation.Status == OperationFailed ||
		operation.Status == OperationRolledBack || operation.Status == OperationCancelled {
		return err
	}
	var request types.ApplyUpdatesReq
	if err := json.Unmarshal(operation.Request, &request); err != nil {
		return fmt.Errorf("decode managed update operation: %w", err)
	}
	request.OperationID = operation.OperationID
	result, workErr := agent.ApplyUpdates(ctx, request)
	return w.manager.finishOperation(ctx, operation, result, workErr, "server.updates", "server_updates")
}

type HostPowerWorker struct {
	river.WorkerDefaults[HostPowerArgs]
	manager *Manager
}

func NewHostPowerWorker(manager *Manager) *HostPowerWorker {
	return &HostPowerWorker{manager: manager}
}

func (w *HostPowerWorker) Work(ctx context.Context, job *river.Job[HostPowerArgs]) error {
	if w.manager == nil || w.manager.store == nil {
		return errors.New("host power worker is not configured")
	}
	agent, ok := any(w.manager.agent).(hostPowerAgent)
	if !ok {
		return errors.New("host power worker is not configured")
	}
	operation, err := w.manager.beginOperation(ctx, job.Args.OperationID)
	if err != nil || operation.Status == OperationSucceeded || operation.Status == OperationFailed {
		return err
	}
	var request types.HostPowerReq
	if err := json.Unmarshal(operation.Request, &request); err != nil {
		return fmt.Errorf("decode host power operation: %w", err)
	}
	request.OperationID = operation.OperationID
	result, workErr := agent.ControlHostPower(ctx, request)
	return w.manager.finishOperation(ctx, operation, result, workErr, "server.host_"+request.Action, "server_host")
}

func (m *Manager) beginOperation(ctx context.Context, operationID string) (Operation, error) {
	operation, err := m.store.GetOperation(ctx, operationID)
	if err != nil {
		return Operation{}, fmt.Errorf("load server operation: %w", err)
	}
	if operation.Status == OperationSucceeded || operation.Status == OperationFailed {
		return operation, nil
	}
	_, err = m.store.UpdateOperation(ctx, UpdateOperationParams{
		OperationID: operation.OperationID,
		Status:      OperationRunning,
		Result:      json.RawMessage(`{}`),
		StartedAt:   operation.StartedAt,
	})
	if err != nil {
		return Operation{}, fmt.Errorf("mark server operation running: %w", err)
	}
	return operation, nil
}

func (m *Manager) finishOperation(ctx context.Context, operation Operation, result any, workErr error, auditPrefix, auditTarget string) error {
	status := OperationSucceeded
	suffix := "_succeeded"
	lastError := ""
	if workErr != nil {
		status = OperationFailed
		suffix = "_failed"
		lastError = workErr.Error()
	}
	payload, err := json.Marshal(result)
	if err != nil {
		payload = json.RawMessage(`{}`)
	}
	if len(payload) == 0 || string(payload) == "null" {
		payload = json.RawMessage(`{}`)
	}
	_, finishErr := m.store.FinishOperation(ctx, FinishOperationParams{
		UpdateOperationParams: UpdateOperationParams{
			OperationID: operation.OperationID,
			Status:      status,
			Result:      payload,
			LastError:   lastError,
			StartedAt:   sql.NullTime{Time: m.now(), Valid: true},
			CompletedAt: sql.NullTime{Time: m.now(), Valid: true},
		},
		AuditAction: auditPrefix + suffix,
		AuditTarget: auditTarget,
		AuditData: mustJSONObject(map[string]any{
			"operation_id": operation.OperationID,
			"action":       operation.Action,
		}),
	})
	if finishErr != nil {
		if workErr != nil {
			return fmt.Errorf("%w (record operation failure: %v)", workErr, finishErr)
		}
		return fmt.Errorf("finish server operation: %w", finishErr)
	}
	if workErr != nil {
		return fmt.Errorf("%s: %w", strings.ReplaceAll(operation.Action, "_", " "), workErr)
	}
	return nil
}
