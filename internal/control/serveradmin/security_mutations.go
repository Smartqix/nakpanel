package serveradmin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

// Panel-side mutation paths for the production security surface: fail2ban
// policy apply (queued, direct-rollback on the agent), ban listing/unbanning
// (direct reads/small mutations), and the staged firewall lifecycle
// (queued stage, synchronous confirm/revert so the confirmation window is
// never missed behind the single-worker system queue).

type fail2banAgent interface {
	ApplyFail2BanPolicy(context.Context, types.ApplyFail2BanPolicyReq) (types.ApplyFail2BanPolicyResult, error)
	ListSecurityBans(context.Context) (types.SecurityBansResult, error)
	UnbanSecurityAddress(context.Context, types.UnbanSecurityAddressReq) (types.UnbanSecurityAddressResult, error)
}

type ApplyFail2BanArgs struct {
	OperationID string `json:"operation_id" river:"unique"`
}

func (ApplyFail2BanArgs) Kind() string { return "system_apply_fail2ban" }

func (ApplyFail2BanArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       SystemQueue,
		MaxAttempts: 1,
		UniqueOpts:  river.UniqueOpts{ByArgs: true, ByState: activeJobStates},
	}
}

type StageFirewallArgs struct {
	OperationID string `json:"operation_id" river:"unique"`
}

func (StageFirewallArgs) Kind() string { return "system_stage_firewall" }

func (StageFirewallArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       SystemQueue,
		MaxAttempts: 1,
		UniqueOpts:  river.UniqueOpts{ByArgs: true, ByState: activeJobStates},
	}
}

func (m *Manager) ListSecurityBans(ctx context.Context) (types.SecurityBansResult, error) {
	if m == nil {
		return types.SecurityBansResult{}, errors.New("security manager is not configured")
	}
	agent, ok := any(m.agent).(fail2banAgent)
	if !ok {
		return types.SecurityBansResult{}, errors.New("fail2ban agent is not configured")
	}
	return agent.ListSecurityBans(ctx)
}

func (m *Manager) UnbanSecurityAddress(ctx context.Context, req types.UnbanSecurityAddressReq, actorUserID int64) (types.UnbanSecurityAddressResult, error) {
	if m == nil || m.store == nil {
		return types.UnbanSecurityAddressResult{}, errors.New("security manager is not configured")
	}
	agent, ok := any(m.agent).(fail2banAgent)
	if !ok {
		return types.UnbanSecurityAddressResult{}, errors.New("fail2ban agent is not configured")
	}
	result, err := agent.UnbanSecurityAddress(ctx, req)
	if err != nil {
		return result, err
	}
	tx, err := m.store.db.BeginTx(ctx, nil)
	if err != nil {
		return result, nil
	}
	defer func() { _ = tx.Rollback() }()
	if err := backupAudit(ctx, tx, actorUserID, "", "security.address_unbanned", "server_security",
		mustJSONObject(map[string]any{"jail": req.JailID, "address": req.Address, "unbanned": result.Unbanned})); err == nil {
		_ = tx.Commit()
	}
	return result, nil
}

func (m *Manager) ApplyFail2Ban(ctx context.Context, req types.ApplyFail2BanPolicyReq, actorUserID int64) error {
	if m == nil || m.store == nil || m.river == nil {
		return errors.New("fail2ban queue is not configured")
	}
	if actorUserID <= 0 {
		return errors.New("fail2ban actor is required")
	}
	if _, ok := any(m.agent).(fail2banAgent); !ok {
		return errors.New("fail2ban agent is not configured")
	}
	return m.queueOperation(ctx, CreateOperationParams{
		OperationID:    req.OperationID,
		Category:       CategoryServerManagement,
		Action:         "apply_fail2ban",
		TargetType:     "server_security",
		TargetKey:      "fail2ban",
		IdempotencyKey: req.OperationID,
		ActorUserID:    actorUserID,
	}, req, ApplyFail2BanArgs{OperationID: req.OperationID})
}

func (m *Manager) StageFirewall(ctx context.Context, req types.StageServerSecurityReq, actorUserID int64) error {
	if m == nil || m.store == nil || m.river == nil {
		return errors.New("firewall queue is not configured")
	}
	if actorUserID <= 0 {
		return errors.New("firewall actor is required")
	}
	if _, ok := any(m.agent).(SecurityAgent); !ok {
		return errors.New("server security agent is not configured")
	}
	if req.Scope != "firewall" {
		return errors.New("only the managed firewall scope can be staged")
	}
	return m.queueOperation(ctx, CreateOperationParams{
		OperationID:    req.OperationID,
		Category:       CategoryServerManagement,
		Action:         "stage_firewall",
		TargetType:     "server_security",
		TargetKey:      "firewall",
		IdempotencyKey: req.OperationID,
		ActorUserID:    actorUserID,
	}, req, StageFirewallArgs{OperationID: req.OperationID})
}

// ConfirmSecurityOperation and RevertSecurityOperation call the agent
// synchronously: a confirm queued behind the single-worker system queue could
// miss the agent's rollback deadline.
func (m *Manager) ConfirmSecurityOperation(ctx context.Context, operationID string, actorUserID int64) (types.StagedSecurityResult, error) {
	if m == nil || m.store == nil {
		return types.StagedSecurityResult{}, errors.New("security manager is not configured")
	}
	agent, ok := any(m.agent).(SecurityAgent)
	if !ok {
		return types.StagedSecurityResult{}, errors.New("server security agent is not configured")
	}
	result, err := agent.ConfirmServerSecurity(ctx, operationID)
	status := OperationSucceeded
	auditAction := "server.security_confirmed"
	lastError := ""
	if err != nil {
		status = OperationFailed
		auditAction = "server.security_confirm_failed"
		lastError = err.Error()
	}
	m.finishSecurityOperation(ctx, operationID, status, auditAction, lastError, result, actorUserID)
	return result, err
}

func (m *Manager) RevertSecurityOperation(ctx context.Context, operationID string, actorUserID int64) (types.StagedSecurityResult, error) {
	if m == nil || m.store == nil {
		return types.StagedSecurityResult{}, errors.New("security manager is not configured")
	}
	agent, ok := any(m.agent).(SecurityAgent)
	if !ok {
		return types.StagedSecurityResult{}, errors.New("server security agent is not configured")
	}
	result, err := agent.RevertServerSecurity(ctx, operationID)
	status := OperationRolledBack
	auditAction := "server.security_reverted"
	lastError := ""
	if err != nil {
		status = OperationFailed
		auditAction = "server.security_revert_failed"
		lastError = err.Error()
	}
	m.finishSecurityOperation(ctx, operationID, status, auditAction, lastError, result, actorUserID)
	return result, err
}

func (m *Manager) finishSecurityOperation(ctx context.Context, operationID string, status OperationStatus, auditAction, lastError string, result any, actorUserID int64) {
	if m == nil || m.store == nil {
		return
	}
	payload, err := json.Marshal(result)
	if err != nil || len(payload) == 0 || string(payload) == "null" {
		payload = json.RawMessage(`{}`)
	}
	operation, err := m.store.GetOperation(ctx, operationID)
	if err != nil {
		return
	}
	_, _ = m.store.FinishOperation(ctx, FinishOperationParams{
		UpdateOperationParams: UpdateOperationParams{
			OperationID:          operationID,
			Status:               status,
			Result:               payload,
			LastError:            lastError,
			StartedAt:            operation.StartedAt,
			CompletedAt:          sql.NullTime{Time: m.now(), Valid: true},
			ConfirmationDeadline: operation.ConfirmationDeadline,
		},
		AuditAction: auditAction,
		AuditTarget: "server_security",
		AuditData:   mustJSONObject(map[string]any{"operation_id": operationID, "actor_user_id": actorUserID}),
	})
}

type ApplyFail2BanWorker struct {
	river.WorkerDefaults[ApplyFail2BanArgs]
	manager *Manager
}

func NewApplyFail2BanWorker(manager *Manager) *ApplyFail2BanWorker {
	return &ApplyFail2BanWorker{manager: manager}
}

func (w *ApplyFail2BanWorker) Work(ctx context.Context, job *river.Job[ApplyFail2BanArgs]) error {
	if w.manager == nil || w.manager.store == nil {
		return errors.New("fail2ban worker is not configured")
	}
	agent, ok := any(w.manager.agent).(fail2banAgent)
	if !ok {
		return errors.New("fail2ban worker is not configured")
	}
	operation, err := w.manager.beginOperation(ctx, job.Args.OperationID)
	if err != nil || operation.Status == OperationSucceeded || operation.Status == OperationFailed {
		return err
	}
	var request types.ApplyFail2BanPolicyReq
	if err := json.Unmarshal(operation.Request, &request); err != nil {
		return fmt.Errorf("decode fail2ban operation: %w", err)
	}
	request.OperationID = operation.OperationID
	result, workErr := agent.ApplyFail2BanPolicy(ctx, request)
	return w.manager.finishOperation(ctx, operation, result, workErr, "server.fail2ban", "server_security")
}

type StageFirewallWorker struct {
	river.WorkerDefaults[StageFirewallArgs]
	manager *Manager
}

func NewStageFirewallWorker(manager *Manager) *StageFirewallWorker {
	return &StageFirewallWorker{manager: manager}
}

func (w *StageFirewallWorker) Work(ctx context.Context, job *river.Job[StageFirewallArgs]) error {
	if w.manager == nil || w.manager.store == nil {
		return errors.New("firewall worker is not configured")
	}
	agent, ok := any(w.manager.agent).(SecurityAgent)
	if !ok {
		return errors.New("firewall worker is not configured")
	}
	operation, err := w.manager.beginOperation(ctx, job.Args.OperationID)
	if err != nil || operation.Status == OperationSucceeded || operation.Status == OperationFailed ||
		operation.Status == OperationRolledBack || operation.Status == OperationCancelled {
		return err
	}
	var request types.StageServerSecurityReq
	if err := json.Unmarshal(operation.Request, &request); err != nil {
		return fmt.Errorf("decode firewall stage operation: %w", err)
	}
	request.OperationID = operation.OperationID
	result, workErr := agent.StageServerSecurity(ctx, request)
	if workErr != nil {
		return w.manager.finishOperation(ctx, operation, result, workErr, "server.firewall_stage", "server_security")
	}
	payload, err := json.Marshal(result)
	if err != nil {
		payload = json.RawMessage(`{}`)
	}
	if _, err := w.manager.store.UpdateOperation(ctx, UpdateOperationParams{
		OperationID:          operation.OperationID,
		Status:               OperationAwaitingConfirmation,
		Result:               payload,
		StartedAt:            sql.NullTime{Time: w.manager.now(), Valid: true},
		ConfirmationDeadline: sql.NullTime{Time: result.RollbackDeadline, Valid: !result.RollbackDeadline.IsZero()},
	}); err != nil {
		return fmt.Errorf("mark firewall stage awaiting confirmation: %w", err)
	}
	return nil
}
