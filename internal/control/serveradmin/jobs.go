package serveradmin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

const SystemQueue = "system"

var ErrInventoryCacheFallback = errors.New("live server inventory is unavailable; using cached inventory")

var activeJobStates = []rivertype.JobState{
	rivertype.JobStateAvailable,
	rivertype.JobStatePending,
	rivertype.JobStateRetryable,
	rivertype.JobStateRunning,
	rivertype.JobStateScheduled,
}

type Agent interface {
	InspectServer(context.Context) (types.ServerInventory, error)
	ControlManagedService(context.Context, types.ControlManagedServiceReq) (types.ControlManagedServiceResult, error)
}

type SecurityAgent interface {
	InspectServerSecurity(context.Context) (types.ServerSecurityPolicy, error)
	StageServerSecurity(context.Context, types.StageServerSecurityReq) (types.StagedSecurityResult, error)
	ConfirmServerSecurity(context.Context, string) (types.StagedSecurityResult, error)
	RevertServerSecurity(context.Context, string) (types.StagedSecurityResult, error)
}

type riverInserter interface {
	InsertTx(context.Context, *sql.Tx, river.JobArgs, *river.InsertOpts) (*rivertype.JobInsertResult, error)
}

type RefreshInventoryArgs struct{}

func (RefreshInventoryArgs) Kind() string { return "system_refresh_inventory" }

func (RefreshInventoryArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: SystemQueue,
		UniqueOpts: river.UniqueOpts{
			ByArgs:  true,
			ByState: activeJobStates,
		},
	}
}

type ControlServiceArgs struct {
	OperationID string `json:"operation_id" river:"unique"`
}

func (ControlServiceArgs) Kind() string { return "system_control_service" }

func (ControlServiceArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: SystemQueue,
		// Service actions are not generally replay-safe if the agent response is
		// lost after systemctl succeeds. Surface a terminal result and let the
		// operator explicitly retry after inspecting current state.
		MaxAttempts: 1,
		UniqueOpts: river.UniqueOpts{
			ByArgs:  true,
			ByState: activeJobStates,
		},
	}
}

type Manager struct {
	store *Store
	river riverInserter
	agent Agent
	now   func() time.Time
}

func NewManager(store *Store, client *river.Client[*sql.Tx], agent Agent) *Manager {
	return &Manager{store: store, river: client, agent: agent, now: time.Now}
}

func (m *Manager) SetRiverClient(client *river.Client[*sql.Tx]) {
	m.river = client
}

func (m *Manager) Store() *Store {
	if m == nil {
		return nil
	}
	return m.store
}

// InspectServer is a bounded read-only operation. It refreshes the durable
// cache so later health views can distinguish fresh state from stale state.
func (m *Manager) InspectServer(ctx context.Context) (types.ServerInventory, error) {
	if m == nil || m.agent == nil || m.store == nil {
		return types.ServerInventory{}, errors.New("server inventory agent is not configured")
	}
	inventory, err := m.agent.InspectServer(ctx)
	if err != nil {
		cached, cacheErr := m.cachedServerInventory(ctx)
		if cacheErr != nil {
			return types.ServerInventory{}, fmt.Errorf("inspect server: %w (cached inventory unavailable: %v)", err, cacheErr)
		}
		cached.Status = types.ServerStateUnknown
		cached.LastError = "Live inspection failed; showing cached inventory."
		return cached, fmt.Errorf("%w: %v", ErrInventoryCacheFallback, err)
	}
	if err := m.persistInventory(ctx, inventory); err != nil {
		return inventory, fmt.Errorf("persist server inventory: %w", err)
	}
	return inventory, nil
}

func (m *Manager) ControlManagedService(ctx context.Context, req types.ControlManagedServiceReq) (types.ControlManagedServiceResult, error) {
	if m == nil || m.store == nil || m.river == nil {
		return types.ControlManagedServiceResult{}, errors.New("server operation queue is not configured")
	}
	if req.ActorUserID <= 0 {
		return types.ControlManagedServiceResult{}, errors.New("server operation actor is required")
	}
	request, err := json.Marshal(req)
	if err != nil {
		return types.ControlManagedServiceResult{}, fmt.Errorf("encode managed service operation: %w", err)
	}
	tx, err := m.store.db.BeginTx(ctx, nil)
	if err != nil {
		return types.ControlManagedServiceResult{}, fmt.Errorf("begin managed service operation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := m.store.CreateOperationTx(ctx, tx, CreateOperationParams{
		OperationID:    req.OperationID,
		Category:       "services",
		Action:         req.Action,
		TargetType:     "server_service",
		TargetKey:      req.ServiceID,
		Request:        request,
		IdempotencyKey: req.OperationID,
		ActorUserID:    req.ActorUserID,
	}); err != nil {
		return types.ControlManagedServiceResult{}, fmt.Errorf("persist managed service operation: %w", err)
	}
	if err := m.store.RecordOperationRequestTx(ctx, tx, req.ActorUserID,
		"server.service_"+req.Action+"_requested", "server_service",
		mustJSONObject(map[string]any{"operation_id": req.OperationID, "service_id": req.ServiceID})); err != nil {
		return types.ControlManagedServiceResult{}, fmt.Errorf("record managed service request: %w", err)
	}
	if _, err := m.river.InsertTx(ctx, tx, ControlServiceArgs{OperationID: req.OperationID}, nil); err != nil {
		return types.ControlManagedServiceResult{}, fmt.Errorf("queue managed service operation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return types.ControlManagedServiceResult{}, fmt.Errorf("commit managed service operation: %w", err)
	}
	return types.ControlManagedServiceResult{
		OperationID: req.OperationID,
		ServiceID:   req.ServiceID,
		Action:      req.Action,
		Validation:  "queued",
	}, nil
}

func (m *Manager) InspectServerSecurity(ctx context.Context) (types.ServerSecurityPolicy, error) {
	if m == nil || m.agent == nil {
		return types.ServerSecurityPolicy{}, errors.New("server security agent is not configured")
	}
	agent, ok := m.agent.(SecurityAgent)
	if !ok {
		return types.ServerSecurityPolicy{}, errors.New("server security agent is not configured")
	}
	return agent.InspectServerSecurity(ctx)
}

func (m *Manager) persistInventory(ctx context.Context, inventory types.ServerInventory) error {
	payload, err := json.Marshal(inventory)
	if err != nil {
		return fmt.Errorf("encode server inventory: %w", err)
	}
	checkedAt := inventory.CheckedAt
	if checkedAt.IsZero() {
		checkedAt = m.now().UTC()
	}
	health := HealthUnknown
	switch inventory.Status {
	case types.ServerStateHealthy:
		health = HealthHealthy
	case types.ServerStateWarning:
		health = HealthWarning
	case types.ServerStateCritical:
		health = HealthCritical
	case types.ServerStateUnavailable:
		health = HealthUnavailable
	}
	if _, err := m.store.UpsertInventory(ctx, UpsertInventoryParams{
		Kind:         "server",
		ResourceKey:  "host",
		HealthStatus: health,
		Payload:      payload,
		LastError:    inventory.LastError,
		CheckedAt:    checkedAt,
		ExpiresAt:    checkedAt.Add(2 * time.Minute),
	}); err != nil {
		return err
	}
	return nil
}

func (m *Manager) cachedServerInventory(ctx context.Context) (types.ServerInventory, error) {
	item, err := m.store.GetInventory(ctx, "server", "host")
	if err != nil {
		return types.ServerInventory{}, err
	}
	var inventory types.ServerInventory
	if err := json.Unmarshal(item.Payload, &inventory); err != nil {
		return types.ServerInventory{}, fmt.Errorf("decode cached server inventory: %w", err)
	}
	if inventory.CheckedAt.IsZero() {
		inventory.CheckedAt = item.CheckedAt
	}
	return inventory, nil
}

type RefreshInventoryWorker struct {
	river.WorkerDefaults[RefreshInventoryArgs]
	manager *Manager
}

func NewRefreshInventoryWorker(manager *Manager) *RefreshInventoryWorker {
	return &RefreshInventoryWorker{manager: manager}
}

func (w *RefreshInventoryWorker) Work(ctx context.Context, _ *river.Job[RefreshInventoryArgs]) error {
	_, err := w.manager.InspectServer(ctx)
	return err
}

type ControlServiceWorker struct {
	river.WorkerDefaults[ControlServiceArgs]
	manager *Manager
}

func NewControlServiceWorker(manager *Manager) *ControlServiceWorker {
	return &ControlServiceWorker{manager: manager}
}

func (w *ControlServiceWorker) Work(ctx context.Context, job *river.Job[ControlServiceArgs]) (err error) {
	if w.manager == nil || w.manager.store == nil || w.manager.agent == nil {
		return errors.New("managed service worker is not configured")
	}
	operation, err := w.manager.store.GetOperation(ctx, job.Args.OperationID)
	if err != nil {
		return fmt.Errorf("load managed service operation: %w", err)
	}
	switch operation.Status {
	case OperationSucceeded, OperationFailed, OperationRolledBack, OperationCancelled:
		return nil
	}
	var request types.ControlManagedServiceReq
	if err := json.Unmarshal(operation.Request, &request); err != nil {
		return fmt.Errorf("decode managed service operation: %w", err)
	}
	request.OperationID = operation.OperationID
	startedAt := w.manager.now()
	if _, err := w.manager.store.UpdateOperation(ctx, UpdateOperationParams{
		OperationID: operation.OperationID,
		Status:      OperationRunning,
		Result:      json.RawMessage(`{}`),
		StartedAt:   sql.NullTime{Time: startedAt, Valid: true},
	}); err != nil {
		return fmt.Errorf("mark managed service operation running: %w", err)
	}

	result, err := w.manager.agent.ControlManagedService(ctx, request)
	if err != nil {
		_, finishErr := w.manager.store.FinishOperation(ctx, FinishOperationParams{
			UpdateOperationParams: UpdateOperationParams{
				OperationID: operation.OperationID,
				Status:      OperationFailed,
				Result:      json.RawMessage(`{}`),
				LastError:   err.Error(),
				StartedAt:   sql.NullTime{Time: startedAt, Valid: true},
				CompletedAt: sql.NullTime{Time: w.manager.now(), Valid: true},
			},
			AuditAction: "server.service_" + request.Action + "_failed",
			AuditTarget: "server_service",
			AuditData: mustJSONObject(map[string]any{
				"operation_id": operation.OperationID,
				"service_id":   request.ServiceID,
			}),
		})
		if finishErr != nil {
			return fmt.Errorf("%w (record terminal failure: %v)", err, finishErr)
		}
		return err
	}
	payload, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return fmt.Errorf("encode managed service result: %w", marshalErr)
	}
	_, err = w.manager.store.FinishOperation(ctx, FinishOperationParams{
		UpdateOperationParams: UpdateOperationParams{
			OperationID: operation.OperationID,
			Status:      OperationSucceeded,
			Result:      payload,
			StartedAt:   sql.NullTime{Time: startedAt, Valid: true},
			CompletedAt: sql.NullTime{Time: w.manager.now(), Valid: true},
		},
		AuditAction: "server.service_" + request.Action + "_succeeded",
		AuditTarget: "server_service",
		AuditData: mustJSONObject(map[string]any{
			"operation_id": operation.OperationID,
			"service_id":   request.ServiceID,
			"changed":      result.Changed,
		}),
	})
	if err != nil {
		return fmt.Errorf("complete managed service operation: %w", err)
	}
	return nil
}

func mustJSONObject(value map[string]any) json.RawMessage {
	payload, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return payload
}
