package databaseadmin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

var activeMutationStates = []rivertype.JobState{
	rivertype.JobStateAvailable,
	rivertype.JobStatePending,
	rivertype.JobStateRetryable,
	rivertype.JobStateRunning,
	rivertype.JobStateScheduled,
}

type MutationArgs struct {
	OperationID string `json:"operation_id"`
	DatabaseID  int64  `json:"database_id" river:"unique"`
}

func (MutationArgs) Kind() string { return "system_database_mutation" }

func (MutationArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       serveradmin.SystemQueue,
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs:  true,
			ByState: activeMutationStates,
		},
	}
}

type MutationWorker struct {
	river.WorkerDefaults[MutationArgs]
	manager *Manager
	now     func() time.Time
}

func NewMutationWorker(manager *Manager) *MutationWorker {
	return &MutationWorker{manager: manager, now: time.Now}
}

func (w *MutationWorker) Work(ctx context.Context, job *river.Job[MutationArgs]) error {
	if w == nil || w.manager == nil || w.manager.db == nil || w.manager.agent == nil || w.manager.secrets == nil {
		return errors.New("database administration worker is not configured")
	}
	operation, err := w.manager.secrets.GetOperation(ctx, job.Args.OperationID)
	if err != nil {
		return fmt.Errorf("load database administration operation: %w", err)
	}
	switch operation.Status {
	case serveradmin.OperationSucceeded, serveradmin.OperationFailed,
		serveradmin.OperationRolledBack, serveradmin.OperationCancelled:
		return nil
	}
	var request mutationRequest
	if err := json.Unmarshal(operation.Request, &request); err != nil {
		return fmt.Errorf("decode database administration operation: %w", err)
	}
	if request.Target.DatabaseID != job.Args.DatabaseID ||
		operation.TargetKey != strconv.FormatInt(job.Args.DatabaseID, 10) {
		return errors.New("database administration operation target mismatch")
	}
	startedAt := w.now().UTC()
	if _, err := w.manager.secrets.UpdateOperation(ctx, serveradmin.UpdateOperationParams{
		OperationID: operation.OperationID, Status: serveradmin.OperationRunning,
		Result: json.RawMessage(`{}`), StartedAt: sql.NullTime{Time: startedAt, Valid: true},
	}); err != nil {
		return fmt.Errorf("mark database administration operation running: %w", err)
	}

	agentRequest := types.ManageDatabaseAdminReq{
		OperationID: operation.OperationID, Action: request.Action,
		Target: request.Target, Role: request.Role,
	}
	var plaintext []byte
	if request.Action == types.DatabaseAdminRotatePassword {
		if request.CredentialScope != pendingSecretScope || request.CredentialName == "" {
			return w.failOrRetry(ctx, job, operation, request, startedAt, errors.New("staged database credential reference is invalid"))
		}
		plaintext, _, err = w.manager.secrets.GetSecret(ctx, request.CredentialScope, request.CredentialName)
		if err != nil {
			return w.failOrRetry(ctx, job, operation, request, startedAt, fmt.Errorf("resolve staged database credential: %w", err))
		}
		defer clear(plaintext)
		agentRequest.Password = string(plaintext)
	}

	result, err := w.manager.agent.ManageDatabaseAdmin(ctx, agentRequest)
	agentRequest.Password = ""
	if err != nil {
		return w.failOrRetry(ctx, job, operation, request, startedAt, err)
	}
	result.OperationID = operation.OperationID
	result.Status = "succeeded"
	if err := w.finish(ctx, operation, request, result, plaintext, serveradmin.OperationSucceeded, ""); err != nil {
		return fmt.Errorf("finish database administration operation: %w", err)
	}
	return nil
}

func (w *MutationWorker) failOrRetry(
	ctx context.Context,
	job *river.Job[MutationArgs],
	operation serveradmin.Operation,
	request mutationRequest,
	startedAt time.Time,
	failure error,
) error {
	terminal := job.JobRow != nil && job.JobRow.Attempt >= job.JobRow.MaxAttempts
	if terminal {
		result := types.ManageDatabaseAdminResult{
			OperationID: operation.OperationID, DatabaseID: request.Target.DatabaseID,
			Action: request.Action, Role: request.Role, Status: "failed",
		}
		if err := w.finish(ctx, operation, request, result, nil, serveradmin.OperationFailed,
			"Database administration operation failed."); err != nil {
			return fmt.Errorf("%w (record terminal database failure: %v)", failure, err)
		}
		return failure
	}
	if _, err := w.manager.secrets.UpdateOperation(ctx, serveradmin.UpdateOperationParams{
		OperationID: operation.OperationID, Status: serveradmin.OperationPending,
		Result: json.RawMessage(`{}`), LastError: "Database administration operation will be retried.",
		StartedAt: sql.NullTime{Time: startedAt, Valid: true},
	}); err != nil {
		return fmt.Errorf("%w (persist database retry state: %v)", failure, err)
	}
	return failure
}

func (w *MutationWorker) finish(
	ctx context.Context,
	operation serveradmin.Operation,
	request mutationRequest,
	result types.ManageDatabaseAdminResult,
	plaintext []byte,
	status serveradmin.OperationStatus,
	lastError string,
) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode database administration result: %w", err)
	}
	tx, err := w.manager.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin database administration completion: %w", err)
	}
	defer tx.Rollback()

	if request.Action == types.DatabaseAdminRotatePassword {
		if status == serveradmin.OperationSucceeded {
			if len(plaintext) == 0 {
				return errors.New("successful database password rotation is missing its credential")
			}
			if _, err := w.manager.secrets.PutSecretTx(ctx, tx, serveradmin.PutSecretParams{
				Scope: canonicalSecretScope, Name: canonicalCredentialName(request.Target.DatabaseID),
				Plaintext: plaintext, ActorUserID: operation.ActorUserID,
				Metadata: mustJSON(map[string]any{"database_id": request.Target.DatabaseID}),
			}); err != nil {
				return fmt.Errorf("promote rotated database credential: %w", err)
			}
		}
		if err := w.manager.secrets.DeleteSecretTx(ctx, tx, request.CredentialScope, request.CredentialName); err != nil {
			return fmt.Errorf("scrub staged database credential: %w", err)
		}
	}
	completedAt := w.now().UTC()
	update, err := tx.ExecContext(ctx, `
UPDATE server_operations
SET status=$2,result=$3::jsonb,last_error=$4,completed_at=$5,updated_at=now()
WHERE operation_id=$1`, operation.OperationID, status, payload, lastError, completedAt)
	if err != nil {
		return fmt.Errorf("complete database administration operation: %w", err)
	}
	affected, err := update.RowsAffected()
	if err != nil || affected != 1 {
		return errors.New("database administration operation completion was not persisted")
	}
	outcome := "succeeded"
	if status == serveradmin.OperationFailed {
		outcome = "failed"
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_events(actor_user_id,action,target_type,target_id,metadata)
VALUES ($1,$2,'database',$3,$4::jsonb)`,
		operation.ActorUserID, "database."+string(request.Action)+"_"+outcome,
		request.Target.DatabaseID, mustJSON(map[string]any{
			"operation_id": operation.OperationID, "role": request.Role, "changed": result.Changed,
		})); err != nil {
		return fmt.Errorf("audit database administration outcome: %w", err)
	}
	return tx.Commit()
}

func canonicalCredentialName(databaseID int64) string {
	return "provision-" + strconv.FormatInt(databaseID, 10)
}
