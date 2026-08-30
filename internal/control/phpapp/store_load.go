package phpapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/nakroteck/nakpanel/internal/types"
)

const deploymentSelect = `SELECT deployment.id,deployment.subscription_id,deployment.application_id,
COALESCE(deployment.requested_by_user_id,0),deployment.requested_revision,deployment.resolved_revision,
deployment.release_number,COALESCE(deployment.previous_deployment_id,0),deployment.status,
deployment.health_message,deployment.last_error,deployment.composer_audit,deployment.started_at,
deployment.finished_at,deployment.created_at FROM php_deployments deployment `

func scanDeployment(row interface{ Scan(...any) error }) (types.PHPDeployment, error) {
	var deployment types.PHPDeployment
	var audit []byte
	var started, finished sql.NullTime
	err := row.Scan(&deployment.ID, &deployment.SubscriptionID, &deployment.ApplicationID,
		&deployment.RequestedByUserID, &deployment.RequestedRevision, &deployment.ResolvedRevision,
		&deployment.ReleaseNumber, &deployment.PreviousDeploymentID, &deployment.Status,
		&deployment.HealthMessage, &deployment.LastError, &audit, &started, &finished, &deployment.CreatedAt)
	if err != nil {
		return deployment, err
	}
	deployment.ComposerAudit = string(audit)
	if started.Valid {
		deployment.StartedAt = started.Time
	}
	if finished.Valid {
		deployment.FinishedAt = finished.Time
	}
	return deployment, nil
}

func loadDeploymentsTx(ctx context.Context, tx *sql.Tx, applicationID int64, limit int) ([]types.PHPDeployment, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	rows, err := tx.QueryContext(ctx, deploymentSelect+` WHERE deployment.application_id=$1 ORDER BY deployment.release_number DESC LIMIT $2`, applicationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]types.PHPDeployment, 0)
	for rows.Next() {
		item, err := scanDeployment(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func loadEnvironmentMetadataTx(ctx context.Context, tx *sql.Tx, applicationID int64) ([]types.PHPEnvironmentVariable, error) {
	rows, err := tx.QueryContext(ctx, `SELECT binding.id,binding.application_id,binding.name,
COALESCE(binding.plain_value,''),COALESCE(binding.secret_id,0),binding.updated_at
FROM php_environment_bindings binding WHERE binding.application_id=$1 ORDER BY binding.name`, applicationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]types.PHPEnvironmentVariable, 0)
	for rows.Next() {
		var item types.PHPEnvironmentVariable
		if err := rows.Scan(&item.ID, &item.ApplicationID, &item.Name, &item.Value, &item.SecretID, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if item.SecretID > 0 {
			item.Value = ""
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func loadWorkersTx(ctx context.Context, tx *sql.Tx, applicationID int64) ([]types.PHPWorker, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,subscription_id,application_id,name,script,arguments,processes,
desired_state,observed_state,desired_revision,applied_revision,convergence_status,last_error,updated_at
FROM php_workers WHERE application_id=$1 ORDER BY name,id`, applicationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]types.PHPWorker, 0)
	for rows.Next() {
		var item types.PHPWorker
		var arguments []byte
		if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.ApplicationID, &item.Name, &item.Script,
			&arguments, &item.Processes, &item.DesiredState, &item.ObservedState, &item.DesiredRevision,
			&item.AppliedRevision, &item.ConvergenceStatus, &item.LastError, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(arguments, &item.Arguments); err != nil {
			return nil, fmt.Errorf("decode PHP worker arguments: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func loadWorkerSpecsTx(ctx context.Context, tx *sql.Tx, applicationID int64) ([]types.PHPWorkerSpec, error) {
	workers, err := loadWorkersTx(ctx, tx, applicationID)
	if err != nil {
		return nil, err
	}
	items := make([]types.PHPWorkerSpec, 0, len(workers))
	for _, worker := range workers {
		items = append(items, types.PHPWorkerSpec{WorkerID: worker.ID, Name: worker.Name, Script: worker.Script,
			Arguments: append([]string(nil), worker.Arguments...), Processes: worker.Processes, DesiredState: worker.DesiredState})
	}
	return items, nil
}
