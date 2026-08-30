package phpapp

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

func phpSecretScope(applicationID int64) string {
	return fmt.Sprintf("php.application.%d", applicationID)
}
func phpSecretName(name string) string {
	digest := sha256.Sum256([]byte(strings.ToUpper(name)))
	return fmt.Sprintf("env.%x", digest[:])
}

func requireExistingWorkerTx(ctx context.Context, tx *sql.Tx, applicationID, workerID int64) error {
	if workerID <= 0 {
		return ErrNotFound
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM php_workers WHERE application_id=$1 AND id=$2)`, applicationID, workerID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func configuredSubscriptionWorkerProcessesTx(ctx context.Context, tx *sql.Tx, subscriptionID, excludeWorkerID int64) (int, error) {
	var processes int
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(processes),0)::int FROM php_workers WHERE subscription_id=$1 AND id<>$2`,
		subscriptionID, excludeWorkerID).Scan(&processes)
	return processes, err
}

func (s *SQLStore) UpsertEnvironment(ctx context.Context, actorID, siteID int64, input EnvironmentInput) (types.PHPEnvironmentVariable, error) {
	input, err := validateEnvironment(input)
	if err != nil {
		return types.PHPEnvironmentVariable{}, err
	}
	tx, err := s.beginMutation(ctx)
	if err != nil {
		return types.PHPEnvironmentVariable{}, err
	}
	defer tx.Rollback()
	record, err := s.lockApplicationTx(ctx, tx, siteID)
	if err != nil {
		return types.PHPEnvironmentVariable{}, err
	}
	if err = requireManagedMutation(record); err != nil {
		return types.PHPEnvironmentVariable{}, err
	}
	var reference serveradmin.SecretReference
	plain := any(input.Value)
	secret := any(nil)
	scope, secretName := phpSecretScope(record.spec.ApplicationID), phpSecretName(input.Name)
	if input.Secret {
		if s.secrets == nil {
			return types.PHPEnvironmentVariable{}, serveradmin.ErrSecretUnavailable
		}
		reference, err = s.secrets.PutSecretTx(ctx, tx, serveradmin.PutSecretParams{
			Scope: scope, Name: secretName, Plaintext: []byte(input.Value),
			Metadata: json.RawMessage(`{"kind":"php_environment"}`), ActorUserID: actorID,
		})
		if err != nil {
			return types.PHPEnvironmentVariable{}, err
		}
		plain, secret = nil, reference.ID
	}
	var item types.PHPEnvironmentVariable
	err = tx.QueryRowContext(ctx, `INSERT INTO php_environment_bindings(subscription_id,application_id,name,plain_value,secret_id)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(application_id,name) DO UPDATE SET plain_value=EXCLUDED.plain_value,
secret_id=EXCLUDED.secret_id,desired_revision=php_environment_bindings.desired_revision+1,updated_at=now()
RETURNING id,application_id,name,COALESCE(plain_value,''),COALESCE(secret_id,0),updated_at`,
		record.spec.SubscriptionID, record.spec.ApplicationID, input.Name, plain, secret).Scan(
		&item.ID, &item.ApplicationID, &item.Name, &item.Value, &item.SecretID, &item.UpdatedAt)
	if err != nil {
		return types.PHPEnvironmentVariable{}, err
	}
	if !input.Secret && s.secrets != nil {
		if err = s.secrets.DeleteSecretTx(ctx, tx, scope, secretName); err != nil {
			return types.PHPEnvironmentVariable{}, err
		}
	}
	revision, err := s.advanceApplicationTx(ctx, tx, record.spec.ApplicationID, ReconcilePHPApplicationArgs{})
	if err != nil {
		return types.PHPEnvironmentVariable{}, err
	}
	if err = auditTx(ctx, tx, actorID, record.customerID, record.spec.SubscriptionID, "php.environment.upsert", "php_application", record.spec.ApplicationID,
		map[string]any{"name": input.Name, "secret": input.Secret, "revision": revision}); err != nil {
		return types.PHPEnvironmentVariable{}, err
	}
	if err = tx.Commit(); err != nil {
		return types.PHPEnvironmentVariable{}, err
	}
	if input.Secret {
		item.Value = ""
	}
	return item, nil
}

func (s *SQLStore) DeleteEnvironment(ctx context.Context, actorID, siteID int64, name string) error {
	input, err := validateEnvironment(EnvironmentInput{Name: name, Value: ""})
	if err != nil {
		return err
	}
	tx, err := s.beginMutation(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	record, err := s.lockApplicationTx(ctx, tx, siteID)
	if err != nil {
		return err
	}
	if err = requireManagedMutation(record); err != nil {
		return err
	}
	var secretID int64
	err = tx.QueryRowContext(ctx, `DELETE FROM php_environment_bindings WHERE application_id=$1 AND name=$2 RETURNING COALESCE(secret_id,0)`, record.spec.ApplicationID, input.Name).Scan(&secretID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if secretID > 0 && s.secrets != nil {
		if err = s.secrets.DeleteSecretTx(ctx, tx, phpSecretScope(record.spec.ApplicationID), phpSecretName(input.Name)); err != nil {
			return err
		}
	}
	revision, err := s.advanceApplicationTx(ctx, tx, record.spec.ApplicationID, ReconcilePHPApplicationArgs{})
	if err != nil {
		return err
	}
	if err = auditTx(ctx, tx, actorID, record.customerID, record.spec.SubscriptionID, "php.environment.delete", "php_application", record.spec.ApplicationID,
		map[string]any{"name": input.Name, "revision": revision}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) UpsertWorker(ctx context.Context, actorID, siteID int64, input WorkerInput) (types.PHPWorker, error) {
	tx, err := s.beginMutation(ctx)
	if err != nil {
		return types.PHPWorker{}, err
	}
	defer tx.Rollback()
	record, err := s.lockApplicationTx(ctx, tx, siteID)
	if err != nil {
		return types.PHPWorker{}, err
	}
	if err = requireManagedMutation(record); err != nil {
		return types.PHPWorker{}, err
	}
	if input.ID != 0 {
		if err = requireExistingWorkerTx(ctx, tx, record.spec.ApplicationID, input.ID); err != nil {
			return types.PHPWorker{}, err
		}
	}
	otherProcesses, err := configuredSubscriptionWorkerProcessesTx(ctx, tx, record.spec.SubscriptionID, input.ID)
	if err != nil {
		return types.PHPWorker{}, err
	}
	input, err = validateWorker(input, record.spec.Policy, otherProcesses)
	if err != nil {
		return types.PHPWorker{}, err
	}
	arguments, err := json.Marshal(input.Arguments)
	if err != nil {
		return types.PHPWorker{}, err
	}
	var worker types.PHPWorker
	var rawArguments []byte
	err = tx.QueryRowContext(ctx, `INSERT INTO php_workers(id,subscription_id,application_id,name,script,arguments,processes,desired_state)
VALUES(CASE WHEN $1=0 THEN nextval('php_workers_id_seq') ELSE $1 END,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,script=EXCLUDED.script,arguments=EXCLUDED.arguments,
processes=EXCLUDED.processes,desired_state=EXCLUDED.desired_state,desired_revision=php_workers.desired_revision+1,
convergence_status='pending',last_error='',updated_at=now()
WHERE php_workers.application_id=EXCLUDED.application_id AND php_workers.subscription_id=EXCLUDED.subscription_id
RETURNING id,subscription_id,application_id,name,script,arguments,processes,desired_state,observed_state,
desired_revision,applied_revision,convergence_status,last_error,updated_at`, input.ID, record.spec.SubscriptionID,
		record.spec.ApplicationID, input.Name, input.Script, arguments, input.Processes, input.DesiredState).Scan(
		&worker.ID, &worker.SubscriptionID, &worker.ApplicationID, &worker.Name, &worker.Script, &rawArguments,
		&worker.Processes, &worker.DesiredState, &worker.ObservedState, &worker.DesiredRevision,
		&worker.AppliedRevision, &worker.ConvergenceStatus, &worker.LastError, &worker.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return types.PHPWorker{}, ErrNotFound
	}
	if err != nil {
		return types.PHPWorker{}, err
	}
	if err = json.Unmarshal(rawArguments, &worker.Arguments); err != nil {
		return types.PHPWorker{}, err
	}
	revision, err := s.advanceApplicationTx(ctx, tx, record.spec.ApplicationID, ReconcilePHPWorkersArgs{})
	if err != nil {
		return types.PHPWorker{}, err
	}
	if err = auditTx(ctx, tx, actorID, record.customerID, record.spec.SubscriptionID, "php.worker.upsert", "php_worker", worker.ID,
		map[string]any{"application_id": record.spec.ApplicationID, "name": worker.Name, "processes": worker.Processes, "desired_state": worker.DesiredState, "revision": revision}); err != nil {
		return types.PHPWorker{}, err
	}
	if err = tx.Commit(); err != nil {
		return types.PHPWorker{}, err
	}
	return worker, nil
}

func (s *SQLStore) DeleteWorker(ctx context.Context, actorID, siteID, workerID int64) error {
	if workerID <= 0 {
		return ErrNotFound
	}
	tx, err := s.beginMutation(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	record, err := s.lockApplicationTx(ctx, tx, siteID)
	if err != nil {
		return err
	}
	if err = requireManagedMutation(record); err != nil {
		return err
	}
	var name string
	if err = tx.QueryRowContext(ctx, `DELETE FROM php_workers WHERE id=$1 AND application_id=$2 RETURNING name`, workerID, record.spec.ApplicationID).Scan(&name); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	revision, err := s.advanceApplicationTx(ctx, tx, record.spec.ApplicationID, ReconcilePHPWorkersArgs{})
	if err != nil {
		return err
	}
	if err = auditTx(ctx, tx, actorID, record.customerID, record.spec.SubscriptionID, "php.worker.delete", "php_worker", workerID,
		map[string]any{"application_id": record.spec.ApplicationID, "name": name, "revision": revision}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) SetWorkerState(ctx context.Context, actorID, siteID, workerID int64, state string) error {
	state = strings.ToLower(strings.TrimSpace(state))
	if state != "running" && state != "stopped" {
		return errors.New("worker state must be running or stopped")
	}
	tx, err := s.beginMutation(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	record, err := s.lockApplicationTx(ctx, tx, siteID)
	if err != nil {
		return err
	}
	if err = requireManagedMutation(record); err != nil {
		return err
	}
	if !record.spec.Policy.Permissions.PHPWorkers {
		return fmt.Errorf("%w: PHP workers are disabled", controlquota.ErrExceeded)
	}
	var name string
	err = tx.QueryRowContext(ctx, `UPDATE php_workers SET desired_state=$3,desired_revision=desired_revision+1,
convergence_status='pending',last_error='',updated_at=now() WHERE id=$1 AND application_id=$2 RETURNING name`, workerID, record.spec.ApplicationID, state).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	revision, err := s.advanceApplicationTx(ctx, tx, record.spec.ApplicationID, ReconcilePHPWorkersArgs{})
	if err != nil {
		return err
	}
	if err = auditTx(ctx, tx, actorID, record.customerID, record.spec.SubscriptionID, "php.worker.state", "php_worker", workerID,
		map[string]any{"application_id": record.spec.ApplicationID, "name": name, "desired_state": state, "revision": revision}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) RequestReconcile(ctx context.Context, actorID, siteID int64) error {
	tx, err := s.beginMutation(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	record, err := s.lockApplicationTx(ctx, tx, siteID)
	if err != nil {
		return err
	}
	if err = requireActive(record); err != nil {
		return err
	}
	revision, err := s.advanceApplicationTx(ctx, tx, record.spec.ApplicationID, ReconcilePHPApplicationArgs{})
	if err != nil {
		return err
	}
	if err = auditTx(ctx, tx, actorID, record.customerID, record.spec.SubscriptionID, "php.application.reconcile", "php_application", record.spec.ApplicationID,
		map[string]any{"revision": revision}); err != nil {
		return err
	}
	return tx.Commit()
}

func requireManagedMutation(record applicationRecord) error {
	if err := requireActive(record); err != nil {
		return err
	}
	if record.spec.HostingMode != types.PHPHostingModeManaged {
		return errors.New("managed PHP application is not configured")
	}
	if !record.spec.Policy.Permissions.ManagedPHPDeployments {
		return fmt.Errorf("%w: managed PHP deployments are disabled", controlquota.ErrExceeded)
	}
	return nil
}

func (s *SQLStore) advanceApplicationTx(ctx context.Context, tx *sql.Tx, applicationID int64, job river.JobArgs) (int64, error) {
	if err := supersedeDeploymentIntentsTx(ctx, tx, applicationID); err != nil {
		return 0, err
	}
	var revision int64
	if err := tx.QueryRowContext(ctx, `UPDATE php_applications SET desired_revision=desired_revision+1,
convergence_status='pending',last_error='',updated_at=now() WHERE id=$1 RETURNING desired_revision`, applicationID).Scan(&revision); err != nil {
		return 0, err
	}
	switch value := job.(type) {
	case ReconcilePHPApplicationArgs:
		value.ApplicationID, value.DesiredRevision = applicationID, revision
		job = value
	case ReconcilePHPWorkersArgs:
		value.ApplicationID, value.DesiredRevision = applicationID, revision
		job = value
	default:
		return 0, errors.New("unsupported PHP reconciliation job")
	}
	if err := s.enqueueTx(ctx, tx, job); err != nil {
		return 0, err
	}
	return revision, nil
}
