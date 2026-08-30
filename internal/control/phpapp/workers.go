package phpapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

const maxPersistedErrorBytes = 1000

var phpApplicationWorkerLocks sync.Map

// The panel lock coalesces local job kinds; the privileged agent provides the
// cross-process application lock around host mutations. Database advisory locks
// stay transaction-scoped so Phase 30 teardown triggers can safely reacquire the
// subscription lock on the same connection as each state write.
func lockPHPApplicationWorker(applicationID int64) func() {
	value, _ := phpApplicationWorkerLocks.LoadOrStore(applicationID, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	return lock.Unlock
}

type PHPApplicationAgent interface {
	DeployPHPRelease(context.Context, types.DeployPHPReleaseReq) (types.DeployPHPReleaseResult, error)
	RollbackPHPRelease(context.Context, types.RollbackPHPReleaseReq) (types.RollbackPHPReleaseResult, error)
	ReconcilePHPApplication(context.Context, types.ReconcilePHPApplicationReq) (types.ReconcilePHPApplicationResult, error)
	ReconcilePHPWorkers(context.Context, types.ReconcilePHPWorkersReq) (types.ReconcilePHPWorkersResult, error)
}

type loadedApplication struct {
	record      applicationRecord
	environment []types.PHPEnvironmentPayload
	active      *types.PHPDeployment
	previous    *types.PHPDeployment
}

type environmentDescriptor struct {
	name, value, scope, secretName string
}

func (s *SQLStore) loadForWorker(ctx context.Context, applicationID, revision int64, capabilities CapabilityReader) (loadedApplication, bool, error) {
	var loaded loadedApplication
	if s == nil || s.db == nil {
		return loaded, false, errors.New("PHP application database is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return loaded, false, err
	}
	defer tx.Rollback()
	loaded.record, err = scanApplication(tx.QueryRowContext(ctx, applicationSelect+` WHERE application.id=$1`, applicationID))
	if errors.Is(err, sql.ErrNoRows) {
		return loaded, true, nil
	}
	if err != nil {
		return loaded, false, err
	}
	if loaded.record.spec.DesiredRevision != revision {
		return loaded, true, nil
	}
	loaded.record.spec.Policy, err = controlquota.EffectiveSitePolicyTx(ctx, tx, loaded.record.spec.SiteID)
	if err != nil {
		return loaded, false, err
	}
	loaded.record.spec.Workers, err = loadWorkerSpecsTx(ctx, tx, applicationID)
	if err != nil {
		return loaded, false, err
	}
	totalWorkerProcesses, err := configuredSubscriptionWorkerProcessesTx(ctx, tx, loaded.record.spec.SubscriptionID, 0)
	if err != nil {
		return loaded, false, err
	}
	if err = validateSubscriptionWorkerProcesses(loaded.record.spec.Policy, totalWorkerProcesses); err != nil {
		return loaded, false, err
	}
	if requireActive(loaded.record) != nil {
		loaded.record.spec.DesiredState = "suspended"
	}
	if loaded.record.spec.HostingMode == types.PHPHostingModeManaged && loaded.record.spec.DesiredState == "active" {
		input := ConfigureApplicationInput{HostingMode: loaded.record.spec.HostingMode, PHPVersion: loaded.record.spec.PHPVersion,
			RepositoryID: loaded.record.spec.RepositoryID, RepositoryRef: loaded.record.spec.RepositoryRef,
			FrameworkProfile: loaded.record.spec.FrameworkProfile, PublicPath: loaded.record.spec.PublicPath,
			HealthPath: loaded.record.spec.HealthPath, SharedPaths: append([]string(nil), loaded.record.spec.SharedPaths...),
			ReleaseRetention: loaded.record.spec.ReleaseRetention, Composer: loaded.record.spec.Composer}
		if _, err = validateApplicationConfiguration(input, loaded.record.spec.Policy, types.PHPHostingModeManaged); err != nil {
			return loaded, false, err
		}
		if capabilities == nil {
			return loaded, false, ErrRuntimeUnavailable
		}
		var inventory types.RuntimeCapabilities
		inventory, err = capabilities.RuntimeCapabilities(ctx)
		if err != nil {
			return loaded, false, err
		}
		if _, err = readyPHPRuntime(inventory, loaded.record.spec.PHPVersion); err != nil {
			return loaded, false, err
		}
	}
	if loaded.record.activeDeploymentID > 0 {
		deployment, loadErr := scanDeployment(tx.QueryRowContext(ctx, deploymentSelect+` WHERE deployment.id=$1 AND deployment.application_id=$2`, loaded.record.activeDeploymentID, applicationID))
		if loadErr != nil {
			return loaded, false, loadErr
		}
		loaded.active = &deployment
	}
	if loaded.record.previousDeploymentID > 0 {
		deployment, loadErr := scanDeployment(tx.QueryRowContext(ctx, deploymentSelect+` WHERE deployment.id=$1 AND deployment.application_id=$2`, loaded.record.previousDeploymentID, applicationID))
		if loadErr != nil {
			return loaded, false, loadErr
		}
		loaded.previous = &deployment
	}
	descriptors, err := loadEnvironmentDescriptorsTx(ctx, tx, applicationID)
	if err != nil {
		return loaded, false, err
	}
	if err = tx.Commit(); err != nil {
		return loaded, false, err
	}
	loaded.environment, err = s.decryptEnvironment(ctx, descriptors)
	return loaded, false, err
}

func loadEnvironmentDescriptorsTx(ctx context.Context, tx *sql.Tx, applicationID int64) ([]environmentDescriptor, error) {
	rows, err := tx.QueryContext(ctx, `SELECT binding.name,COALESCE(binding.plain_value,''),
COALESCE(secret.scope,''),COALESCE(secret.name,'') FROM php_environment_bindings binding
LEFT JOIN service_secrets secret ON secret.id=binding.secret_id WHERE binding.application_id=$1 ORDER BY binding.name`, applicationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]environmentDescriptor, 0)
	for rows.Next() {
		var item environmentDescriptor
		if err := rows.Scan(&item.name, &item.value, &item.scope, &item.secretName); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLStore) decryptEnvironment(ctx context.Context, descriptors []environmentDescriptor) ([]types.PHPEnvironmentPayload, error) {
	items := make([]types.PHPEnvironmentPayload, 0, len(descriptors))
	for _, descriptor := range descriptors {
		item := types.PHPEnvironmentPayload{Name: descriptor.name, Value: descriptor.value}
		if descriptor.secretName != "" {
			if s.secrets == nil {
				clearEnvironment(items)
				return nil, errors.New("PHP application secret store is unavailable")
			}
			plaintext, _, err := s.secrets.GetSecret(ctx, descriptor.scope, descriptor.secretName)
			if err != nil {
				clearEnvironment(items)
				return nil, err
			}
			item.Value = ""
			item.Secret = string(plaintext)
			clear(plaintext)
		}
		items = append(items, item)
	}
	return items, nil
}

func clearEnvironment(environment []types.PHPEnvironmentPayload) {
	for index := range environment {
		environment[index].Value = ""
		environment[index].Secret = ""
	}
}

type DeployPHPReleaseWorker struct {
	river.WorkerDefaults[DeployPHPReleaseArgs]
	store        *SQLStore
	agent        PHPApplicationAgent
	capabilities CapabilityReader
}

func NewDeployPHPReleaseWorker(store *SQLStore, agent PHPApplicationAgent, capabilities CapabilityReader) *DeployPHPReleaseWorker {
	return &DeployPHPReleaseWorker{store: store, agent: agent, capabilities: capabilities}
}

func (w *DeployPHPReleaseWorker) Work(ctx context.Context, job *river.Job[DeployPHPReleaseArgs]) error {
	unlock := lockPHPApplicationWorker(job.Args.ApplicationID)
	defer unlock()
	finalAttempt := finalPHPJobAttempt(job)
	loaded, stale, err := w.store.loadForWorker(ctx, job.Args.ApplicationID, job.Args.DesiredRevision, w.capabilities)
	if stale {
		return w.store.settleSupersededDeployment(ctx, job.Args.ApplicationID, job.Args.DeploymentID, job.Args.DesiredRevision)
	}
	if err != nil {
		return w.fail(ctx, job.Args, nil, err, finalAttempt)
	}
	defer clearEnvironment(loaded.environment)
	if err = requireActive(loaded.record); err != nil {
		return w.fail(ctx, job.Args, loaded.environment, err, finalAttempt)
	}
	if w.agent == nil {
		return w.fail(ctx, job.Args, loaded.environment, errors.New("PHP application agent is unavailable"), finalAttempt)
	}
	deployment, err := w.store.deployment(ctx, job.Args.DeploymentID)
	if err != nil || deployment.ApplicationID != job.Args.ApplicationID {
		if err == nil {
			err = ErrNotFound
		}
		return w.fail(ctx, job.Args, loaded.environment, err, finalAttempt)
	}
	if deployment.Status == "healthy" && loaded.record.activeDeploymentID == deployment.ID && loaded.record.appliedRevision == job.Args.DesiredRevision {
		return nil
	}
	loaded.record.spec.RepositoryRef = deployment.RequestedRevision
	claimed, err := w.store.markDeploymentRunning(ctx, job.Args, "preparing")
	if err != nil {
		return err
	}
	if !claimed {
		return nil
	}
	result, err := w.agent.DeployPHPRelease(ctx, types.DeployPHPReleaseReq{Application: loaded.record.spec, Deployment: deployment, Environment: loaded.environment})
	if err != nil {
		return w.fail(ctx, job.Args, loaded.environment, err, finalAttempt)
	}
	if result.DeploymentID != deployment.ID || !resolvedRevisionPattern.MatchString(result.ResolvedRevision) {
		return w.fail(ctx, job.Args, loaded.environment, errors.New("agent returned an invalid PHP deployment result"), finalAttempt)
	}
	if err = w.store.completeDeployment(ctx, job.Args, loaded, result); err != nil {
		return err
	}
	return nil
}

func (w *DeployPHPReleaseWorker) fail(ctx context.Context, args DeployPHPReleaseArgs, environment []types.PHPEnvironmentPayload, cause error, finalAttempt bool) error {
	message := redactPHPFailure(cause, environment)
	terminal := isTerminalPHPJobError(cause) || finalAttempt
	if w.store != nil {
		var err error
		if terminal {
			err = w.store.failDeployment(ctx, args.ApplicationID, args.DeploymentID, args.DesiredRevision, message)
		} else {
			err = w.store.retryDeployment(ctx, args.ApplicationID, args.DeploymentID, args.DesiredRevision, message)
		}
		if err != nil {
			return errors.Join(cause, err)
		}
	}
	if terminal {
		return river.JobCancel(cause)
	}
	return terminalPHPJobError(cause)
}

type RollbackPHPReleaseWorker struct {
	river.WorkerDefaults[RollbackPHPReleaseArgs]
	store        *SQLStore
	agent        PHPApplicationAgent
	capabilities CapabilityReader
}

func NewRollbackPHPReleaseWorker(store *SQLStore, agent PHPApplicationAgent, capabilities CapabilityReader) *RollbackPHPReleaseWorker {
	return &RollbackPHPReleaseWorker{store: store, agent: agent, capabilities: capabilities}
}

func (w *RollbackPHPReleaseWorker) Work(ctx context.Context, job *river.Job[RollbackPHPReleaseArgs]) error {
	unlock := lockPHPApplicationWorker(job.Args.ApplicationID)
	defer unlock()
	finalAttempt := finalPHPJobAttempt(job)
	loaded, stale, err := w.store.loadForWorker(ctx, job.Args.ApplicationID, job.Args.DesiredRevision, w.capabilities)
	if stale {
		return w.store.settleSupersededDeployment(ctx, job.Args.ApplicationID, job.Args.DeploymentID, job.Args.DesiredRevision)
	}
	if err != nil {
		return w.fail(ctx, job.Args, nil, err, finalAttempt)
	}
	defer clearEnvironment(loaded.environment)
	if err = requireActive(loaded.record); err != nil {
		return w.fail(ctx, job.Args, loaded.environment, err, finalAttempt)
	}
	intent, err := w.store.deployment(ctx, job.Args.DeploymentID)
	if err != nil || intent.ApplicationID != job.Args.ApplicationID {
		if err == nil {
			err = ErrNotFound
		}
		return w.fail(ctx, job.Args, loaded.environment, err, finalAttempt)
	}
	target, err := w.store.deployment(ctx, job.Args.TargetDeploymentID)
	if err != nil || target.ApplicationID != loaded.record.spec.ApplicationID {
		if err == nil {
			err = ErrNotFound
		}
		return w.fail(ctx, job.Args, loaded.environment, err, finalAttempt)
	}
	if err = validateRollbackTarget(loaded.record, target); err != nil {
		return w.fail(ctx, job.Args, loaded.environment, err, finalAttempt)
	}
	if w.agent == nil {
		return w.fail(ctx, job.Args, loaded.environment, errors.New("PHP application agent is unavailable"), finalAttempt)
	}
	claimed, err := w.store.markRollbackRunning(ctx, job.Args, "preparing")
	if err != nil {
		return err
	}
	if !claimed {
		return nil
	}
	result, err := w.agent.RollbackPHPRelease(ctx, types.RollbackPHPReleaseReq{Application: loaded.record.spec, DeploymentID: intent.ID, TargetDeployment: target, Environment: loaded.environment})
	if err != nil {
		return w.fail(ctx, job.Args, loaded.environment, err, finalAttempt)
	}
	if result.ActiveDeploymentID != target.ID {
		return w.fail(ctx, job.Args, loaded.environment, errors.New("agent returned an invalid PHP rollback result"), finalAttempt)
	}
	return w.store.completeRollback(ctx, job.Args, loaded, target, result)
}

func (w *RollbackPHPReleaseWorker) fail(ctx context.Context, args RollbackPHPReleaseArgs, environment []types.PHPEnvironmentPayload, cause error, finalAttempt bool) error {
	message := redactPHPFailure(cause, environment)
	terminal := isTerminalPHPJobError(cause) || finalAttempt
	if w.store != nil {
		var err error
		if terminal {
			err = w.store.failDeployment(ctx, args.ApplicationID, args.DeploymentID, args.DesiredRevision, message)
		} else {
			err = w.store.retryDeployment(ctx, args.ApplicationID, args.DeploymentID, args.DesiredRevision, message)
		}
		if err != nil {
			return errors.Join(cause, err)
		}
	}
	if terminal {
		return river.JobCancel(cause)
	}
	return terminalPHPJobError(cause)
}

type ReconcilePHPApplicationWorker struct {
	river.WorkerDefaults[ReconcilePHPApplicationArgs]
	store        *SQLStore
	agent        PHPApplicationAgent
	capabilities CapabilityReader
}

func NewReconcilePHPApplicationWorker(store *SQLStore, agent PHPApplicationAgent, capabilities CapabilityReader) *ReconcilePHPApplicationWorker {
	return &ReconcilePHPApplicationWorker{store: store, agent: agent, capabilities: capabilities}
}

func (w *ReconcilePHPApplicationWorker) Work(ctx context.Context, job *river.Job[ReconcilePHPApplicationArgs]) error {
	unlock := lockPHPApplicationWorker(job.Args.ApplicationID)
	defer unlock()
	finalAttempt := finalPHPJobAttempt(job)
	loaded, stale, err := w.store.loadForWorker(ctx, job.Args.ApplicationID, job.Args.DesiredRevision, w.capabilities)
	if stale {
		return nil
	}
	if err != nil {
		return w.fail(ctx, job.Args, nil, err, finalAttempt)
	}
	defer clearEnvironment(loaded.environment)
	if w.agent == nil {
		return w.fail(ctx, job.Args, loaded.environment, errors.New("PHP application agent is unavailable"), finalAttempt)
	}
	result, err := w.agent.ReconcilePHPApplication(ctx, types.ReconcilePHPApplicationReq{Application: loaded.record.spec, ActiveDeployment: loaded.active, PreviousDeployment: loaded.previous, Environment: loaded.environment})
	if err != nil {
		return w.fail(ctx, job.Args, loaded.environment, err, finalAttempt)
	}
	if result.ApplicationID != loaded.record.spec.ApplicationID {
		return w.fail(ctx, job.Args, loaded.environment, errors.New("agent returned an invalid PHP reconciliation result"), finalAttempt)
	}
	if loaded.record.spec.HostingMode == types.PHPHostingModeManaged && loaded.record.spec.DesiredState == "active" && loaded.active != nil {
		workerResult, workerErr := w.agent.ReconcilePHPWorkers(ctx, types.ReconcilePHPWorkersReq{Application: loaded.record.spec, Workers: workersFromSpecs(loaded.record.spec), Environment: loaded.environment})
		if workerErr != nil {
			return w.fail(ctx, job.Args, loaded.environment, workerErr, finalAttempt)
		}
		if len(workerResult.Errors) > 0 {
			return w.fail(ctx, job.Args, loaded.environment, errors.New(strings.Join(workerResult.Errors, "; ")), finalAttempt)
		}
	}
	return w.store.completeReconcile(ctx, job.Args, loaded, result)
}

func (w *ReconcilePHPApplicationWorker) fail(ctx context.Context, args ReconcilePHPApplicationArgs, environment []types.PHPEnvironmentPayload, cause error, finalAttempt bool) error {
	message := redactPHPFailure(cause, environment)
	terminal := isTerminalPHPJobError(cause) || finalAttempt
	if w.store != nil {
		var err error
		if terminal {
			err = w.store.failReconcile(ctx, args.ApplicationID, args.DesiredRevision, message)
		} else {
			err = w.store.retryReconcile(ctx, args.ApplicationID, args.DesiredRevision, message)
		}
		if err != nil {
			return errors.Join(cause, err)
		}
	}
	if terminal {
		return river.JobCancel(cause)
	}
	return terminalPHPJobError(cause)
}

type ReconcilePHPWorkersWorker struct {
	river.WorkerDefaults[ReconcilePHPWorkersArgs]
	store        *SQLStore
	agent        PHPApplicationAgent
	capabilities CapabilityReader
}

func NewReconcilePHPWorkersWorker(store *SQLStore, agent PHPApplicationAgent, capabilities CapabilityReader) *ReconcilePHPWorkersWorker {
	return &ReconcilePHPWorkersWorker{store: store, agent: agent, capabilities: capabilities}
}

func (w *ReconcilePHPWorkersWorker) Work(ctx context.Context, job *river.Job[ReconcilePHPWorkersArgs]) error {
	unlock := lockPHPApplicationWorker(job.Args.ApplicationID)
	defer unlock()
	finalAttempt := finalPHPJobAttempt(job)
	loaded, stale, err := w.store.loadForWorker(ctx, job.Args.ApplicationID, job.Args.DesiredRevision, w.capabilities)
	if stale {
		return nil
	}
	if err != nil {
		return w.fail(ctx, job.Args, nil, err, finalAttempt)
	}
	defer clearEnvironment(loaded.environment)
	workers, err := w.store.workers(ctx, loaded.record.spec.ApplicationID)
	if err != nil {
		return w.fail(ctx, job.Args, loaded.environment, err, finalAttempt)
	}
	runningAllowed := loaded.record.spec.HostingMode == types.PHPHostingModeManaged &&
		loaded.record.spec.DesiredState == "active" && loaded.active != nil
	if !shouldCallWorkerAgent(loaded) {
		return w.store.completeWorkers(ctx, loaded, job.Args.DesiredRevision, workers, false)
	}
	if w.agent == nil {
		return w.fail(ctx, job.Args, loaded.environment, errors.New("PHP application agent is unavailable"), finalAttempt)
	}
	result, err := w.agent.ReconcilePHPWorkers(ctx, types.ReconcilePHPWorkersReq{Application: loaded.record.spec, Workers: workers, Environment: loaded.environment})
	if err != nil {
		return w.fail(ctx, job.Args, loaded.environment, err, finalAttempt)
	}
	if len(result.Errors) > 0 {
		return w.fail(ctx, job.Args, loaded.environment, errors.New(strings.Join(result.Errors, "; ")), finalAttempt)
	}
	return w.store.completeWorkers(ctx, loaded, job.Args.DesiredRevision, workers, runningAllowed)
}

func shouldCallWorkerAgent(loaded loadedApplication) bool {
	return loaded.record.spec.HostingMode != types.PHPHostingModeManaged ||
		loaded.record.spec.DesiredState != "active" || loaded.active != nil
}

func (w *ReconcilePHPWorkersWorker) fail(ctx context.Context, args ReconcilePHPWorkersArgs, environment []types.PHPEnvironmentPayload, cause error, finalAttempt bool) error {
	message := redactPHPFailure(cause, environment)
	terminal := isTerminalPHPJobError(cause) || finalAttempt
	if w.store != nil {
		var err error
		if terminal {
			err = w.store.failWorkers(ctx, args.ApplicationID, args.DesiredRevision, message)
		} else {
			err = w.store.retryWorkers(ctx, args.ApplicationID, args.DesiredRevision, message)
		}
		if err != nil {
			return errors.Join(cause, err)
		}
	}
	if terminal {
		return river.JobCancel(cause)
	}
	return terminalPHPJobError(cause)
}

func (s *SQLStore) workers(ctx context.Context, applicationID int64) ([]types.PHPWorker, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	items, err := loadWorkersTx(ctx, tx, applicationID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return items, nil
}

func workersFromSpecs(spec types.PHPApplicationSpec) []types.PHPWorker {
	items := make([]types.PHPWorker, 0, len(spec.Workers))
	for _, worker := range spec.Workers {
		items = append(items, types.PHPWorker{ID: worker.WorkerID, SubscriptionID: spec.SubscriptionID,
			ApplicationID: spec.ApplicationID, Name: worker.Name, Script: worker.Script,
			Arguments: append([]string(nil), worker.Arguments...), Processes: worker.Processes, DesiredState: worker.DesiredState})
	}
	return items
}

func redactPHPFailure(err error, environment []types.PHPEnvironmentPayload) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	for _, item := range environment {
		for _, value := range []string{item.Value, item.Secret} {
			if value != "" {
				message = strings.ReplaceAll(message, value, "[redacted]")
			}
		}
	}
	message = strings.Map(func(value rune) rune {
		if value == '\n' || value == '\r' || value == '\x00' || (unicode.IsControl(value) && value != '\t') {
			return ' '
		}
		return value
	}, message)
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > maxPersistedErrorBytes {
		message = message[:maxPersistedErrorBytes]
	}
	return message
}

func terminalPHPJobError(err error) error {
	if err == nil {
		return nil
	}
	if isTerminalPHPJobError(err) {
		return river.JobCancel(err)
	}
	return err
}

func finalPHPJobAttempt[T river.JobArgs](job *river.Job[T]) bool {
	return job != nil && job.JobRow != nil && job.MaxAttempts > 0 && job.Attempt >= job.MaxAttempts
}

func isTerminalPHPJobError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	for _, marker := range []string{
		"disabled", "inactive", "not allowed", "invalid", "required", "exceeds", "malware", "audit", "unsafe", "not found",
		"failed readiness", "health probe returned",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func validateSubscriptionWorkerProcesses(policy types.HostingPolicy, processes int) error {
	if processes < 0 {
		return errors.New("PHP worker process count is invalid")
	}
	if processes > 0 && !policy.Permissions.PHPWorkers {
		return fmt.Errorf("%w: PHP workers are disabled", controlquota.ErrExceeded)
	}
	if policy.Resources.MaxPHPWorkers >= 0 && processes > policy.Resources.MaxPHPWorkers {
		return fmt.Errorf("%w: PHP worker processes %d / %d", controlquota.ErrExceeded, processes, policy.Resources.MaxPHPWorkers)
	}
	return nil
}

func reconcileCanApply(record applicationRecord, result types.ReconcilePHPApplicationResult) bool {
	if record.spec.HostingMode != types.PHPHostingModeManaged || record.spec.DesiredState != "active" {
		return true
	}
	return result.ObservedState == "healthy" && (record.activeDeploymentID > 0 || result.ActiveDeploymentID > 0)
}

func workerObservedState(desired string, runningAllowed bool) string {
	if desired == "running" && runningAllowed {
		return "running"
	}
	return "stopped"
}

func (s *SQLStore) markDeploymentRunning(ctx context.Context, args DeployPHPReleaseArgs, state string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE php_deployments deployment SET status=$4,started_at=COALESCE(started_at,now()),last_error=''
FROM php_applications application WHERE deployment.id=$1 AND deployment.application_id=$2 AND application.id=$2
AND application.desired_revision=$3 AND deployment.status IN ('pending','preparing','validating','activating')`, args.DeploymentID, args.ApplicationID, args.DesiredRevision, state)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func (s *SQLStore) markRollbackRunning(ctx context.Context, args RollbackPHPReleaseArgs, state string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE php_deployments intent SET status=$5,
started_at=COALESCE(intent.started_at,now()),last_error=''
FROM php_applications application,php_deployments target
WHERE intent.id=$1 AND intent.application_id=$2 AND target.id=$3 AND target.application_id=$2
AND application.id=$2 AND application.desired_revision=$4
AND intent.status IN ('pending','preparing','validating','activating')
AND target.status IN ('healthy','retired') AND target.resolved_revision<>''
AND COALESCE(application.active_deployment_id,0)<>target.id`, args.DeploymentID, args.ApplicationID,
		args.TargetDeploymentID, args.DesiredRevision, state)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func (s *SQLStore) settleSupersededDeployment(ctx context.Context, applicationID, deploymentID, revision int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE php_deployments SET status='failed',
last_error='superseded by a newer application revision',finished_at=COALESCE(finished_at,now())
WHERE id=$1 AND application_id=$2 AND status IN ('pending','preparing','validating','activating')
AND EXISTS (SELECT 1 FROM php_applications WHERE id=$2 AND desired_revision<>$3)`, deploymentID, applicationID, revision)
	return err
}

func (s *SQLStore) completeDeployment(ctx context.Context, args DeployPHPReleaseArgs, loaded loadedApplication, result types.DeployPHPReleaseResult) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentRevision, oldActive int64
	if err = tx.QueryRowContext(ctx, `SELECT desired_revision,COALESCE(active_deployment_id,0) FROM php_applications WHERE id=$1 FOR UPDATE`, args.ApplicationID).Scan(&currentRevision, &oldActive); err != nil {
		return err
	}
	if currentRevision != args.DesiredRevision {
		if _, err = tx.ExecContext(ctx, `UPDATE php_deployments SET status='failed',
last_error='superseded by a newer application revision',finished_at=COALESCE(finished_at,now())
WHERE id=$1 AND application_id=$2 AND status IN ('pending','preparing','validating','activating')`, args.DeploymentID, args.ApplicationID); err != nil {
			return err
		}
		if s.river != nil {
			if err = s.enqueueTx(ctx, tx, ReconcilePHPApplicationArgs{ApplicationID: args.ApplicationID, DesiredRevision: currentRevision}); err != nil {
				return err
			}
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		return ErrRevisionConflict
	}
	if oldActive > 0 && oldActive != args.DeploymentID {
		if _, err = tx.ExecContext(ctx, `UPDATE php_deployments SET status='retired',finished_at=COALESCE(finished_at,now()) WHERE id=$1 AND application_id=$2 AND status='healthy'`, oldActive, args.ApplicationID); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE php_deployments SET resolved_revision=$3,status='healthy',composer_audit=jsonb_build_object('summary',$4::text),
health_message=$5,last_error='',activated_at=now(),finished_at=now() WHERE id=$1 AND application_id=$2`, args.DeploymentID, args.ApplicationID, result.ResolvedRevision, result.ComposerAudit, result.HealthMessage); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE php_applications SET active_deployment_id=$2,previous_deployment_id=NULLIF($3,0),
observed_state='healthy',observed_message=$4,applied_revision=$5,convergence_status='in_sync',last_error='',last_reconciled_at=now(),updated_at=now()
WHERE id=$1 AND desired_revision=$5`, args.ApplicationID, args.DeploymentID, oldActive, result.HealthMessage, args.DesiredRevision); err != nil {
		return err
	}
	if err = markWorkersAppliedTx(ctx, tx, args.ApplicationID, true); err != nil {
		return err
	}
	if err = resolveNotificationTx(ctx, tx, deploymentFailureKey(args.ApplicationID)); err != nil {
		return err
	}
	if err = reconcileComposerNotificationTx(ctx, tx, loaded, args.ApplicationID, result.ComposerAudit); err != nil {
		return err
	}
	if err = auditTx(ctx, tx, 0, loaded.record.customerID, loaded.record.spec.SubscriptionID,
		"php.deployment.healthy", "php_deployment", args.DeploymentID, map[string]any{"resolved_revision": result.ResolvedRevision, "revision": args.DesiredRevision}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) completeRollback(ctx context.Context, args RollbackPHPReleaseArgs, loaded loadedApplication, target types.PHPDeployment, result types.RollbackPHPReleaseResult) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var revision, oldActive int64
	if err = tx.QueryRowContext(ctx, `SELECT desired_revision,COALESCE(active_deployment_id,0) FROM php_applications WHERE id=$1 FOR UPDATE`, args.ApplicationID).Scan(&revision, &oldActive); err != nil {
		return err
	}
	if revision != args.DesiredRevision {
		if _, err = tx.ExecContext(ctx, `UPDATE php_deployments SET status='failed',
last_error='superseded by a newer application revision',finished_at=COALESCE(finished_at,now())
WHERE id=$1 AND application_id=$2 AND status IN ('pending','preparing','validating','activating')`, args.DeploymentID, args.ApplicationID); err != nil {
			return err
		}
		if s.river != nil {
			if err = s.enqueueTx(ctx, tx, ReconcilePHPApplicationArgs{ApplicationID: args.ApplicationID, DesiredRevision: revision}); err != nil {
				return err
			}
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		return ErrRevisionConflict
	}
	if oldActive > 0 && oldActive != target.ID {
		if _, err = tx.ExecContext(ctx, `UPDATE php_deployments SET status='retired' WHERE id=$1 AND application_id=$2 AND status='healthy'`, oldActive, args.ApplicationID); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE php_deployments SET status='healthy',health_message=$3,last_error='',activated_at=now() WHERE id=$1 AND application_id=$2`, target.ID, args.ApplicationID, result.HealthMessage); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE php_deployments SET status='rolled_back',resolved_revision=$3,health_message=$4,last_error='',finished_at=now() WHERE id=$1 AND application_id=$2`, args.DeploymentID, args.ApplicationID, target.ResolvedRevision, result.HealthMessage); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE php_applications SET active_deployment_id=$2,previous_deployment_id=NULLIF($3,0),observed_state='healthy',
observed_message=$4,applied_revision=$5,convergence_status='in_sync',last_error='',last_reconciled_at=now(),updated_at=now() WHERE id=$1 AND desired_revision=$5`,
		args.ApplicationID, target.ID, oldActive, result.HealthMessage, args.DesiredRevision); err != nil {
		return err
	}
	if err = markWorkersAppliedTx(ctx, tx, args.ApplicationID, true); err != nil {
		return err
	}
	if err = resolveNotificationTx(ctx, tx, deploymentFailureKey(args.ApplicationID)); err != nil {
		return err
	}
	if err = reconcileComposerNotificationTx(ctx, tx, loaded, args.ApplicationID, target.ComposerAudit); err != nil {
		return err
	}
	if err = auditTx(ctx, tx, 0, loaded.record.customerID, loaded.record.spec.SubscriptionID, "php.deployment.rolled_back", "php_deployment", args.DeploymentID,
		map[string]any{"target_deployment_id": target.ID, "revision": args.DesiredRevision}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) completeReconcile(ctx context.Context, args ReconcilePHPApplicationArgs, loaded loadedApplication, result types.ReconcilePHPApplicationResult) error {
	if result.ObservedState == "" {
		result.ObservedState = "pending"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentRevision, activeDeploymentID int64
	if err = tx.QueryRowContext(ctx, `SELECT desired_revision,COALESCE(active_deployment_id,0)
FROM php_applications WHERE id=$1 FOR UPDATE`, args.ApplicationID).Scan(&currentRevision, &activeDeploymentID); err != nil {
		return err
	}
	if currentRevision != args.DesiredRevision {
		return tx.Commit()
	}
	recovered := false
	if result.ActiveDeploymentID > 0 && activeDeploymentID == 0 {
		if !resolvedRevisionPattern.MatchString(result.ResolvedRevision) {
			return errors.New("observed PHP release marker has an invalid revision")
		}
		var deploymentApplicationID int64
		if err = tx.QueryRowContext(ctx, `SELECT application_id FROM php_deployments WHERE id=$1 FOR UPDATE`, result.ActiveDeploymentID).Scan(&deploymentApplicationID); errors.Is(err, sql.ErrNoRows) {
			return ErrRevisionConflict
		} else if err != nil {
			return err
		}
		if deploymentApplicationID != args.ApplicationID {
			return ErrRevisionConflict
		}
		previousDeploymentID := int64(0)
		if result.PreviousDeploymentID > 0 {
			var exists bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM php_deployments WHERE id=$1 AND application_id=$2)`, result.PreviousDeploymentID, args.ApplicationID).Scan(&exists); err != nil {
				return err
			}
			if exists {
				previousDeploymentID = result.PreviousDeploymentID
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE php_deployments SET status='healthy',resolved_revision=$3,
health_message=$4,last_error='',activated_at=COALESCE(activated_at,now()),finished_at=COALESCE(finished_at,now())
WHERE id=$1 AND application_id=$2`, result.ActiveDeploymentID, args.ApplicationID, result.ResolvedRevision, safeMessage(result.Message)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE php_applications SET active_deployment_id=$2,
previous_deployment_id=NULLIF($3,0) WHERE id=$1`, args.ApplicationID, result.ActiveDeploymentID, previousDeploymentID); err != nil {
			return err
		}
		loaded.record.activeDeploymentID = result.ActiveDeploymentID
		activeDeploymentID = result.ActiveDeploymentID
		recovered = true
		if err = auditTx(ctx, tx, 0, loaded.record.customerID, loaded.record.spec.SubscriptionID,
			"php.deployment.observed_recovered", "php_deployment", result.ActiveDeploymentID,
			map[string]any{"revision": args.DesiredRevision}); err != nil {
			return err
		}
	} else if result.ActiveDeploymentID > 0 && activeDeploymentID != result.ActiveDeploymentID {
		return ErrRevisionConflict
	}
	apply := reconcileCanApply(loaded.record, result) && !recovered
	if apply {
		_, err = tx.ExecContext(ctx, `UPDATE php_applications SET observed_state=$3,observed_message=$4,
applied_revision=$2,convergence_status='in_sync',last_error='',last_reconciled_at=now(),updated_at=now()
WHERE id=$1 AND desired_revision=$2`, args.ApplicationID, args.DesiredRevision, result.ObservedState, safeMessage(result.Message))
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE php_applications SET observed_state=$3,observed_message=$4,
convergence_status='pending',last_error='',last_reconciled_at=now(),updated_at=now()
WHERE id=$1 AND desired_revision=$2`, args.ApplicationID, args.DesiredRevision, result.ObservedState, safeMessage(result.Message))
	}
	if err != nil {
		return err
	}
	if apply {
		if err = markWorkersAppliedTx(ctx, tx, args.ApplicationID, result.ObservedState == "healthy"); err != nil {
			return err
		}
	}
	if err = resolveNotificationTx(ctx, tx, reconcileFailureKey(args.ApplicationID)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) completeWorkers(ctx context.Context, loaded loadedApplication, revision int64, workers []types.PHPWorker, runningAllowed bool) error {
	applicationID := loaded.record.spec.ApplicationID
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int64
	if err = tx.QueryRowContext(ctx, `SELECT desired_revision FROM php_applications WHERE id=$1 FOR UPDATE`, applicationID).Scan(&current); err != nil {
		return err
	}
	if current != revision {
		return tx.Commit()
	}
	for _, worker := range workers {
		if _, err = tx.ExecContext(ctx, `UPDATE php_workers SET observed_state=$3,applied_revision=desired_revision,
convergence_status='in_sync',last_error='',last_reconciled_at=now(),updated_at=now() WHERE id=$1 AND application_id=$2`, worker.ID, applicationID, workerObservedState(worker.DesiredState, runningAllowed)); err != nil {
			return err
		}
	}
	if loaded.record.spec.HostingMode == types.PHPHostingModeManaged && loaded.record.spec.DesiredState == "active" && loaded.active == nil {
		if _, err = tx.ExecContext(ctx, `UPDATE php_applications SET convergence_status='pending',last_error='',last_reconciled_at=now(),updated_at=now() WHERE id=$1 AND desired_revision=$2`, applicationID, revision); err != nil {
			return err
		}
	} else {
		if _, err = tx.ExecContext(ctx, `UPDATE php_applications SET applied_revision=$2,convergence_status='in_sync',last_error='',last_reconciled_at=now(),updated_at=now() WHERE id=$1 AND desired_revision=$2`, applicationID, revision); err != nil {
			return err
		}
	}
	if err = resolveNotificationTx(ctx, tx, workerFailureKey(applicationID)); err != nil {
		return err
	}
	return tx.Commit()
}

func markWorkersAppliedTx(ctx context.Context, tx *sql.Tx, applicationID int64, runningAllowed bool) error {
	_, err := tx.ExecContext(ctx, `UPDATE php_workers SET observed_state=CASE WHEN desired_state='running' AND $2 THEN 'running' ELSE 'stopped' END,
applied_revision=desired_revision,convergence_status='in_sync',last_error='',last_reconciled_at=now(),updated_at=now() WHERE application_id=$1`, applicationID, runningAllowed)
	return err
}

func (s *SQLStore) failDeployment(ctx context.Context, applicationID, deploymentID, revision int64, message string) error {
	err := s.recordFailure(ctx, applicationID, deploymentID, revision, "php_deployment_failed", "PHP deployment failed", message, deploymentFailureKey(applicationID), true)
	composer := phpFailureNotification(phpFailureDeployment, applicationID, errors.New(message))
	if composer.kind == "php_composer_security" {
		err = errors.Join(err, s.recordComposerSecurityFailure(ctx, applicationID, revision, message))
	}
	return err
}
func (s *SQLStore) failReconcile(ctx context.Context, applicationID, revision int64, message string) error {
	notification := phpFailureNotification(phpFailureReconcile, applicationID, errors.New(message))
	return s.recordFailure(ctx, applicationID, 0, revision, notification.kind, notification.title, message, notification.key, false)
}
func (s *SQLStore) failWorkers(ctx context.Context, applicationID, revision int64, message string) error {
	notification := phpFailureNotification(phpFailureWorker, applicationID, errors.New(message))
	return s.recordFailure(ctx, applicationID, 0, revision, notification.kind, notification.title, message, notification.key, false)
}

type phpFailureType string

const (
	phpFailureDeployment phpFailureType = "deployment"
	phpFailureReconcile  phpFailureType = "reconcile"
	phpFailureWorker     phpFailureType = "worker"
)

type phpNotification struct {
	kind  string
	title string
	key   string
}

func phpFailureNotification(failureType phpFailureType, applicationID int64, cause error) phpNotification {
	message := ""
	if cause != nil {
		message = cause.Error()
	}
	if failureType == phpFailureDeployment && strings.Contains(message, "Composer audit found a blocking security advisory") {
		return phpNotification{kind: "php_composer_security", title: "Composer security findings", key: composerSecurityKey(applicationID)}
	}
	switch failureType {
	case phpFailureWorker:
		return phpNotification{kind: "php_worker_failed", title: "PHP worker reconciliation failed", key: workerFailureKey(applicationID)}
	case phpFailureReconcile:
		return phpNotification{kind: "php_reconciliation_failed", title: "PHP reconciliation failed", key: reconcileFailureKey(applicationID)}
	default:
		return phpNotification{kind: "php_deployment_failed", title: "PHP deployment failed", key: deploymentFailureKey(applicationID)}
	}
}

func composerAuditNotification(summary string) (kind, body string, resolve bool) {
	summary = strings.TrimSpace(summary)
	if strings.HasPrefix(summary, "{") {
		var document struct {
			Summary string `json:"summary"`
		}
		if json.Unmarshal([]byte(summary), &document) == nil {
			summary = strings.TrimSpace(document.Summary)
		}
	}
	if summary == "" || summary == "clean" || summary == "not required" {
		return "", "", true
	}
	return "php_composer_security", safeMessage("Composer audit findings: " + summary), false
}

func reconcileComposerNotificationTx(ctx context.Context, tx *sql.Tx, loaded loadedApplication, applicationID int64, summary string) error {
	kind, body, resolve := composerAuditNotification(summary)
	if resolve {
		return resolveNotificationTx(ctx, tx, composerSecurityKey(applicationID))
	}
	return upsertNotificationTx(ctx, tx, loaded.record.spec.SubscriptionID, loaded.record.customerID,
		kind, "warning", "Composer security findings", body, composerSecurityKey(applicationID))
}

func (s *SQLStore) retryDeployment(ctx context.Context, applicationID, deploymentID, revision int64, message string) error {
	return s.recordRetryableFailure(ctx, applicationID, deploymentID, revision, message, true, false)
}

func (s *SQLStore) retryReconcile(ctx context.Context, applicationID, revision int64, message string) error {
	return s.recordRetryableFailure(ctx, applicationID, 0, revision, message, false, false)
}

func (s *SQLStore) retryWorkers(ctx context.Context, applicationID, revision int64, message string) error {
	return s.recordRetryableFailure(ctx, applicationID, 0, revision, message, false, true)
}

func (s *SQLStore) recordRetryableFailure(ctx context.Context, applicationID, deploymentID, revision int64, message string, deployment, workers bool) error {
	message = safeMessage(message)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var subscriptionID, customerID, current int64
	if err = tx.QueryRowContext(ctx, `SELECT application.subscription_id,site.customer_id,application.desired_revision
FROM php_applications application JOIN sites site ON site.id=application.site_id WHERE application.id=$1 FOR UPDATE OF application`, applicationID).Scan(&subscriptionID, &customerID, &current); err != nil {
		return err
	}
	if current != revision {
		return tx.Commit()
	}
	if deployment && deploymentID > 0 {
		if _, err = tx.ExecContext(ctx, `UPDATE php_deployments SET status='pending',last_error=$3,
started_at=NULL,finished_at=NULL WHERE id=$1 AND application_id=$2 AND status<>'healthy'`, deploymentID, applicationID, message); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE php_applications SET convergence_status='pending',last_error=$3,
last_reconciled_at=now(),updated_at=now() WHERE id=$1 AND desired_revision=$2`, applicationID, revision, message); err != nil {
		return err
	}
	if workers {
		if _, err = tx.ExecContext(ctx, `UPDATE php_workers SET convergence_status='pending',last_error=$2,
last_reconciled_at=now(),updated_at=now() WHERE application_id=$1`, applicationID, message); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) recordFailure(ctx context.Context, applicationID, deploymentID, revision int64, kind, title, message, key string, deployment bool) error {
	message = safeMessage(message)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var subscriptionID, customerID, current int64
	if err = tx.QueryRowContext(ctx, `SELECT application.subscription_id,site.customer_id,application.desired_revision
FROM php_applications application JOIN sites site ON site.id=application.site_id WHERE application.id=$1 FOR UPDATE OF application`, applicationID).Scan(&subscriptionID, &customerID, &current); err != nil {
		return err
	}
	if current != revision {
		return tx.Commit()
	}
	if deployment && deploymentID > 0 {
		if _, err = tx.ExecContext(ctx, `UPDATE php_deployments SET status='failed',last_error=$3,finished_at=now() WHERE id=$1 AND application_id=$2 AND status<>'healthy'`, deploymentID, applicationID, message); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE php_applications SET convergence_status='failed',last_error=$3,last_reconciled_at=now(),updated_at=now() WHERE id=$1 AND desired_revision=$2`, applicationID, revision, message); err != nil {
		return err
	}
	if strings.Contains(title, "worker") {
		if _, err = tx.ExecContext(ctx, `UPDATE php_workers SET observed_state='failed',convergence_status='failed',last_error=$2,last_reconciled_at=now(),updated_at=now() WHERE application_id=$1`, applicationID, message); err != nil {
			return err
		}
	}
	if err = upsertNotificationTx(ctx, tx, subscriptionID, customerID, kind, "critical", title, message, key); err != nil {
		return err
	}
	if err = auditTx(ctx, tx, 0, customerID, subscriptionID, "php.convergence.failed", "php_application", applicationID, map[string]any{"error": message, "revision": revision}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) recordComposerSecurityFailure(ctx context.Context, applicationID, revision int64, message string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var subscriptionID, customerID, current int64
	if err = tx.QueryRowContext(ctx, `SELECT application.subscription_id,site.customer_id,application.desired_revision
FROM php_applications application JOIN sites site ON site.id=application.site_id WHERE application.id=$1 FOR UPDATE OF application`, applicationID).Scan(&subscriptionID, &customerID, &current); err != nil {
		return err
	}
	if current != revision {
		return tx.Commit()
	}
	if err = upsertNotificationTx(ctx, tx, subscriptionID, customerID, "php_composer_security", "critical",
		"Composer security findings", message, composerSecurityKey(applicationID)); err != nil {
		return err
	}
	return tx.Commit()
}

func upsertNotificationTx(ctx context.Context, tx *sql.Tx, subscriptionID, customerID int64, kind, severity, title, body, key string) error {
	_, err := tx.ExecContext(ctx, `WITH recipient AS (SELECT login_user_id,reseller_id,email FROM customers WHERE id=$1), upserted AS (
INSERT INTO notifications(recipient_user_id,customer_id,reseller_id,subscription_id,kind,severity,title,body,dedupe_key)
SELECT login_user_id,$1,reseller_id,$2,$3,$4,$5,$6,$7 FROM recipient
ON CONFLICT(dedupe_key) WHERE resolved_at IS NULL DO UPDATE SET severity=EXCLUDED.severity,title=EXCLUDED.title,body=EXCLUDED.body,updated_at=now()
RETURNING id) INSERT INTO notification_deliveries(notification_id,channel,recipient)
SELECT upserted.id,'smtp',recipient.email FROM upserted CROSS JOIN recipient WHERE recipient.email<>''
ON CONFLICT(notification_id,channel,recipient) DO NOTHING`, customerID, subscriptionID, kind, severity, title, safeMessage(body), key)
	return err
}

func resolveNotificationTx(ctx context.Context, tx *sql.Tx, key string) error {
	_, err := tx.ExecContext(ctx, `UPDATE notifications SET resolved_at=now(),updated_at=now() WHERE dedupe_key=$1 AND resolved_at IS NULL`, key)
	return err
}

func deploymentFailureKey(applicationID int64) string {
	return fmt.Sprintf("php:deployment:%d", applicationID)
}
func reconcileFailureKey(applicationID int64) string {
	return fmt.Sprintf("php:reconcile:%d", applicationID)
}
func workerFailureKey(applicationID int64) string {
	return fmt.Sprintf("php:workers:%d", applicationID)
}
func composerSecurityKey(applicationID int64) string {
	return fmt.Sprintf("php:composer:%d", applicationID)
}
func safeMessage(value string) string { return redactPHPFailure(errors.New(value), nil) }
