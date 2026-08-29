package quota

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

const (
	HeavyQueue     = "heavy"
	MigrationQueue = "migration"
	SystemQueue    = "system"
)

type ConvergeSubscriptionArgs struct {
	SubscriptionID int64 `json:"subscription_id" river:"unique"`
	Revision       int64 `json:"revision" river:"unique"`
}

type ConvergePendingSubscriptionsArgs struct{}
type ReconcileApplicationsArgs struct{}
type ConvergeApplicationArgs struct {
	ApplicationID        int64 `json:"application_id" river:"unique"`
	Revision             int64 `json:"revision" river:"unique"`
	SubscriptionRevision int64 `json:"subscription_revision" river:"unique"`
}

type SweepLegacyAccountMigrationsArgs struct{}
type SweepLegacyAccountCleanupArgs struct{}
type MigrateSubscriptionAccountArgs struct {
	SubscriptionID int64 `json:"subscription_id" river:"unique"`
}
type CleanupLegacyHomesArgs struct {
	SubscriptionID int64 `json:"subscription_id" river:"unique"`
}

func (SweepLegacyAccountCleanupArgs) Kind() string { return "sweep_legacy_account_cleanup" }
func (SweepLegacyAccountCleanupArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "maintenance", UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}
func (CleanupLegacyHomesArgs) Kind() string { return "cleanup_legacy_homes" }
func (CleanupLegacyHomesArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "maintenance", MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

func (SweepLegacyAccountMigrationsArgs) Kind() string { return "sweep_legacy_account_migrations" }
func (SweepLegacyAccountMigrationsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: MigrationQueue, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}
func (MigrateSubscriptionAccountArgs) Kind() string { return "migrate_subscription_account" }
func (MigrateSubscriptionAccountArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: MigrationQueue, MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

func (ConvergePendingSubscriptionsArgs) Kind() string { return "converge_pending_subscriptions" }
func (ConvergePendingSubscriptionsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

func (ReconcileApplicationsArgs) Kind() string { return "reconcile_applications" }
func (ReconcileApplicationsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: SystemQueue, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

func (ConvergeSubscriptionArgs) Kind() string { return "converge_subscription" }
func (ConvergeSubscriptionArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

var mutationRevision atomic.Int64
var subscriptionConvergenceLocks sync.Map
var applicationConvergenceLocks sync.Map

func lockSubscriptionConvergence(subscriptionID int64) func() {
	value, _ := subscriptionConvergenceLocks.LoadOrStore(subscriptionID, &sync.Mutex{})
	mutex := value.(*sync.Mutex)
	mutex.Lock()
	return mutex.Unlock
}

func lockApplicationConvergence(applicationID int64) func() {
	value, _ := applicationConvergenceLocks.LoadOrStore(applicationID, &sync.Mutex{})
	mutex := value.(*sync.Mutex)
	mutex.Lock()
	return mutex.Unlock
}

func nextMutationRevision() int64 {
	for {
		previous := mutationRevision.Load()
		next := time.Now().UnixNano()
		if next <= previous {
			next = previous + 1
		}
		if mutationRevision.CompareAndSwap(previous, next) {
			return next
		}
	}
}

func newConvergeSubscriptionArgs(subscriptionID, revision int64) ConvergeSubscriptionArgs {
	return ConvergeSubscriptionArgs{
		SubscriptionID: subscriptionID,
		Revision:       revision,
	}
}

// NewConvergeSubscriptionArgs remains available to older callers. Mutating
// database paths should use EnqueueSubscriptionConvergenceTx so the revision is
// durable and committed atomically with the desired state.
func NewConvergeSubscriptionArgs(subscriptionID int64) ConvergeSubscriptionArgs {
	return newConvergeSubscriptionArgs(subscriptionID, nextMutationRevision())
}

// ConfigureMailArgs reconciles Stalwart with every enabled mail domain: the
// worker lives in the provision package. River's unique gate must include
// the Running state, so a bare singleton would silently drop a change made
// while a reconciliation is already running — the revision gives every
// mutation its own job, and the idempotent worker makes extra runs free.
type ConfigureMailArgs struct {
	Revision int64 `json:"revision" river:"unique"`
}

func (ConfigureMailArgs) Kind() string { return "configure_mail" }
func (ConfigureMailArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: SystemQueue, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

// NewConfigureMailArgs stamps the job with the mutation moment.
func NewConfigureMailArgs() ConfigureMailArgs {
	return ConfigureMailArgs{Revision: nextMutationRevision()}
}

func (ConvergeApplicationArgs) Kind() string { return "converge_application" }
func (ConvergeApplicationArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: HeavyQueue, MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

type SubscriptionConvergenceAgent interface {
	EnsureSubscriptionAccount(context.Context, types.EnsureSubscriptionAccountReq) (types.Response, error)
	ApplyScheduledTasks(context.Context, types.ApplyScheduledTasksReq) (types.Response, error)
	EnsureApplication(context.Context, types.EnsureApplicationReq) (types.Response, error)
	MigrateSubscriptionAccount(context.Context, types.MigrateSubscriptionAccountReq) (types.Response, error)
	CleanupLegacyHomes(context.Context, types.CleanupLegacyHomesReq) (types.Response, error)
	EnsureFTPS(context.Context, types.EnsureFTPSReq) (types.EnsureFTPSResult, error)
	EnsureValkey(context.Context, types.EnsureValkeyReq) (types.EnsureValkeyResult, error)
}

type GitConvergenceAgent interface {
	EnsureGitRepository(context.Context, types.EnsureGitRepositoryReq) (types.EnsureGitRepositoryResult, error)
}

type ProtectedDirectoryConvergenceAgent interface {
	EnsureProtectedDirectories(context.Context, types.EnsureProtectedDirectoriesReq) (types.EnsureProtectedDirectoriesResult, error)
}

type ApplicationGenerationAgent interface {
	DeployApplicationGeneration(context.Context, types.EnsureApplicationReq) (types.DeployApplicationGenerationResult, error)
}

type ApplicationInspectionAgent interface {
	ApplicationStatus(context.Context, types.ApplicationControlReq) (types.ApplicationObservedState, error)
}

type ConvergeSubscriptionWorker struct {
	river.WorkerDefaults[ConvergeSubscriptionArgs]
	db    *sql.DB
	agent SubscriptionConvergenceAgent
	river *river.Client[*sql.Tx]
}

func (w *ConvergeSubscriptionWorker) SetRiverClient(client *river.Client[*sql.Tx]) { w.river = client }

type ConvergeApplicationWorker struct {
	river.WorkerDefaults[ConvergeApplicationArgs]
	db      *sql.DB
	agent   SubscriptionConvergenceAgent
	secrets *serveradmin.Store
}

func NewConvergeApplicationWorker(db *sql.DB, agent SubscriptionConvergenceAgent, secrets ...*serveradmin.Store) *ConvergeApplicationWorker {
	worker := &ConvergeApplicationWorker{db: db, agent: agent}
	if len(secrets) > 0 {
		worker.secrets = secrets[0]
	}
	return worker
}

func (w *ConvergeApplicationWorker) Work(ctx context.Context, job *river.Job[ConvergeApplicationArgs]) error {
	if w.db == nil || w.agent == nil {
		return errors.New("application convergence is not configured")
	}
	if job.Args.ApplicationID <= 0 || job.Args.Revision <= 0 {
		return errors.New("application convergence requires an id and revision")
	}
	unlock := lockApplicationConvergence(job.Args.ApplicationID)
	defer unlock()
	var subscriptionID, appliedRevision int64
	var convergenceStatus string
	if err := w.db.QueryRowContext(ctx, `SELECT subscription_id,applied_revision,convergence_status
FROM application_instances WHERE id=$1`, job.Args.ApplicationID).
		Scan(&subscriptionID, &appliedRevision, &convergenceStatus); err != nil {
		return err
	}
	if job.Args.SubscriptionRevision == 0 &&
		applicationObservationJobAlreadyConverged(job.Args.Revision, appliedRevision, convergenceStatus) {
		return nil
	}
	snapshot, err := loadSubscriptionConvergence(ctx, w.db, subscriptionID)
	if err != nil {
		return err
	}
	for _, application := range snapshot.Applications {
		if application.Request.ApplicationID != job.Args.ApplicationID {
			continue
		}
		if application.Revision != job.Args.Revision {
			// A newer desired revision superseded this job while it was queued.
			return nil
		}
		application.Request.DesiredRevision = application.Revision
		if err = w.loadApplicationSecrets(ctx, &application.Request); err != nil {
			return w.failApplicationGeneration(ctx, job.Args, err)
		}
		if _, err = w.db.ExecContext(ctx, `INSERT INTO application_generations(
application_id,desired_revision,image_ref,endpoint_port,status,started_at)
VALUES($1,$2,$3,$4,'starting',now())
ON CONFLICT(application_id,desired_revision) DO UPDATE
SET status='starting',health_message='',started_at=now(),finished_at=NULL`,
			job.Args.ApplicationID, job.Args.Revision, application.Request.ImageRef, application.Request.Endpoint.HostPort); err != nil {
			return err
		}

		var result types.DeployApplicationGenerationResult
		var workErr error
		if generationAgent, ok := w.agent.(ApplicationGenerationAgent); ok {
			result, workErr = generationAgent.DeployApplicationGeneration(ctx, application.Request)
		} else {
			var resp types.Response
			resp, workErr = w.agent.EnsureApplication(ctx, application.Request)
			if workErr == nil && !resp.OK {
				workErr = errors.New(resp.Error)
			}
			if workErr == nil {
				observed := "stopped"
				if application.Request.DesiredState == "running" {
					observed = "healthy"
				}
				result = types.DeployApplicationGenerationResult{ApplicationObservedState: types.ApplicationObservedState{
					ApplicationID:  application.Request.ApplicationID,
					ActiveRevision: application.Revision,
					EndpointPort:   application.Request.Endpoint.HostPort,
					ObservedState:  observed,
					DesiredState:   application.Request.DesiredState,
					ObservedAt:     time.Now().UTC(),
				}, Changed: true}
			}
		}
		if workErr != nil {
			// A generation failure has already been rolled back by the agent.
			// Cancel this River attempt so an unhealthy immutable revision is
			// not recreated immediately. A user reconciliation or the periodic
			// observer may enqueue a fresh attempt later.
			return terminalApplicationConvergenceError(w.failApplicationGeneration(ctx, job.Args, workErr))
		}
		if application.Request.Remove {
			_, err = w.db.ExecContext(ctx, `DELETE FROM application_instances
WHERE id=$1 AND delete_requested=true AND desired_revision=$2`, job.Args.ApplicationID, job.Args.Revision)
			return err
		}
		return w.completeApplicationGeneration(ctx, job.Args, application.Request, result)
	}
	return sql.ErrNoRows
}

func applicationObservationJobAlreadyConverged(desiredRevision, appliedRevision int64, status string) bool {
	return desiredRevision > 0 && desiredRevision == appliedRevision && status == "in_sync"
}

func terminalApplicationConvergenceError(err error) error {
	return river.JobCancel(err)
}

func (w *ConvergeApplicationWorker) loadApplicationSecrets(ctx context.Context, request *types.EnsureApplicationReq) error {
	rows, err := w.db.QueryContext(ctx, `SELECT name FROM application_secret_bindings WHERE application_id=$1 ORDER BY name`, request.ApplicationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(names) == 0 {
		return nil
	}
	if w.secrets == nil {
		return errors.New("application secret decryption is not configured")
	}
	request.Secrets = make(map[string]string, len(names))
	for _, name := range names {
		secretName := "app-" + fmt.Sprintf("%d", request.ApplicationID) + "-env-" +
			strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		plaintext, _, err := w.secrets.GetSecret(ctx, "application", secretName)
		if err != nil {
			return err
		}
		request.Secrets[name] = string(plaintext)
	}
	return nil
}

func (w *ConvergeApplicationWorker) failApplicationGeneration(ctx context.Context, args ConvergeApplicationArgs, cause error) error {
	message := truncateConvergenceOutput(cause.Error())
	_, generationErr := w.db.ExecContext(ctx, `UPDATE application_generations
SET status='failed',health_message=$3,finished_at=now()
WHERE application_id=$1 AND desired_revision=$2`, args.ApplicationID, args.Revision, message)
	_, markErr := w.db.ExecContext(ctx, `UPDATE application_instances
SET convergence_status='failed',observed_state='failed',observed_message=$2,observed_at=now(),
last_reconciled_at=now(),last_error=$2,updated_at=now()
WHERE id=$1 AND desired_revision=$3`, args.ApplicationID, message, args.Revision)
	return errors.Join(cause, generationErr, markErr)
}

func (w *ConvergeApplicationWorker) completeApplicationGeneration(
	ctx context.Context,
	args ConvergeApplicationArgs,
	request types.EnsureApplicationReq,
	result types.DeployApplicationGenerationResult,
) error {
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	status := "healthy"
	if request.DesiredState != "running" {
		status = "retired"
	}
	endpointPort := applicationGenerationEndpointPort(request, result)
	if _, err = tx.ExecContext(ctx, `UPDATE application_generations
SET endpoint_port=$3,unit_name=$4,container_name=$5,status=$6,health_message=$7,
healthy_at=CASE WHEN $6='healthy' THEN now() ELSE healthy_at END,finished_at=CASE WHEN $6='retired' THEN now() ELSE NULL END
WHERE application_id=$1 AND desired_revision=$2`, args.ApplicationID, args.Revision, endpointPort,
		result.UnitName, result.ContainerName, status, result.Message); err != nil {
		return err
	}
	if status == "healthy" {
		if _, err = tx.ExecContext(ctx, `UPDATE application_generations
SET status='retired',finished_at=now()
WHERE application_id=$1 AND desired_revision<>$2 AND status='healthy'`, args.ApplicationID, args.Revision); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE application_instances
SET endpoint_port=$3,active_generation=$4,applied_state=$5,applied_revision=$2,
convergence_status='in_sync',observed_state=$6,observed_message=$7,observed_at=now(),
last_reconciled_at=now(),last_error='',updated_at=now()
WHERE id=$1 AND desired_revision=$2`, args.ApplicationID, args.Revision, endpointPort,
		result.ActiveRevision, request.DesiredState, result.ObservedState, result.Message)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func applicationGenerationEndpointPort(request types.EnsureApplicationReq, result types.DeployApplicationGenerationResult) int {
	if result.EndpointPort >= 20000 && result.EndpointPort <= 29999 {
		return result.EndpointPort
	}
	return request.Endpoint.HostPort
}

func NewConvergeSubscriptionWorker(db *sql.DB, agent SubscriptionConvergenceAgent) *ConvergeSubscriptionWorker {
	return &ConvergeSubscriptionWorker{db: db, agent: agent}
}

type ConvergePendingSubscriptionsWorker struct {
	river.WorkerDefaults[ConvergePendingSubscriptionsArgs]
	db    *sql.DB
	river *river.Client[*sql.Tx]
}

type ReconcileApplicationsWorker struct {
	river.WorkerDefaults[ReconcileApplicationsArgs]
	db    *sql.DB
	agent ApplicationInspectionAgent
	river *river.Client[*sql.Tx]
}

func NewReconcileApplicationsWorker(db *sql.DB, agent ApplicationInspectionAgent) *ReconcileApplicationsWorker {
	return &ReconcileApplicationsWorker{db: db, agent: agent}
}

func (w *ReconcileApplicationsWorker) SetRiverClient(client *river.Client[*sql.Tx]) {
	w.river = client
}

func (w *ReconcileApplicationsWorker) Work(ctx context.Context, _ *river.Job[ReconcileApplicationsArgs]) error {
	if w.db == nil || w.agent == nil || w.river == nil {
		return errors.New("application observation is not configured")
	}
	rows, err := w.db.QueryContext(ctx, `SELECT application.id,application.subscription_id,account.username,
CASE WHEN application.desired_state='running' AND account.desired_state='active' AND site.desired_status='active'
     THEN 'running' ELSE 'stopped' END,
application.desired_revision,application.convergence_status,
application.active_generation,application.endpoint_port,application.container_port,application.health_kind,application.health_path
FROM application_instances application
JOIN subscription_system_accounts account ON account.subscription_id=application.subscription_id
JOIN sites site ON site.id=application.site_id AND site.subscription_id=application.subscription_id
WHERE application.runtime='oci' AND NOT application.delete_requested
ORDER BY application.id LIMIT 250`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type candidate struct {
		id, subscriptionID, revision, activeRevision int64
		username, desired, convergence               string
		endpointPort, containerPort                  int
		healthKind, healthPath                       string
	}
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.subscriptionID, &item.username, &item.desired,
			&item.revision, &item.convergence, &item.activeRevision, &item.endpointPort, &item.containerPort,
			&item.healthKind, &item.healthPath); err != nil {
			return err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range candidates {
		observed, inspectErr := w.agent.ApplicationStatus(ctx, types.ApplicationControlReq{
			ApplicationID: item.id, SubscriptionID: item.subscriptionID, Username: item.username,
			ActiveRevision: item.activeRevision,
			Endpoint:       types.ApplicationEndpointSpec{HostPort: item.endpointPort, ContainerPort: item.containerPort},
			Health:         types.ApplicationHealthSpec{Kind: item.healthKind, Path: item.healthPath, TimeoutSeconds: 2},
		})
		if inspectErr != nil {
			_, _ = w.db.ExecContext(ctx, `UPDATE application_instances
SET observed_state='failed',observed_message=$2,observed_at=now(),last_reconciled_at=now()
WHERE id=$1`, item.id, truncateConvergenceOutput(inspectErr.Error()))
			continue
		}
		_, err = w.db.ExecContext(ctx, `UPDATE application_instances
SET observed_state=$2,observed_message=$3,observed_at=now(),last_reconciled_at=now()
WHERE id=$1`, item.id, observed.ObservedState, truncateConvergenceOutput(observed.Message))
		if err != nil {
			return err
		}
		drifted := item.desired == "running" && observed.ObservedState != "healthy"
		drifted = drifted || item.desired == "stopped" && observed.ObservedState != "stopped" && observed.ObservedState != "missing"
		if drifted || item.convergence == "pending" || item.convergence == "failed" {
			if drifted {
				if _, err = w.db.ExecContext(ctx, `UPDATE application_instances
SET convergence_status='pending',last_error='',updated_at=now()
WHERE id=$1 AND desired_revision=$2`, item.id, item.revision); err != nil {
					return err
				}
			}
			if _, err = w.river.Insert(ctx, ConvergeApplicationArgs{
				ApplicationID: item.id, Revision: item.revision,
			}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func NewConvergePendingSubscriptionsWorker(db *sql.DB) *ConvergePendingSubscriptionsWorker {
	return &ConvergePendingSubscriptionsWorker{db: db}
}

type SweepLegacyAccountMigrationsWorker struct {
	river.WorkerDefaults[SweepLegacyAccountMigrationsArgs]
	db    *sql.DB
	river *river.Client[*sql.Tx]
}

type SweepLegacyAccountCleanupWorker struct {
	river.WorkerDefaults[SweepLegacyAccountCleanupArgs]
	db    *sql.DB
	river *river.Client[*sql.Tx]
}

func NewSweepLegacyAccountCleanupWorker(db *sql.DB) *SweepLegacyAccountCleanupWorker {
	return &SweepLegacyAccountCleanupWorker{db: db}
}
func (w *SweepLegacyAccountCleanupWorker) SetRiverClient(client *river.Client[*sql.Tx]) {
	w.river = client
}
func (w *SweepLegacyAccountCleanupWorker) Work(ctx context.Context, _ *river.Job[SweepLegacyAccountCleanupArgs]) error {
	if w.db == nil || w.river == nil {
		return errors.New("legacy account cleanup sweep is not configured")
	}
	rows, err := w.db.QueryContext(ctx, `SELECT subscription_id FROM subscription_system_accounts WHERE cleanup_after<=now() AND jsonb_array_length(legacy_homes)>0 ORDER BY id LIMIT 25`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var subscriptionID int64
		if err := rows.Scan(&subscriptionID); err != nil {
			return err
		}
		if _, err := w.river.Insert(ctx, CleanupLegacyHomesArgs{SubscriptionID: subscriptionID}, nil); err != nil {
			return err
		}
	}
	return rows.Err()
}

type CleanupLegacyHomesWorker struct {
	river.WorkerDefaults[CleanupLegacyHomesArgs]
	db    *sql.DB
	agent SubscriptionConvergenceAgent
}

func NewCleanupLegacyHomesWorker(db *sql.DB, agent SubscriptionConvergenceAgent) *CleanupLegacyHomesWorker {
	return &CleanupLegacyHomesWorker{db: db, agent: agent}
}
func (w *CleanupLegacyHomesWorker) Work(ctx context.Context, job *river.Job[CleanupLegacyHomesArgs]) error {
	if w.db == nil || w.agent == nil {
		return errors.New("legacy account cleanup is not configured")
	}
	var homePath string
	var homesRaw []byte
	if err := w.db.QueryRowContext(ctx, `SELECT home_path,legacy_homes FROM subscription_system_accounts WHERE subscription_id=$1 AND cleanup_after<=now() FOR UPDATE`, job.Args.SubscriptionID).Scan(&homePath, &homesRaw); err != nil {
		return err
	}
	var homes []string
	if err := json.Unmarshal(homesRaw, &homes); err != nil {
		return err
	}
	resp, err := w.agent.CleanupLegacyHomes(ctx, types.CleanupLegacyHomesReq{SubscriptionID: job.Args.SubscriptionID, ActiveHome: homePath, LegacyHomes: homes})
	if err != nil || !resp.OK {
		if err == nil {
			err = errors.New(resp.Error)
		}
		_, markErr := w.db.ExecContext(ctx, `UPDATE subscription_system_accounts SET migration_error=$2,updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID, err.Error())
		return errors.Join(err, markErr)
	}
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE subscription_system_accounts SET legacy_homes='[]'::jsonb,cleanup_after=NULL,migration_error='',updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata)
SELECT scheduler.id,sub.customer_id,sub.id,'subscription.legacy_homes_deleted','subscription',sub.id,jsonb_build_object('homes',$2::jsonb)
FROM subscriptions sub CROSS JOIN LATERAL(SELECT id FROM users WHERE email='scheduler@nakpanel.internal') scheduler WHERE sub.id=$1`, job.Args.SubscriptionID, homesRaw); err != nil {
		return err
	}
	return tx.Commit()
}

func NewSweepLegacyAccountMigrationsWorker(db *sql.DB) *SweepLegacyAccountMigrationsWorker {
	return &SweepLegacyAccountMigrationsWorker{db: db}
}
func (w *SweepLegacyAccountMigrationsWorker) SetRiverClient(client *river.Client[*sql.Tx]) {
	w.river = client
}
func (w *SweepLegacyAccountMigrationsWorker) Work(ctx context.Context, _ *river.Job[SweepLegacyAccountMigrationsArgs]) error {
	if w.db == nil || w.river == nil {
		return errors.New("legacy account migration sweep is not configured")
	}
	rows, err := w.db.QueryContext(ctx, `SELECT subscription_id FROM subscription_system_accounts
WHERE migration_status='legacy' OR (migration_status='failed' AND updated_at<now()-interval '15 minutes') ORDER BY id LIMIT 10`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if _, err := w.river.Insert(ctx, MigrateSubscriptionAccountArgs{SubscriptionID: id}, nil); err != nil {
			return err
		}
	}
	return rows.Err()
}

type MigrateSubscriptionAccountWorker struct {
	river.WorkerDefaults[MigrateSubscriptionAccountArgs]
	db    *sql.DB
	agent SubscriptionConvergenceAgent
	river *river.Client[*sql.Tx]
}

func NewMigrateSubscriptionAccountWorker(db *sql.DB, agent SubscriptionConvergenceAgent) *MigrateSubscriptionAccountWorker {
	return &MigrateSubscriptionAccountWorker{db: db, agent: agent}
}
func (w *MigrateSubscriptionAccountWorker) SetRiverClient(client *river.Client[*sql.Tx]) {
	w.river = client
}
func (w *MigrateSubscriptionAccountWorker) Work(ctx context.Context, job *river.Job[MigrateSubscriptionAccountArgs]) error {
	if w.db == nil || w.agent == nil || w.river == nil {
		return errors.New("legacy account migration is not configured")
	}
	snapshot, err := loadSubscriptionConvergence(ctx, w.db, job.Args.SubscriptionID)
	if err != nil {
		return err
	}
	rows, err := w.db.QueryContext(ctx, `SELECT id,domain,username,php_version FROM sites WHERE subscription_id=$1 ORDER BY id`, job.Args.SubscriptionID)
	if err != nil {
		return err
	}
	request := types.MigrateSubscriptionAccountReq{SubscriptionID: job.Args.SubscriptionID, Username: snapshot.Account.Username, HomePath: snapshot.Account.HomePath, Policy: snapshot.Account.Policy}
	for rows.Next() {
		var item types.LegacySiteMigration
		if err := rows.Scan(&item.SiteID, &item.Domain, &item.LegacyUsername, &item.PHPVersion); err != nil {
			rows.Close()
			return err
		}
		item.LegacyHome = "/home/" + item.LegacyUsername
		item.LegacyDocroot = item.LegacyHome + "/public_html"
		item.TargetDocroot = snapshot.Account.HomePath + "/domains/" + item.Domain + "/public_html"
		request.Sites = append(request.Sites, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(request.Sites) == 0 {
		tx, txErr := w.db.BeginTx(ctx, nil)
		if txErr != nil {
			return txErr
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, `UPDATE subscription_system_accounts SET migration_status='complete',migrated_at=now(),updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID); err != nil {
			return err
		}
		if _, err = EnqueueSubscriptionConvergenceTx(ctx, tx, w.river, job.Args.SubscriptionID); err != nil {
			return err
		}
		return tx.Commit()
	}
	if _, err = w.db.ExecContext(ctx, `UPDATE subscription_system_accounts SET migration_status='preflight',migration_error='',updated_at=now() WHERE subscription_id=$1 AND migration_status IN('legacy','failed','preflight')`, job.Args.SubscriptionID); err != nil {
		return err
	}
	if _, err = w.db.ExecContext(ctx, `UPDATE subscription_system_accounts SET migration_status='copying',updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID); err != nil {
		return err
	}
	resp, err := w.agent.MigrateSubscriptionAccount(ctx, request)
	if err != nil || !resp.OK {
		if err == nil {
			err = errors.New(resp.Error)
		}
		_, markErr := w.db.ExecContext(ctx, `UPDATE subscription_system_accounts SET migration_status='failed',migration_error=$2,updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID, err.Error())
		return errors.Join(err, markErr)
	}
	var result types.MigrateSubscriptionAccountResult
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return err
	}
	legacy, _ := json.Marshal(result.LegacyHomes)
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE sites site SET username=account.username,document_root=account.home_path||'/domains/'||site.domain||'/public_html',updated_at=now() FROM subscription_system_accounts account WHERE site.subscription_id=$1 AND account.subscription_id=site.subscription_id`, job.Args.SubscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE subscription_system_accounts SET migration_status='complete',migration_error='',legacy_homes=$2,migrated_at=now(),cleanup_after=now()+interval '7 days',updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID, legacy); err != nil {
		return err
	}
	if _, err = EnqueueSubscriptionConvergenceTx(ctx, tx, w.river, job.Args.SubscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata)
SELECT scheduler.id,sub.customer_id,sub.id,'subscription.account_migrated','subscription',sub.id,jsonb_build_object('snapshot_path',$2::text)
FROM subscriptions sub CROSS JOIN LATERAL(SELECT id FROM users WHERE email='scheduler@nakpanel.internal') scheduler WHERE sub.id=$1`, job.Args.SubscriptionID, result.SnapshotPath); err != nil {
		return err
	}
	return tx.Commit()
}

func (w *ConvergePendingSubscriptionsWorker) SetRiverClient(client *river.Client[*sql.Tx]) {
	w.river = client
}

func (w *ConvergePendingSubscriptionsWorker) Work(ctx context.Context, _ *river.Job[ConvergePendingSubscriptionsArgs]) error {
	if w.db == nil || w.river == nil {
		return errors.New("pending subscription convergence is not configured")
	}
	rows, err := w.db.QueryContext(ctx, `SELECT subscription_id,desired_revision FROM subscription_system_accounts
WHERE convergence_status='pending' AND migration_status IN('pending','complete') ORDER BY id LIMIT 100`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, revision int64
		if err := rows.Scan(&id, &revision); err != nil {
			return err
		}
		if _, err := w.river.Insert(ctx, newConvergeSubscriptionArgs(id, revision), nil); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (w *ConvergeSubscriptionWorker) Work(ctx context.Context, job *river.Job[ConvergeSubscriptionArgs]) error {
	if w.db == nil || w.agent == nil || w.river == nil {
		return errors.New("subscription convergence is not configured")
	}
	unlock := lockSubscriptionConvergence(job.Args.SubscriptionID)
	defer unlock()

	var migrationStatus string
	if err := w.db.QueryRowContext(ctx, `SELECT migration_status FROM subscription_system_accounts WHERE subscription_id=$1`, job.Args.SubscriptionID).Scan(&migrationStatus); err != nil {
		return err
	}
	if migrationStatus != "pending" && migrationStatus != "complete" {
		return nil
	}
	snapshot, err := loadSubscriptionConvergence(ctx, w.db, job.Args.SubscriptionID)
	if err != nil {
		return err
	}
	runtimeCandidates, err := prepareRuntimeGenerations(ctx, w.db, snapshot.Account.Domains)
	if err != nil {
		return err
	}
	resp, err := w.agent.EnsureSubscriptionAccount(ctx, snapshot.Account)
	if err != nil {
		_ = failRuntimeGenerations(ctx, w.db, runtimeCandidates, err.Error())
		return errors.Join(err, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", err.Error(), 0))
	}
	if !resp.OK {
		err = fmt.Errorf("agent account convergence failed: %s", resp.Error)
		_ = failRuntimeGenerations(ctx, w.db, runtimeCandidates, err.Error())
		return errors.Join(err, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", err.Error(), 0))
	}
	if err = activateRuntimeGenerations(ctx, w.db, runtimeCandidates); err != nil {
		return errors.Join(err, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", err.Error(), 0))
	}
	var result types.EnsureSubscriptionAccountResult
	if err = json.Unmarshal(resp.Data, &result); err != nil {
		return errors.Join(err, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", err.Error(), 0))
	}
	resp, err = w.agent.ApplyScheduledTasks(ctx, types.ApplyScheduledTasksReq{
		SubscriptionID: job.Args.SubscriptionID, Username: snapshot.Account.Username,
		HomePath: snapshot.Account.HomePath, Tasks: snapshot.Account.Tasks,
	})
	if err != nil || !resp.OK {
		if err == nil {
			err = errors.New(resp.Error)
		}
		_, _ = w.db.ExecContext(ctx, `UPDATE scheduled_tasks SET convergence_status='failed',last_error=$2,updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID, err.Error())
		return errors.Join(err, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", err.Error(), result.LinuxUID))
	}
	if _, err = w.db.ExecContext(ctx, `UPDATE scheduled_tasks SET convergence_status='in_sync',last_error='',updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID); err != nil {
		return errors.Join(err, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", err.Error(), result.LinuxUID))
	}
	if snapshot.FTPS != nil {
		if _, err = w.agent.EnsureFTPS(ctx, *snapshot.FTPS); err != nil {
			_, _ = w.db.ExecContext(ctx, `UPDATE ftp_accounts SET convergence_status='failed',last_error=$1,updated_at=now()`, err.Error())
			return errors.Join(err, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", err.Error(), result.LinuxUID))
		}
		if _, err = w.db.ExecContext(ctx, `UPDATE ftp_accounts SET convergence_status='in_sync',last_error='',updated_at=now()`); err != nil {
			return err
		}
	}
	if snapshot.Valkey != nil {
		valkeyResult, valkeyErr := w.agent.EnsureValkey(ctx, *snapshot.Valkey)
		if valkeyErr != nil {
			_, _ = w.db.ExecContext(ctx, `UPDATE valkey_instances SET applied_state='failed',convergence_status='failed',last_error=$2,updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID, valkeyErr.Error())
			return errors.Join(valkeyErr, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", valkeyErr.Error(), result.LinuxUID))
		}
		applied := "stopped"
		if valkeyResult.Running {
			applied = "running"
		}
		if snapshot.Valkey.Flush && !valkeyResult.Flushed {
			err = errors.New("Valkey flush was not acknowledged by the agent")
			return errors.Join(err, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", err.Error(), result.LinuxUID))
		}
		if _, err = w.db.ExecContext(ctx, `UPDATE valkey_instances SET applied_state=$2,socket_path=$3,flush_requested=false,convergence_status='in_sync',last_error='',updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID, applied, valkeyResult.SocketPath); err != nil {
			return err
		}
	}
	if len(snapshot.Git) > 0 {
		gitAgent, ok := w.agent.(GitConvergenceAgent)
		if !ok {
			err = errors.New("Git convergence is not configured")
			return errors.Join(err, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", err.Error(), result.LinuxUID))
		}
		for _, repository := range snapshot.Git {
			var deploymentID sql.NullInt64
			deploymentErr := w.db.QueryRowContext(ctx, `WITH next AS (
    SELECT id FROM git_deployments WHERE repository_id=$1 AND status='pending' ORDER BY id LIMIT 1
)
UPDATE git_deployments deployment SET status='running',rollback_revision=repository.last_revision
FROM next,git_repositories repository
WHERE deployment.id=next.id AND repository.id=$1
RETURNING deployment.id`, repository.RepositoryID).Scan(&deploymentID)
			if deploymentErr != nil && !errors.Is(deploymentErr, sql.ErrNoRows) {
				return deploymentErr
			}
			runAgent, deploy := gitConvergenceAction(repository.Mode, repository.Automatic, deploymentID.Valid)
			if !runAgent {
				if _, err = w.db.ExecContext(ctx, `UPDATE git_repositories SET convergence_status='in_sync',last_error='',updated_at=now() WHERE id=$1`, repository.RepositoryID); err != nil {
					return err
				}
				continue
			}
			repository.Deploy = deploy
			gitResult, gitErr := gitAgent.EnsureGitRepository(ctx, repository)
			if gitErr != nil {
				_, _ = w.db.ExecContext(ctx, `UPDATE git_repositories SET convergence_status='failed',last_error=$2,updated_at=now() WHERE id=$1`, repository.RepositoryID, gitErr.Error())
				if deploymentID.Valid {
					_, _ = w.db.ExecContext(ctx, `UPDATE git_deployments SET status='failed',output=$2,finished_at=now() WHERE id=$1`, deploymentID.Int64, truncateConvergenceOutput(gitErr.Error()))
				}
				return errors.Join(gitErr, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", gitErr.Error(), result.LinuxUID))
			}
			if _, err = w.db.ExecContext(ctx, `UPDATE git_repositories SET convergence_status='in_sync',last_revision=COALESCE(NULLIF($2,''),last_revision),deploy_public_key=COALESCE(NULLIF($3,''),deploy_public_key),last_error='',updated_at=now() WHERE id=$1`,
				repository.RepositoryID, gitResult.Revision, gitResult.DeployPublicKey); err != nil {
				return err
			}
			if deploymentID.Valid {
				if gitResult.Revision == "" {
					if _, err = w.db.ExecContext(ctx, `UPDATE git_deployments SET status='failed',output='The hosted branch has no commits to deploy.',finished_at=now() WHERE id=$1`, deploymentID.Int64); err != nil {
						return err
					}
					continue
				}
				if _, err = w.db.ExecContext(ctx, `UPDATE git_deployments SET revision=$2,status='succeeded',output='',finished_at=now() WHERE id=$1`, deploymentID.Int64, gitResult.Revision); err != nil {
					return err
				}
			}
		}
	}
	if len(snapshot.ProtectedDirectories) > 0 {
		protectedAgent, ok := w.agent.(ProtectedDirectoryConvergenceAgent)
		if !ok {
			err = errors.New("protected-directory convergence is not configured")
			return errors.Join(err, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", err.Error(), result.LinuxUID))
		}
		for _, siteConfig := range snapshot.ProtectedDirectories {
			if _, protectedErr := protectedAgent.EnsureProtectedDirectories(ctx, siteConfig); protectedErr != nil {
				return errors.Join(protectedErr, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", protectedErr.Error(), result.LinuxUID))
			}
		}
	}
	if snapshot.MailDomainCount > 0 {
		// Mail is reconciled node-wide (one Stalwart config covers every
		// hosted domain), so hand off to the configure_mail singleton.
		if _, err = w.river.Insert(ctx, NewConfigureMailArgs(), nil); err != nil {
			return errors.Join(err, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", err.Error(), result.LinuxUID))
		}
	}
	for _, application := range snapshot.Applications {
		if _, err = w.river.Insert(ctx, ConvergeApplicationArgs{
			ApplicationID:        application.Request.ApplicationID,
			Revision:             application.Revision,
			SubscriptionRevision: snapshot.DesiredRevision,
		}, nil); err != nil {
			return errors.Join(err, w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "failed", err.Error(), result.LinuxUID))
		}
	}
	return w.markAccountConvergence(ctx, job.Args.SubscriptionID, snapshot.DesiredRevision, "in_sync", "", result.LinuxUID)
}

func gitConvergenceAction(mode string, automatic, hasPendingDeployment bool) (runAgent, deploy bool) {
	deploy = automatic || hasPendingDeployment
	return mode == "hosted" || mode == "remote", deploy
}

func truncateConvergenceOutput(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 8192 {
		return value[:8192]
	}
	return value
}

type convergenceSnapshot struct {
	DesiredRevision      int64
	Account              types.EnsureSubscriptionAccountReq
	MailDomainCount      int
	Applications         []applicationConvergence
	FTPS                 *types.EnsureFTPSReq
	Valkey               *types.EnsureValkeyReq
	Git                  []types.EnsureGitRepositoryReq
	ProtectedDirectories []types.EnsureProtectedDirectoriesReq
}

type applicationConvergence struct {
	Request  types.EnsureApplicationReq
	Revision int64
}

func effectiveApplicationState(accountState, desiredState string, permitted bool) string {
	if permitted && accountState == "active" && desiredState == "running" {
		return "running"
	}
	return "stopped"
}

func effectiveValkeyState(accountState, desiredState string, policy types.HostingPolicy) string {
	if !policy.Permissions.Valkey || !policy.Valkey.Enabled {
		return "disabled"
	}
	if desiredState != "enabled" {
		return "disabled"
	}
	if accountState == "active" {
		return "enabled"
	}
	return "suspended"
}

func effectiveFTPSAccountEnabled(lifecycleEnabled bool, policy types.HostingPolicy) bool {
	return lifecycleEnabled && policy.Permissions.FTPS && policy.Access.FTPSEnabled
}

func loadSubscriptionConvergence(ctx context.Context, db *sql.DB, subscriptionID int64) (convergenceSnapshot, error) {
	if subscriptionID <= 0 {
		return convergenceSnapshot{}, errors.New("subscription id is required")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return convergenceSnapshot{}, err
	}
	defer tx.Rollback()
	snapshot := convergenceSnapshot{}
	var account types.EnsureSubscriptionAccountReq
	var desiredState string
	err = tx.QueryRowContext(ctx, `SELECT account.subscription_id,account.username,account.home_path,account.desired_revision,
CASE WHEN sub.status='active' AND customer.status='active'
          AND (customer.reseller_id IS NULL OR (
              reseller.status='active' AND EXISTS (
                  SELECT 1 FROM reseller_subscriptions allocation
                  WHERE allocation.reseller_id=customer.reseller_id AND allocation.status='active'
              )
          ))
     THEN account.desired_state ELSE 'suspended' END
FROM subscription_system_accounts account
JOIN subscriptions sub ON sub.id=account.subscription_id
JOIN customers customer ON customer.id=sub.customer_id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
	WHERE account.subscription_id=$1`, subscriptionID).Scan(&account.SubscriptionID, &account.Username, &account.HomePath, &snapshot.DesiredRevision, &desiredState)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	account.State = desiredState
	entitlements, err := readSubscriptionEntitlementsTx(ctx, tx, subscriptionID)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	base := controlpolicy.DefaultFromEntitlements(entitlements)
	var storedPolicy, subscriptionPatch []byte
	err = tx.QueryRowContext(ctx, `SELECT e.hosting_policy,COALESCE(o.policy_patch,'{}'::jsonb)
FROM subscription_entitlements e LEFT JOIN subscription_policy_overrides o ON o.subscription_id=e.subscription_id
WHERE e.subscription_id=$1`, subscriptionID).Scan(&storedPolicy, &subscriptionPatch)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	if hasConfiguredPolicy(storedPolicy) {
		var configured types.HostingPolicy
		if err := json.Unmarshal(storedPolicy, &configured); err != nil {
			return convergenceSnapshot{}, err
		}
		base = configured
	}
	account.Policy, err = controlpolicy.Resolve(base, subscriptionPatch, nil)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	policyCache := map[int64]types.HostingPolicy{subscriptionID: account.Policy}
	policyForSubscription := func(candidateID int64) (types.HostingPolicy, error) {
		if policy, ok := policyCache[candidateID]; ok {
			return policy, nil
		}
		candidateBase, candidatePatch, loadErr := effectiveSubscriptionPolicyTx(ctx, tx, candidateID)
		if loadErr != nil {
			return types.HostingPolicy{}, loadErr
		}
		policy, resolveErr := controlpolicy.Resolve(candidateBase, candidatePatch, nil)
		if resolveErr != nil {
			return types.HostingPolicy{}, resolveErr
		}
		policyCache[candidateID] = policy
		return policy, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT site.id,site.domain,site.document_root,
CASE WHEN $2='active' AND site.desired_status='active' THEN 'active' ELSE 'suspended' END,
COALESCE(o.policy_patch,'{}'::jsonb)
FROM sites site LEFT JOIN site_policy_overrides o ON o.site_id=site.id
WHERE site.subscription_id=$1 ORDER BY site.id`, subscriptionID, desiredState)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	for rows.Next() {
		var domain types.SubscriptionDomain
		var sitePatch []byte
		if err := rows.Scan(&domain.SiteID, &domain.Domain, &domain.DocumentRoot, &domain.State, &sitePatch); err != nil {
			rows.Close()
			return convergenceSnapshot{}, err
		}
		domain.Policy, err = controlpolicy.Resolve(account.Policy, nil, sitePatch)
		if err != nil {
			rows.Close()
			return convergenceSnapshot{}, fmt.Errorf("site %d policy: %w", domain.SiteID, err)
		}
		if !domain.Policy.Permissions.Hosting {
			domain.State = "suspended"
		}
		account.Domains = append(account.Domains, domain)
	}
	if err := rows.Close(); err != nil {
		return convergenceSnapshot{}, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,name,public_key,relative_root,enabled FROM sftp_access_identities WHERE subscription_id=$1 ORDER BY id`, subscriptionID)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	for rows.Next() {
		var identity types.SFTPAccessIdentity
		if err := rows.Scan(&identity.ID, &identity.Name, &identity.PublicKey, &identity.RelativeRoot, &identity.Enabled); err != nil {
			rows.Close()
			return convergenceSnapshot{}, err
		}
		identity.Enabled = identity.Enabled && desiredState == "active" && account.Policy.Permissions.SFTP
		account.SFTPIdentities = append(account.SFTPIdentities, identity)
	}
	rows.Close()
	rows, err = tx.QueryContext(ctx, `SELECT task.id,COALESCE(task.site_id,0),COALESCE(site.domain,''),task.name,task.schedule,task.command,task.working_directory,task.timeout_seconds,task.enabled,task.kind,task.url,task.script_path,task.timezone
FROM scheduled_tasks task LEFT JOIN sites site ON site.id=task.site_id WHERE task.subscription_id=$1 ORDER BY task.id`, subscriptionID)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	for rows.Next() {
		var task types.ScheduledTask
		if err := rows.Scan(&task.ID, &task.SiteID, &task.Domain, &task.Name, &task.Schedule, &task.Command, &task.WorkingDirectory, &task.TimeoutSeconds, &task.Enabled, &task.Kind, &task.URL, &task.Script, &task.Timezone); err != nil {
			rows.Close()
			return convergenceSnapshot{}, err
		}
		task.Enabled = task.Enabled && desiredState == "active" && account.Policy.Permissions.ScheduledTasks
		account.Tasks = append(account.Tasks, task)
	}
	rows.Close()
	snapshot.Account = account
	ftps := types.EnsureFTPSReq{Revision: time.Now().UnixNano(), State: "suspended"}
	rows, err = tx.QueryContext(ctx, `SELECT ftp.id,ftp.subscription_id,account.username,COALESCE(ftp.site_id,0),COALESCE(site.domain,''),ftp.name,ftp.password_hash,
ftp.enabled AND sub.status='active' AND customer.status='active' AND (customer.reseller_id IS NULL OR reseller.status='active')
AND (customer.reseller_id IS NULL OR EXISTS (
    SELECT 1 FROM reseller_subscriptions allocation
    WHERE allocation.reseller_id=customer.reseller_id AND allocation.status='active'
))
FROM ftp_accounts ftp
JOIN subscriptions sub ON sub.id=ftp.subscription_id
JOIN customers customer ON customer.id=sub.customer_id
JOIN subscription_system_accounts account ON account.subscription_id=sub.id
LEFT JOIN sites site ON site.id=ftp.site_id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
ORDER BY ftp.id`)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	type pendingFTPSAccount struct {
		account          types.EnsureFTPSAccount
		subscriptionID   int64
		lifecycleEnabled bool
	}
	pendingFTPSAccounts := make([]pendingFTPSAccount, 0)
	for rows.Next() {
		var pending pendingFTPSAccount
		if err := rows.Scan(&pending.account.ID, &pending.subscriptionID, &pending.account.Username, &pending.account.SiteID, &pending.account.Domain, &pending.account.Name, &pending.account.PasswordHash, &pending.lifecycleEnabled); err != nil {
			rows.Close()
			return convergenceSnapshot{}, err
		}
		pendingFTPSAccounts = append(pendingFTPSAccounts, pending)
	}
	if err := rows.Close(); err != nil {
		return convergenceSnapshot{}, err
	}
	// FTPS configuration is node-wide, so rows can belong to subscriptions
	// other than the one being converged. Close the active result set before
	// loading those subscriptions' policies from the same transaction.
	for _, pending := range pendingFTPSAccounts {
		itemPolicy, policyErr := policyForSubscription(pending.subscriptionID)
		if policyErr != nil {
			return convergenceSnapshot{}, policyErr
		}
		pending.account.Enabled = effectiveFTPSAccountEnabled(pending.lifecycleEnabled, itemPolicy)
		if pending.account.Enabled {
			ftps.State = "active"
		}
		ftps.Accounts = append(ftps.Accounts, pending.account)
	}
	snapshot.FTPS = &ftps
	var valkey types.EnsureValkeyReq
	err = tx.QueryRowContext(ctx, `SELECT instance.subscription_id,account.username,instance.desired_state,
instance.memory_mb,instance.max_clients,instance.idle_timeout_seconds,instance.cpu_percent,instance.process_limit,instance.acl_hash,instance.flush_requested
FROM valkey_instances instance JOIN subscription_system_accounts account ON account.subscription_id=instance.subscription_id
WHERE instance.subscription_id=$1`, subscriptionID).Scan(
		&valkey.SubscriptionID, &valkey.Username, &valkey.State, &valkey.MemoryMB, &valkey.MaxClients,
		&valkey.IdleTimeout, &valkey.CPUPercent, &valkey.ProcessLimit, &valkey.ACLHash, &valkey.Flush,
	)
	if err == nil {
		valkey.State = effectiveValkeyState(desiredState, valkey.State, account.Policy)
		snapshot.Valkey = &valkey
	} else if !errors.Is(err, sql.ErrNoRows) {
		return convergenceSnapshot{}, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mail_domains WHERE subscription_id=$1`, subscriptionID).Scan(&snapshot.MailDomainCount); err != nil {
		return convergenceSnapshot{}, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT application.id,application.subscription_id,application.site_id,site.domain,application.name,
application.runtime,application.image_ref,application.desired_state,
application.delete_requested,application.environment,application.desired_revision,
application.route_mode,application.route_prefix,application.container_port,application.endpoint_port,
application.health_kind,application.health_path,application.health_timeout_seconds,site.desired_status
FROM application_instances application
JOIN sites site ON site.id=application.site_id AND site.subscription_id=application.subscription_id
WHERE application.subscription_id=$1 ORDER BY application.id`, subscriptionID)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	for rows.Next() {
		var item applicationConvergence
		var environment []byte
		var applicationDesiredState, siteDesiredState string
		if err := rows.Scan(
			&item.Request.ApplicationID, &item.Request.SubscriptionID, &item.Request.SiteID, &item.Request.Domain, &item.Request.Name,
			&item.Request.Runtime, &item.Request.ImageRef, &applicationDesiredState,
			&item.Request.Remove, &environment, &item.Revision,
			&item.Request.Endpoint.RouteMode, &item.Request.Endpoint.RoutePrefix, &item.Request.Endpoint.ContainerPort,
			&item.Request.Endpoint.HostPort, &item.Request.Health.Kind, &item.Request.Health.Path,
			&item.Request.Health.TimeoutSeconds, &siteDesiredState,
		); err != nil {
			rows.Close()
			return convergenceSnapshot{}, err
		}
		if err := json.Unmarshal(environment, &item.Request.Environment); err != nil {
			rows.Close()
			return convergenceSnapshot{}, err
		}
		item.Request.DesiredState = effectiveApplicationState(desiredState, applicationDesiredState,
			account.Policy.Permissions.Applications && siteDesiredState == "active")
		item.Request.Username, item.Request.Policy = account.Username, account.Policy
		snapshot.Applications = append(snapshot.Applications, item)
	}
	if err := rows.Close(); err != nil {
		return convergenceSnapshot{}, err
	}
	applicationIndex := make(map[int64]int, len(snapshot.Applications))
	for index := range snapshot.Applications {
		applicationIndex[snapshot.Applications[index].Request.ApplicationID] = index
	}
	rows, err = tx.QueryContext(ctx, `SELECT volume.application_id,volume.name,volume.container_path,volume.size_mb,volume.read_only
FROM application_volumes volume JOIN application_instances application ON application.id=volume.application_id
WHERE application.subscription_id=$1 ORDER BY volume.application_id,volume.id`, subscriptionID)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	for rows.Next() {
		var applicationID int64
		var volume types.ApplicationVolumeSpec
		if err := rows.Scan(&applicationID, &volume.Name, &volume.Target, &volume.SizeMB, &volume.ReadOnly); err != nil {
			rows.Close()
			return convergenceSnapshot{}, err
		}
		if index, ok := applicationIndex[applicationID]; ok {
			snapshot.Applications[index].Request.Volumes = append(snapshot.Applications[index].Request.Volumes, volume)
		}
	}
	if err := rows.Close(); err != nil {
		return convergenceSnapshot{}, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT repository.id,site.id,account.username,site.domain,repository.mode,
repository.remote_url,repository.branch,repository.deploy_target,repository.automatic,repository.known_host_key,
CASE WHEN $2='active' AND site.desired_status='active' THEN 'active' ELSE 'suspended' END
FROM git_repositories repository
JOIN sites site ON site.id=repository.site_id
JOIN subscription_system_accounts account ON account.subscription_id=site.subscription_id
WHERE site.subscription_id=$1 ORDER BY repository.id`, subscriptionID, desiredState)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	for rows.Next() {
		var item types.EnsureGitRepositoryReq
		if err := rows.Scan(&item.RepositoryID, &item.SiteID, &item.Username, &item.Domain, &item.Mode,
			&item.RemoteURL, &item.Branch, &item.DeployTarget, &item.Automatic, &item.KnownHostKey, &item.State); err != nil {
			rows.Close()
			return convergenceSnapshot{}, err
		}
		if !account.Policy.Permissions.Git {
			item.State = "suspended"
		}
		snapshot.Git = append(snapshot.Git, item)
	}
	if err := rows.Close(); err != nil {
		return convergenceSnapshot{}, err
	}
	for _, domain := range account.Domains {
		item := types.EnsureProtectedDirectoriesReq{
			SiteID: domain.SiteID, Username: account.Username, Domain: domain.Domain,
		}
		protectedRows, queryErr := tx.QueryContext(ctx, `SELECT id,relative_path,realm,username,password_hash,enabled
FROM protected_directories WHERE site_id=$1 ORDER BY id`, domain.SiteID)
		if queryErr != nil {
			return convergenceSnapshot{}, queryErr
		}
		for protectedRows.Next() {
			var directory types.EnsureProtectedDirectory
			if scanErr := protectedRows.Scan(&directory.ID, &directory.Path, &directory.Realm, &directory.Username, &directory.PasswordHash, &directory.Enabled); scanErr != nil {
				protectedRows.Close()
				return convergenceSnapshot{}, scanErr
			}
			item.Directories = append(item.Directories, directory)
		}
		if rowsErr := protectedRows.Close(); rowsErr != nil {
			return convergenceSnapshot{}, rowsErr
		}
		snapshot.ProtectedDirectories = append(snapshot.ProtectedDirectories, item)
	}
	if err := tx.Commit(); err != nil {
		return convergenceSnapshot{}, err
	}
	return snapshot, nil
}

func hasConfiguredPolicy(raw []byte) bool {
	var value map[string]json.RawMessage
	return json.Unmarshal(raw, &value) == nil && (len(value) > 1 || value["resources"] != nil)
}

func (w *ConvergeSubscriptionWorker) markAccountConvergence(ctx context.Context, subscriptionID, desiredRevision int64, status, message string, uid int) error {
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	applied, err := updateAccountConvergenceTx(ctx, tx, subscriptionID, desiredRevision, status, message, uid)
	if err != nil {
		return err
	}
	if !applied {
		var currentRevision int64
		if err = tx.QueryRowContext(ctx, `SELECT desired_revision FROM subscription_system_accounts WHERE subscription_id=$1 FOR UPDATE`, subscriptionID).Scan(&currentRevision); err != nil {
			return err
		}
		if _, err = w.river.InsertTx(ctx, tx, newConvergeSubscriptionArgs(subscriptionID, currentRevision), nil); err != nil {
			return err
		}
		if err = wakeSubscriptionConvergenceTx(ctx, tx, subscriptionID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func updateAccountConvergenceTx(ctx context.Context, tx *sql.Tx, subscriptionID, desiredRevision int64, status, message string, uid int) (bool, error) {
	appliedState := "failed"
	if status == "in_sync" {
		appliedState = "active"
	}
	result, err := tx.ExecContext(ctx, `UPDATE subscription_system_accounts
SET linux_uid=CASE WHEN $5>0 THEN $5 ELSE linux_uid END,applied_state=$3,convergence_status=$4,
    applied_revision=$2,last_error=$6,updated_at=now()
WHERE subscription_id=$1 AND desired_revision=$2`,
		subscriptionID, desiredRevision, appliedState, status, uid, strings.TrimSpace(message))
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

// EnqueueSubscriptionConvergenceTx advances desired state and queues that exact
// revision in the same transaction. A worker may only acknowledge this revision.
func EnqueueSubscriptionConvergenceTx(ctx context.Context, tx *sql.Tx, client *river.Client[*sql.Tx], subscriptionID int64) (int64, error) {
	var revision int64
	err := tx.QueryRowContext(ctx, `UPDATE subscription_system_accounts
SET desired_revision=desired_revision+1,convergence_status='pending',last_error='',updated_at=now()
WHERE subscription_id=$1
RETURNING desired_revision`, subscriptionID).Scan(&revision)
	if err != nil {
		return 0, err
	}
	if client == nil {
		return revision, nil
	}
	if _, err = client.InsertTx(ctx, tx, newConvergeSubscriptionArgs(subscriptionID, revision), nil); err != nil {
		return 0, err
	}
	if err = wakeSubscriptionConvergenceTx(ctx, tx, subscriptionID); err != nil {
		return 0, err
	}
	return revision, nil
}

func prepareRuntimeGenerations(ctx context.Context, db *sql.DB, domains []types.SubscriptionDomain) ([]int64, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	candidates := make([]int64, 0, len(domains))
	for _, domain := range domains {
		policyJSON, marshalErr := json.Marshal(domain.Policy)
		if marshalErr != nil {
			return nil, marshalErr
		}
		webJSON, marshalErr := json.Marshal(domain.Policy.Web)
		if marshalErr != nil {
			return nil, marshalErr
		}
		phpJSON, marshalErr := json.Marshal(domain.Policy.PHP)
		if marshalErr != nil {
			return nil, marshalErr
		}
		nginxHash := fmt.Sprintf("%x", sha256.Sum256(webJSON))
		phpHash := fmt.Sprintf("%x", sha256.Sum256(phpJSON))
		var id int64
		err = tx.QueryRowContext(ctx, `SELECT id FROM site_runtime_generations
WHERE site_id=$1 AND nginx_sha256=$2 AND php_sha256=$3 AND status IN ('candidate','active')
ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END,id DESC LIMIT 1`,
			domain.SiteID, nginxHash, phpHash,
		).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			err = tx.QueryRowContext(ctx, `INSERT INTO site_runtime_generations(
site_id,generation,php_version,policy,nginx_sha256,php_sha256,status)
SELECT $1,COALESCE(MAX(generation),0)+1,$2,$3,$4,$5,'candidate'
FROM site_runtime_generations WHERE site_id=$1
RETURNING id`, domain.SiteID, domain.Policy.PHP.DefaultVersion, policyJSON, nginxHash, phpHash).Scan(&id)
		}
		if err != nil {
			return nil, err
		}
		var status string
		if err = tx.QueryRowContext(ctx, `SELECT status FROM site_runtime_generations WHERE id=$1`, id).Scan(&status); err != nil {
			return nil, err
		}
		if status == "candidate" {
			candidates = append(candidates, id)
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return candidates, nil
}

func activateRuntimeGenerations(ctx context.Context, db *sql.DB, candidates []int64) error {
	if len(candidates) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range candidates {
		var siteID int64
		if err = tx.QueryRowContext(ctx, `SELECT site_id FROM site_runtime_generations WHERE id=$1 AND status='candidate' FOR UPDATE`, id).Scan(&siteID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE site_runtime_generations SET status='retired' WHERE site_id=$1 AND status='active'`, siteID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE site_runtime_generations SET status='active',last_error='',activated_at=now() WHERE id=$1`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func failRuntimeGenerations(ctx context.Context, db *sql.DB, candidates []int64, message string) error {
	for _, id := range candidates {
		if _, err := db.ExecContext(ctx, `UPDATE site_runtime_generations SET status='failed',last_error=$2 WHERE id=$1 AND status='candidate'`, id, truncateConvergenceOutput(message)); err != nil {
			return err
		}
	}
	return nil
}

func wakeSubscriptionConvergenceTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE river_job SET state='available',scheduled_at=now()
WHERE kind='converge_subscription' AND args->>'subscription_id'=CAST($1 AS bigint)::text AND state IN ('retryable','scheduled')`, subscriptionID)
	return err
}
