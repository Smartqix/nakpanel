package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type StagingOperationArgs struct {
	OperationID int64 `json:"operation_id" river:"unique"`
}

func (StagingOperationArgs) Kind() string { return "run_staging_operation" }

func (StagingOperationArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       HeavyQueue,
		MaxAttempts: 5,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{
				rivertype.JobStateAvailable,
				rivertype.JobStatePending,
				rivertype.JobStateRetryable,
				rivertype.JobStateRunning,
				rivertype.JobStateScheduled,
			},
		},
	}
}

type StagingStore interface {
	QueueStagingOperation(context.Context, int64, types.StagingOperationInput) (int64, error)
}

func (s *SQLStore) QueueStagingOperation(ctx context.Context, actorID int64, input types.StagingOperationInput) (int64, error) {
	if s == nil || s.db == nil || s.river == nil {
		return 0, errors.New("staging jobs are not configured")
	}
	if input.SourceSiteID <= 0 || input.TargetSiteID <= 0 || input.SourceSiteID == input.TargetSiteID {
		return 0, errors.New("two different domains are required")
	}
	if actorID <= 0 {
		return 0, errors.New("a user actor is required")
	}
	if input.Direction != "copy_to_staging" && input.Direction != "promote" {
		return 0, errors.New("unsupported staging direction")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var subscriptionID, targetSubscriptionID int64
	err = tx.QueryRowContext(ctx, `SELECT source.subscription_id,target.subscription_id
FROM sites source
JOIN sites target ON target.id=$2
WHERE source.id=$1`, input.SourceSiteID, input.TargetSiteID).
		Scan(&subscriptionID, &targetSubscriptionID)
	if err != nil {
		return 0, err
	}
	if subscriptionID != targetSubscriptionID {
		return 0, errors.New("staging domains must belong to the same subscription")
	}
	if err = LockSubscriptionMutationTx(ctx, tx, subscriptionID); err != nil {
		return 0, err
	}
	lockedSubscriptionID := subscriptionID

	var subscriptionStatus, customerStatus string
	err = tx.QueryRowContext(ctx, `SELECT source.subscription_id,target.subscription_id,account.username,
source.domain,target.domain,subscription.status,customer.status
FROM sites source
JOIN sites target ON target.id=$2
JOIN subscriptions subscription ON subscription.id=source.subscription_id
JOIN customers customer ON customer.id=subscription.customer_id
JOIN subscription_system_accounts account ON account.subscription_id=source.subscription_id
WHERE source.id=$1
FOR UPDATE OF source,target,subscription,account`,
		input.SourceSiteID, input.TargetSiteID,
	).Scan(&subscriptionID, &targetSubscriptionID, new(string), new(string), new(string), &subscriptionStatus, &customerStatus)
	if err != nil {
		return 0, err
	}
	if subscriptionID != targetSubscriptionID {
		return 0, errors.New("staging domains must belong to the same subscription")
	}
	if subscriptionID != lockedSubscriptionID {
		return 0, errors.New("staging domain ownership changed while acquiring its mutation lock")
	}
	if err = lockActiveSubscriptionTx(ctx, tx, subscriptionID); err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(2424,$1)`, input.TargetSiteID); err != nil {
		return 0, err
	}
	var targetBusy bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(
    SELECT 1 FROM staging_operations
    WHERE target_site_id=$1 AND status IN ('pending','running')
)`, input.TargetSiteID).Scan(&targetBusy); err != nil {
		return 0, err
	}
	if targetBusy {
		return 0, errors.New("another staging operation is already changing the target domain")
	}
	if subscriptionStatus != "active" || customerStatus != "active" {
		return 0, errors.New("staging requires an active customer and subscription")
	}
	effective, err := EffectiveSitePolicyTx(ctx, tx, input.SourceSiteID)
	if err != nil {
		return 0, err
	}
	if !effective.Permissions.Staging {
		return 0, errors.New("staging is disabled by the subscription policy")
	}
	targetPolicy, err := EffectiveSitePolicyTx(ctx, tx, input.TargetSiteID)
	if err != nil {
		return 0, err
	}
	if !targetPolicy.Permissions.Staging {
		return 0, errors.New("staging is disabled for the target domain")
	}

	var operationID int64
	err = tx.QueryRowContext(ctx, `INSERT INTO staging_operations(source_site_id,target_site_id,direction,include_database)
VALUES($1,$2,$3,$4) RETURNING id`,
		input.SourceSiteID, input.TargetSiteID, input.Direction, input.IncludeDatabase,
	).Scan(&operationID)
	if err != nil {
		return 0, err
	}
	if _, err = s.river.InsertTx(ctx, tx, StagingOperationArgs{OperationID: operationID}, nil); err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,subscription_id,action,target_type,target_id,metadata)
VALUES(NULLIF($1,0),$2,'staging.queued','staging_operation',$3,
jsonb_build_object('source_site_id',$4,'target_site_id',$5,'direction',$6,'include_database',$7))`,
		actorID, subscriptionID, operationID, input.SourceSiteID, input.TargetSiteID, input.Direction, input.IncludeDatabase,
	); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return operationID, nil
}

type StagingOperationAgent interface {
	RunStagingOperation(context.Context, types.RunStagingOperationReq) (types.RunStagingOperationResult, error)
}

type StagingOperationWorker struct {
	river.WorkerDefaults[StagingOperationArgs]
	db    *sql.DB
	agent StagingOperationAgent
}

func NewStagingOperationWorker(db *sql.DB, agent StagingOperationAgent) *StagingOperationWorker {
	return &StagingOperationWorker{db: db, agent: agent}
}

func (w *StagingOperationWorker) Work(ctx context.Context, job *river.Job[StagingOperationArgs]) error {
	if w == nil || w.db == nil || w.agent == nil {
		return errors.New("staging worker is not configured")
	}
	claim, err := w.db.ExecContext(ctx, `UPDATE staging_operations
SET status='running',last_error=''
WHERE id=$1 AND (status='pending' OR (status='running' AND $2>1))`,
		job.Args.OperationID, stagingAttempt(job))
	if err != nil {
		return err
	}
	if err = requireOneStagingRow(claim); err != nil {
		return err
	}
	req, err := loadStagingOperation(ctx, w.db, job.Args.OperationID)
	if err != nil {
		return errors.Join(err, w.markAttemptFailure(ctx, job, err))
	}
	result, runErr := w.agent.RunStagingOperation(ctx, req)
	if runErr != nil {
		return errors.Join(runErr, w.markAttemptFailure(ctx, job, runErr))
	}
	updated, err := w.db.ExecContext(ctx, `UPDATE staging_operations
SET status='succeeded',snapshot_path=$2,database_snapshot_paths=$3,copied_bytes=$4,last_error='',finished_at=now()
WHERE id=$1 AND status='running'`, job.Args.OperationID, result.SnapshotPath, pq.Array(result.DatabaseSnapshots), result.CopiedBytes)
	if err != nil {
		return err
	}
	return requireOneStagingRow(updated)
}

func (w *StagingOperationWorker) markAttemptFailure(ctx context.Context, job *river.Job[StagingOperationArgs], cause error) error {
	status := "pending"
	finishedAt := "NULL"
	if stagingAttemptIsTerminal(job) {
		status = "failed"
		finishedAt = "now()"
	}
	updated, err := w.db.ExecContext(ctx, `UPDATE staging_operations
SET status=$2,last_error=$3,finished_at=`+finishedAt+`
WHERE id=$1 AND status='running'`, job.Args.OperationID, status, truncateError(cause))
	if err != nil {
		return err
	}
	return requireOneStagingRow(updated)
}

func stagingAttemptIsTerminal(job *river.Job[StagingOperationArgs]) bool {
	return job != nil && job.JobRow != nil && job.MaxAttempts > 0 && job.Attempt >= job.MaxAttempts
}

func stagingAttempt(job *river.Job[StagingOperationArgs]) int {
	if job != nil && job.JobRow != nil && job.Attempt > 0 {
		return job.Attempt
	}
	return 1
}

func requireOneStagingRow(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func loadStagingOperation(ctx context.Context, db *sql.DB, operationID int64) (types.RunStagingOperationReq, error) {
	var req types.RunStagingOperationReq
	var includeDatabase bool
	var sourceSubscriptionID, targetSubscriptionID int64
	var lifecycleActive, sourceAllowed, targetAllowed bool
	err := db.QueryRowContext(ctx, `SELECT operation.id,operation.source_site_id,operation.target_site_id,
account.username,source.domain,target.domain,operation.direction,operation.include_database,
source.subscription_id,target.subscription_id,
subscription.status='active' AND customer.status='active' AND (
    customer.reseller_id IS NULL OR (
        reseller.status='active' AND EXISTS (
            SELECT 1 FROM reseller_subscriptions allocation
            WHERE allocation.reseller_id=customer.reseller_id AND allocation.status='active'
        )
    )
),
COALESCE((source_override.policy_patch #>> '{permissions,staging}')::boolean,
         (subscription_override.policy_patch #>> '{permissions,staging}')::boolean,
         (entitlement.hosting_policy #>> '{permissions,staging}')::boolean,false),
COALESCE((target_override.policy_patch #>> '{permissions,staging}')::boolean,
         (subscription_override.policy_patch #>> '{permissions,staging}')::boolean,
         (entitlement.hosting_policy #>> '{permissions,staging}')::boolean,false)
FROM staging_operations operation
JOIN sites source ON source.id=operation.source_site_id
JOIN sites target ON target.id=operation.target_site_id
JOIN subscription_system_accounts account ON account.subscription_id=source.subscription_id
JOIN subscriptions subscription ON subscription.id=source.subscription_id
JOIN customers customer ON customer.id=subscription.customer_id
JOIN subscription_entitlements entitlement ON entitlement.subscription_id=subscription.id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
LEFT JOIN subscription_policy_overrides subscription_override ON subscription_override.subscription_id=subscription.id
LEFT JOIN site_policy_overrides source_override ON source_override.site_id=source.id
LEFT JOIN site_policy_overrides target_override ON target_override.site_id=target.id
WHERE operation.id=$1 AND operation.status='running'`,
		operationID,
	).Scan(&req.OperationID, &req.SourceSiteID, &req.TargetSiteID, &req.Username, &req.SourceDomain,
		&req.TargetDomain, &req.Direction, &includeDatabase, &sourceSubscriptionID, &targetSubscriptionID,
		&lifecycleActive, &sourceAllowed, &targetAllowed)
	if err != nil {
		return types.RunStagingOperationReq{}, err
	}
	if sourceSubscriptionID != targetSubscriptionID {
		return types.RunStagingOperationReq{}, errors.New("staging ownership changed before execution")
	}
	if !lifecycleActive {
		return types.RunStagingOperationReq{}, errors.New("staging customer, provider, or subscription was suspended before execution")
	}
	if !sourceAllowed || !targetAllowed {
		return types.RunStagingOperationReq{}, errors.New("staging entitlement was revoked before execution")
	}
	if !includeDatabase {
		return req, nil
	}
	sourceNames, err := stagingDatabaseNames(ctx, db, req.SourceSiteID)
	if err != nil {
		return types.RunStagingOperationReq{}, err
	}
	targetNames, err := stagingDatabaseNames(ctx, db, req.TargetSiteID)
	if err != nil {
		return types.RunStagingOperationReq{}, err
	}
	if len(sourceNames) == 0 || len(sourceNames) != len(targetNames) {
		return types.RunStagingOperationReq{}, fmt.Errorf("database copy requires matching non-empty source and target database counts")
	}
	for index := range sourceNames {
		req.Databases = append(req.Databases, types.StagingDatabaseCopy{SourceName: sourceNames[index], TargetName: targetNames[index]})
	}
	return req, nil
}

func stagingDatabaseNames(ctx context.Context, db *sql.DB, siteID int64) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT db_name FROM databases WHERE site_id=$1 AND status='active' AND engine IN ('mariadb','mysql') ORDER BY id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		result = append(result, name)
	}
	return result, rows.Err()
}
