package provision

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"slices"
	"time"
)

type SiteTeardownAgent interface {
	TeardownSite(context.Context, types.TeardownSiteReq) (types.TeardownSiteResult, error)
}
type removalSharedConverger interface {
	Converge(context.Context, types.SiteRemovalOperation) (types.TeardownSiteResult, error)
}
type RemoveSiteWorker struct {
	river.WorkerDefaults[RemoveSiteArgs]
	service *SiteRemovalService
	agent   SiteTeardownAgent
	shared  removalSharedConverger
}

func NewRemoveSiteWorker(service *SiteRemovalService, agent SiteTeardownAgent, shared removalSharedConverger) *RemoveSiteWorker {
	return &RemoveSiteWorker{service: service, agent: agent, shared: shared}
}
func (*RemoveSiteWorker) Timeout(*river.Job[RemoveSiteArgs]) time.Duration { return 15 * time.Minute }

func (w *RemoveSiteWorker) Work(ctx context.Context, job *river.Job[RemoveSiteArgs]) error {
	if w.service == nil || w.service.db == nil || w.agent == nil {
		return errors.New("website removal worker is not configured")
	}
	connection, err := w.service.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err = acquireServerSnapshotGate(ctx, connection, true); err != nil {
		return err
	}
	defer releaseServerSnapshotGate(connection, true)
	key := fmt.Sprintf("nakpanel:site-removal:%d", job.Args.OperationID)
	var locked bool
	if err = connection.QueryRowContext(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", key).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return river.JobSnooze(time.Second)
	}
	defer func() {
		timeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := connection.ExecContext(timeout, "SELECT pg_advisory_unlock(hashtextextended($1,0))", key); err != nil {
			discardRemovalLeaseConnection(connection)
		}
	}()
	op, err := readRemoval(w.service.db.QueryRowContext(ctx, "SELECT "+removalOperationColumns+" FROM site_removal_operations WHERE id=$1", job.Args.OperationID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if op.Revision != job.Args.Revision || op.State == "completed" || op.State == "failed" {
		return nil
	}
	ready, err := w.service.drainSiteJobs(ctx, op)
	if err != nil {
		return err
	}
	if !ready {
		_, err = w.service.db.ExecContext(ctx, "UPDATE site_removal_operations SET state='waiting',stage='waiting',updated_at=now() WHERE id=$1 AND revision=$2 AND state<>'completed'", op.ID, op.Revision)
		if err != nil {
			return err
		}
		return river.JobSnooze(2 * time.Second)
	}
	if w.shared == nil {
		return w.service.failRemoval(ctx, op, types.RemovalShared)
	}
	if err = w.service.advanceRemoval(ctx, op, types.RemovalStopServices, nil); err != nil {
		return err
	}
	for _, stage := range []types.SiteRemovalStage{types.RemovalStopServices, types.RemovalHosting, types.RemovalShared, types.RemovalFinalize} {
		if err = w.service.advanceRemoval(ctx, op, stage, nil); err != nil {
			return err
		}
		unlock := quota.LockSubscriptionRuntime(op.SubscriptionID)
		result, stageErr := w.agent.TeardownSite(ctx, types.TeardownSiteReq{OperationID: op.ID, Revision: op.Revision, SubscriptionID: op.SubscriptionID, Snapshot: op.Snapshot, Stage: stage, DeleteDatabaseIDs: op.DeleteDatabaseIDs})
		unlock()
		if stageErr != nil || result.OperationID != op.ID || result.Revision != op.Revision || !slices.Contains(result.Checkpoints, string(stage)) {
			return w.service.failRemoval(ctx, op, stage)
		}
		if err = w.service.advanceRemoval(ctx, op, stage, result.Checkpoints); err != nil {
			return err
		}
		if stage == types.RemovalShared {
			result, err = w.shared.Converge(ctx, op)
			if err != nil || result.OperationID != op.ID || result.Revision != op.Revision {
				return w.service.failRemoval(ctx, op, stage)
			}
			if err = w.service.advanceRemoval(ctx, op, stage, result.Checkpoints); err != nil {
				return err
			}
		}
	}
	if err = w.service.Finalize(ctx, op.ID, op.Revision); err != nil {
		return w.service.failRemoval(ctx, op, types.RemovalFinalize)
	}
	return nil
}

func (s *SiteRemovalService) drainSiteJobs(ctx context.Context, op types.SiteRemovalOperation) (bool, error) {
	scope, args := TargetSiteJobScope(op.Snapshot)
	if _, err := s.db.ExecContext(ctx, `UPDATE river_job SET state='cancelled',finalized_at=now() WHERE state IN ('available','pending','scheduled','retryable') AND `+scope, args...); err != nil {
		return false, err
	}
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM river_job WHERE state='running' AND "+scope, args...).Scan(&count)
	if err != nil || count != 0 {
		return false, err
	}
	return true, s.removeCancelledCertificateStaging(ctx, scope, args)
}

func (s *SiteRemovalService) advanceRemoval(ctx context.Context, op types.SiteRemovalOperation, stage types.SiteRemovalStage, checkpoints []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = quota.LockSubscriptionMutationTx(ctx, tx, op.SubscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "SELECT set_config('nakpanel.site_removal_operation',$1,true)", fmt.Sprint(op.ID)); err != nil {
		return err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE site_removal_operations SET state='running',stage=$3,checkpoints=ARRAY(SELECT DISTINCT checkpoint FROM unnest(checkpoints||$4::text[]) AS checkpoint ORDER BY checkpoint),last_error='',updated_at=now() WHERE id=$1 AND revision=$2 AND state IN ('queued','waiting','running')`, op.ID, op.Revision, stage, pq.Array(checkpoints))
	if err != nil {
		return err
	}
	count, err := updated.RowsAffected()
	if err != nil || count != 1 {
		return errors.New("website removal operation changed")
	}
	if _, err = tx.ExecContext(ctx, "UPDATE sites SET removal_state='removing' WHERE id=ANY($1)", pq.Array(removalSelectedSites(op.Snapshot))); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SiteRemovalService) failRemoval(ctx context.Context, op types.SiteRemovalOperation, stage types.SiteRemovalStage) error {
	message := fmt.Sprintf("Website removal could not complete %s. Correct the service issue and retry this operation; retained data is unchanged.", stage)
	timeout, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(timeout, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = quota.LockSubscriptionMutationTx(timeout, tx, op.SubscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(timeout, "SELECT set_config('nakpanel.site_removal_operation',$1,true)", fmt.Sprint(op.ID)); err != nil {
		return err
	}
	updated, err := tx.ExecContext(timeout, "UPDATE site_removal_operations SET state='failed',stage=$3,last_error=$4,updated_at=now() WHERE id=$1 AND revision=$2 AND state<>'completed'", op.ID, op.Revision, stage, message)
	if err != nil {
		return err
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	if _, err = tx.ExecContext(timeout, "UPDATE sites SET removal_state='failed' WHERE id=ANY($1)", pq.Array(removalSelectedSites(op.Snapshot))); err != nil {
		return err
	}
	metadata, _ := json.Marshal(map[string]string{"stage": string(stage)})
	if err = removalAudit(timeout, tx, auth.SessionUser{ID: op.ActorUserID, Email: op.ActorLabel}, op, "site.removal_failed", metadata); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return river.JobCancel(errors.New(message))
}

type SweepSiteRemovalsArgs struct{}

func (SweepSiteRemovalsArgs) Kind() string { return "sweep_site_removals" }

type SweepSiteRemovalsWorker struct {
	river.WorkerDefaults[SweepSiteRemovalsArgs]
	service *SiteRemovalService
}

func NewSweepSiteRemovalsWorker(service *SiteRemovalService) *SweepSiteRemovalsWorker {
	return &SweepSiteRemovalsWorker{service: service}
}
func (s *SiteRemovalService) SetRiverClient(client *river.Client[*sql.Tx]) { s.river = client }
func (w *SweepSiteRemovalsWorker) Work(ctx context.Context, _ *river.Job[SweepSiteRemovalsArgs]) error {
	if w.service == nil || w.service.river == nil {
		return errors.New("website removal recovery is not configured")
	}
	rows, err := w.service.db.QueryContext(ctx, "SELECT id FROM site_removal_operations WHERE state IN ('queued','waiting','running') ORDER BY id LIMIT 100")
	if err != nil {
		return err
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		op, err := readRemoval(w.service.db.QueryRowContext(ctx, "SELECT "+removalOperationColumns+" FROM site_removal_operations WHERE id=$1", id))
		if err != nil {
			return err
		}
		var active bool
		if err = w.service.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM river_job WHERE kind='remove_site' AND args->>'operation_id'=$1 AND args->>'revision'=$2 AND state IN ('available','pending','scheduled','retryable','running'))`, fmt.Sprint(id), fmt.Sprint(op.Revision)).Scan(&active); err != nil {
			return err
		}
		if active {
			continue
		}
		var latest string
		err = w.service.db.QueryRowContext(ctx, `SELECT state FROM river_job WHERE kind='remove_site' AND args->>'operation_id'=$1 AND args->>'revision'=$2 ORDER BY id DESC LIMIT 1`, fmt.Sprint(id), fmt.Sprint(op.Revision)).Scan(&latest)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if latest == "cancelled" || latest == "discarded" {
			err = w.service.failRemoval(ctx, op, op.Stage)
			var cancellation *river.JobCancelError
			if err != nil && !errors.As(err, &cancellation) {
				return err
			}
			continue
		}
		if _, err = w.service.river.Insert(ctx, RemoveSiteArgs{OperationID: id, Revision: op.Revision}, nil); err != nil {
			return err
		}
	}
	return nil
}
