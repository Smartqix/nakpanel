package provision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"

	"github.com/riverqueue/river/rivertype"
)

var (
	ErrJobNotRetryable    = errors.New("job is not retryable")
	ErrUnsupportedJobKind = errors.New("unsupported job kind")
)

type jobRetryRecord struct {
	Kind  string
	State rivertype.JobState
}

type JobRetrier struct {
	store jobRetryStore
}

type jobRetryStore interface {
	GetJob(ctx context.Context, id int64) (jobRetryRecord, error)
	RetryDiscardedProvisioningJob(ctx context.Context, id int64) error
}

func NewJobRetrier(store jobRetryStore) *JobRetrier {
	return &JobRetrier{store: store}
}

func NewSQLJobRetrier(db *sql.DB) *JobRetrier {
	return NewJobRetrier(&SQLJobRetryStore{db: db})
}

type SQLJobRetryStore struct {
	db *sql.DB
}

const getJobForRetrySQL = `SELECT kind, state::text FROM river_job WHERE id = $1`

const retryDiscardedProvisioningJobSQL = `UPDATE river_job
SET
    state = 'available',
    scheduled_at = now(),
    max_attempts = CASE WHEN attempt = max_attempts THEN max_attempts + 1 ELSE max_attempts END,
    finalized_at = NULL
WHERE id = $1
  AND kind IN ('create_site', 'create_database', 'issue_cert', 'create_backup', 'restore_backup', 'configure_webmail', 'configure_dns_zone', 'reconcile_system')
  AND state = 'discarded'`

func (r *JobRetrier) RetryProvisioningJob(ctx context.Context, jobID int64) error {
	if jobID <= 0 {
		return fmt.Errorf("%w: invalid job id", ErrJobNotRetryable)
	}
	if r.store == nil {
		return errors.New("job retry store is not configured")
	}

	job, err := r.store.GetJob(ctx, jobID)
	if err != nil {
		return err
	}
	if !isProvisioningJobKind(job.Kind) {
		return fmt.Errorf("%w: %s", ErrUnsupportedJobKind, job.Kind)
	}
	if job.State != rivertype.JobStateDiscarded {
		return fmt.Errorf("%w: state %s", ErrJobNotRetryable, job.State)
	}

	if err := r.store.RetryDiscardedProvisioningJob(ctx, jobID); err != nil {
		return err
	}
	return nil
}

func (s *SQLJobRetryStore) GetJob(ctx context.Context, id int64) (jobRetryRecord, error) {
	if s == nil || s.db == nil {
		return jobRetryRecord{}, errors.New("job retry database is not configured")
	}

	var job jobRetryRecord
	if err := s.db.QueryRowContext(ctx, getJobForRetrySQL, id).Scan(&job.Kind, &job.State); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return jobRetryRecord{}, rivertype.ErrNotFound
		}
		return jobRetryRecord{}, err
	}
	return job, nil
}

func (s *SQLJobRetryStore) RetryDiscardedProvisioningJob(ctx context.Context, id int64) error {
	if s == nil || s.db == nil {
		return errors.New("job retry database is not configured")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var kind string
	var backupID int64
	if err = tx.QueryRowContext(ctx, `SELECT kind,COALESCE(NULLIF(args->>'backup_id','')::bigint,0) FROM river_job WHERE id=$1`, id).Scan(&kind, &backupID); err != nil {
		return err
	}
	if kind == "create_backup" {
		var subscriptionID int64
		if err = tx.QueryRowContext(ctx, `SELECT subscription_id FROM backups WHERE id=$1`, backupID).Scan(&subscriptionID); err != nil {
			return ErrJobNotRetryable
		}
		if err = controlquota.LockSubscriptionMutationTx(ctx, tx, subscriptionID); err != nil {
			return err
		}
		var status string
		if err = tx.QueryRowContext(ctx, `SELECT status FROM backups WHERE id=$1 FOR UPDATE`, backupID).Scan(&status); err != nil || (status != "pending" && status != "failed") {
			return ErrJobNotRetryable
		}
	}
	result, err := tx.ExecContext(ctx, retryDiscardedProvisioningJobSQL, id)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected != 1 {
		return fmt.Errorf("%w: state changed before retry", ErrJobNotRetryable)
	}
	return tx.Commit()
}

func isProvisioningJobKind(kind string) bool {
	switch kind {
	case (CreateSiteArgs{}).Kind(),
		(CreateDatabaseArgs{}).Kind(),
		(IssueCertArgs{}).Kind(),
		(CreateBackupArgs{}).Kind(),
		(RestoreBackupArgs{}).Kind(),
		(ConfigureWebmailArgs{}).Kind(),
		(ConfigureDNSZoneArgs{}).Kind(),
		(ReconcileSystemArgs{}).Kind():
		return true
	default:
		return false
	}
}
