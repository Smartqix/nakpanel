package provision

import (
	"context"
	"database/sql"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"time"
)

type SweepOperationsArgs struct{}

func (SweepOperationsArgs) Kind() string { return "sweep_operations" }

type VerifyIssueArgs struct {
	IssueID int64 `json:"issue_id"`
}

func (VerifyIssueArgs) Kind() string { return "verify_operation_issue" }

type VerifyArchiveArgs struct {
	SiteID int64 `json:"site_id"`
}

func (VerifyArchiveArgs) Kind() string { return "verify_operation_archive" }
func checkOpts(queue string) river.InsertOpts {
	return river.InsertOpts{Queue: queue, MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning, rivertype.JobStateRetryable, rivertype.JobStateScheduled}}}
}
func (SweepOperationsArgs) InsertOpts() river.InsertOpts { return checkOpts("system") }
func (VerifyIssueArgs) InsertOpts() river.InsertOpts     { return checkOpts("heavy") }
func (VerifyArchiveArgs) InsertOpts() river.InsertOpts   { return checkOpts("backup") }

type SweepOperationsWorker struct {
	river.WorkerDefaults[SweepOperationsArgs]
	Manager *OperationsManager
}

func (w *SweepOperationsWorker) Work(ctx context.Context, _ *river.Job[SweepOperationsArgs]) error {
	return w.Manager.SweepChecks(ctx)
}

type VerifyIssueWorker struct {
	river.WorkerDefaults[VerifyIssueArgs]
	Manager *OperationsManager
}

func (w *VerifyIssueWorker) Work(ctx context.Context, j *river.Job[VerifyIssueArgs]) error {
	err := w.Manager.VerifyIssue(ctx, j.Args.IssueID)
	switch {
	case errors.Is(err, operations.ErrConflict):
		return river.JobSnooze(time.Minute)
	case errors.Is(err, ErrRecoveryUnverified), errors.Is(err, operations.ErrNotFound), errors.Is(err, sql.ErrNoRows), errors.Is(err, controlquota.ErrNoActiveSubscription), errors.Is(err, controlquota.ErrSiteRemoving):
		return nil
	}
	return err
}

type VerifyArchiveWorker struct {
	river.WorkerDefaults[VerifyArchiveArgs]
	Manager *OperationsManager
}

func (w *VerifyArchiveWorker) Timeout(*river.Job[VerifyArchiveArgs]) time.Duration {
	return 3 * time.Minute
}
func (w *VerifyArchiveWorker) Work(ctx context.Context, j *river.Job[VerifyArchiveArgs]) error {
	err := w.Manager.VerifyLatestArchive(ctx, j.Args.SiteID)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, controlquota.ErrNoActiveSubscription) || errors.Is(err, controlquota.ErrSiteRemoving) {
		return nil
	}
	return err
}
func (m *OperationsManager) SetQueue(q *river.Client[*sql.Tx]) { m.queue = q }
func (m *OperationsManager) RequestVerification(ctx context.Context, a auth.SessionUser, id int64) error {
	i, err := m.Issue(ctx, a, id)
	if err != nil {
		return err
	}
	switch i.Kind {
	case "backup", "tls", "hosting", "mail":
	default:
		return operations.ErrInvalid
	}
	if i.ResolvedAt != nil {
		return operations.ErrConflict
	}
	_, err = m.queue.Insert(ctx, VerifyIssueArgs{IssueID: id}, nil)
	return err
}
func (m *OperationsManager) SweepChecks(ctx context.Context) error {
	if err := m.DetectConditions(ctx); err != nil {
		return err
	}
	// Bound each sweep. Heavy archive hashing uses the serial backup queue.
	rows, err := m.db.QueryContext(ctx, `SELECT id FROM issues WHERE resolved_at IS NULL AND kind IN ('backup','tls','hosting','mail') AND (last_check_at IS NULL OR last_check_at<now()-interval '15 minutes') ORDER BY last_check_at NULLS FIRST,id LIMIT 100`)
	if err != nil {
		return err
	}
	var ids []int64
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
		if _, err = m.queue.Insert(ctx, VerifyIssueArgs{IssueID: id}, nil); err != nil {
			return err
		}
	}
	rows, err = m.db.QueryContext(ctx, `SELECT s.id FROM sites s JOIN LATERAL (SELECT b.id FROM backups b WHERE b.site_id=s.id AND b.status='active' AND b.completed_at IS NOT NULL ORDER BY b.completed_at DESC,b.id DESC LIMIT 1) b ON true LEFT JOIN backup_readiness_checks c ON c.backup_id=b.id WHERE s.status='active' AND s.desired_status='active' AND s.removal_state='none' AND (c.last_checked_at IS NULL OR c.last_checked_at<now()-CASE WHEN c.last_check_status='verified' THEN interval '24 hours' ELSE interval '15 minutes' END) ORDER BY c.last_checked_at NULLS FIRST,s.id LIMIT 100`)
	if err != nil {
		return err
	}
	ids = nil
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
		if _, err = m.queue.Insert(ctx, VerifyArchiveArgs{SiteID: id}, nil); err != nil {
			return err
		}
	}
	return nil
}
func (m *OperationsManager) VerifyLatestArchive(ctx context.Context, siteID int64) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	in, err := m.snapshotOperationIntentTx(ctx, tx, operations.Resource{Kind: operations.ResourceSite, ID: siteID})
	if err != nil {
		return err
	}
	if in.Archive.ID == 0 {
		return nil
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	receipt, probeErr := m.probeOperation(probeCtx, operations.Issue{Kind: "backup"}, in)
	end, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer end.Rollback()
	current, err := m.snapshotOperationIntentTx(ctx, end, in.Resource)
	if err != nil {
		return err
	}
	if current.Hash != in.Hash {
		return nil
	}
	status := "verified"
	var verified any = receipt.ObservedAt
	if probeErr != nil {
		status = "unknown"
		verified = nil
	}
	_, err = end.ExecContext(ctx, `INSERT INTO backup_readiness_checks(backup_id,checksum,size_bytes,verified_at,data_scope_hash,last_check_status,last_checked_at) VALUES($1,$2,$3,$4,$5,$6,now()) ON CONFLICT(backup_id) DO UPDATE SET checksum=EXCLUDED.checksum,size_bytes=EXCLUDED.size_bytes,verified_at=CASE WHEN EXCLUDED.last_check_status='verified' THEN EXCLUDED.verified_at ELSE backup_readiness_checks.verified_at END,data_scope_hash=EXCLUDED.data_scope_hash,last_check_status=EXCLUDED.last_check_status,last_checked_at=EXCLUDED.last_checked_at`, in.Archive.ID, in.Archive.Checksum, in.Archive.Size, verified, in.DataScopeHash, status)
	if err != nil {
		return err
	}
	return end.Commit()
}
