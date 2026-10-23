package operations

import (
	"context"
	"database/sql"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type DispatchArgs struct{}

func (DispatchArgs) Kind() string { return "dispatch_operation_events" }
func (DispatchArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "system", UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning, rivertype.JobStateRetryable, rivertype.JobStateScheduled}}}
}

type DispatchWorker struct {
	river.WorkerDefaults[DispatchArgs]
	Store *Store
}

func (w *DispatchWorker) Work(ctx context.Context, _ *river.Job[DispatchArgs]) error {
	_, err := w.Store.Dispatch(ctx, 200)
	return err
}
func (s *Store) Dispatch(ctx context.Context, limit int) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n, err := s.DispatchTx(ctx, tx, limit)
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// DispatchTx serializes publication, not source transactions. Source IDs allocated
// by uncommitted transactions cannot be mistaken for committed feed cursors.
// Projection and acknowledgement are in this transaction; a crash replays both.
func (s *Store) DispatchTx(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
	if limit <= 0 || limit > 1000 {
		return 0, ErrInvalid
	}
	var cursor int64
	if err := tx.QueryRowContext(ctx, `SELECT cursor FROM operation_feed_clock WHERE singleton FOR UPDATE`).Scan(&cursor); err != nil {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM operation_events WHERE dispatched_at IS NULL ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $1`, limit)
	if err != nil {
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		if err = s.projectIncidentTx(ctx, tx, id); err != nil {
			return 0, err
		}
		cursor++
		if _, err = tx.ExecContext(ctx, `UPDATE operation_events SET feed_cursor=$2,dispatched_at=now() WHERE id=$1`, id, cursor); err != nil {
			return 0, err
		}
	}
	if len(ids) > 0 {
		if _, err = tx.ExecContext(ctx, `UPDATE operation_feed_clock SET cursor=$1 WHERE singleton`, cursor); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

func (s *Store) projectIncidentTx(ctx context.Context, tx *sql.Tx, eventID int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE notifications n SET issue_id=i.id FROM operation_events e JOIN issues i ON i.id=e.issue_id WHERE e.id=$1 AND i.resolved_at IS NULL AND n.resolved_at IS NULL AND n.operation_id=i.operation_id AND n.kind IN `+workerFailureNoticeKinds, eventID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO notifications(issue_id,operation_id,kind,severity,title,body,dedupe_key)
 SELECT i.id,i.operation_id,'operation_failed',i.severity,i.title,i.summary,'issue:'||i.id FROM operation_events e JOIN issues i ON i.id=e.issue_id WHERE e.id=$1 AND i.resolved_at IS NULL AND NOT EXISTS(SELECT 1 FROM notifications linked WHERE linked.issue_id=i.id AND linked.resolved_at IS NULL)
 ON CONFLICT(dedupe_key) WHERE resolved_at IS NULL DO UPDATE SET severity=EXCLUDED.severity,title=EXCLUDED.title,body=EXCLUDED.body,updated_at=now()`, eventID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO notifications(issue_id,operation_id,kind,severity,title,body,dedupe_key)
 SELECT i.id,i.operation_id,'issue_recovered','info','Recovery verified',e.summary,'issue:'||i.id||':recovered' FROM operation_events e JOIN issues i ON i.id=e.issue_id WHERE e.id=$1 AND e.kind='issue.resolved' AND i.resolved_at IS NOT NULL
 ON CONFLICT(dedupe_key) WHERE resolved_at IS NULL DO NOTHING`, eventID)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT n.id FROM notifications n JOIN operation_events e ON e.issue_id=n.issue_id WHERE e.id=$1 AND n.resolved_at IS NULL AND ((e.kind IN ('task.failed','issue.observed') AND n.kind='operation_failed') OR (e.kind='issue.resolved' AND n.kind='issue_recovered'))`, eventID)
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
		if err = EnqueueNotificationTx(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}
