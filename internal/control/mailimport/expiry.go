package mailimport

import (
	"context"
	"errors"

	"github.com/riverqueue/river"
)

// ExpirePreviews retires abandoned intake, never a paused or running copy.
func (s *SQLStore) ExpirePreviews(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM mail_imports WHERE state='preview' AND expires_at<=now() ORDER BY expires_at,id LIMIT 100 FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
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
		if s.queue == nil {
			return errors.New("mail cleanup worker unavailable")
		}
		var revision int64
		if err = tx.QueryRowContext(ctx, `UPDATE mail_imports SET state='cancelled',desired_revision=desired_revision+1,last_error='Preview expired. Start a new import to check the source again.',updated_at=now() WHERE id=$1 RETURNING desired_revision`, id).Scan(&revision); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM service_secrets WHERE scope='mail-import' AND metadata->>'import_id'=$1`, id); err != nil {
			return err
		}
		if _, err = s.queue.InsertTx(ctx, tx, ImportArgs{ImportID: id, Revision: revision}, &river.InsertOpts{MaxAttempts: 3}); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,subscription_id,action,target_type,target_id,metadata) SELECT actor_user_id,subscription_id,'mail_import.expire','mailbox',mailbox_id,jsonb_build_object('import_id',id,'reason','preview_expired') FROM mail_imports WHERE id=$1`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type ExpirePreviewsArgs struct{}

func (ExpirePreviewsArgs) Kind() string { return "expire_mail_import_previews" }

type ExpirePreviewsWorker struct {
	river.WorkerDefaults[ExpirePreviewsArgs]
	Store *SQLStore
}

func (w *ExpirePreviewsWorker) Work(ctx context.Context, _ *river.Job[ExpirePreviewsArgs]) error {
	if w.Store == nil {
		return errors.New("mail import store unavailable")
	}
	return w.Store.ExpirePreviews(ctx)
}
