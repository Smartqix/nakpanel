package operations

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// EnqueueNotificationTx snapshots no addresses. The user and current ownership
// are checked again immediately before SMTP. A preference change never backfills.
func EnqueueNotificationTx(ctx context.Context, tx *sql.Tx, id int64) error {
	return EnqueueNotificationForEmailTx(ctx, tx, id, "")
}
func EnqueueNotificationForEmailTx(ctx context.Context, tx *sql.Tx, id int64, selectedEmail string) error {
	if err := correlateNotificationTx(ctx, tx, id); err != nil {
		return err
	}
	visible := strings.NewReplacer("$1", "u.id", "$2", "u.role").Replace(NotificationVisibilitySQL("n", 1, 2))
	rows, err := tx.QueryContext(ctx, `SELECT u.id,p.email_mode FROM notifications n CROSS JOIN users u JOIN notification_preferences p ON p.user_id=u.id LEFT JOIN issues ni ON ni.id=n.issue_id WHERE n.id=$1 AND ($2='' OR u.email=$2) AND NOT u.login_disabled AND p.email_mode<>'off' AND COALESCE(ni.kind,'')<>'notification_delivery' AND EXISTS(SELECT 1 FROM notification_delivery_policy WHERE singleton AND enabled) AND `+visible, id, selectedEmail)
	if err != nil {
		return err
	}
	type recipient struct {
		id   int64
		mode string
	}
	var recipients []recipient
	for rows.Next() {
		var r recipient
		if err = rows.Scan(&r.id, &r.mode); err != nil {
			rows.Close()
			return err
		}
		recipients = append(recipients, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, r := range recipients {
		now := time.Now().UTC()
		key := fmt.Sprintf("immediate:%d:%d", r.id, id)
		due := now
		if r.mode == "digest" {
			key = fmt.Sprintf("digest:%d:%s", r.id, now.Format("2006-01-02"))
			due = time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
		}
		var batchID int64
		if err = tx.QueryRowContext(ctx, `INSERT INTO notification_email_batches(batch_key,recipient_user_id,mode,next_attempt_at) VALUES($1,$2,$3,$4) ON CONFLICT(batch_key) DO UPDATE SET batch_key=EXCLUDED.batch_key RETURNING id`, key, r.id, r.mode, due).Scan(&batchID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO notification_email_items(batch_id,notification_id,user_id) VALUES($1,$2,$3) ON CONFLICT(notification_id,user_id) DO NOTHING`, batchID, id, r.id); err != nil {
			return err
		}
	}
	return nil
}
