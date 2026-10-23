package operations

import (
	"context"
	"database/sql"
)

// Hold the current audience's identity rows until SMTP returns. Ownership or role
// changes cannot commit between the final authorization read and transmission.
// No SMTP call is made until every lock and the visibility query have succeeded.
func lockEmailScopeTx(ctx context.Context, tx *sql.Tx, batchID, userID int64) error {
	const scopes = `WITH scope AS (SELECT COALESCE(i.resource_kind,CASE WHEN n.subscription_id IS NOT NULL THEN 'subscription' WHEN n.customer_id IS NOT NULL THEN 'customer' WHEN n.recipient_user_id IS NOT NULL THEN 'user' ELSE 'server' END) kind,COALESCE(i.resource_id,n.subscription_id,n.customer_id,n.recipient_user_id,0) id,n.reseller_id FROM notification_email_items item JOIN notifications n ON n.id=item.notification_id LEFT JOIN issues i ON i.id=n.issue_id WHERE item.batch_id=$1) `
	queries := []struct {
		sql  string
		args []any
	}{
		{`SELECT user_id FROM notification_preferences WHERE user_id=$1 FOR SHARE`, []any{userID}},
		{`SELECT n.id FROM notifications n JOIN notification_email_items item ON item.notification_id=n.id WHERE item.batch_id=$1 ORDER BY n.id FOR SHARE OF n`, []any{batchID}},
		{scopes + `SELECT s.id FROM scope q JOIN sites s ON q.kind='site' AND s.id=q.id JOIN subscriptions sub ON sub.id=s.subscription_id JOIN customers c ON c.id=sub.customer_id ORDER BY s.id FOR SHARE OF s,sub,c`, []any{batchID}},
		{scopes + `SELECT sub.id FROM scope q JOIN subscriptions sub ON q.kind='subscription' AND sub.id=q.id JOIN customers c ON c.id=sub.customer_id ORDER BY sub.id FOR SHARE OF sub,c`, []any{batchID}},
		{scopes + `SELECT c.id FROM scope q JOIN customers c ON q.kind='customer' AND c.id=q.id ORDER BY c.id FOR SHARE OF c`, []any{batchID}},
		{scopes + `SELECT r.id FROM reseller_accounts r WHERE r.id IN (SELECT reseller_id FROM scope UNION SELECT c.reseller_id FROM customers c WHERE c.id IN(SELECT q.id FROM scope q WHERE q.kind='customer' UNION SELECT sub.customer_id FROM scope q JOIN subscriptions sub ON q.kind='subscription' AND sub.id=q.id UNION SELECT sub.customer_id FROM scope q JOIN sites s ON q.kind='site' AND s.id=q.id JOIN subscriptions sub ON sub.id=s.subscription_id)) ORDER BY r.id FOR SHARE OF r`, []any{batchID}},
	}
	for _, q := range queries {
		rows, err := tx.QueryContext(ctx, q.sql, q.args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
