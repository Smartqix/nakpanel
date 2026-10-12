package databaseadmin

import (
	"context"
	"database/sql"
	"errors"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	dbvalidation "github.com/nakroteck/nakpanel/internal/database"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (m *Manager) RotatePasswordForSubscription(ctx context.Context, actorID, databaseID, subscriptionID int64, password string) (types.ManageDatabaseAdminResult, error) {
	if subscriptionID <= 0 {
		return types.ManageDatabaseAdminResult{}, errors.New("subscription is required")
	}
	target, err := m.loadTarget(ctx, databaseID)
	if err != nil {
		return types.ManageDatabaseAdminResult{}, err
	}
	if err = dbvalidation.ValidateCreateDatabaseRequest(types.CreateDatabaseReq{Engine: types.EngineMariaDB, DBName: target.Name, DBUser: target.Principal, Password: password}); err != nil {
		return types.ManageDatabaseAdminResult{}, err
	}
	plaintext := []byte(password)
	defer clear(plaintext)
	return m.queueMutation(ctx, actorID, mutationRequest{Action: types.DatabaseAdminRotatePassword, Target: target, SubscriptionID: subscriptionID}, plaintext)
}

func guardScopedDatabaseMutation(ctx context.Context, tx *sql.Tx, databaseID, subscriptionID int64) error {
	if err := controlquota.LockSubscriptionMutationTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	var id int64
	return tx.QueryRowContext(ctx, `SELECT d.id FROM databases d
 JOIN subscriptions s ON s.id=d.subscription_id
 JOIN customers c ON c.id=s.customer_id
 LEFT JOIN reseller_accounts r ON r.id=c.reseller_id
 WHERE d.id=$1 AND d.subscription_id=$2 AND d.status='active'
 AND s.status='active' AND c.status='active'
 AND (c.reseller_id IS NULL OR (r.status='active' AND EXISTS(SELECT 1 FROM reseller_subscriptions rs WHERE rs.reseller_id=r.id AND rs.status='active')))
 FOR SHARE OF d,s,c`, databaseID, subscriptionID).Scan(&id)
}

func (m *Manager) DatabaseCredentialState(ctx context.Context, databaseID, subscriptionID int64) (string, error) {
	if m == nil || m.db == nil {
		return "", errors.New("database administration unavailable")
	}
	var status string
	err := m.db.QueryRowContext(ctx, `SELECT COALESCE((SELECT o.status FROM server_operations o
 WHERE o.target_type='database' AND o.target_key=d.id::text AND o.action='rotate_password'
 ORDER BY o.id DESC LIMIT 1),'succeeded') FROM databases d WHERE d.id=$1 AND d.subscription_id=$2`, databaseID, subscriptionID).Scan(&status)
	if err != nil {
		return "", err
	}
	switch status {
	case "pending", "running", "awaiting_confirmation":
		return "updating", nil
	case "succeeded":
		return "active", nil
	default:
		return "failed", nil
	}
}
