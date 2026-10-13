package quota

import (
	"context"
	"database/sql"
	"errors"
)

var ErrSiteRemoving = errors.New("website removal has started")

func LockSiteMutationTx(ctx context.Context, tx *sql.Tx, siteID int64) error {
	var subscriptionID int64
	if err := tx.QueryRowContext(ctx, "SELECT subscription_id FROM sites WHERE id=$1", siteID).Scan(&subscriptionID); err != nil {
		return err
	}
	if err := LockSubscriptionMutationTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	var state string
	if err := tx.QueryRowContext(ctx, "SELECT removal_state FROM sites WHERE id=$1 FOR UPDATE", siteID).Scan(&state); err != nil {
		return err
	}
	if state != "none" {
		return ErrSiteRemoving
	}
	return nil
}
