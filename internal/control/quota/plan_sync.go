package quota

import (
	"context"
	"database/sql"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

func (s *SQLStore) PlanSynchronization(ctx context.Context, planID int64) (types.PlanSynchronization, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return types.PlanSynchronization{}, err
	}
	defer tx.Rollback()
	view := types.PlanSynchronization{PlanID: planID, State: "in_sync", Subscriptions: []types.PlanSubscriptionSync{}}
	if err := tx.QueryRowContext(ctx, "SELECT revision FROM plans WHERE id=$1", planID).Scan(&view.Revision); err != nil {
		return view, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT sub.id,sub.name,sub.sync_mode,sub.sync_status,
 COALESCE(ent.source_revision,0),sub.sync_error,COALESCE(account.convergence_status,'missing'),
 COALESCE(account.desired_revision,0),COALESCE(account.applied_revision,0),COALESCE(account.last_error,'')
 FROM subscriptions sub
 LEFT JOIN subscription_entitlements ent ON ent.subscription_id=sub.id
 LEFT JOIN subscription_system_accounts account ON account.subscription_id=sub.id
 WHERE sub.plan_id=$1 ORDER BY sub.id`, planID)
	if err != nil {
		return view, err
	}
	defer rows.Close()
	for rows.Next() {
		var item types.PlanSubscriptionSync
		var snapshotStatus, serviceStatus, serviceError string
		var desired, applied int64
		if err := rows.Scan(&item.ID, &item.Name, &item.Mode, &snapshotStatus, &item.SnapshotRevision,
			&item.Error, &serviceStatus, &desired, &applied, &serviceError); err != nil {
			return view, err
		}
		switch {
		case item.Mode != "synced":
			item.State, item.Error = "excluded", ""
			view.Excluded++
		case snapshotStatus == "out_of_sync" || strings.TrimSpace(item.Error) != "":
			item.State = "failed"
			view.Failed++
		case item.SnapshotRevision != view.Revision || snapshotStatus != "in_sync":
			item.State = "pending"
			view.Pending++
		case serviceStatus == "failed":
			item.State, item.Error = "failed", serviceError
			view.Failed++
		case serviceStatus != "in_sync" || desired != applied:
			item.State = "applying"
			view.Pending++
		default:
			item.State = "in_sync"
			view.Synced++
		}
		if len(item.Error) > 512 {
			item.Error = item.Error[:512]
		}
		view.Subscriptions = append(view.Subscriptions, item)
	}
	if err := rows.Err(); err != nil {
		return view, err
	}
	if view.Failed > 0 {
		view.State = "failed"
	} else if view.Pending > 0 {
		view.State = "pending"
	}
	return view, tx.Commit()
}
