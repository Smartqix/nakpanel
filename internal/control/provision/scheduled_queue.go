package provision

import (
	"context"
	"database/sql"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
)

func (r *SQLSiteRepository) EnqueueManualScheduledTask(ctx context.Context, actor auth.SessionUser, subscriptionID, taskID int64) (int64, error) {
	if r.river == nil {
		return 0, errors.New("scheduled task queue is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err = controlquota.LockSubscriptionMutationTx(ctx, tx, subscriptionID); err != nil {
		return 0, err
	}
	var siteID int64
	err = tx.QueryRowContext(ctx, `SELECT task.site_id FROM scheduled_tasks task
 JOIN sites site ON site.id=task.site_id AND site.subscription_id=task.subscription_id
 JOIN subscriptions sub ON sub.id=task.subscription_id
 JOIN customers c ON c.id=sub.customer_id
 JOIN users u ON u.id=$3 AND u.role=$4 AND NOT u.login_disabled
 WHERE task.id=$1 AND task.subscription_id=$2 AND task.enabled AND site.status='active' AND site.desired_status='active' AND site.removal_state='none' AND sub.status='active' AND c.status='active'
 AND (c.reseller_id IS NULL OR EXISTS(SELECT 1 FROM reseller_accounts a JOIN reseller_subscriptions allocation ON allocation.reseller_id=a.id AND allocation.status='active' WHERE a.id=c.reseller_id AND a.status='active'))
 AND (u.role='admin' OR (u.role='client' AND c.login_user_id=u.id) OR (u.role='reseller' AND EXISTS(SELECT 1 FROM reseller_accounts a WHERE a.id=c.reseller_id AND a.login_user_id=u.id AND a.status='active')))
 FOR SHARE OF task,site,sub,c,u`, taskID, subscriptionID, actor.ID, string(actor.Role)).Scan(&siteID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrForbidden
	}
	if err != nil {
		return 0, err
	}
	policy, err := controlquota.EffectiveSitePolicyTx(ctx, tx, siteID)
	if err != nil {
		return 0, err
	}
	if !policy.Permissions.ScheduledTasks {
		return 0, controlquota.ErrExceeded
	}
	var runID int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO scheduled_task_runs(task_id,status) VALUES($1,'pending') RETURNING id`, taskID).Scan(&runID); err != nil {
		return 0, err
	}
	if _, err = r.river.InsertTx(ctx, tx, controlquota.RunScheduledTaskArgs{RunID: runID}, nil); err != nil {
		return 0, err
	}
	return runID, tx.Commit()
}
