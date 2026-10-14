package quota

import (
	"context"
	"database/sql"
	"errors"
	"github.com/nakroteck/nakpanel/internal/types"
)

// Only access and surviving hosting intent converge here; deployments,
// migrations, and shared cache lifecycle are deliberately left untouched.
func ConvergeRemovalAccess(ctx context.Context, db *sql.DB, agent SubscriptionConvergenceAgent, subscriptionID int64) error {
	unlock := lockSubscriptionConvergence(subscriptionID)
	defer unlock()
	snapshot, err := loadSubscriptionConvergence(ctx, db, subscriptionID)
	if err != nil {
		return err
	}
	response, err := agent.EnsureSubscriptionAccount(ctx, snapshot.Account)
	if err != nil {
		return err
	}
	if !response.OK {
		return errors.New("surviving hosting and SFTP configuration failed")
	}
	response, err = agent.ApplyScheduledTasks(ctx, types.ApplyScheduledTasksReq{SubscriptionID: subscriptionID, Username: snapshot.Account.Username, HomePath: snapshot.Account.HomePath, Tasks: snapshot.Account.Tasks})
	if err != nil {
		return err
	}
	if !response.OK {
		return errors.New("surviving scheduled task configuration failed")
	}
	if err = convergeFTPSAccounts(ctx, db, agent); err != nil {
		return err
	}
	var current int64
	if err = db.QueryRowContext(ctx, "SELECT desired_revision FROM subscription_system_accounts WHERE subscription_id=$1", subscriptionID).Scan(&current); err != nil {
		return err
	}
	if current != snapshot.DesiredRevision {
		return errors.New("subscription access intent changed during removal convergence")
	}
	return nil
}
