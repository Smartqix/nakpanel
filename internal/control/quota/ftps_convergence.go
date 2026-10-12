package quota

import (
	"context"
	"database/sql"
	"time"

	"github.com/lib/pq"
	"github.com/nakroteck/nakpanel/internal/types"
)

func acknowledgeFTPSConvergence(ctx context.Context, db *sql.DB, req types.EnsureFTPSReq, status, message string) error {
	ids := make([]int64, 0, len(req.Accounts))
	for _, account := range req.Accounts {
		ids = append(ids, account.ID)
	}
	if len(ids) == 0 {
		return nil
	}
	// A node-wide snapshot must not acknowledge accounts created or edited
	// while the agent was applying it for another subscription.
	_, err := db.ExecContext(ctx, `UPDATE ftp_accounts SET convergence_status=$1,last_error=$2
WHERE id=ANY($3) AND updated_at<=$4`, status, message, pq.Array(ids), time.Unix(0, req.Revision))
	return err
}
