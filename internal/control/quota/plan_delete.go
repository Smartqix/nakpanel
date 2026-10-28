package quota

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

var ErrPlanInUse = errors.New("this plan has subscriptions; move or remove all subscriptions before deleting it")

func (s *SQLStore) DeletePlan(ctx context.Context, planID, resellerID int64, unrestricted bool) error {
	if s == nil || s.db == nil {
		return errors.New("plan database is not configured")
	}
	if planID <= 0 || (!unrestricted && resellerID <= 0) {
		return ErrProviderScope
	}
	// One statement binds authorization to deletion. The subscriptions FK also
	// protects assignments racing this request; cascaded history is atomic.
	result, err := s.db.ExecContext(ctx, `DELETE FROM plans
WHERE id=$1 AND ($3 OR reseller_id=$2)`, planID, resellerID, unrestricted)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "23001") && pgErr.ConstraintName == "subscriptions_plan_id_fkey" {
			return ErrPlanInUse
		}
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrProviderScope
	}
	return nil
}
