package workspace

import (
	"context"
	"database/sql"
	"github.com/nakroteck/nakpanel/internal/control/auth"
)

func (s *Store) CanRemoveSite(ctx context.Context, actor auth.SessionUser, siteID int64) (bool, error) {
	return canRemoveSite(ctx, s.db, actor, siteID)
}

func (s *Store) CanRemoveSiteTx(ctx context.Context, tx *sql.Tx, actor auth.SessionUser, siteID int64) (bool, error) {
	return canRemoveSite(ctx, tx, actor, siteID)
}

func canRemoveSite(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, actor auth.SessionUser, siteID int64) (bool, error) {
	if siteID <= 0 {
		return false, nil
	}
	if actor.Role == auth.RoleAdmin {
		return true, nil
	}
	if actor.Role != auth.RoleClient && actor.Role != auth.RoleReseller {
		return false, nil
	}
	var allowed bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(
 SELECT 1 FROM sites site JOIN subscriptions sub ON sub.id=site.subscription_id
 JOIN customers customer ON customer.id=sub.customer_id
 LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
 WHERE site.id=$1 AND (
 ($3::text='client' AND customer.login_user_id=$2 AND customer.status='active' AND sub.status='active'
   AND (customer.reseller_id IS NULL OR (reseller.status='active' AND EXISTS(SELECT 1 FROM reseller_subscriptions WHERE reseller_id=reseller.id AND status='active'))))
 OR ($3::text='reseller' AND reseller.login_user_id=$2 AND reseller.status='active'
   AND EXISTS(SELECT 1 FROM reseller_subscriptions WHERE reseller_id=reseller.id AND status='active'))
 ))`, siteID, actor.ID, string(actor.Role)).Scan(&allowed)
	return allowed, err
}
