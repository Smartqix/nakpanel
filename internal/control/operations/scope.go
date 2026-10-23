package operations

import (
	"context"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/control/auth"
)

// resourcePredicate is shared by detail/list/count/action queries. Alias and
// parameter positions are internal SQL construction, never request input.
func resourcePredicate(alias string, user, role int) string {
	u, r := fmt.Sprintf("$%d", user), fmt.Sprintf("$%d", role)
	return fmt.Sprintf(`EXISTS(SELECT 1 FROM users viewer WHERE viewer.id=%s AND viewer.role=%s) AND (
 (%s.resource_kind='user' AND %s.resource_id=%s) OR
 (%s.resource_kind<>'user' AND %s='admin') OR
 (%s.resource_kind IN ('site','subscription','customer') AND EXISTS(
 SELECT 1 FROM customers scope_customer WHERE
 ((%s.resource_kind='customer' AND scope_customer.id=%s.resource_id) OR
 (%s.resource_kind='subscription' AND EXISTS(SELECT 1 FROM subscriptions scope_sub WHERE scope_sub.id=%s.resource_id AND scope_sub.customer_id=scope_customer.id)) OR
 (%s.resource_kind='site' AND EXISTS(SELECT 1 FROM sites scope_site JOIN subscriptions scope_sub ON scope_sub.id=scope_site.subscription_id WHERE scope_site.id=%s.resource_id AND scope_sub.customer_id=scope_customer.id)))
 AND ((%s='client' AND scope_customer.login_user_id=%s) OR (%s='reseller' AND EXISTS(SELECT 1 FROM reseller_accounts scope_reseller WHERE scope_reseller.id=scope_customer.reseller_id AND scope_reseller.login_user_id=%s))))))`, u, r, alias, alias, u, alias, r, alias, alias, alias, alias, alias, alias, alias, r, u, r, u)
}

// NotificationVisibilitySQL uses the same current ownership boundary for inbox,
// receipts and existing quota callers. Personal security messages remain private
// even from other administrators. $user and $role are bound SQL parameters.
func NotificationVisibilitySQL(alias string, user, role int) string {
	u, r := fmt.Sprintf("$%d", user), fmt.Sprintf("$%d", role)
	return fmt.Sprintf(`EXISTS(SELECT 1 FROM users viewer WHERE viewer.id=%s AND viewer.role=%s) AND (
 (%s.subscription_id IS NOT NULL AND EXISTS(SELECT 1 FROM subscriptions ns JOIN customers nc ON nc.id=ns.customer_id WHERE ns.id=%s.subscription_id AND (%s='admin' OR (%s='client' AND nc.login_user_id=%s) OR (%s='reseller' AND EXISTS(SELECT 1 FROM reseller_accounts nr WHERE nr.id=nc.reseller_id AND nr.login_user_id=%s))))) OR
 (%s.subscription_id IS NULL AND %s.customer_id IS NOT NULL AND EXISTS(SELECT 1 FROM customers nc WHERE nc.id=%s.customer_id AND (%s='admin' OR (%s='client' AND nc.login_user_id=%s) OR (%s='reseller' AND EXISTS(SELECT 1 FROM reseller_accounts nr WHERE nr.id=nc.reseller_id AND nr.login_user_id=%s))))) OR
 (%s.subscription_id IS NULL AND %s.customer_id IS NULL AND %s.reseller_id IS NOT NULL AND (%s='admin' OR (%s='reseller' AND EXISTS(SELECT 1 FROM reseller_accounts nr WHERE nr.id=%s.reseller_id AND nr.login_user_id=%s)))) OR
 (%s.subscription_id IS NULL AND %s.customer_id IS NULL AND %s.reseller_id IS NULL AND ((%s.recipient_user_id=%s) OR (%s.recipient_user_id IS NULL AND %s='admin'))))`, u, r, alias, alias, r, r, u, r, u, alias, alias, alias, r, r, u, r, u, alias, alias, alias, r, r, alias, u, alias, alias, alias, alias, u, alias, r)
}

func (s *Store) CanView(ctx context.Context, actor auth.SessionUser, resource Resource) (bool, error) {
	if !actor.Role.Valid() || actor.ID <= 0 || !resource.Valid() {
		return false, nil
	}
	var allowed bool
	err := s.db.QueryRowContext(ctx, `SELECT `+resourcePredicate("scope", 1, 2)+` FROM (SELECT $3::text AS resource_kind,$4::bigint AS resource_id) scope`, actor.ID, string(actor.Role), string(resource.Kind), resource.ID).Scan(&allowed)
	return allowed, err
}
