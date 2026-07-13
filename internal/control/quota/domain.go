package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

func (s *SQLStore) SiteDomain(ctx context.Context, siteID int64) (string, error) {
	var domain string
	err := s.db.QueryRowContext(ctx, `SELECT domain FROM sites WHERE id=$1`, siteID).Scan(&domain)
	return domain, err
}

func (s *SQLStore) SetTLSAutoRenew(ctx context.Context, siteID int64, enabled bool) error {
	result, err := s.db.ExecContext(ctx, `UPDATE sites SET tls_auto_renew=$2,updated_at=now() WHERE id=$1`, siteID, enabled)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLStore) UpdateSiteSettings(ctx context.Context, req types.UpdateSiteSettingsReq) error {
	if s == nil || s.db == nil {
		return errors.New("quota database is not configured")
	}
	if req.SiteID <= 0 {
		return errors.New("site id is required")
	}
	req.DesiredStatus = strings.ToLower(strings.TrimSpace(req.DesiredStatus))
	if req.DesiredStatus != "active" && req.DesiredStatus != "suspended" {
		return errors.New("site status must be active or suspended")
	}
	req.DesiredPHPVersion = strings.TrimSpace(req.DesiredPHPVersion)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var username, domain, currentPHP, allowlist, tlsStatus string
	var limits types.SiteResourceLimits
	err = tx.QueryRowContext(ctx, `SELECT site.username,site.domain,site.php_version,e.php_allowlist,site.tls_status,e.site_disk_quota_mb,e.php_fpm_max_children,e.php_memory_mb
FROM sites site JOIN subscriptions sub ON sub.id=site.subscription_id JOIN subscription_entitlements e ON e.subscription_id=sub.id
WHERE site.id=$1 FOR UPDATE OF site`, req.SiteID).Scan(&username, &domain, &currentPHP, &allowlist, &tlsStatus, &limits.DiskQuotaMB, &limits.PHPFPMMaxChildren, &limits.PHPMemoryMB)
	if err != nil {
		return err
	}
	allowed := false
	for _, version := range strings.Split(allowlist, ",") {
		if strings.TrimSpace(version) == req.DesiredPHPVersion {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("PHP %s is not allowed by this subscription", req.DesiredPHPVersion)
	}
	if req.DesiredHTTPSRedirect && tlsStatus != "active" {
		return errors.New("https redirect requires an active certificate")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE sites SET desired_status=$2,desired_php_version=$3,desired_https_redirect=$4,settings_status='pending',settings_error='',updated_at=now() WHERE id=$1`, req.SiteID, req.DesiredStatus, req.DesiredPHPVersion, req.DesiredHTTPSRedirect); err != nil {
		return err
	}
	state := req.DesiredStatus
	if s.river == nil {
		_, err = tx.ExecContext(ctx, `UPDATE sites SET status=$2,php_version=$3,https_redirect=$4,settings_status='in_sync',updated_at=now() WHERE id=$1`, req.SiteID, state, req.DesiredPHPVersion, req.DesiredHTTPSRedirect)
	} else {
		_, err = s.river.InsertTx(ctx, tx, SetHostingStateArgs{SiteID: req.SiteID, SettingsKey: siteSettingsKey(state, req.DesiredPHPVersion, req.DesiredHTTPSRedirect, limits), Username: username, Domain: domain, PHPVersion: currentPHP, State: state}, nil)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) ChangeSubscriptionPlans(ctx context.Context, ids []int64, planID int64) error {
	if len(ids) == 0 || planID <= 0 {
		return errors.New("subscriptions and plan are required")
	}
	if s == nil || s.db == nil {
		return errors.New("quota database is not configured")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	plan, err := selectPlanForUpdateTx(ctx, tx, planID)
	if err != nil {
		return err
	}
	if !plan.IsActive {
		return fmt.Errorf("plan %q is inactive", plan.Name)
	}
	for _, id := range uniqueSortedIDs(ids) {
		var resellerID int64
		var status string
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(c.reseller_id,0),s.status FROM subscriptions s JOIN customers c ON c.id=s.customer_id WHERE s.id=$1 FOR UPDATE OF s,c`, id).Scan(&resellerID, &status); err != nil {
			return err
		}
		if resellerID != plan.ResellerID {
			return errors.New("plan and subscription must belong to the same provider")
		}
		if _, err = subscriptionOversellWarningForSubscriptionTx(ctx, tx, id, plan, status); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE subscriptions SET plan_id=$2,sync_mode='synced',sync_status='pending',sync_error='',updated_at=now() WHERE id=$1`, id, planID); err != nil {
			return err
		}
		if err = syncSubscriptionTx(ctx, tx, id, true); err != nil {
			return err
		}
		if err = s.enqueueSubscriptionHostingStateTx(ctx, tx, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) ChangeSubscriptionSubscriber(ctx context.Context, ids []int64, customerID int64) error {
	if len(ids) == 0 || customerID <= 0 {
		return errors.New("subscriptions and customer are required")
	}
	if s == nil || s.db == nil {
		return errors.New("quota database is not configured")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	target, err := selectCustomerTx(ctx, tx, customerID)
	if err != nil {
		return err
	}
	if target.Status != "active" {
		return fmt.Errorf("customer %d is %s", target.ID, target.Status)
	}
	for _, id := range uniqueSortedIDs(ids) {
		var resellerID int64
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(c.reseller_id,0) FROM subscriptions s JOIN customers c ON c.id=s.customer_id WHERE s.id=$1 FOR UPDATE OF s,c`, id).Scan(&resellerID); err != nil {
			return err
		}
		if resellerID != target.ResellerID {
			return errors.New("subscriber and subscription must belong to the same provider")
		}
		if _, err = tx.ExecContext(ctx, `UPDATE subscriptions SET customer_id=$2,customer_user_id=$3,updated_at=now() WHERE id=$1`, id, customerID, nullableInt64(target.LoginUserID)); err != nil {
			return err
		}
		if err = relinkSubscriptionResourcesToCustomerTx(ctx, tx, id, customerID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func uniqueSortedIDs(ids []int64) []int64 {
	seen := make(map[int64]struct{}, len(ids))
	result := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
