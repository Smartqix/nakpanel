package provision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type lockedSubscriptionLimits struct {
	MaxSites        int
	MaxDatabases    int
	MaxBackups      int
	BackupStorageMB int
	OverusePolicy   types.PlanOverusePolicy
	HostingEnabled  bool
	AllowBackups    bool
}

func lockActiveSubscriptionLimits(ctx context.Context, tx *sql.Tx, subscriptionID int64) (lockedSubscriptionLimits, error) {
	var limits lockedSubscriptionLimits
	err := tx.QueryRowContext(ctx, `SELECT e.max_sites,e.max_databases,e.max_backups,e.backup_storage_mb,e.overuse_policy,e.hosting_enabled,e.allow_backups
FROM subscriptions s
JOIN subscription_entitlements e ON e.subscription_id=s.id
JOIN customers c ON c.id=s.customer_id
LEFT JOIN reseller_accounts r ON r.id=c.reseller_id
LEFT JOIN reseller_subscriptions rs ON rs.reseller_id=r.id AND rs.status='active'
WHERE s.id=$1 AND s.status='active' AND c.status='active'
  AND (c.reseller_id IS NULL OR (r.status='active' AND rs.id IS NOT NULL))
FOR UPDATE OF s,c`, subscriptionID).Scan(&limits.MaxSites, &limits.MaxDatabases, &limits.MaxBackups, &limits.BackupStorageMB, &limits.OverusePolicy, &limits.HostingEnabled, &limits.AllowBackups)
	if errors.Is(err, sql.ErrNoRows) {
		return lockedSubscriptionLimits{}, controlquota.ErrNoActiveSubscription
	}
	return limits, err
}

func guardSiteIntentTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, domain string) error {
	limits, err := lockActiveSubscriptionLimits(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	if !limits.HostingEnabled {
		return fmt.Errorf("%w: hosting is disabled by the subscription", controlquota.ErrExceeded)
	}
	var existingSubscription int64
	err = tx.QueryRowContext(ctx, `SELECT subscription_id FROM sites WHERE domain=$1 FOR UPDATE`, domain).Scan(&existingSubscription)
	if err == nil {
		if existingSubscription != subscriptionID {
			return ErrForbidden
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return enforceCountLimitTx(ctx, tx, "sites", subscriptionID, limits.MaxSites, limits.OverusePolicy)
}

func guardDatabaseIntentTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, name string) error {
	limits, err := lockActiveSubscriptionLimits(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	var existingSubscription int64
	err = tx.QueryRowContext(ctx, `SELECT subscription_id FROM databases WHERE db_name=$1 FOR UPDATE`, name).Scan(&existingSubscription)
	if err == nil {
		if existingSubscription != subscriptionID {
			return ErrForbidden
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return enforceCountLimitTx(ctx, tx, "databases", subscriptionID, limits.MaxDatabases, limits.OverusePolicy)
}

func guardBackupIntentTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) error {
	limits, err := lockActiveSubscriptionLimits(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	if !limits.AllowBackups {
		return fmt.Errorf("%w: backups are disabled by the subscription", controlquota.ErrExceeded)
	}
	if err := enforceCountLimitTx(ctx, tx, "backups", subscriptionID, limits.MaxBackups, limits.OverusePolicy); err != nil {
		return err
	}
	if limits.BackupStorageMB >= 0 {
		var used int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size_bytes),0)::bigint FROM backups WHERE subscription_id=$1 AND status='active'`, subscriptionID).Scan(&used); err != nil {
			return err
		}
		allowed := int64(limits.BackupStorageMB) * 1024 * 1024
		if used >= allowed {
			return fmt.Errorf("%w: backup storage %d / %d bytes", controlquota.ErrExceeded, used, allowed)
		}
	}
	return nil
}

func enforceCountLimitTx(ctx context.Context, tx *sql.Tx, table string, subscriptionID int64, allowed int, policy types.PlanOverusePolicy) error {
	if policy == types.PlanOveruseNormal || policy == types.PlanOveruseNotify {
		return nil
	}
	if allowed < 0 {
		return nil
	}
	query := map[string]string{
		"sites":     `SELECT COUNT(*)::int FROM sites WHERE subscription_id=$1 AND status<>'failed'`,
		"databases": `SELECT COUNT(*)::int FROM databases WHERE subscription_id=$1 AND status<>'failed'`,
		"backups":   `SELECT COUNT(*)::int FROM backups WHERE subscription_id=$1 AND status<>'failed'`,
	}[table]
	if query == "" {
		return errors.New("unsupported entitlement resource")
	}
	var used int
	if err := tx.QueryRowContext(ctx, query, subscriptionID).Scan(&used); err != nil {
		return err
	}
	if used >= allowed {
		return fmt.Errorf("%w: %s %d / %d", controlquota.ErrExceeded, table, used, allowed)
	}
	return nil
}
