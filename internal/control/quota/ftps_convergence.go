package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/types"
)

type ftpsAccountVersion struct {
	ID      int64  `json:"id"`
	Version string `json:"version"`
}

// Status acknowledgements must not invalidate another captured intent.
// Compare all desired fields and the exact intent timestamp, not xmin or a
// transaction-start cutoff. Normalize timestamps across database sessions.
const ftpsIntentVersionSQL = `jsonb_build_array(ftp.subscription_id,ftp.site_id,ftp.name,ftp.password_hash,ftp.enabled,ftp.updated_at AT TIME ZONE 'UTC')::text`

type ftpsConvergenceExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func acknowledgeFTPSConvergence(ctx context.Context, db ftpsConvergenceExecer, versions []ftpsAccountVersion, status, message string) error {
	if len(versions) == 0 {
		return nil
	}
	raw, err := json.Marshal(versions)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `UPDATE ftp_accounts ftp SET convergence_status=$1,last_error=$2
FROM jsonb_to_recordset($3::jsonb) AS applied(id bigint,version text)
WHERE ftp.id=applied.id AND `+ftpsIntentVersionSQL+`=applied.version`, status, message, string(raw))
	return err
}

func lockFTPSTx(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err := LockFTPSConvergenceTx(ctx, tx); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

// LockFTPSConvergenceTx serializes node-wide FTP changes through their runtime
// apply and acknowledgement. Acquire it before resource mutation locks.
func LockFTPSConvergenceTx(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7443,21)`)
	return err
}

func convergeFTPSAccounts(ctx context.Context, db *sql.DB, agent SubscriptionConvergenceAgent) error {
	tx, err := lockFTPSTx(ctx, db)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	req, versions, err := loadFTPSConvergenceTx(ctx, tx)
	if err != nil {
		return err
	}
	_, applyErr := agent.EnsureFTPS(ctx, req)
	status, message := "in_sync", ""
	if applyErr != nil {
		status, message = "failed", applyErr.Error()
	}
	if err := acknowledgeFTPSConvergence(ctx, tx, versions, status, message); err != nil {
		return errors.Join(applyErr, err)
	}
	return errors.Join(applyErr, tx.Commit())
}

func loadFTPSConvergenceTx(ctx context.Context, tx *sql.Tx) (types.EnsureFTPSReq, []ftpsAccountVersion, error) {
	req := types.EnsureFTPSReq{Revision: time.Now().UnixNano(), State: "suspended"}
	rows, err := tx.QueryContext(ctx, `SELECT ftp.id,ftp.subscription_id,account.username,COALESCE(ftp.site_id,0),COALESCE(site.domain,''),ftp.name,ftp.password_hash,
ftp.enabled AND sub.status='active' AND customer.status='active' AND (customer.reseller_id IS NULL OR reseller.status='active')
AND (customer.reseller_id IS NULL OR EXISTS (
    SELECT 1 FROM reseller_subscriptions allocation
    WHERE allocation.reseller_id=customer.reseller_id AND allocation.status='active'
)),`+ftpsIntentVersionSQL+`
FROM ftp_accounts ftp
JOIN subscriptions sub ON sub.id=ftp.subscription_id
JOIN customers customer ON customer.id=sub.customer_id
JOIN subscription_system_accounts account ON account.subscription_id=sub.id
LEFT JOIN sites site ON site.id=ftp.site_id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
ORDER BY ftp.id`)
	if err != nil {
		return req, nil, err
	}
	type pendingAccount struct {
		account          types.EnsureFTPSAccount
		subscriptionID   int64
		lifecycleEnabled bool
		version          string
	}
	var accounts []pendingAccount
	for rows.Next() {
		var pending pendingAccount
		if err := rows.Scan(&pending.account.ID, &pending.subscriptionID, &pending.account.Username, &pending.account.SiteID, &pending.account.Domain, &pending.account.Name, &pending.account.PasswordHash, &pending.lifecycleEnabled, &pending.version); err != nil {
			rows.Close()
			return req, nil, err
		}
		accounts = append(accounts, pending)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return req, nil, err
	}
	if err := rows.Close(); err != nil {
		return req, nil, err
	}
	policies := make(map[int64]types.HostingPolicy)
	versions := make([]ftpsAccountVersion, 0, len(accounts))
	for _, pending := range accounts {
		policy, ok := policies[pending.subscriptionID]
		if !ok {
			base, patch, err := effectiveSubscriptionPolicyTx(ctx, tx, pending.subscriptionID)
			if err != nil {
				return req, nil, err
			}
			policy, err = controlpolicy.Resolve(base, patch, nil)
			if err != nil {
				return req, nil, err
			}
			policies[pending.subscriptionID] = policy
		}
		pending.account.Enabled = effectiveFTPSAccountEnabled(pending.lifecycleEnabled, policy)
		if pending.account.Enabled {
			req.State = "active"
		}
		req.Accounts = append(req.Accounts, pending.account)
		versions = append(versions, ftpsAccountVersion{ID: pending.account.ID, Version: pending.version})
	}
	return req, versions, nil
}
