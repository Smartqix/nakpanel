package provision

import (
	"context"
	"database/sql"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"slices"
)

func (r *SQLPhase6Repository) CreateSiteRequest(ctx context.Context, id int64) (types.CreateSiteReq, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return types.CreateSiteReq{}, err
	}
	defer tx.Rollback()
	var req types.CreateSiteReq
	var root string
	err = tx.QueryRowContext(ctx, `SELECT site.id,site.subscription_id,site.username,site.domain,COALESCE(NULLIF(site.desired_php_version,''),site.php_version),site.document_root
 FROM sites site JOIN subscriptions sub ON sub.id=site.subscription_id JOIN customers customer ON customer.id=sub.customer_id
 LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
 WHERE site.id=$1 AND site.removal_state='none' AND site.desired_status='active' AND sub.status='active' AND customer.status='active'
 AND (customer.reseller_id IS NULL OR (reseller.status='active' AND EXISTS(SELECT 1 FROM reseller_subscriptions allocation WHERE allocation.reseller_id=reseller.id AND allocation.status='active')))`, id).Scan(&req.SiteID, &req.SubscriptionID, &req.Username, &req.Domain, &req.PHPVersion, &root)
	if err != nil {
		return req, err
	}
	policy, err := controlquota.EffectiveSitePolicyTx(ctx, tx, id)
	if err != nil {
		return req, err
	}
	if !policy.Permissions.Hosting {
		return req, sql.ErrNoRows
	}
	req.SharedAccount = controlquota.IsSharedSiteDocumentRoot(req.Username, req.Domain, root)
	req.Limits = controlquota.SiteResourceLimitsFromPolicy(policy)
	return req, tx.Commit()
}

func (s *SQLPhase6StatusStore) WebmailRequest(ctx context.Context, id int64) (types.ConfigureWebmailReq, error) {
	var req types.ConfigureWebmailReq
	err := s.db.QueryRowContext(ctx, `SELECT site.id,site.subscription_id,site.domain,host.hostname FROM webmail_hosts host
 JOIN sites site ON site.id=host.site_id JOIN subscriptions sub ON sub.id=site.subscription_id JOIN customers customer ON customer.id=sub.customer_id
 LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
 WHERE host.id=$1 AND site.removal_state='none' AND site.status='active' AND site.desired_status='active' AND sub.status='active' AND customer.status='active'
 AND (customer.reseller_id IS NULL OR (reseller.status='active' AND EXISTS(SELECT 1 FROM reseller_subscriptions allocation WHERE allocation.reseller_id=reseller.id AND allocation.status='active')))`, id).Scan(&req.SiteID, &req.SubscriptionID, &req.Domain, &req.Hostname)
	if err != nil {
		return req, err
	}
	policy, err := controlquota.NewSQLStore(s.db).EffectiveSitePolicy(ctx, req.SiteID)
	if err != nil {
		return req, err
	}
	if !policy.Permissions.Mail || !policy.Mail.Enabled || !policy.Mail.Webmail {
		return req, sql.ErrNoRows
	}
	return req, nil
}

func (s *SQLPhase6StatusStore) RestoreJobRequest(ctx context.Context, args RestoreBackupArgs) (types.RestoreBackupReq, error) {
	var req types.RestoreBackupReq
	targetID := args.SiteID
	if targetID == 0 {
		var id sql.NullInt64
		if err := s.db.QueryRowContext(ctx, "SELECT site_id FROM backups WHERE id=$1", args.BackupID).Scan(&id); err != nil {
			return req, err
		}
		if !id.Valid {
			return req, sql.ErrNoRows
		}
		targetID = id.Int64
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return req, err
	}
	defer tx.Rollback()
	if err = controlquota.LockSiteMutationTx(ctx, tx, targetID); err != nil {
		return req, err
	}
	backup, err := selectRestorableBackupTarget(ctx, tx, args.BackupID, targetID)
	if err != nil {
		return req, err
	}
	active, err := selectActiveSubscriptionDatabases(ctx, tx, backup.subscriptionID)
	if err != nil {
		return req, err
	}
	for _, name := range backup.databases {
		if !slices.Contains(active, name) {
			return req, sql.ErrNoRows
		}
	}
	req = types.RestoreBackupReq{SiteID: backup.siteID, SubscriptionID: backup.subscriptionID, Domain: backup.domain, Username: backup.username, Docroot: backup.documentRoot, ArchivePath: backup.archivePath, SHA256: backup.sha256, Databases: backup.databases}
	return req, tx.Commit()
}
