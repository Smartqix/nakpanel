package maintenance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

const Queue = "maintenance"

func uniqueSweepOpts() river.InsertOpts {
	return river.InsertOpts{Queue: Queue, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

type RenewCertsArgs struct{}

func (RenewCertsArgs) Kind() string                 { return "maintenance_renew_certs" }
func (RenewCertsArgs) InsertOpts() river.InsertOpts { return uniqueSweepOpts() }

type ScheduledBackupsArgs struct {
	Window string `json:"window" river:"unique"`
}

func (ScheduledBackupsArgs) Kind() string                 { return "maintenance_scheduled_backups" }
func (ScheduledBackupsArgs) InsertOpts() river.InsertOpts { return uniqueSweepOpts() }

type PruneBackupsArgs struct{}

func (PruneBackupsArgs) Kind() string                 { return "maintenance_prune_backups" }
func (PruneBackupsArgs) InsertOpts() river.InsertOpts { return uniqueSweepOpts() }

type PruneSiteArgs struct {
	SiteID int64 `json:"site_id" river:"unique"`
}

func (PruneSiteArgs) Kind() string                 { return "maintenance_prune_site_backups" }
func (PruneSiteArgs) InsertOpts() river.InsertOpts { return uniqueSweepOpts() }

type DeleteBackupArgs struct {
	BackupID int64 `json:"backup_id" river:"unique"`
}

func (DeleteBackupArgs) Kind() string { return "maintenance_delete_backup" }
func (DeleteBackupArgs) InsertOpts() river.InsertOpts {
	opts := uniqueSweepOpts()
	opts.MaxAttempts = 3
	return opts
}

type ReconcileArgs struct {
	Scope string `json:"scope" river:"unique"`
}

func (ReconcileArgs) Kind() string                 { return "maintenance_reconcile" }
func (ReconcileArgs) InsertOpts() river.InsertOpts { return uniqueSweepOpts() }

type AgentDeleteClient interface {
	DeleteBackup(context.Context, types.DeleteBackupReq) (types.Response, error)
}

type Service struct {
	db    *sql.DB
	river *river.Client[*sql.Tx]
	agent AgentDeleteClient
	now   func() time.Time
}

func NewService(db *sql.DB, client *river.Client[*sql.Tx], agent AgentDeleteClient) *Service {
	return &Service{db: db, river: client, agent: agent, now: time.Now}
}

func (s *Service) SetRiverClient(client *river.Client[*sql.Tx]) { s.river = client }

func (s *Service) schedulerID(ctx context.Context) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM users WHERE email='scheduler@nakpanel.internal' AND login_disabled=true`).Scan(&id)
	return id, err
}

type RenewCertsWorker struct {
	river.WorkerDefaults[RenewCertsArgs]
	service *Service
}

func NewRenewCertsWorker(s *Service) *RenewCertsWorker { return &RenewCertsWorker{service: s} }
func (w *RenewCertsWorker) Work(ctx context.Context, _ *river.Job[RenewCertsArgs]) error {
	return w.service.renewCertificates(ctx)
}

func (s *Service) renewCertificates(ctx context.Context) error {
	actorID, err := s.schedulerID(ctx)
	if err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT site.id,site.username,site.domain,site.php_version,site.tls_issuer,site.subscription_id,site.customer_id
FROM sites site JOIN subscriptions sub ON sub.id=site.subscription_id
JOIN customers c ON c.id=site.customer_id JOIN subscription_entitlements e ON e.subscription_id=sub.id
WHERE site.status='active' AND site.tls_status IN ('active','failed') AND site.tls_auto_renew=true
AND site.tls_issuer='acme' AND site.tls_expires_at < now()+interval '30 days'
	AND site.tls_cert_path<>'' AND site.tls_key_path<>''
AND sub.status='active' AND c.status='active' AND e.allow_tls=true ORDER BY site.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var a provision.IssueCertArgs
		if err := rows.Scan(&a.SiteID, &a.Username, &a.Domain, &a.PHPVersion, &a.Issuer, &a.SubscriptionID, &a.CustomerID); err != nil {
			return err
		}
		a.Automated, a.ActorUserID = true, actorID
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE sites SET tls_status='pending',tls_last_error='',updated_at=now() WHERE id=$1 AND tls_status IN ('active','failed')`, a.SiteID); err == nil {
			opts := a.InsertOpts()
			opts.Queue = Queue
			opts.MaxAttempts = 3
			_, err = s.river.InsertTx(ctx, tx, a, &opts)
		}
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err != nil {
			return err
		}
	}
	return rows.Err()
}

type ScheduledBackupsWorker struct {
	river.WorkerDefaults[ScheduledBackupsArgs]
	service *Service
}

func NewScheduledBackupsWorker(s *Service) *ScheduledBackupsWorker {
	return &ScheduledBackupsWorker{service: s}
}
func (w *ScheduledBackupsWorker) Work(ctx context.Context, job *river.Job[ScheduledBackupsArgs]) error {
	window, err := time.ParseInLocation("2006-01-02", job.Args.Window, time.Local)
	if err != nil {
		return err
	}
	return w.service.scheduleBackups(ctx, window)
}

func (s *Service) scheduleBackups(ctx context.Context, window time.Time) error {
	actorID, err := s.schedulerID(ctx)
	if err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT site.id,site.owner_user_id,site.customer_id,site.subscription_id,site.username,site.domain
FROM sites site JOIN subscriptions sub ON sub.id=site.subscription_id JOIN customers c ON c.id=site.customer_id
JOIN subscription_entitlements e ON e.subscription_id=sub.id
WHERE site.status='active' AND sub.status='active' AND c.status='active' AND e.allow_backups=true
AND e.max_backups<>0 AND e.backup_storage_mb<>0
AND NOT EXISTS (SELECT 1 FROM backups b WHERE b.site_id=site.id AND b.status='active' AND b.created_at >= $1 AND b.created_at < $1+interval '1 day')
AND NOT EXISTS (SELECT 1 FROM river_job job WHERE job.kind='create_backup' AND job.state IN ('available','retryable','running','scheduled') AND job.args->>'site_id'=site.id::text)
ORDER BY site.id`, window)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var siteID, ownerID, customerID, subscriptionID int64
		var username, domain string
		if err := rows.Scan(&siteID, &ownerID, &customerID, &subscriptionID, &username, &domain); err != nil {
			return err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var backupID int64
		if err = tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE id=$1 FOR UPDATE`, siteID).Scan(&siteID); err == nil {
			err = tx.QueryRowContext(ctx, `INSERT INTO backups(owner_user_id,customer_id,site_id,subscription_id,target_kind,target_name,status,scheduled_for)
SELECT $1,$2,$3,$4,'site',$5,'pending',$6 WHERE NOT EXISTS(SELECT 1 FROM backups existing WHERE existing.site_id=$3 AND existing.status='active' AND existing.created_at >= $6 AND existing.created_at < $6+interval '1 day')
ON CONFLICT(site_id,scheduled_for) WHERE scheduled_for IS NOT NULL DO NOTHING RETURNING id`, ownerID, customerID, siteID, subscriptionID, domain, window).Scan(&backupID)
		}
		if errors.Is(err, sql.ErrNoRows) {
			_ = tx.Rollback()
			continue
		}
		if err == nil {
			dbRows, qerr := tx.QueryContext(ctx, `SELECT db_name FROM databases WHERE site_id=$1 AND status='active' ORDER BY db_name`, siteID)
			var databases []string
			if qerr == nil {
				for dbRows.Next() {
					var name string
					if qerr = dbRows.Scan(&name); qerr != nil {
						break
					}
					databases = append(databases, name)
				}
				if closeErr := dbRows.Close(); qerr == nil {
					qerr = closeErr
				}
			}
			err = qerr
			if err == nil {
				a := provision.CreateBackupArgs{BackupID: backupID, SiteID: siteID, SubscriptionID: subscriptionID, CustomerID: customerID, ActorUserID: actorID, Automated: true, Domain: domain, Username: username, Docroot: "/home/" + username + "/public_html", Databases: databases}
				opts := a.InsertOpts()
				opts.Queue = Queue
				opts.MaxAttempts = 3
				_, err = s.river.InsertTx(ctx, tx, a, &opts)
			}
		}
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err != nil {
			return err
		}
	}
	return rows.Err()
}

type PruneBackupsWorker struct {
	river.WorkerDefaults[PruneBackupsArgs]
	service *Service
}

func NewPruneBackupsWorker(s *Service) *PruneBackupsWorker { return &PruneBackupsWorker{service: s} }
func (w *PruneBackupsWorker) Work(ctx context.Context, _ *river.Job[PruneBackupsArgs]) error {
	return w.service.enqueuePrunes(ctx, 0)
}

type PruneSiteWorker struct {
	river.WorkerDefaults[PruneSiteArgs]
	service *Service
}

func NewPruneSiteWorker(s *Service) *PruneSiteWorker { return &PruneSiteWorker{service: s} }
func (w *PruneSiteWorker) Work(ctx context.Context, j *river.Job[PruneSiteArgs]) error {
	return w.service.enqueuePrunes(ctx, j.Args.SiteID)
}

func (s *Service) enqueuePrunes(ctx context.Context, siteID int64) error {
	rows, err := s.db.QueryContext(ctx, `WITH ranked AS (
SELECT b.id,b.site_id,b.created_at,e.max_backups,e.backup_retention_days,row_number() OVER(PARTITION BY b.site_id ORDER BY b.created_at DESC,b.id DESC) rank
FROM backups b JOIN sites site ON site.id=b.site_id JOIN subscription_entitlements e ON e.subscription_id=site.subscription_id
WHERE b.status='active' AND b.archive_path<>'' AND ($1::bigint=0 OR b.site_id=$1)
AND NOT EXISTS(SELECT 1 FROM river_job job JOIN backups in_flight ON in_flight.id=(job.args->>'backup_id')::bigint WHERE job.kind='create_backup' AND job.state IN('available','retryable','running','scheduled') AND in_flight.site_id=b.site_id AND in_flight.status<>'active'))
SELECT id FROM ranked WHERE (max_backups>=0 AND rank>max_backups) OR (backup_retention_days>=0 AND created_at < now()-(backup_retention_days*interval '1 day')) ORDER BY id`, siteID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			return err
		}
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		res, e := tx.ExecContext(ctx, `UPDATE backups SET status='deleting',last_error='',updated_at=now() WHERE id=$1 AND status='active'`, id)
		if e == nil {
			var n int64
			n, _ = res.RowsAffected()
			if n > 0 {
				a := DeleteBackupArgs{BackupID: id}
				o := a.InsertOpts()
				_, e = s.river.InsertTx(ctx, tx, a, &o)
			}
		}
		if e == nil {
			e = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if e != nil {
			return e
		}
	}
	return rows.Err()
}

type DeleteBackupWorker struct {
	river.WorkerDefaults[DeleteBackupArgs]
	service *Service
}

func NewDeleteBackupWorker(s *Service) *DeleteBackupWorker { return &DeleteBackupWorker{service: s} }
func (w *DeleteBackupWorker) Work(ctx context.Context, j *river.Job[DeleteBackupArgs]) error {
	return w.service.deleteBackup(ctx, j.Args.BackupID)
}

func (s *Service) deleteBackup(ctx context.Context, id int64) error {
	if s.agent == nil {
		return errors.New("delete backup agent is not configured")
	}
	actorID, err := s.schedulerID(ctx)
	if err != nil {
		return err
	}
	var path string
	var customerID, subscriptionID int64
	err = s.db.QueryRowContext(ctx, `UPDATE backups backup SET status='deleting',updated_at=now() FROM sites site WHERE backup.id=$1 AND backup.status IN('deleting','delete_failed') AND site.id=backup.site_id RETURNING backup.archive_path,site.customer_id,site.subscription_id`, id).Scan(&path, &customerID, &subscriptionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	resp, err := s.agent.DeleteBackup(ctx, types.DeleteBackupReq{ArchivePath: path})
	if err == nil && !resp.OK {
		err = errors.New(resp.Error)
	}
	if err != nil {
		_, _ = s.db.ExecContext(ctx, `UPDATE backups SET status='delete_failed',last_error=$2,updated_at=now() WHERE id=$1`, id, err.Error())
		if reportErr := s.recordFailure(ctx, actorID, customerID, subscriptionID, "backup.delete_failed", "backup", id, "Backup deletion failed", err.Error(), fmt.Sprintf("maintenance:backup-delete:%d", id)); reportErr != nil {
			return errors.Join(err, reportErr)
		}
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM backups WHERE id=$1`, id); err != nil {
		return err
	}
	if err = s.auditTx(ctx, tx, actorID, customerID, subscriptionID, "backup.deleted", "backup", id, map[string]any{"archive_path": path}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) ReportCertificate(ctx context.Context, a provision.IssueCertArgs, workErr error) error {
	if !a.Automated {
		return nil
	}
	if workErr != nil {
		return s.recordFailure(ctx, a.ActorUserID, a.CustomerID, a.SubscriptionID, "certificate.renew_failed", "site", a.SiteID, "Certificate renewal failed", workErr.Error(), fmt.Sprintf("maintenance:cert:%d", a.SiteID))
	}
	return s.recordSuccess(ctx, a.ActorUserID, a.CustomerID, a.SubscriptionID, "certificate.renewed", "site", a.SiteID, map[string]any{"domain": a.Domain}, fmt.Sprintf("maintenance:cert:%d", a.SiteID))
}
func (s *Service) ReportBackup(ctx context.Context, a provision.CreateBackupArgs, workErr error) error {
	if !a.Automated {
		if workErr == nil && a.SiteID > 0 {
			pa := PruneSiteArgs{SiteID: a.SiteID}
			o := pa.InsertOpts()
			_, err := s.river.Insert(ctx, pa, &o)
			return err
		}
		return nil
	}
	if workErr != nil {
		return s.recordFailure(ctx, a.ActorUserID, a.CustomerID, a.SubscriptionID, "backup.create_failed", "backup", a.BackupID, "Scheduled backup failed", workErr.Error(), fmt.Sprintf("maintenance:backup:%d", a.BackupID))
	}
	if err := s.recordSuccess(ctx, a.ActorUserID, a.CustomerID, a.SubscriptionID, "backup.created", "backup", a.BackupID, map[string]any{"domain": a.Domain}, fmt.Sprintf("maintenance:backup:%d", a.BackupID)); err != nil {
		return err
	}
	pa := PruneSiteArgs{SiteID: a.SiteID}
	o := pa.InsertOpts()
	_, err := s.river.Insert(ctx, pa, &o)
	return err
}
func (s *Service) ReportReconcile(ctx context.Context, a provision.ReconcileSystemArgs, result *types.ReconcileSystemResult, workErr error) error {
	if !a.Automated {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	meta := map[string]any{}
	if result != nil {
		meta["sites_total"] = result.SitesTotal
		meta["sites_ok"] = result.SitesOK
		meta["failed"] = result.Failed
		meta["attention"] = result.Attention
		for _, item := range result.Resources {
			if item.Outcome == "unchanged" {
				continue
			}
			action := item.ResourceType + ".reconcile_" + item.Outcome
			if err = s.auditTx(ctx, tx, a.ActorUserID, item.CustomerID, item.SubscriptionID, action, item.ResourceType, item.ResourceID, map[string]any{"name": item.Name, "outcome": item.Outcome, "error": item.Error}); err != nil {
				return err
			}
			if item.Outcome == "failed" || item.Outcome == "detected_only" {
				key := fmt.Sprintf("maintenance:reconcile:%s:%d", item.ResourceType, item.ResourceID)
				if err = s.notifyCustomerTx(ctx, tx, item.CustomerID, item.SubscriptionID, "Configuration drift requires attention", item.Name+": "+item.Error, key); err != nil {
					return err
				}
			}
		}
	}
	action := "system.reconciled"
	if workErr != nil {
		action = "system.reconcile_failed"
		meta["error"] = workErr.Error()
		if _, err = tx.ExecContext(ctx, `INSERT INTO notifications(recipient_user_id,kind,severity,title,body,dedupe_key)VALUES($1,'maintenance_failed','critical','System reconciliation failed',$2,'maintenance:reconcile') ON CONFLICT(dedupe_key) WHERE resolved_at IS NULL DO UPDATE SET body=EXCLUDED.body,updated_at=now()`, a.ActorUserID, workErr.Error()); err != nil {
			return err
		}
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE notifications SET resolved_at=now(),updated_at=now() WHERE dedupe_key='maintenance:reconcile' AND resolved_at IS NULL`)
		if err != nil {
			return err
		}
	}
	if err = s.auditTx(ctx, tx, a.ActorUserID, 0, 0, action, "reconciliation", a.RunID, meta); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) recordFailure(ctx context.Context, actor, customer, subscription int64, action, target string, targetID int64, title, body, key string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.notifyCustomerTx(ctx, tx, customer, subscription, title, body, key); err != nil {
		return err
	}
	if err = s.auditTx(ctx, tx, actor, customer, subscription, action, target, targetID, map[string]any{"error": body}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) notifyCustomerTx(ctx context.Context, tx *sql.Tx, customer, subscription int64, title, body, key string) error {
	_, err := tx.ExecContext(ctx, `WITH recipient AS (
SELECT id,login_user_id,reseller_id,email FROM customers WHERE id=$1
), upserted AS (
INSERT INTO notifications(recipient_user_id,customer_id,reseller_id,subscription_id,kind,severity,title,body,dedupe_key)
SELECT login_user_id,id,reseller_id,NULLIF($2,0),'maintenance_failed','critical',$3,$4,$5 FROM recipient
ON CONFLICT(dedupe_key) WHERE resolved_at IS NULL DO UPDATE SET title=EXCLUDED.title,body=EXCLUDED.body,updated_at=now()
RETURNING id
)
INSERT INTO notification_deliveries(notification_id,channel,recipient)
SELECT upserted.id,'smtp',recipient.email FROM upserted CROSS JOIN recipient WHERE recipient.email<>''
ON CONFLICT(notification_id,channel,recipient) DO NOTHING`, customer, subscription, title, body, key)
	return err
}
func (s *Service) recordSuccess(ctx context.Context, actor, customer, subscription int64, action, target string, targetID int64, meta map[string]any, key string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE notifications SET resolved_at=now(),updated_at=now() WHERE dedupe_key=$1 AND resolved_at IS NULL`, key); err != nil {
		return err
	}
	if err = s.auditTx(ctx, tx, actor, customer, subscription, action, target, targetID, meta); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, actor, customer, subscription int64, action, target string, targetID int64, meta map[string]any) error {
	b, _ := json.Marshal(meta)
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata)VALUES($1,NULLIF($2,0),NULLIF($3,0),$4,$5,$6,$7)`, actor, customer, subscription, action, target, targetID, b)
	return err
}

type ReconcileWorker struct {
	river.WorkerDefaults[ReconcileArgs]
	service *Service
}

func NewReconcileWorker(s *Service) *ReconcileWorker { return &ReconcileWorker{service: s} }
func (w *ReconcileWorker) Work(ctx context.Context, _ *river.Job[ReconcileArgs]) error {
	actor, err := w.service.schedulerID(ctx)
	if err != nil {
		return err
	}
	return w.service.enqueueReconcile(ctx, actor)
}
func (s *Service) enqueueReconcile(ctx context.Context, actor int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT site.id,site.customer_id,site.subscription_id,site.username,site.domain,site.php_version,site.desired_php_version,
EXISTS(SELECT 1 FROM webmail_hosts w WHERE w.site_id=site.id),EXISTS(SELECT 1 FROM dns_zones dz WHERE dz.site_id=site.id),COALESCE(z.id,0),COALESCE(z.serial,0),COALESCE(z.address,''),
CASE WHEN c.status='active' AND sub.status='active' THEN site.desired_status ELSE 'suspended' END,
site.desired_https_redirect AND site.tls_status='active',CASE WHEN site.tls_status='active' THEN site.tls_cert_path ELSE '' END,CASE WHEN site.tls_status='active' THEN site.tls_key_path ELSE '' END,
e.site_disk_quota_mb,e.php_fpm_max_children,e.php_memory_mb
FROM sites site JOIN subscriptions sub ON sub.id=site.subscription_id JOIN customers c ON c.id=site.customer_id
JOIN subscription_entitlements e ON e.subscription_id=sub.id LEFT JOIN dns_zones z ON z.site_id=site.id
WHERE site.status<>'failed' ORDER BY site.domain`)
	if err != nil {
		return err
	}
	var sites []types.ReconcileSiteReq
	for rows.Next() {
		var x types.ReconcileSiteReq
		if err = rows.Scan(&x.SiteID, &x.CustomerID, &x.SubscriptionID, &x.Username, &x.Domain, &x.PHPVersion, &x.DesiredPHPVersion, &x.EnableWebmail, &x.EnableDNS, &x.DNSZoneID, &x.DNSSerial, &x.Address, &x.State, &x.HTTPSRedirect, &x.TLSCertPath, &x.TLSKeyPath, &x.Limits.DiskQuotaMB, &x.Limits.PHPFPMMaxChildren, &x.Limits.PHPMemoryMB); err != nil {
			break
		}
		sites = append(sites, x)
	}
	if closeErr := rows.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	for i := range sites {
		if !sites[i].EnableDNS {
			continue
		}
		recordRows, qerr := tx.QueryContext(ctx, `SELECT r.id,r.zone_id,r.host,r.record_type,r.value,COALESCE(r.priority,0),r.ttl FROM dns_records r JOIN dns_zones z ON z.id=r.zone_id WHERE z.site_id=$1 ORDER BY r.host,r.record_type,r.id`, sites[i].SiteID)
		if qerr != nil {
			return qerr
		}
		for recordRows.Next() {
			var record types.DNSRecord
			if qerr = recordRows.Scan(&record.ID, &record.ZoneID, &record.Host, &record.Type, &record.Value, &record.Priority, &record.TTL); qerr != nil {
				break
			}
			sites[i].DNSRecords = append(sites[i].DNSRecords, record)
		}
		if closeErr := recordRows.Close(); qerr == nil {
			qerr = closeErr
		}
		if qerr != nil {
			return qerr
		}
	}
	dbRows, err := tx.QueryContext(ctx, `SELECT d.id,d.customer_id,d.subscription_id,d.db_name FROM databases d JOIN subscriptions sub ON sub.id=d.subscription_id JOIN customers c ON c.id=d.customer_id WHERE d.status='active' AND sub.status='active' AND c.status='active' ORDER BY d.id`)
	if err != nil {
		return err
	}
	var databases []types.ReconcileDatabaseReq
	for dbRows.Next() {
		var d types.ReconcileDatabaseReq
		if err = dbRows.Scan(&d.DatabaseID, &d.CustomerID, &d.SubscriptionID, &d.Name); err != nil {
			break
		}
		databases = append(databases, d)
	}
	if closeErr := dbRows.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	var runID int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO reconciliation_runs(owner_user_id,status,sites_total)VALUES($1,'pending',$2)RETURNING id`, actor, len(sites)).Scan(&runID); err != nil {
		return err
	}
	a := provision.ReconcileSystemArgs{RunID: runID, ScopeKey: "system", ActorUserID: actor, Automated: true, Sites: sites, Databases: databases}
	o := a.InsertOpts()
	o.Queue = Queue
	o.MaxAttempts = 3
	if _, err = s.river.InsertTx(ctx, tx, a, &o); err != nil {
		return err
	}
	return tx.Commit()
}
