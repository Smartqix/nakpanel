package quota

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

const usageCollectionInterval = 15 * time.Minute

type CollectUsageArgs struct{}

func (CollectUsageArgs) Kind() string { return "collect_subscription_usage" }
func (CollectUsageArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

type DeliverNotificationsArgs struct{}

func (DeliverNotificationsArgs) Kind() string { return "deliver_notifications" }
func (DeliverNotificationsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

type UsageAgent interface {
	CollectUsage(context.Context, types.CollectUsageReq) (types.CollectUsageResult, error)
}

type CollectUsageWorker struct {
	river.WorkerDefaults[CollectUsageArgs]
	db    *sql.DB
	agent UsageAgent
	now   func() time.Time
	river *river.Client[*sql.Tx]
}

func (w *CollectUsageWorker) SetRiverClient(client *river.Client[*sql.Tx]) { w.river = client }

func NewCollectUsageWorker(db *sql.DB, agent UsageAgent) *CollectUsageWorker {
	return &CollectUsageWorker{db: db, agent: agent, now: time.Now}
}

func (w *CollectUsageWorker) Work(ctx context.Context, _ *river.Job[CollectUsageArgs]) error {
	if w.db == nil || w.agent == nil {
		return errors.New("usage collection is not configured")
	}
	rows, err := w.db.QueryContext(ctx, `SELECT s.id FROM subscriptions s JOIN customers c ON c.id=s.customer_id
WHERE (s.status='active' OR (s.status='suspended' AND s.suspension_reason='resource_overuse'))
  AND c.status='active'
ORDER BY s.id`)
	if err != nil {
		return err
	}
	var subscriptionIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		subscriptionIDs = append(subscriptionIDs, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var collectionErrors []error
	for _, subscriptionID := range subscriptionIDs {
		if err := w.collectSubscription(ctx, subscriptionID); err != nil {
			collectionErrors = append(collectionErrors, fmt.Errorf("subscription %d: %w", subscriptionID, err))
			_ = w.recordCollectionFailure(ctx, subscriptionID, err)
		}
	}
	return errors.Join(collectionErrors...)
}

func (w *CollectUsageWorker) collectSubscription(ctx context.Context, subscriptionID int64) error {
	now := w.now().UTC()
	period := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	sites, err := w.loadUsageSites(ctx, subscriptionID, period)
	if err != nil {
		return err
	}
	databaseNames, err := w.loadDatabaseNames(ctx, subscriptionID)
	if err != nil {
		return err
	}
	result, err := w.agent.CollectUsage(ctx, types.CollectUsageReq{Sites: sites, Databases: databaseNames, PeriodStart: period})
	if err != nil {
		return err
	}
	var siteBytes, trafficDelta int64
	for _, site := range result.Sites {
		siteBytes += site.HomeBytes
		trafficDelta += site.TrafficBytes
	}
	var backupBytes int64
	if err := w.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(size_bytes),0)::bigint FROM backups WHERE subscription_id=$1 AND status='active'`, subscriptionID).Scan(&backupBytes); err != nil {
		return err
	}
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, site := range result.Sites {
		if _, err := tx.ExecContext(ctx, `INSERT INTO site_traffic_cursors (site_id,device_id,inode,byte_offset,period_start,traffic_bytes)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (site_id) DO UPDATE SET device_id=EXCLUDED.device_id,inode=EXCLUDED.inode,
byte_offset=EXCLUDED.byte_offset,period_start=EXCLUDED.period_start,
traffic_bytes=CASE WHEN site_traffic_cursors.period_start=EXCLUDED.period_start THEN site_traffic_cursors.traffic_bytes+EXCLUDED.traffic_bytes ELSE EXCLUDED.traffic_bytes END,
updated_at=now()`, site.SiteID, site.Cursor.DeviceID, site.Cursor.Inode, site.Cursor.Offset, period, site.TrafficBytes); err != nil {
			return err
		}
	}
	var previousTraffic int64
	var previousPeriod time.Time
	err = tx.QueryRowContext(ctx, `SELECT period_start,traffic_bytes FROM subscription_usage_current WHERE subscription_id=$1 FOR UPDATE`, subscriptionID).Scan(&previousPeriod, &previousTraffic)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if !sameMonth(previousPeriod, period) {
		previousTraffic = 0
	}
	usage := types.SubscriptionUsage{SubscriptionID: subscriptionID, PeriodStart: period,
		SiteBytes: siteBytes, DatabaseBytes: result.DatabaseBytes, BackupBytes: backupBytes,
		DiskBytes: siteBytes + result.DatabaseBytes + backupBytes, TrafficBytes: previousTraffic + trafficDelta,
		Complete: true, CollectedAt: now}
	if _, err := tx.ExecContext(ctx, `INSERT INTO subscription_usage_current
(subscription_id,period_start,site_bytes,database_bytes,backup_bytes,disk_bytes,traffic_bytes,is_complete,collected_at,last_error)
VALUES ($1,$2,$3,$4,$5,$6,$7,true,$8,'')
ON CONFLICT (subscription_id) DO UPDATE SET period_start=EXCLUDED.period_start,site_bytes=EXCLUDED.site_bytes,
database_bytes=EXCLUDED.database_bytes,backup_bytes=EXCLUDED.backup_bytes,disk_bytes=EXCLUDED.disk_bytes,
traffic_bytes=EXCLUDED.traffic_bytes,is_complete=true,collected_at=EXCLUDED.collected_at,last_error=''`,
		usage.SubscriptionID, usage.PeriodStart, usage.SiteBytes, usage.DatabaseBytes, usage.BackupBytes,
		usage.DiskBytes, usage.TrafficBytes, usage.CollectedAt); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE notifications SET resolved_at=now(),updated_at=now()
WHERE subscription_id=$1 AND kind='collection_failed' AND resolved_at IS NULL`, subscriptionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO subscription_usage_history
(subscription_id,period_start,site_bytes,database_bytes,backup_bytes,disk_bytes,traffic_bytes,recorded_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, usage.SubscriptionID, usage.PeriodStart, usage.SiteBytes,
		usage.DatabaseBytes, usage.BackupBytes, usage.DiskBytes, usage.TrafficBytes, usage.CollectedAt); err != nil {
		return err
	}
	if err := evaluateUsageTx(ctx, tx, usage, w.river); err != nil {
		return err
	}
	return tx.Commit()
}

func (w *CollectUsageWorker) loadUsageSites(ctx context.Context, subscriptionID int64, period time.Time) ([]types.SiteUsageInput, error) {
	rows, err := w.db.QueryContext(ctx, `SELECT s.id,s.username,s.domain,COALESCE(c.device_id,0),COALESCE(c.inode,0),
COALESCE(CASE WHEN c.period_start=$2::date THEN c.byte_offset ELSE 0 END,0)
FROM sites s LEFT JOIN site_traffic_cursors c ON c.site_id=s.id
WHERE s.subscription_id=$1 AND s.status<>'failed' ORDER BY s.id`, subscriptionID, period)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.SiteUsageInput
	for rows.Next() {
		var site types.SiteUsageInput
		var domain string
		if err := rows.Scan(&site.SiteID, &site.Username, &domain, &site.Cursor.DeviceID, &site.Cursor.Inode, &site.Cursor.Offset); err != nil {
			return nil, err
		}
		site.AccessLog = site.Username + "-" + strings.ReplaceAll(domain, ".", "-") + ".access.log"
		out = append(out, site)
	}
	return out, rows.Err()
}

func (w *CollectUsageWorker) loadDatabaseNames(ctx context.Context, subscriptionID int64) ([]string, error) {
	rows, err := w.db.QueryContext(ctx, `SELECT db_name FROM databases WHERE subscription_id=$1 AND status<>'failed' ORDER BY id`, subscriptionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func (w *CollectUsageWorker) recordCollectionFailure(ctx context.Context, subscriptionID int64, cause error) error {
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO subscription_usage_current (subscription_id,period_start,is_complete,last_error,collected_at)
VALUES ($1,date_trunc('month',now())::date,false,$2,now()) ON CONFLICT (subscription_id) DO UPDATE SET is_complete=false,last_error=EXCLUDED.last_error`, subscriptionID, truncateError(cause)); err != nil {
		return err
	}
	if _, err := upsertNotificationTx(ctx, tx, subscriptionID, "collection_failed", "warning", "Usage collection failed", "Nakpanel retained the last complete usage values.", "usage:"+strconv.FormatInt(subscriptionID, 10)+":collection"); err != nil {
		return err
	}
	return tx.Commit()
}

func evaluateUsageTx(ctx context.Context, tx *sql.Tx, usage types.SubscriptionUsage, riverClient *river.Client[*sql.Tx]) error {
	var entitlement types.SubscriptionEntitlements
	var customerID, recipientUserID, resellerID int64
	var email string
	err := tx.QueryRowContext(ctx, `SELECT e.disk_mb,e.bandwidth_mb,e.overuse_policy,e.disk_warning_percent,e.traffic_warning_percent,
s.customer_id,COALESCE(c.login_user_id,0),COALESCE(c.reseller_id,0),c.email
FROM subscriptions s JOIN subscription_entitlements e ON e.subscription_id=s.id JOIN customers c ON c.id=s.customer_id
WHERE s.id=$1 FOR UPDATE OF s`, usage.SubscriptionID).Scan(&entitlement.DiskMB, &entitlement.BandwidthMB,
		&entitlement.OverusePolicy, &entitlement.DiskWarningPercent, &entitlement.TrafficWarningPercent,
		&customerID, &recipientUserID, &resellerID, &email)
	if err != nil {
		return err
	}
	periodKey := usage.PeriodStart.Format("2006-01")
	diskOver, diskWarning := usageLevel(usage.DiskBytes, entitlement.DiskMB, entitlement.DiskWarningPercent)
	trafficOver, trafficWarning := usageLevel(usage.TrafficBytes, entitlement.BandwidthMB, entitlement.TrafficWarningPercent)
	notify := entitlement.OverusePolicy == types.PlanOveruseNotify || entitlement.OverusePolicy == types.PlanOveruseNotSuspendNotify || entitlement.OverusePolicy == types.PlanOveruseBlock
	if notify && diskWarning {
		if _, err := upsertUsageAlertTx(ctx, tx, usage.SubscriptionID, customerID, recipientUserID, resellerID, email, "disk", periodKey, diskOver, usage.DiskBytes, entitlement.DiskMB); err != nil {
			return err
		}
	} else if err := resolveUsageAlertTx(ctx, tx, usage.SubscriptionID, "disk", periodKey); err != nil {
		return err
	}
	if notify && trafficWarning {
		if _, err := upsertUsageAlertTx(ctx, tx, usage.SubscriptionID, customerID, recipientUserID, resellerID, email, "traffic", periodKey, trafficOver, usage.TrafficBytes, entitlement.BandwidthMB); err != nil {
			return err
		}
	} else if err := resolveUsageAlertTx(ctx, tx, usage.SubscriptionID, "traffic", periodKey); err != nil {
		return err
	}
	if entitlement.OverusePolicy == types.PlanOveruseBlock && (diskOver || trafficOver) {
		res, err := tx.ExecContext(ctx, `UPDATE subscriptions SET status='suspended',suspension_reason='resource_overuse',updated_at=now() WHERE id=$1 AND status='active'`, usage.SubscriptionID)
		if err != nil {
			return err
		}
		if count, _ := res.RowsAffected(); count > 0 {
			if err := NewSQLStore(nil, riverClient).enqueueSubscriptionHostingStateTx(ctx, tx, usage.SubscriptionID); err != nil {
				return err
			}
			_, err = upsertNotificationTx(ctx, tx, usage.SubscriptionID, "suspended", "critical", "Subscription suspended for overuse", "Hosted websites now return a maintenance response until an operator reactivates the subscription.", "usage:"+strconv.FormatInt(usage.SubscriptionID, 10)+":suspended:"+periodKey)
			return err
		}
	}
	return nil
}

func usageLevel(usedBytes int64, limitMB, warningPercent int) (bool, bool) {
	if limitMB < 0 {
		return false, false
	}
	limitBytes := int64(limitMB) * 1024 * 1024
	if limitBytes == 0 {
		return usedBytes > 0, usedBytes > 0
	}
	return usedBytes > limitBytes, usedBytes*100 >= limitBytes*int64(warningPercent)
}

func validateOveruseReactivationTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, entitlements types.SubscriptionEntitlements) error {
	var reason string
	if err := tx.QueryRowContext(ctx, `SELECT suspension_reason FROM subscriptions WHERE id=$1 FOR UPDATE`, subscriptionID).Scan(&reason); err != nil {
		return err
	}
	if reason != "resource_overuse" {
		return nil
	}
	var collectedAt time.Time
	var complete bool
	var diskBytes, trafficBytes int64
	if err := tx.QueryRowContext(ctx, `SELECT collected_at,is_complete,disk_bytes,traffic_bytes FROM subscription_usage_current WHERE subscription_id=$1`, subscriptionID).Scan(&collectedAt, &complete, &diskBytes, &trafficBytes); err != nil {
		return fmt.Errorf("fresh usage is required before reactivation: %w", err)
	}
	if !complete || time.Since(collectedAt) > 2*usageCollectionInterval {
		return errors.New("fresh complete usage is required before reactivation")
	}
	diskOver, _ := usageLevel(diskBytes, entitlements.DiskMB, 100)
	trafficOver, _ := usageLevel(trafficBytes, entitlements.BandwidthMB, 100)
	if diskOver || trafficOver {
		return errors.New("subscription remains over its disk or traffic limit")
	}
	return nil
}

func upsertUsageAlertTx(ctx context.Context, tx *sql.Tx, subscriptionID, customerID, userID, resellerID int64, email, resource, period string, over bool, usedBytes int64, limitMB int) (int64, error) {
	kind, severity, label := "threshold", "warning", "approaching its limit"
	if over {
		kind, severity, label = "over_limit", "critical", "over its limit"
	}
	key := "usage:" + strconv.FormatInt(subscriptionID, 10) + ":" + resource + ":" + kind + ":" + period
	resourceLabel := usageResourceLabel(resource)
	body := fmt.Sprintf("%s usage is %s: %d MB used of %d MB.", resourceLabel, label, usedBytes/(1024*1024), limitMB)
	id, err := upsertNotificationDetailedTx(ctx, tx, subscriptionID, customerID, userID, resellerID, kind, severity, resourceLabel+" usage alert", body, key)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE notifications SET resolved_at=now(),updated_at=now()
WHERE subscription_id=$1 AND resolved_at IS NULL AND id<>$2 AND dedupe_key LIKE $3`, subscriptionID, id, "usage:"+strconv.FormatInt(subscriptionID, 10)+":"+resource+":%:"+period); err != nil {
		return 0, err
	}
	if err := enqueueNotificationRecipientsTx(ctx, tx, id, email, resellerID); err != nil {
		return 0, err
	}
	return id, nil
}

func usageResourceLabel(resource string) string {
	if resource == "disk" {
		return "Disk"
	}
	if resource == "traffic" {
		return "Traffic"
	}
	return "Resource"
}

func enqueueNotificationRecipientsTx(ctx context.Context, tx *sql.Tx, notificationID int64, customerEmail string, resellerID int64) error {
	recipients := map[string]struct{}{}
	if email := strings.TrimSpace(customerEmail); email != "" {
		recipients[email] = struct{}{}
	}
	query := `SELECT email FROM users WHERE role='admin' ORDER BY id`
	args := []any{}
	if resellerID > 0 {
		query = `SELECT email FROM reseller_accounts WHERE id=$1`
		args = append(args, resellerID)
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			rows.Close()
			return err
		}
		if email = strings.TrimSpace(email); email != "" {
			recipients[email] = struct{}{}
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for email := range recipients {
		if _, err := tx.ExecContext(ctx, `INSERT INTO notification_deliveries (notification_id,channel,recipient) VALUES ($1,'smtp',$2) ON CONFLICT DO NOTHING`, notificationID, email); err != nil {
			return err
		}
	}
	return nil
}

func upsertNotificationTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, kind, severity, title, body, key string) (int64, error) {
	var customerID, userID, resellerID int64
	var email string
	if err := tx.QueryRowContext(ctx, `SELECT s.customer_id,COALESCE(c.login_user_id,0),COALESCE(c.reseller_id,0),c.email
FROM subscriptions s JOIN customers c ON c.id=s.customer_id WHERE s.id=$1`, subscriptionID).Scan(&customerID, &userID, &resellerID, &email); err != nil {
		return 0, err
	}
	id, err := upsertNotificationDetailedTx(ctx, tx, subscriptionID, customerID, userID, resellerID, kind, severity, title, body, key)
	if err != nil {
		return 0, err
	}
	if err := enqueueNotificationRecipientsTx(ctx, tx, id, email, resellerID); err != nil {
		return 0, err
	}
	return id, nil
}

func recordSubscriptionNotification(ctx context.Context, db *sql.DB, subscriptionID int64, kind, severity, title, body, key string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := upsertNotificationTx(ctx, tx, subscriptionID, kind, severity, title, body, key); err != nil {
		return err
	}
	return tx.Commit()
}

func upsertNotificationDetailedTx(ctx context.Context, tx *sql.Tx, subscriptionID, customerID, userID, resellerID int64, kind, severity, title, body, key string) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `INSERT INTO notifications (recipient_user_id,customer_id,reseller_id,subscription_id,kind,severity,title,body,dedupe_key)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (dedupe_key) WHERE resolved_at IS NULL DO UPDATE SET severity=EXCLUDED.severity,title=EXCLUDED.title,body=EXCLUDED.body,updated_at=now()
RETURNING id`, nullableInt64(userID), nullableInt64(customerID), nullableInt64(resellerID), nullableInt64(subscriptionID), kind, severity, title, body, key).Scan(&id)
	return id, err
}

func resolveUsageAlertTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, resource, period string) error {
	_, err := tx.ExecContext(ctx, `UPDATE notifications SET resolved_at=now(),updated_at=now()
WHERE subscription_id=$1 AND resolved_at IS NULL AND dedupe_key LIKE $2`, subscriptionID, "usage:"+strconv.FormatInt(subscriptionID, 10)+":"+resource+":%:"+period)
	return err
}

func sameMonth(a, b time.Time) bool {
	return !a.IsZero() && a.UTC().Year() == b.UTC().Year() && a.UTC().Month() == b.UTC().Month()
}
func truncateError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 1000 {
		value = value[:1000]
	}
	return value
}

type SMTPConfig struct {
	Host, Username, Password, From, TLSMode string
	Port                                    int
}

func (c SMTPConfig) Enabled() bool {
	return strings.TrimSpace(c.Host) != "" && strings.TrimSpace(c.From) != ""
}

type DeliverNotificationsWorker struct {
	river.WorkerDefaults[DeliverNotificationsArgs]
	db     *sql.DB
	config SMTPConfig
}

func NewDeliverNotificationsWorker(db *sql.DB, config SMTPConfig) *DeliverNotificationsWorker {
	return &DeliverNotificationsWorker{db: db, config: config}
}

func (w *DeliverNotificationsWorker) Work(ctx context.Context, _ *river.Job[DeliverNotificationsArgs]) error {
	if w.db == nil || !w.config.Enabled() {
		return nil
	}
	rows, err := w.db.QueryContext(ctx, `SELECT d.id,d.recipient,n.title,n.body FROM notification_deliveries d JOIN notifications n ON n.id=d.notification_id WHERE d.status IN ('pending','failed') AND d.attempts<8 ORDER BY d.id LIMIT 25`)
	if err != nil {
		return err
	}
	type delivery struct {
		id                     int64
		recipient, title, body string
	}
	var deliveries []delivery
	for rows.Next() {
		var item delivery
		if err := rows.Scan(&item.id, &item.recipient, &item.title, &item.body); err != nil {
			rows.Close()
			return err
		}
		deliveries = append(deliveries, item)
	}
	rows.Close()
	var deliveryErrors []error
	for _, item := range deliveries {
		err := sendSMTP(ctx, w.config, item.recipient, item.title, item.body)
		if err != nil {
			deliveryErrors = append(deliveryErrors, err)
			_, _ = w.db.ExecContext(ctx, `UPDATE notification_deliveries SET status='failed',attempts=attempts+1,last_error=$2,updated_at=now() WHERE id=$1`, item.id, truncateError(err))
			continue
		}
		_, _ = w.db.ExecContext(ctx, `UPDATE notification_deliveries SET status='sent',attempts=attempts+1,last_error='',sent_at=now(),updated_at=now() WHERE id=$1`, item.id)
	}
	return errors.Join(deliveryErrors...)
}

func sendSMTP(ctx context.Context, config SMTPConfig, recipient, subject, body string) error {
	if strings.ContainsAny(config.From+recipient+subject, "\r\n") {
		return errors.New("invalid SMTP header value")
	}
	switch config.TLSMode {
	case "", "starttls", "tls":
	case "none":
		if config.Host != "localhost" && config.Host != "127.0.0.1" && config.Host != "::1" {
			return errors.New("plaintext SMTP is limited to loopback hosts")
		}
	default:
		return fmt.Errorf("unsupported SMTP TLS mode %q", config.TLSMode)
	}
	port := config.Port
	if port == 0 {
		port = 587
	}
	address := net.JoinHostPort(config.Host, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if config.TLSMode == "tls" {
		conn, err = tls.DialWithDialer(&dialer, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: config.Host})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	client, err := smtp.NewClient(conn, config.Host)
	if err != nil {
		return err
	}
	defer client.Close()
	if config.TLSMode == "" || config.TLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP server does not advertise STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: config.Host}); err != nil {
			return err
		}
	}
	if config.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", config.Username, config.Password, config.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(config.From); err != nil {
		return err
	}
	if err := client.Rcpt(recipient); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	message := "From: " + config.From + "\r\nTo: " + recipient + "\r\nSubject: " + subject + "\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body + "\r\n"
	if _, err := writer.Write([]byte(message)); err != nil {
		writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func (s *SQLStore) ListSubscriptionUsage(ctx context.Context, actor auth.SessionUser) ([]types.SubscriptionUsage, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("quota database is not configured")
	}
	query := `SELECT u.subscription_id,u.period_start,u.site_bytes,u.database_bytes,u.backup_bytes,u.disk_bytes,u.traffic_bytes,u.is_complete,u.collected_at,u.last_error
FROM subscription_usage_current u JOIN subscriptions sub ON sub.id=u.subscription_id JOIN customers c ON c.id=sub.customer_id`
	args := []any{}
	if actor.Role == auth.RoleClient {
		query += ` WHERE c.login_user_id=$1`
		args = append(args, actor.ID)
	} else if actor.Role == auth.RoleReseller {
		query += ` WHERE c.reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$1)`
		args = append(args, actor.ID)
	}
	query += ` ORDER BY u.subscription_id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.SubscriptionUsage
	for rows.Next() {
		var item types.SubscriptionUsage
		if err := rows.Scan(&item.SubscriptionID, &item.PeriodStart, &item.SiteBytes, &item.DatabaseBytes,
			&item.BackupBytes, &item.DiskBytes, &item.TrafficBytes, &item.Complete,
			&item.CollectedAt, &item.LastError); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListUsageAlerts(ctx context.Context, actor auth.SessionUser, limit int) ([]types.UsageAlert, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("quota database is not configured")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := `SELECT n.id,COALESCE(n.subscription_id,0),n.kind,n.severity,n.title,n.body,n.read_at,n.resolved_at,n.created_at
FROM notifications n LEFT JOIN subscriptions sub ON sub.id=n.subscription_id LEFT JOIN customers c ON c.id=sub.customer_id`
	args := []any{}
	if actor.Role == auth.RoleClient {
		query += ` WHERE c.login_user_id=$1`
		args = append(args, actor.ID)
	} else if actor.Role == auth.RoleReseller {
		query += ` WHERE c.reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$1)`
		args = append(args, actor.ID)
	}
	args = append(args, limit)
	query += fmt.Sprintf(` ORDER BY n.created_at DESC LIMIT $%d`, len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.UsageAlert
	for rows.Next() {
		var item types.UsageAlert
		var readAt, resolvedAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.Kind, &item.Severity, &item.Title, &item.Body, &readAt, &resolvedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		if readAt.Valid {
			item.ReadAt = readAt.Time
		}
		if resolvedAt.Valid {
			item.ResolvedAt = resolvedAt.Time
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
