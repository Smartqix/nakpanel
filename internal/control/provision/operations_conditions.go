package provision

import (
	"context"
	"database/sql"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/robfig/cron/v3"
	"strings"
	"time"
)

func backupDeadline(schedule string, completed time.Time) (time.Time, error) {
	switch strings.TrimSpace(schedule) {
	case "", "daily":
		schedule = "0 2 * * *"
	case "weekly":
		schedule = "0 2 * * 0"
	case "manual", "disabled":
		return time.Time{}, errors.New("automatic backup protection is not scheduled")
	}
	parsed, err := cron.ParseStandard(schedule)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.Next(completed.UTC()).Add(30 * time.Minute), nil
}

func (m *OperationsManager) DetectConditions(ctx context.Context) error {
	rows, err := m.db.QueryContext(ctx, `SELECT id FROM sites WHERE status='active' AND desired_status='active' AND removal_state='none' ORDER BY id`)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err = m.detectSiteConditions(ctx, id); err != nil {
			if errors.Is(err, controlquota.ErrNoActiveSubscription) || errors.Is(err, controlquota.ErrSiteRemoving) || errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return err
		}
	}
	return nil
}
func (m *OperationsManager) detectSiteConditions(ctx context.Context, id int64) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	in, err := m.snapshotOperationIntentTx(ctx, tx, operations.Resource{Kind: operations.ResourceSite, ID: id})
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	certificateBad := in.Policy.Permissions.TLS && in.TLSExpiresAt != nil && !in.TLSExpiresAt.After(now.Add(14*24*time.Hour))
	severity, title := "warning", "Certificate expires soon"
	if in.TLSExpiresAt != nil && !in.TLSExpiresAt.After(now) {
		severity = "critical"
		title = "Certificate has expired"
	}
	cert := operations.ConditionSample{Resource: in.Resource, Kind: "tls", Condition: "certificate", Signature: in.Hash + severity, Unhealthy: certificateBad, Severity: severity, Title: title, Summary: "Review the certificate before visitors lose trusted HTTPS access.", IntentRevision: in.Revision, ObservedAt: now}
	if err = m.Store.ObserveConditionTx(ctx, tx, cert); err != nil {
		return err
	}
	required := in.Policy.Permissions.Backups && in.Policy.Backups.Enabled && in.Policy.Backups.Schedule != "manual" && in.Policy.Backups.Schedule != "disabled"
	anchor := in.SiteCreatedAt
	var last sql.NullTime
	if err = tx.QueryRowContext(ctx, `SELECT max(b.completed_at) FROM backups b JOIN backup_readiness_checks c ON c.backup_id=b.id WHERE b.site_id=$1 AND b.subscription_id=$2 AND b.customer_id=$3 AND b.owner_user_id=$4 AND b.status='active' AND b.checksum_sha256=c.checksum AND b.size_bytes=c.size_bytes AND c.last_check_status='verified' AND c.data_scope_hash=$5 AND c.verified_at>=b.completed_at AND c.verified_at>now()-interval '24 hours'`, in.SiteID, in.SubscriptionID, in.CustomerID, in.OwnerID, in.DataScopeHash).Scan(&last); err != nil {
		return err
	}
	if last.Valid {
		anchor = last.Time
	}
	due, scheduleErr := backupDeadline(in.Policy.Backups.Schedule, anchor)
	bad := required && (scheduleErr != nil || now.After(due))
	severity, title, summary := "critical", "Backup protection is overdue", "No independently verified backup completed by the scheduled deadline and grace period."
	var latestUnknown bool
	if in.Archive.ID > 0 {
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM backup_readiness_checks WHERE backup_id=$1 AND data_scope_hash=$2 AND last_check_status='unknown')`, in.Archive.ID, in.DataScopeHash).Scan(&latestUnknown); err != nil {
			return err
		}
	}
	if required && latestUnknown && !bad {
		bad = true
		severity = "warning"
		title = "Backup verification needs attention"
		summary = "The latest archive could not be independently verified. Existing archives were preserved."
	}
	if scheduleErr != nil && required {
		title = "Backup schedule needs attention"
		summary = "The configured backup schedule could not be evaluated. Recovery has not been verified."
	}
	backup := operations.ConditionSample{Resource: in.Resource, Kind: "backup", Condition: "protection", Signature: in.Hash + severity, Unhealthy: bad, Severity: severity, Title: title, Summary: summary, IntentRevision: in.Revision, ObservedAt: now}
	if err = m.Store.ObserveConditionTx(ctx, tx, backup); err != nil {
		return err
	}
	return tx.Commit()
}
