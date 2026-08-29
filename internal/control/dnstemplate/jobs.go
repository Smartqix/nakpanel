package dnstemplate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type SyncTemplateArgs struct {
	RunID int64 `json:"run_id" river:"unique"`
}

func (SyncTemplateArgs) Kind() string { return "sync_dns_template" }

func (SyncTemplateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: SystemQueue,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{
				rivertype.JobStateAvailable,
				rivertype.JobStatePending,
				rivertype.JobStateRetryable,
				rivertype.JobStateRunning,
				rivertype.JobStateScheduled,
			},
		},
	}
}

type SyncTemplateWorker struct {
	river.WorkerDefaults[SyncTemplateArgs]
	manager *Manager
}

func NewSyncTemplateWorker(manager *Manager) *SyncTemplateWorker {
	return &SyncTemplateWorker{manager: manager}
}

func (w *SyncTemplateWorker) Work(ctx context.Context, job *river.Job[SyncTemplateArgs]) error {
	if w.manager == nil || w.manager.db == nil || w.manager.river == nil {
		return errors.New("DNS template synchronization is not configured")
	}
	return w.manager.applyRun(ctx, job.Args.RunID)
}

func (m *Manager) applyRun(ctx context.Context, runID int64) error {
	var expectedRevision int64
	var scope, status string
	var targetZoneID sql.NullInt64
	err := m.db.QueryRowContext(ctx, `SELECT expected_template_state_revision,scope,status,target_zone_id
FROM dns_template_sync_runs WHERE id=$1`, runID).Scan(&expectedRevision, &scope, &status, &targetZoneID)
	if err != nil {
		return err
	}
	if status == "active" || status == "partial" {
		return nil
	}
	if status != "pending" && status != "running" {
		return fmt.Errorf("DNS synchronization run %d is %s", runID, status)
	}
	template, err := m.activeTemplate(ctx, m.db)
	if err != nil {
		return err
	}
	if template.OptimisticRevision != expectedRevision {
		_, _ = m.db.ExecContext(ctx, `UPDATE dns_template_sync_runs
SET status='stale',last_error=$2,completed_at=now() WHERE id=$1`, runID, ErrStalePreview.Error())
		return nil
	}
	if _, err := m.db.ExecContext(ctx, `UPDATE dns_template_sync_runs SET status='running',last_error='' WHERE id=$1`, runID); err != nil {
		return err
	}
	rows, err := m.db.QueryContext(ctx, `SELECT zone_id,COALESCE(owner_site_id,0)
FROM dns_template_sync_items WHERE run_id=$1 ORDER BY zone_id`, runID)
	if err != nil {
		return err
	}
	type zoneTarget struct {
		zoneID, ownerSiteID int64
	}
	var zoneIDs []zoneTarget
	for rows.Next() {
		var target zoneTarget
		if err := rows.Scan(&target.zoneID, &target.ownerSiteID); err != nil {
			rows.Close()
			return err
		}
		zoneIDs = append(zoneIDs, target)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, target := range zoneIDs {
		if err := m.applyZonePlan(ctx, runID, scope, template, target.zoneID, target.ownerSiteID); err != nil {
			_, _ = m.db.ExecContext(ctx, `UPDATE dns_template_sync_items
SET outcome='failed',detail=$3,updated_at=now() WHERE run_id=$1 AND zone_id=$2`,
				runID, target.zoneID, boundedError(err))
		}
	}
	return m.refreshRunStatus(ctx, runID)
}

func (m *Manager) applyZonePlan(ctx context.Context, runID int64, scope string, template types.DNSTemplateRevision, zoneID, ownerSiteID int64) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentStatus string
	var expectedZoneRevision, currentZoneRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT zone.template_status,item.expected_zone_revision,zone.desired_revision
FROM dns_zones zone
JOIN dns_template_sync_items item ON item.zone_id=zone.id AND item.run_id=$2
WHERE zone.id=$1 FOR UPDATE OF zone,item`, zoneID, runID).
		Scan(&currentStatus, &expectedZoneRevision, &currentZoneRevision); err != nil {
		return err
	}
	if currentZoneRevision != expectedZoneRevision {
		if _, err := tx.ExecContext(ctx, `UPDATE dns_template_sync_items
SET outcome='failed',detail='Zone changed after the synchronization preview',updated_at=now()
WHERE run_id=$1 AND zone_id=$2`, runID, zoneID); err != nil {
			return err
		}
		return tx.Commit()
	}
	if scope == "unmodified" && currentStatus == "customized" {
		_, err = tx.ExecContext(ctx, `UPDATE dns_template_sync_items SET outcome='unchanged',
detail='Skipped because this zone has local customizations',updated_at=now() WHERE run_id=$1 AND zone_id=$2`, runID, zoneID)
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	zone, err := m.zoneByID(ctx, tx, zoneID, false)
	if err != nil {
		return err
	}
	authoritativeSiteID := zone.SiteID
	if ownerSiteID > 0 {
		zone.SiteID = ownerSiteID
	}
	partialOwnerApply := ownerSiteID > 0 && ownerSiteID != authoritativeSiteID
	plan := zonePlanForApply(template, zone, partialOwnerApply)
	if err := applyZonePlanMutationsTx(ctx, tx, zoneID, template.Revision, plan); err != nil {
		return err
	}
	if partialOwnerApply {
		if _, err := tx.ExecContext(ctx, `UPDATE sites
SET dns_template_adoption_completed=true,updated_at=now() WHERE id=$1`, zone.SiteID); err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE sites
SET dns_template_adoption_completed=true,updated_at=now()
WHERE id=$1 OR (parent_site_id=$1 AND dns_zone_mode='parent')`, authoritativeSiteID); err != nil {
			return err
		}
	}
	changed := plan.settingsChanged || plan.retryConvergence ||
		len(plan.add)+len(plan.update)+len(plan.adopt)+len(plan.remove) > 0
	if !partialOwnerApply {
		if _, err := tx.ExecContext(ctx, `UPDATE dns_zones
SET template_revision=$2,updated_at=now() WHERE id=$1`,
			zoneID, template.Revision); err != nil {
			return err
		}
	}
	if err := m.refreshZoneTemplateStatusTx(ctx, tx, zoneID); err != nil {
		return err
	}
	if !changed {
		if _, err := tx.ExecContext(ctx, `UPDATE dns_template_sync_items SET outcome=$3,
added_count=$4,updated_count=$5,removed_count=$6,override_count=$7,conflict_count=$8,
detail=$9,updated_at=now() WHERE run_id=$1 AND zone_id=$2`,
			runID, zoneID, plan.item.Outcome, plan.item.AddedCount, plan.item.UpdatedCount,
			plan.item.RemovedCount, plan.item.OverrideCount, plan.item.ConflictCount, plan.item.Detail); err != nil {
			return err
		}
		return tx.Commit()
	}
	var desiredRevision int64
	serial, err := m.nextZoneSerialTx(ctx, tx, zoneID)
	if err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `UPDATE dns_zones SET desired_revision=desired_revision+1,serial=$2,status='pending',
last_error='',updated_at=now() WHERE id=$1 RETURNING desired_revision`, zoneID, serial).Scan(&desiredRevision); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dns_template_sync_items SET outcome=$3,desired_revision=$4,
added_count=$5,updated_count=$6,removed_count=$7,override_count=$8,conflict_count=$9,
detail=$10,updated_at=now() WHERE run_id=$1 AND zone_id=$2`,
		runID, zoneID, plan.item.Outcome, desiredRevision, plan.item.AddedCount, plan.item.UpdatedCount,
		plan.item.RemovedCount, plan.item.OverrideCount, plan.item.ConflictCount, plan.item.Detail); err != nil {
		return err
	}
	if _, err := m.river.InsertTx(ctx, tx, provision.ConfigureDNSZoneArgs{
		ZoneID: zoneID, DesiredRevision: desiredRevision, Bulk: true,
	}, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func zonePlanForApply(template types.DNSTemplateRevision, zone zoneSnapshot, partialOwnerApply bool) zonePlan {
	if partialOwnerApply {
		return compareZone(template, zone)
	}
	return compareWholeZone(template, zone)
}

func (m *Manager) refreshRunStatus(ctx context.Context, runID int64) error {
	var pending, failed int
	if err := m.db.QueryRowContext(ctx, `SELECT
count(*) FILTER (WHERE desired_revision IS NOT NULL AND outcome NOT IN ('applied','failed')),
count(*) FILTER (WHERE outcome='failed')
FROM dns_template_sync_items WHERE run_id=$1`, runID).Scan(&pending, &failed); err != nil {
		return err
	}
	if pending > 0 {
		_, err := m.db.ExecContext(ctx, `UPDATE dns_template_sync_runs
SET status='running',failed_zones=$2 WHERE id=$1`, runID, failed)
		return err
	}
	status := "active"
	if failed > 0 {
		status = "partial"
	}
	_, err := m.db.ExecContext(ctx, `UPDATE dns_template_sync_runs
SET status=$2,failed_zones=$3,completed_at=now() WHERE id=$1`, runID, status, failed)
	return err
}

func postgresIntArray(values []int64) string {
	if len(values) == 0 {
		return "{}"
	}
	result := "{"
	for i, value := range values {
		if i > 0 {
			result += ","
		}
		result += fmt.Sprintf("%d", value)
	}
	return result + "}"
}

func boundedError(err error) string {
	value := err.Error()
	if len(value) > 1000 {
		return value[:1000]
	}
	return value
}
