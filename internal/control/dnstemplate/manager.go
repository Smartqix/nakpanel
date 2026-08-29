package dnstemplate

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

const SystemQueue = "system"

var (
	ErrStalePreview = errors.New("DNS synchronization preview is stale")
	ErrConflict     = errors.New("DNS record conflicts with an existing record")
)

type Manager struct {
	db    *sql.DB
	river *river.Client[*sql.Tx]
	now   func() time.Time
}

func NewManager(db *sql.DB, riverClient *river.Client[*sql.Tx]) *Manager {
	return &Manager{db: db, river: riverClient, now: time.Now}
}

func (m *Manager) SetRiverClient(client *river.Client[*sql.Tx]) {
	m.river = client
}

func (m *Manager) View(ctx context.Context, previewID int64) (types.DNSTemplateView, error) {
	template, err := m.activeTemplate(ctx, m.db)
	if err != nil {
		return types.DNSTemplateView{}, err
	}
	runs, err := m.listRuns(ctx, 12)
	if err != nil {
		return types.DNSTemplateView{}, err
	}
	view := types.DNSTemplateView{Template: template, RecentRuns: runs}
	if previewID > 0 {
		run, loadErr := m.loadRun(ctx, previewID)
		if loadErr != nil {
			return types.DNSTemplateView{}, loadErr
		}
		view.Preview = &run
	}
	return view, nil
}

func (m *Manager) SaveSettings(ctx context.Context, actorID int64, input types.DNSTemplateSettingsInput) (int64, error) {
	if err := validateSOA(input.SOA); err != nil {
		return 0, err
	}
	if input.ZoneStatus != "active" && input.ZoneStatus != "disabled" {
		return 0, errors.New("zone status must be active or disabled")
	}
	if input.SubdomainPolicy != "parent" && input.SubdomainPolicy != "separate" {
		return 0, errors.New("subdomain policy must be parent or separate")
	}
	cidrs, err := validateCIDRs(input.TransferCIDRs)
	if err != nil {
		return 0, err
	}
	return m.createRevision(ctx, actorID, input.ExpectedRevision, func(current *types.DNSTemplateRevision) error {
		current.SOA = input.SOA
		current.ZoneStatus = input.ZoneStatus
		current.SubdomainPolicy = input.SubdomainPolicy
		current.TransferCIDRs = cidrs
		return nil
	})
}

func (m *Manager) UpsertTemplateRecord(ctx context.Context, actorID, recordID, expectedRevision int64, record types.DNSTemplateRecord) (int64, error) {
	if recordID == 0 && strings.TrimSpace(record.StableKey) == "" {
		key, err := randomToken("record_", 12)
		if err != nil {
			return 0, err
		}
		record.StableKey = key
	}
	record, err := validateTemplateRecord(record)
	if err != nil {
		return 0, err
	}
	return m.createRevision(ctx, actorID, expectedRevision, func(current *types.DNSTemplateRevision) error {
		if recordID == 0 {
			for _, existing := range current.Records {
				if existing.StableKey == record.StableKey {
					return errors.New("template record key already exists")
				}
			}
			current.Records = append(current.Records, record)
			return nil
		}
		for i := range current.Records {
			if current.Records[i].ID == recordID {
				record.StableKey = current.Records[i].StableKey
				current.Records[i] = record
				return nil
			}
		}
		return sql.ErrNoRows
	})
}

func (m *Manager) DeleteTemplateRecord(ctx context.Context, actorID, recordID, expectedRevision int64) (int64, error) {
	return m.createRevision(ctx, actorID, expectedRevision, func(current *types.DNSTemplateRevision) error {
		for i := range current.Records {
			if current.Records[i].ID == recordID {
				current.Records = append(current.Records[:i], current.Records[i+1:]...)
				return nil
			}
		}
		return sql.ErrNoRows
	})
}

func (m *Manager) ResetTemplate(ctx context.Context, actorID, expectedRevision int64) (int64, error) {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var currentRevision, defaultID int64
	if err := tx.QueryRowContext(ctx, `SELECT optimistic_revision,default_revision_id
FROM dns_template_state WHERE singleton FOR UPDATE`).Scan(&currentRevision, &defaultID); err != nil {
		return 0, err
	}
	if currentRevision != expectedRevision {
		return 0, ErrStalePreview
	}
	current, err := m.activeTemplate(ctx, tx)
	if err != nil {
		return 0, err
	}
	if current.OptimisticRevision != expectedRevision {
		return 0, ErrStalePreview
	}
	defaultTemplate, err := m.templateByID(ctx, tx, defaultID)
	if err != nil {
		return 0, err
	}
	defaultTemplate.ID, defaultTemplate.Revision = 0, 0
	if err := validateTemplateRevision(defaultTemplate); err != nil {
		return 0, err
	}
	id, err := m.insertRevisionTx(ctx, tx, actorID, defaultTemplate)
	if err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE dns_template_state SET active_revision_id=$1,optimistic_revision=optimistic_revision+1,updated_at=now() WHERE singleton`, id); err != nil {
		return 0, err
	}
	if err := markZonesOutOfSyncTx(ctx, tx); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func (m *Manager) createRevision(ctx context.Context, actorID, expectedRevision int64, mutate func(*types.DNSTemplateRevision) error) (int64, error) {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var currentRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT optimistic_revision
FROM dns_template_state WHERE singleton FOR UPDATE`).Scan(&currentRevision); err != nil {
		return 0, err
	}
	if currentRevision != expectedRevision {
		return 0, ErrStalePreview
	}
	current, err := m.activeTemplate(ctx, tx)
	if err != nil {
		return 0, err
	}
	if current.OptimisticRevision != expectedRevision {
		return 0, ErrStalePreview
	}
	if err := mutate(&current); err != nil {
		return 0, err
	}
	if err := validateTemplateRevision(current); err != nil {
		return 0, err
	}
	id, err := m.insertRevisionTx(ctx, tx, actorID, current)
	if err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE dns_template_state
SET active_revision_id=$1,optimistic_revision=optimistic_revision+1,updated_at=now()
WHERE singleton AND optimistic_revision=$2`, id, expectedRevision)
	if err != nil {
		return 0, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return 0, ErrStalePreview
	}
	if err := markZonesOutOfSyncTx(ctx, tx); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func markZonesOutOfSyncTx(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `UPDATE dns_zones
SET template_status='out_of_sync',updated_at=now()
WHERE template_status='in_sync'`)
	return err
}

func (m *Manager) insertRevisionTx(ctx context.Context, tx *sql.Tx, actorID int64, template types.DNSTemplateRevision) (int64, error) {
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(max(revision),0)+1 FROM dns_template_revisions`).Scan(&revision); err != nil {
		return 0, err
	}
	var id int64
	err := tx.QueryRowContext(ctx, `INSERT INTO dns_template_revisions(
revision,primary_nameserver,responsible_mailbox,serial_format,default_ttl,refresh_seconds,retry_seconds,
expire_seconds,minimum_ttl,zone_status,subdomain_policy,transfer_cidrs,created_by
) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::cidr[],$13) RETURNING id`,
		revision, template.SOA.PrimaryNameserver, template.SOA.ResponsibleMailbox, template.SOA.SerialFormat,
		template.SOA.DefaultTTL, template.SOA.RefreshSeconds, template.SOA.RetrySeconds,
		template.SOA.ExpireSeconds, template.SOA.MinimumTTL, template.ZoneStatus,
		template.SubdomainPolicy, postgresArray(template.TransferCIDRs), nullableID(actorID)).Scan(&id)
	if err != nil {
		return 0, err
	}
	for _, record := range template.Records {
		if _, err := tx.ExecContext(ctx, `INSERT INTO dns_template_records(
revision_id,stable_key,scope,host_template,record_type,value_template,priority,weight,port,ttl
) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, record.StableKey, record.Scope, record.HostTemplate,
			record.Type, record.ValueTemplate, nullablePriority(record.Type, record.Priority),
			nullableSRV(record.Type, record.Weight), nullableSRV(record.Type, record.Port), record.TTL); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func (m *Manager) Preview(ctx context.Context, actorID int64, scope string, zoneID int64) (types.DNSSyncRun, error) {
	if scope != "unmodified" && scope != "all" && scope != "zone" {
		return types.DNSSyncRun{}, errors.New("synchronization scope is invalid")
	}
	if scope == "zone" && zoneID <= 0 {
		return types.DNSSyncRun{}, errors.New("zone is required")
	}
	template, err := m.activeTemplate(ctx, m.db)
	if err != nil {
		return types.DNSSyncRun{}, err
	}
	zones, err := m.zonesForSync(ctx, scope, zoneID)
	if err != nil {
		return types.DNSSyncRun{}, err
	}
	token, err := randomToken("dns_", 18)
	if err != nil {
		return types.DNSSyncRun{}, err
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return types.DNSSyncRun{}, err
	}
	defer tx.Rollback()
	var run types.DNSSyncRun
	run.TemplateRevision, run.Scope, run.Status = template.Revision, scope, "preview"
	run.PreviewToken, run.ExpectedStateRevision = token, template.OptimisticRevision
	err = tx.QueryRowContext(ctx, `INSERT INTO dns_template_sync_runs(
template_revision,scope,target_zone_id,status,preview_token,expected_template_state_revision,actor_user_id,total_zones
) VALUES($1,$2,$3,'preview',$4,$5,$6,$7) RETURNING id,created_at`,
		template.Revision, scope, nullableID(zoneID), token, template.OptimisticRevision, nullableID(actorID), len(zones)).
		Scan(&run.ID, &run.CreatedAt)
	if err != nil {
		return types.DNSSyncRun{}, err
	}
	for _, zone := range zones {
		plan := compareWholeZone(template, zone)
		item := plan.item
		item.ZoneID, item.Domain = zone.ID, zone.Domain
		if _, err := tx.ExecContext(ctx, `INSERT INTO dns_template_sync_items(
run_id,zone_id,owner_site_id,expected_zone_revision,outcome,added_count,updated_count,removed_count,override_count,conflict_count,detail
) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, run.ID, zone.ID, zone.SiteID, zone.DesiredRevision, item.Outcome, item.AddedCount,
			item.UpdatedCount, item.RemovedCount, item.OverrideCount, item.ConflictCount, item.Detail); err != nil {
			return types.DNSSyncRun{}, err
		}
		run.Items = append(run.Items, item)
		if item.Outcome != "unchanged" {
			run.ChangedZones++
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dns_template_sync_runs SET changed_zones=$2 WHERE id=$1`, run.ID, run.ChangedZones); err != nil {
		return types.DNSSyncRun{}, err
	}
	if err := tx.Commit(); err != nil {
		return types.DNSSyncRun{}, err
	}
	return run, nil
}

func (m *Manager) ApplyPreview(ctx context.Context, actorID, runID int64, token, confirmation string) error {
	if m.river == nil {
		return errors.New("DNS synchronization queue is not configured")
	}
	if confirmation != "APPLY DNS TEMPLATE" {
		return errors.New(`confirmation must be "APPLY DNS TEMPLATE"`)
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status, storedToken string
	var expected int64
	err = tx.QueryRowContext(ctx, `SELECT status,preview_token,expected_template_state_revision
FROM dns_template_sync_runs WHERE id=$1 FOR UPDATE`, runID).Scan(&status, &storedToken, &expected)
	if err != nil {
		return err
	}
	var current int64
	if err := tx.QueryRowContext(ctx, `SELECT optimistic_revision FROM dns_template_state WHERE singleton`).Scan(&current); err != nil {
		return err
	}
	if status != "preview" || storedToken != token || expected != current {
		_, _ = tx.ExecContext(ctx, `UPDATE dns_template_sync_runs SET status='stale',last_error=$2,completed_at=now() WHERE id=$1`, runID, ErrStalePreview.Error())
		_ = tx.Commit()
		return ErrStalePreview
	}
	var changedZones int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM dns_template_sync_items item
JOIN dns_zones zone ON zone.id=item.zone_id
WHERE item.run_id=$1 AND zone.desired_revision<>item.expected_zone_revision`, runID).Scan(&changedZones); err != nil {
		return err
	}
	if changedZones > 0 {
		_, _ = tx.ExecContext(ctx, `UPDATE dns_template_sync_runs SET status='stale',
last_error='A zone changed after this preview',completed_at=now() WHERE id=$1`, runID)
		_ = tx.Commit()
		return ErrStalePreview
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dns_template_sync_runs SET status='pending',confirmation=$2,actor_user_id=$3,applied_at=now() WHERE id=$1`,
		runID, confirmation, nullableID(actorID)); err != nil {
		return err
	}
	if _, err := m.river.InsertTx(ctx, tx, SyncTemplateArgs{RunID: runID}, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func (m *Manager) RetryPreview(ctx context.Context, actorID, runID int64) (types.DNSSyncRun, error) {
	var scope string
	var targetZoneID sql.NullInt64
	var ownerSiteID int64
	if err := m.db.QueryRowContext(ctx, `SELECT run.scope,run.target_zone_id,
COALESCE((SELECT owner_site_id FROM dns_template_sync_items WHERE run_id=run.id LIMIT 1),0)
FROM dns_template_sync_runs run WHERE run.id=$1`, runID).
		Scan(&scope, &targetZoneID, &ownerSiteID); err != nil {
		return types.DNSSyncRun{}, err
	}
	if scope != "zone" {
		return m.Preview(ctx, actorID, scope, 0)
	}
	if !targetZoneID.Valid {
		return types.DNSSyncRun{}, errors.New("the previous DNS synchronization target no longer exists")
	}
	zone, err := m.zoneByID(ctx, m.db, targetZoneID.Int64, false)
	if err != nil {
		return types.DNSSyncRun{}, err
	}
	if ownerSiteID > 0 && ownerSiteID != zone.SiteID {
		zone.SiteID = ownerSiteID
		return m.previewSiteZone(ctx, actorID, zone)
	}
	return m.Preview(ctx, actorID, "zone", targetZoneID.Int64)
}

func (m *Manager) ApplyZone(ctx context.Context, actorID, siteID int64) (types.DNSSyncRun, error) {
	zone, err := m.zoneForSite(ctx, siteID)
	if err != nil {
		return types.DNSSyncRun{}, err
	}
	if zone.SiteID != siteID {
		zone.SiteID = siteID
		return m.previewSiteZone(ctx, actorID, zone)
	}
	return m.Preview(ctx, actorID, "zone", zone.ID)
}

func (m *Manager) previewSiteZone(ctx context.Context, actorID int64, zone zoneSnapshot) (types.DNSSyncRun, error) {
	template, err := m.activeTemplate(ctx, m.db)
	if err != nil {
		return types.DNSSyncRun{}, err
	}
	token, err := randomToken("dns_", 18)
	if err != nil {
		return types.DNSSyncRun{}, err
	}
	plan := compareZone(template, zone)
	item := plan.item
	item.ZoneID, item.OwnerSiteID, item.Domain = zone.ID, zone.SiteID, zone.Domain
	run := types.DNSSyncRun{
		TemplateRevision: template.Revision, Scope: "zone", Status: "preview",
		PreviewToken: token, ExpectedStateRevision: template.OptimisticRevision,
		TotalZones: 1, Items: []types.DNSSyncItem{item},
	}
	if item.Outcome != "unchanged" {
		run.ChangedZones = 1
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return types.DNSSyncRun{}, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `INSERT INTO dns_template_sync_runs(
template_revision,scope,target_zone_id,status,preview_token,expected_template_state_revision,actor_user_id,total_zones,changed_zones
) VALUES($1,'zone',$2,'preview',$3,$4,$5,1,$6) RETURNING id,created_at`,
		template.Revision, zone.ID, token, template.OptimisticRevision, nullableID(actorID), run.ChangedZones).
		Scan(&run.ID, &run.CreatedAt); err != nil {
		return types.DNSSyncRun{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO dns_template_sync_items(
run_id,zone_id,owner_site_id,expected_zone_revision,outcome,added_count,updated_count,removed_count,override_count,conflict_count,detail
) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, run.ID, zone.ID, zone.SiteID, zone.DesiredRevision, item.Outcome,
		item.AddedCount, item.UpdatedCount, item.RemovedCount, item.OverrideCount, item.ConflictCount, item.Detail); err != nil {
		return types.DNSSyncRun{}, err
	}
	return run, tx.Commit()
}

func (m *Manager) ApplySitePreview(ctx context.Context, actorID, siteID, runID int64, token, confirmation string) error {
	zone, err := m.zoneForSite(ctx, siteID)
	if err != nil {
		return err
	}
	var targetZoneID sql.NullInt64
	var scope string
	var ownerSiteID int64
	if err := m.db.QueryRowContext(ctx, `SELECT run.scope,run.target_zone_id,
COALESCE((SELECT owner_site_id FROM dns_template_sync_items WHERE run_id=run.id LIMIT 1),zone.site_id)
FROM dns_template_sync_runs run LEFT JOIN dns_zones zone ON zone.id=run.target_zone_id WHERE run.id=$1`, runID).
		Scan(&scope, &targetZoneID, &ownerSiteID); err != nil {
		return err
	}
	if scope != "zone" || !targetZoneID.Valid || targetZoneID.Int64 != zone.ID || ownerSiteID != siteID {
		return errors.New("DNS synchronization preview does not belong to this site")
	}
	return m.ApplyPreview(ctx, actorID, runID, token, confirmation)
}

func (m *Manager) RestoreRecord(ctx context.Context, siteID, recordID int64) error {
	if m.river == nil {
		return errors.New("DNS queue is not configured")
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	zone, err := m.zoneForSiteTx(ctx, tx, siteID, true)
	if err != nil {
		return err
	}
	var key string
	var recordOwnerSiteID int64
	err = tx.QueryRowContext(ctx, `SELECT template_record_key,owner_site_id FROM dns_records
WHERE id=$1 AND zone_id=$2 AND template_record_key IS NOT NULL
  AND (owner_site_id=$3 OR $3=$4)`, recordID, zone.ID, siteID, zone.SiteID).Scan(&key, &recordOwnerSiteID)
	if err != nil {
		return err
	}
	template, err := m.activeTemplate(ctx, tx)
	if err != nil {
		return err
	}
	var wanted *types.DNSTemplateRecord
	for i := range template.Records {
		if template.Records[i].StableKey == key {
			wanted = &template.Records[i]
			break
		}
	}
	if wanted == nil {
		return errors.New("this record no longer exists in the active template")
	}
	expanded, omit, err := expandTemplateRecord(*wanted, zone.expansionForSite(recordOwnerSiteID))
	if err != nil {
		return err
	}
	if omit {
		return errors.New("template record is unavailable for this zone")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dns_records SET host=$3,record_type=$4,value=$5,priority=$6,weight=$7,port=$8,ttl=$9,
origin='template',template_revision=$10,locally_modified=false,updated_at=now()
WHERE id=$1 AND zone_id=$2`, recordID, zone.ID, expanded.Host, expanded.Type, expanded.Value,
		nullablePriority(expanded.Type, expanded.Priority), nullableSRV(expanded.Type, expanded.Weight),
		nullableSRV(expanded.Type, expanded.Port), expanded.TTL, template.Revision); err != nil {
		return err
	}
	if err := m.refreshZoneTemplateStatusTx(ctx, tx, zone.ID); err != nil {
		return err
	}
	return m.enqueueZoneTx(ctx, tx, zone.ID, false)
}

func (m *Manager) SetZoneMode(ctx context.Context, siteID int64, input types.DNSZoneModeInput) error {
	if m.river == nil {
		return errors.New("DNS queue is not configured")
	}
	mode := strings.ToLower(strings.TrimSpace(input.Mode))
	if mode != "primary" && mode != "secondary" && mode != "disabled" {
		return errors.New("zone mode must be primary, secondary, or disabled")
	}
	primaries := make([]string, 0, len(input.UpstreamPrimaries))
	for _, value := range input.UpstreamPrimaries {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if net.ParseIP(value) == nil {
			return fmt.Errorf("invalid upstream primary %q", value)
		}
		primaries = append(primaries, value)
	}
	if mode == "secondary" && len(primaries) == 0 {
		return errors.New("a secondary zone requires at least one upstream primary")
	}
	if mode != "secondary" {
		primaries = nil
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	zone, err := m.zoneForSiteTx(ctx, tx, siteID, true)
	if err != nil {
		return err
	}
	if zone.SiteID != siteID {
		return errors.New("authoritative zone mode must be changed from the parent domain")
	}
	if input.ExpectedRevision != zone.DesiredRevision {
		return ErrStalePreview
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dns_zones SET mode=$2,upstream_primaries=$3::text[],updated_at=now() WHERE id=$1`,
		zone.ID, mode, postgresArray(primaries)); err != nil {
		return err
	}
	return m.enqueueZoneTx(ctx, tx, zone.ID, false)
}

func (m *Manager) SetZoneSOA(ctx context.Context, siteID, expectedRevision int64, settings *types.DNSSOASettings, transferCIDRs *[]string) error {
	if m.river == nil {
		return errors.New("DNS queue is not configured")
	}
	if settings != nil {
		if err := validateSOA(*settings); err != nil {
			return err
		}
	}
	var cidrs []string
	if transferCIDRs != nil {
		var err error
		cidrs, err = validateCIDRs(*transferCIDRs)
		if err != nil {
			return err
		}
	}
	var encoded any
	if settings != nil {
		data, marshalErr := json.Marshal(settings)
		if marshalErr != nil {
			return marshalErr
		}
		encoded = data
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	zone, err := m.zoneForSiteTx(ctx, tx, siteID, true)
	if err != nil {
		return err
	}
	if zone.SiteID != siteID {
		return errors.New("SOA and transfer settings must be changed from the parent domain")
	}
	if zone.DesiredRevision != expectedRevision {
		return ErrStalePreview
	}
	var encodedCIDRs any
	if transferCIDRs != nil {
		encodedCIDRs = postgresArray(cidrs)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dns_zones SET soa_override=$2,transfer_cidrs=$3::cidr[],updated_at=now() WHERE id=$1`,
		zone.ID, encoded, encodedCIDRs); err != nil {
		return err
	}
	if err := m.refreshZoneTemplateStatusTx(ctx, tx, zone.ID); err != nil {
		return err
	}
	return m.enqueueZoneTx(ctx, tx, zone.ID, false)
}

func (m *Manager) SetSubdomainZoneMode(ctx context.Context, siteID, expectedRevision int64, mode string) error {
	if m.river == nil {
		return errors.New("DNS queue is not configured")
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "parent" && mode != "separate" {
		return errors.New("subdomain zone mode must be parent or separate")
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var domain, currentMode string
	var parentSiteID sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT domain,parent_site_id,dns_zone_mode
FROM sites WHERE id=$1 FOR UPDATE`, siteID).Scan(&domain, &parentSiteID, &currentMode); err != nil {
		return err
	}
	if !parentSiteID.Valid {
		return errors.New("standalone domains cannot use a parent DNS zone")
	}
	if currentMode == mode {
		return tx.Commit()
	}
	var parentZoneID, parentOwnerID, parentDesiredRevision int64
	var parentDomain, address, ipv6 string
	if err := tx.QueryRowContext(ctx, `SELECT zone.id,zone.owner_user_id,zone.domain,zone.address,zone.ipv6_address,zone.desired_revision
FROM dns_zones zone WHERE zone.site_id=$1 FOR UPDATE`, parentSiteID.Int64).
		Scan(&parentZoneID, &parentOwnerID, &parentDomain, &address, &ipv6, &parentDesiredRevision); err != nil {
		return errors.New("the parent domain does not have an authoritative DNS zone")
	}
	label := strings.TrimSuffix(domain, "."+parentDomain)
	if label == domain || label == "" {
		return errors.New("site is not a subdomain of its selected parent")
	}
	currentDesiredRevision := parentDesiredRevision
	if currentMode == "separate" {
		if err := tx.QueryRowContext(ctx, `SELECT desired_revision FROM dns_zones WHERE site_id=$1 FOR UPDATE`, siteID).
			Scan(&currentDesiredRevision); err != nil {
			return err
		}
	}
	if currentDesiredRevision != expectedRevision {
		return ErrStalePreview
	}
	if mode == "separate" {
		if err := m.moveToSeparateZoneTx(ctx, tx, siteID, parentZoneID, parentOwnerID, domain, label, address, ipv6); err != nil {
			return err
		}
	} else {
		if err := m.moveToParentZoneTx(ctx, tx, siteID, parentZoneID, label); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (m *Manager) moveToSeparateZoneTx(
	ctx context.Context,
	tx *sql.Tx,
	siteID, parentZoneID, ownerID int64,
	domain, label, address, ipv6 string,
) error {
	template, err := m.activeTemplate(ctx, tx)
	if err != nil {
		return err
	}
	childMode := "primary"
	if template.ZoneStatus == "disabled" {
		childMode = "disabled"
	}
	var childZoneID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM dns_zones WHERE site_id=$1 FOR UPDATE`, siteID).Scan(&childZoneID)
	if errors.Is(err, sql.ErrNoRows) {
		serial := m.now().UTC().Unix()
		err = tx.QueryRowContext(ctx, `INSERT INTO dns_zones(
owner_user_id,site_id,domain,address,ipv6_address,serial,status,mode,parent_zone_id,
template_revision,template_status,desired_revision,applied_revision
) VALUES($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9,'pending',1,0) RETURNING id`,
			ownerID, siteID, domain, address, ipv6, serial, childMode, parentZoneID, template.Revision).Scan(&childZoneID)
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dns_zones
SET owner_user_id=$2,domain=$3,address=$4,ipv6_address=$5,mode=$7,
    parent_zone_id=$6,status='pending',template_status='pending',last_error='',updated_at=now()
WHERE id=$1`, childZoneID, ownerID, domain, address, ipv6, parentZoneID, childMode); err != nil {
		return err
	}
	records, err := loadMovableDNSRecords(ctx, tx, parentZoneID, siteID)
	if err != nil {
		return err
	}
	childBeforeMove, err := m.zoneByID(ctx, tx, childZoneID, false)
	if err != nil {
		return err
	}
	transformed := make([]types.DNSRecord, 0, len(records))
	for _, record := range records {
		host := record.Host
		switch {
		case host == label:
			host = "@"
		case strings.HasSuffix(host, "."+label):
			host = strings.TrimSuffix(host, "."+label)
		default:
			continue
		}
		record.ZoneID = childZoneID
		record.Host = host
		transformed = append(transformed, record)
	}
	candidate := append(append([]types.DNSRecord(nil), childBeforeMove.Records...), transformed...)
	if err := validateDNSRecordSet(candidate); err != nil {
		return fmt.Errorf("%w: moving records into the child zone: %v", ErrConflict, err)
	}
	for _, record := range transformed {
		if _, err := tx.ExecContext(ctx, `UPDATE dns_records SET zone_id=$2,host=$3,updated_at=now() WHERE id=$1`,
			record.ID, childZoneID, record.Host); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sites
SET dns_zone_mode='separate',dns_template_adoption_completed=true,updated_at=now()
WHERE id=$1`, siteID); err != nil {
		return err
	}
	child, err := m.zoneByID(ctx, tx, childZoneID, false)
	if err != nil {
		return err
	}
	plan := compareZone(template, child)
	if err := applyZonePlanMutationsTx(ctx, tx, childZoneID, template.Revision, plan); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dns_zones SET template_revision=$2 WHERE id=$1`,
		childZoneID, template.Revision); err != nil {
		return err
	}
	if err := m.refreshZoneTemplateStatusTx(ctx, tx, childZoneID); err != nil {
		return err
	}
	if err := m.refreshZoneTemplateStatusTx(ctx, tx, parentZoneID); err != nil {
		return err
	}
	return m.enqueueTwoZonesTx(ctx, tx, parentZoneID, childZoneID, false)
}

func (m *Manager) moveToParentZoneTx(ctx context.Context, tx *sql.Tx, siteID, parentZoneID int64, label string) error {
	var childZoneID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM dns_zones WHERE site_id=$1 FOR UPDATE`, siteID).Scan(&childZoneID); err != nil {
		return err
	}
	records, err := loadMovableDNSRecords(ctx, tx, childZoneID, siteID)
	if err != nil {
		return err
	}
	parent, err := m.zoneByID(ctx, tx, parentZoneID, false)
	if err != nil {
		return err
	}
	transformed := make([]types.DNSRecord, 0, len(records))
	for _, record := range records {
		host := label
		if record.Host != "@" {
			host = record.Host + "." + label
		}
		record.ZoneID = parentZoneID
		record.Host = host
		transformed = append(transformed, record)
	}
	candidate := append(append([]types.DNSRecord(nil), parent.Records...), transformed...)
	if err := validateDNSRecordSet(candidate); err != nil {
		return fmt.Errorf("%w: moving records into the parent zone: %v", ErrConflict, err)
	}
	for _, record := range transformed {
		if _, err := tx.ExecContext(ctx, `UPDATE dns_records SET zone_id=$2,host=$3,updated_at=now() WHERE id=$1`,
			record.ID, parentZoneID, record.Host); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sites
SET dns_zone_mode='parent',dns_template_adoption_completed=true,updated_at=now()
WHERE id=$1`, siteID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dns_zones SET mode='disabled',template_status='pending' WHERE id=$1`, childZoneID); err != nil {
		return err
	}
	if err := m.refreshZoneTemplateStatusTx(ctx, tx, parentZoneID); err != nil {
		return err
	}
	return m.enqueueTwoZonesTx(ctx, tx, parentZoneID, childZoneID, false)
}

func loadMovableDNSRecords(ctx context.Context, tx *sql.Tx, zoneID, ownerSiteID int64) ([]types.DNSRecord, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,zone_id,owner_site_id,host,record_type,value,
COALESCE(priority,0),COALESCE(weight,0),COALESCE(port,0),ttl,origin,
COALESCE(template_record_key,''),COALESCE(template_revision,0),locally_modified
FROM dns_records
WHERE zone_id=$1 AND owner_site_id=$2
  AND NOT (origin='system' AND (record_type='NS' OR host='ns1'))
ORDER BY id`, zoneID, ownerSiteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []types.DNSRecord
	for rows.Next() {
		var record types.DNSRecord
		if err := rows.Scan(&record.ID, &record.ZoneID, &record.OwnerSiteID, &record.Host,
			&record.Type, &record.Value, &record.Priority, &record.Weight, &record.Port,
			&record.TTL, &record.Origin, &record.TemplateRecordKey, &record.TemplateRevision,
			&record.LocallyModified); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func applyZonePlanMutationsTx(ctx context.Context, tx *sql.Tx, zoneID, templateRevision int64, plan zonePlan) error {
	for _, record := range plan.add {
		if _, err := tx.ExecContext(ctx, `INSERT INTO dns_records(
zone_id,owner_site_id,host,record_type,value,priority,weight,port,ttl,origin,
template_record_key,template_revision,locally_modified
) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'template',$10,$11,false)
ON CONFLICT DO NOTHING`, zoneID, record.OwnerSiteID, record.Host, record.Type, record.Value,
			nullablePriority(record.Type, record.Priority), nullableSRV(record.Type, record.Weight),
			nullableSRV(record.Type, record.Port), record.TTL, record.TemplateRecordKey, templateRevision); err != nil {
			return err
		}
	}
	for id, record := range plan.update {
		if _, err := tx.ExecContext(ctx, `UPDATE dns_records SET host=$3,record_type=$4,value=$5,
priority=$6,weight=$7,port=$8,ttl=$9,template_revision=$10,locally_modified=false,updated_at=now()
WHERE id=$1 AND zone_id=$2 AND origin='template' AND locally_modified=false`,
			id, zoneID, record.Host, record.Type, record.Value, nullablePriority(record.Type, record.Priority),
			nullableSRV(record.Type, record.Weight), nullableSRV(record.Type, record.Port),
			record.TTL, templateRevision); err != nil {
			return err
		}
	}
	for id, record := range plan.adopt {
		if _, err := tx.ExecContext(ctx, `UPDATE dns_records SET owner_site_id=$3,origin='template',
template_record_key=$4,template_revision=$5,locally_modified=false,updated_at=now()
WHERE id=$1 AND zone_id=$2 AND origin='custom'`,
			id, zoneID, record.OwnerSiteID, record.TemplateRecordKey, templateRevision); err != nil {
			return err
		}
	}
	if len(plan.remove) > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM dns_records
WHERE zone_id=$1 AND id=ANY($2::bigint[]) AND origin='template' AND locally_modified=false`,
			zoneID, postgresIntArray(plan.remove)); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) enqueueTwoZonesTx(ctx context.Context, tx *sql.Tx, firstZoneID, secondZoneID int64, bulk bool) error {
	for _, zoneID := range []int64{firstZoneID, secondZoneID} {
		var revision int64
		serial, err := m.nextZoneSerialTx(ctx, tx, zoneID)
		if err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `UPDATE dns_zones SET desired_revision=desired_revision+1,serial=$2,
status='pending',last_error='',updated_at=now() WHERE id=$1 RETURNING desired_revision`, zoneID, serial).Scan(&revision); err != nil {
			return err
		}
		if _, err := m.river.InsertTx(ctx, tx, provision.ConfigureDNSZoneArgs{
			ZoneID: zoneID, DesiredRevision: revision, Bulk: bulk,
		}, nil); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) ResetZone(ctx context.Context, actorID, siteID int64, confirmation string) error {
	zone, err := m.zoneForSite(ctx, siteID)
	if err != nil {
		return err
	}
	if confirmation != zone.Domain {
		return errors.New("confirmation must match the zone name")
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	zone, err = m.zoneForSiteTx(ctx, tx, siteID, true)
	if err != nil {
		return err
	}
	template, err := m.activeTemplate(ctx, tx)
	if err != nil {
		return err
	}
	authoritativeZone := zone.SiteID == siteID
	if _, err := tx.ExecContext(ctx, `DELETE FROM dns_records
WHERE zone_id=$1 AND origin<>'system' AND ($3 OR owner_site_id=$2)`, zone.ID, siteID, authoritativeZone); err != nil {
		return err
	}
	zone, err = m.zoneByID(ctx, tx, zone.ID, false)
	if err != nil {
		return err
	}
	var plan zonePlan
	if authoritativeZone {
		plan = compareWholeZone(template, zone)
	} else {
		zone.SiteID = siteID
		plan = compareZone(template, zone)
	}
	if err := applyZonePlanMutationsTx(ctx, tx, zone.ID, template.Revision, plan); err != nil {
		return err
	}
	if authoritativeZone {
		if _, err := tx.ExecContext(ctx, `UPDATE sites
SET dns_template_adoption_completed=true,updated_at=now()
WHERE id=$1 OR (parent_site_id=$1 AND dns_zone_mode='parent')`, siteID); err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE sites
SET dns_template_adoption_completed=true,updated_at=now() WHERE id=$1`, siteID); err != nil {
			return err
		}
	}
	if authoritativeZone {
		if _, err := tx.ExecContext(ctx, `UPDATE dns_zones SET template_revision=$2 WHERE id=$1`,
			zone.ID, template.Revision); err != nil {
			return err
		}
	}
	if err := m.refreshZoneTemplateStatusTx(ctx, tx, zone.ID); err != nil {
		return err
	}
	_ = actorID
	return m.enqueueZoneTx(ctx, tx, zone.ID, false)
}

type zoneSnapshot struct {
	types.DNSZoneView
	AuthoritativeSiteID int64
	SiteDomain          string
	ParentDomain        string
	Hostname            string
	AdoptionCompleted   bool
	SubdomainSite       map[int64]siteExpansion
}

type siteExpansion struct {
	Domain            string
	Subdomain         string
	AdoptionCompleted bool
}

func (z zoneSnapshot) expansionForSite(siteID int64) expansionContext {
	domain := z.Domain
	subdomain := ""
	if expansion, ok := z.SubdomainSite[siteID]; ok {
		domain, subdomain = z.Domain, expansion.Subdomain
	}
	return expansionContext{
		domain: domain, subdomain: subdomain, hostname: z.Hostname,
		ipv4: z.Address, ipv6: z.IPv6Address,
	}
}

type zonePlan struct {
	item             types.DNSSyncItem
	add              []types.DNSRecord
	update           map[int64]types.DNSRecord
	remove           []int64
	adopt            map[int64]types.DNSRecord
	settingsChanged  bool
	retryConvergence bool
}

func compareZone(template types.DNSTemplateRevision, zone zoneSnapshot) zonePlan {
	plan := zonePlan{update: map[int64]types.DNSRecord{}, adopt: map[int64]types.DNSRecord{}}
	byKey := map[string]types.DNSRecord{}
	for _, record := range zone.Records {
		if record.OwnerSiteID != 0 && record.OwnerSiteID != zone.SiteID {
			continue
		}
		if record.Origin == "template" && record.TemplateRecordKey != "" {
			byKey[record.TemplateRecordKey] = record
		}
	}
	if zone.SiteID == zone.AuthoritativeSiteID && zone.TemplateRevision != template.Revision {
		plan.settingsChanged = true
		plan.item.UpdatedCount++
	}
	if zone.SiteID == zone.AuthoritativeSiteID && zone.Status == "failed" {
		plan.retryConvergence = true
		if !plan.settingsChanged {
			plan.item.UpdatedCount++
		}
	}
	wantedKeys := map[string]bool{}
	for _, templateRecord := range template.Records {
		expanded, omit, err := expandTemplateRecord(templateRecord, zone.expansionForSite(zone.SiteID))
		if err != nil {
			plan.item.ConflictCount++
			continue
		}
		if omit {
			continue
		}
		expanded.OwnerSiteID = zone.SiteID
		expanded.TemplateRevision = template.Revision
		wantedKeys[templateRecord.StableKey] = true
		if existing, ok := byKey[templateRecord.StableKey]; ok {
			if existing.LocallyModified {
				plan.item.OverrideCount++
			} else if !recordsEqual(existing, expanded) {
				expanded.ID = existing.ID
				plan.update[existing.ID] = expanded
				plan.item.UpdatedCount++
			}
			continue
		}
		systemSatisfied, systemConflict := systemRecordDisposition(zone.Records, expanded)
		if systemSatisfied {
			continue
		}
		if systemConflict {
			plan.item.OverrideCount++
			continue
		}
		equivalent, conflict := findEquivalent(zone.Records, expanded, zone.SiteID)
		if equivalent.ID > 0 {
			if !zone.AdoptionCompleted {
				expanded.ID = equivalent.ID
				plan.adopt[equivalent.ID] = expanded
			}
			continue
		}
		if conflict {
			plan.item.ConflictCount++
			continue
		}
		plan.add = append(plan.add, expanded)
		plan.item.AddedCount++
	}
	for _, existing := range zone.Records {
		if existing.OwnerSiteID != 0 && existing.OwnerSiteID != zone.SiteID {
			continue
		}
		if existing.Origin != "template" || wantedKeys[existing.TemplateRecordKey] {
			continue
		}
		if existing.LocallyModified {
			plan.item.OverrideCount++
			continue
		}
		plan.remove = append(plan.remove, existing.ID)
		plan.item.RemovedCount++
	}
	return validateZonePlan(zone, plan)
}

func compareWholeZone(template types.DNSTemplateRevision, zone zoneSnapshot) zonePlan {
	combined := zonePlan{update: map[int64]types.DNSRecord{}, adopt: map[int64]types.DNSRecord{}}
	mergeZonePlan(&combined, compareZone(template, zone))
	siteIDs := make([]int64, 0, len(zone.SubdomainSite))
	for siteID := range zone.SubdomainSite {
		siteIDs = append(siteIDs, siteID)
	}
	sort.Slice(siteIDs, func(i, j int) bool { return siteIDs[i] < siteIDs[j] })
	for _, siteID := range siteIDs {
		child := zone
		child.SiteID = siteID
		child.AdoptionCompleted = zone.SubdomainSite[siteID].AdoptionCompleted
		mergeZonePlan(&combined, compareZone(template, child))
	}
	return validateZonePlan(zone, combined)
}

func mergeZonePlan(target *zonePlan, source zonePlan) {
	target.add = append(target.add, source.add...)
	target.remove = append(target.remove, source.remove...)
	for id, record := range source.update {
		target.update[id] = record
	}
	for id, record := range source.adopt {
		target.adopt[id] = record
	}
	target.item.AddedCount += source.item.AddedCount
	target.item.UpdatedCount += source.item.UpdatedCount
	target.item.RemovedCount += source.item.RemovedCount
	target.item.OverrideCount += source.item.OverrideCount
	target.item.ConflictCount += source.item.ConflictCount
	target.settingsChanged = target.settingsChanged || source.settingsChanged
	target.retryConvergence = target.retryConvergence || source.retryConvergence
}

func finalizeZonePlan(plan zonePlan) zonePlan {
	switch {
	case plan.item.ConflictCount > 0:
		plan.item.Outcome = "conflict"
	case plan.item.OverrideCount > 0:
		plan.item.Outcome = "overridden"
	case plan.item.AddedCount > 0:
		plan.item.Outcome = "added"
	case plan.item.UpdatedCount > 0:
		plan.item.Outcome = "updated"
	case plan.item.RemovedCount > 0:
		plan.item.Outcome = "removed"
	default:
		plan.item.Outcome = "unchanged"
	}
	parts := []string{}
	if plan.item.AddedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d add", plan.item.AddedCount))
	}
	if plan.item.UpdatedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d update", plan.item.UpdatedCount))
	}
	if plan.item.RemovedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d remove", plan.item.RemovedCount))
	}
	if plan.item.OverrideCount > 0 {
		parts = append(parts, fmt.Sprintf("%d override preserved", plan.item.OverrideCount))
	}
	if plan.item.ConflictCount > 0 {
		parts = append(parts, fmt.Sprintf("%d conflict", plan.item.ConflictCount))
	}
	plan.item.Detail = strings.Join(parts, ", ")
	return plan
}

func validateZonePlan(zone zoneSnapshot, plan zonePlan) zonePlan {
	removed := make(map[int64]struct{}, len(plan.remove))
	for _, id := range plan.remove {
		removed[id] = struct{}{}
	}
	candidate := make([]types.DNSRecord, 0, len(zone.Records)+len(plan.add))
	for _, record := range zone.Records {
		if _, drop := removed[record.ID]; drop {
			continue
		}
		if replacement, ok := plan.update[record.ID]; ok {
			candidate = append(candidate, replacement)
			continue
		}
		candidate = append(candidate, record)
	}
	candidate = append(candidate, plan.add...)
	if err := validateDNSRecordSet(candidate); err != nil {
		plan.add = nil
		plan.update = map[int64]types.DNSRecord{}
		plan.remove = nil
		plan.adopt = map[int64]types.DNSRecord{}
		plan.item.AddedCount = 0
		plan.item.UpdatedCount = 0
		plan.item.RemovedCount = 0
		plan.item.ConflictCount++
		plan.item.Detail = err.Error()
	}
	return finalizeZonePlan(plan)
}

func systemRecordDisposition(records []types.DNSRecord, wanted types.DNSRecord) (satisfied, conflict bool) {
	for _, record := range records {
		if record.Origin != "system" {
			continue
		}
		if recordsEqual(record, wanted) {
			return true, false
		}
		if recordsSameRData(record, wanted) {
			conflict = true
		}
		if strings.EqualFold(record.Host, wanted.Host) &&
			(record.Type == "CNAME" || wanted.Type == "CNAME") {
			conflict = true
		}
	}
	return false, conflict
}

func recordsEqual(left, right types.DNSRecord) bool {
	return recordsSameRData(left, right) && left.TTL == right.TTL
}

func recordsSameRData(left, right types.DNSRecord) bool {
	return strings.EqualFold(left.Host, right.Host) && left.Type == right.Type &&
		strings.EqualFold(strings.TrimSuffix(left.Value, "."), strings.TrimSuffix(right.Value, ".")) &&
		left.Priority == right.Priority && left.Weight == right.Weight && left.Port == right.Port
}

func findEquivalent(records []types.DNSRecord, wanted types.DNSRecord, ownerSiteID int64) (types.DNSRecord, bool) {
	conflict := false
	for _, record := range records {
		if record.Origin == "system" {
			continue
		}
		sameOwner := record.OwnerSiteID == 0 || record.OwnerSiteID == ownerSiteID
		if sameOwner && recordsEqual(record, wanted) {
			return record, false
		}
		if sameOwner && recordsSameRData(record, wanted) {
			conflict = true
		}
		if strings.EqualFold(record.Host, wanted.Host) {
			if record.Type == "CNAME" || wanted.Type == "CNAME" {
				conflict = true
			}
		}
	}
	return types.DNSRecord{}, conflict
}

func nullableID(value int64) any {
	if value <= 0 {
		return nil
	}
	return value
}

func nullablePriority(recordType string, value int) any {
	if recordType == "MX" || recordType == "SRV" {
		return value
	}
	return nil
}

func nullableSRV(recordType string, value int) any {
	if recordType == "SRV" {
		return value
	}
	return nil
}

func postgresArray(values []string) string {
	if len(values) == 0 {
		return "{}"
	}
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	}
	return "{" + strings.Join(quoted, ",") + "}"
}

func randomToken(prefix string, bytesCount int) (string, error) {
	value := make([]byte, bytesCount)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value), nil
}

func (m *Manager) activeTemplate(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (types.DNSTemplateRevision, error) {
	var id int64
	var optimistic int64
	if err := q.QueryRowContext(ctx, `SELECT active_revision_id,optimistic_revision FROM dns_template_state WHERE singleton`).Scan(&id, &optimistic); err != nil {
		return types.DNSTemplateRevision{}, err
	}
	template, err := m.templateByID(ctx, q, id)
	template.OptimisticRevision = optimistic
	return template, err
}

func (m *Manager) templateByID(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, id int64) (types.DNSTemplateRevision, error) {
	var template types.DNSTemplateRevision
	var cidrsJSON string
	err := q.QueryRowContext(ctx, `SELECT id,revision,primary_nameserver,responsible_mailbox,serial_format,
default_ttl,refresh_seconds,retry_seconds,expire_seconds,minimum_ttl,zone_status,subdomain_policy,
COALESCE(array_to_json(transfer_cidrs)::text,'[]'),COALESCE(created_by,0),created_at
FROM dns_template_revisions WHERE id=$1`, id).Scan(
		&template.ID, &template.Revision, &template.SOA.PrimaryNameserver, &template.SOA.ResponsibleMailbox,
		&template.SOA.SerialFormat, &template.SOA.DefaultTTL, &template.SOA.RefreshSeconds,
		&template.SOA.RetrySeconds, &template.SOA.ExpireSeconds, &template.SOA.MinimumTTL,
		&template.ZoneStatus, &template.SubdomainPolicy, &cidrsJSON, &template.CreatedBy, &template.CreatedAt)
	if err != nil {
		return template, err
	}
	_ = json.Unmarshal([]byte(cidrsJSON), &template.TransferCIDRs)
	rows, err := q.QueryContext(ctx, `SELECT id,stable_key,scope,host_template,record_type,value_template,
COALESCE(priority,0),COALESCE(weight,0),COALESCE(port,0),ttl
FROM dns_template_records WHERE revision_id=$1 ORDER BY scope,host_template,record_type,stable_key`, id)
	if err != nil {
		return template, err
	}
	defer rows.Close()
	for rows.Next() {
		var record types.DNSTemplateRecord
		if err := rows.Scan(&record.ID, &record.StableKey, &record.Scope, &record.HostTemplate,
			&record.Type, &record.ValueTemplate, &record.Priority, &record.Weight, &record.Port, &record.TTL); err != nil {
			return template, err
		}
		template.Records = append(template.Records, record)
	}
	return template, rows.Err()
}

func (m *Manager) templateByRevision(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, revision int64) (types.DNSTemplateRevision, error) {
	var id int64
	if err := q.QueryRowContext(ctx, `SELECT id FROM dns_template_revisions WHERE revision=$1`, revision).Scan(&id); err != nil {
		return types.DNSTemplateRevision{}, err
	}
	return m.templateByID(ctx, q, id)
}

func (m *Manager) listRuns(ctx context.Context, limit int) ([]types.DNSSyncRun, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT id,template_revision,scope,status,expected_template_state_revision,
total_zones,changed_zones,failed_zones,last_error,created_at,completed_at
FROM dns_template_sync_runs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []types.DNSSyncRun
	for rows.Next() {
		var run types.DNSSyncRun
		if err := rows.Scan(&run.ID, &run.TemplateRevision, &run.Scope, &run.Status,
			&run.ExpectedStateRevision, &run.TotalZones, &run.ChangedZones, &run.FailedZones,
			&run.LastError, &run.CreatedAt, &run.CompletedAt); err != nil {
			return nil, err
		}
		result = append(result, run)
	}
	return result, rows.Err()
}

func (m *Manager) loadRun(ctx context.Context, id int64) (types.DNSSyncRun, error) {
	var run types.DNSSyncRun
	err := m.db.QueryRowContext(ctx, `SELECT id,template_revision,scope,status,preview_token,
expected_template_state_revision,total_zones,changed_zones,failed_zones,last_error,created_at,completed_at
FROM dns_template_sync_runs WHERE id=$1`, id).Scan(
		&run.ID, &run.TemplateRevision, &run.Scope, &run.Status, &run.PreviewToken,
		&run.ExpectedStateRevision, &run.TotalZones, &run.ChangedZones, &run.FailedZones,
		&run.LastError, &run.CreatedAt, &run.CompletedAt)
	if err != nil {
		return run, err
	}
	rows, err := m.db.QueryContext(ctx, `SELECT item.id,item.zone_id,COALESCE(item.owner_site_id,zone.site_id),zone.domain,item.outcome,item.added_count,
item.updated_count,item.removed_count,item.override_count,item.conflict_count,item.detail
FROM dns_template_sync_items item JOIN dns_zones zone ON zone.id=item.zone_id
WHERE item.run_id=$1 ORDER BY zone.domain`, id)
	if err != nil {
		return run, err
	}
	defer rows.Close()
	for rows.Next() {
		var item types.DNSSyncItem
		if err := rows.Scan(&item.ID, &item.ZoneID, &item.OwnerSiteID, &item.Domain, &item.Outcome, &item.AddedCount,
			&item.UpdatedCount, &item.RemovedCount, &item.OverrideCount, &item.ConflictCount, &item.Detail); err != nil {
			return run, err
		}
		run.Items = append(run.Items, item)
	}
	return run, rows.Err()
}

func (m *Manager) zonesForSync(ctx context.Context, scope string, zoneID int64) ([]zoneSnapshot, error) {
	query := `SELECT id FROM dns_zones WHERE ($1::bigint=0 OR id=$1) ORDER BY id`
	rows, err := m.db.QueryContext(ctx, query, zoneID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []zoneSnapshot
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		zone, err := m.zoneByID(ctx, m.db, id, false)
		if err != nil {
			return nil, err
		}
		if scope == "unmodified" && zone.TemplateStatus == "customized" {
			continue
		}
		result = append(result, zone)
	}
	return result, rows.Err()
}

func (m *Manager) zoneForSite(ctx context.Context, siteID int64) (zoneSnapshot, error) {
	return m.zoneForSiteTx(ctx, m.db, siteID, false)
}

func (m *Manager) zoneForSiteTx(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, siteID int64, forUpdate bool) (zoneSnapshot, error) {
	suffix := ""
	if forUpdate {
		suffix = " FOR UPDATE OF zone"
	}
	var zoneID int64
	err := q.QueryRowContext(ctx, `SELECT zone.id
FROM sites site
LEFT JOIN sites parent ON parent.id=site.parent_site_id
JOIN dns_zones zone ON zone.site_id=CASE WHEN site.dns_zone_mode='parent' AND parent.id IS NOT NULL THEN parent.id ELSE site.id END
WHERE site.id=$1`+suffix, siteID).Scan(&zoneID)
	if err != nil {
		return zoneSnapshot{}, err
	}
	return m.zoneByID(ctx, q, zoneID, false)
}

func (m *Manager) zoneByID(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, zoneID int64, _ bool) (zoneSnapshot, error) {
	var zone zoneSnapshot
	var primariesJSON, cidrsJSON, soaJSON string
	err := q.QueryRowContext(ctx, `SELECT zone.id,zone.site_id,COALESCE(zone.parent_zone_id,0),zone.domain,zone.address,
zone.ipv6_address,zone.mode,COALESCE(array_to_json(zone.upstream_primaries)::text,'[]'),
COALESCE(array_to_json(zone.transfer_cidrs)::text,'[]'),COALESCE(zone.soa_override::text,'null'),
	COALESCE(zone.template_revision,0),zone.template_status,zone.desired_revision,zone.applied_revision,
	zone.status,zone.last_error,site.domain,COALESCE(parent.domain,''),
	site.dns_template_adoption_completed,
	COALESCE(NULLIF((SELECT payload->>'hostname' FROM server_inventory
	    WHERE kind='server' AND resource_key='host'),''),zone.domain)
FROM dns_zones zone JOIN sites site ON site.id=zone.site_id
LEFT JOIN sites parent ON parent.id=site.parent_site_id WHERE zone.id=$1`, zoneID).Scan(
		&zone.ID, &zone.SiteID, &zone.ParentZoneID, &zone.Domain, &zone.Address, &zone.IPv6Address,
		&zone.Mode, &primariesJSON, &cidrsJSON, &soaJSON, &zone.TemplateRevision,
		&zone.TemplateStatus, &zone.DesiredRevision, &zone.AppliedRevision, &zone.Status,
		&zone.LastError, &zone.SiteDomain, &zone.ParentDomain, &zone.AdoptionCompleted, &zone.Hostname)
	if err != nil {
		return zone, err
	}
	zone.AuthoritativeSiteID = zone.SiteID
	_ = json.Unmarshal([]byte(primariesJSON), &zone.UpstreamPrimaries)
	_ = json.Unmarshal([]byte(cidrsJSON), &zone.TransferCIDRs)
	if soaJSON != "null" {
		_ = json.Unmarshal([]byte(soaJSON), &zone.SOA)
	}
	template, err := m.templateByRevision(ctx, q, zone.TemplateRevision)
	if err != nil {
		return zone, err
	}
	if zone.SOA.PrimaryNameserver == "" {
		zone.SOA = expandSOA(template.SOA, zone.Domain, zone.Hostname)
	}
	if zone.TransferCIDRs == nil {
		zone.TransferCIDRs = append([]string(nil), template.TransferCIDRs...)
	}
	records, err := q.QueryContext(ctx, `SELECT id,zone_id,COALESCE(owner_site_id,0),host,record_type,value,
COALESCE(priority,0),COALESCE(weight,0),COALESCE(port,0),ttl,origin,COALESCE(template_record_key,''),
COALESCE(template_revision,0),locally_modified
FROM dns_records WHERE zone_id=$1 ORDER BY host,record_type,id`, zoneID)
	if err != nil {
		return zone, err
	}
	for records.Next() {
		var record types.DNSRecord
		if err := records.Scan(&record.ID, &record.ZoneID, &record.OwnerSiteID, &record.Host,
			&record.Type, &record.Value, &record.Priority, &record.Weight, &record.Port, &record.TTL,
			&record.Origin, &record.TemplateRecordKey, &record.TemplateRevision, &record.LocallyModified); err != nil {
			return zone, err
		}
		zone.Records = append(zone.Records, record)
	}
	if err := records.Close(); err != nil {
		return zone, err
	}
	zone.SubdomainSite = map[int64]siteExpansion{}
	sites, err := q.QueryContext(ctx, `SELECT child.id,child.domain,child.dns_template_adoption_completed FROM sites child
WHERE child.parent_site_id=$1 AND child.dns_zone_mode='parent'`, zone.SiteID)
	if err != nil {
		return zone, err
	}
	for sites.Next() {
		var id int64
		var domain string
		var adoptionCompleted bool
		if err := sites.Scan(&id, &domain, &adoptionCompleted); err != nil {
			return zone, err
		}
		subdomain := strings.TrimSuffix(domain, "."+zone.Domain)
		zone.SubdomainSite[id] = siteExpansion{
			Domain: domain, Subdomain: subdomain, AdoptionCompleted: adoptionCompleted,
		}
	}
	if err := sites.Err(); err != nil {
		sites.Close()
		return zone, err
	}
	return zone, sites.Close()
}

func expandSOA(settings types.DNSSOASettings, domain, hostname string) types.DNSSOASettings {
	values := expansionContext{domain: domain, hostname: hostname}
	settings.PrimaryNameserver = expandPlaceholders(settings.PrimaryNameserver, values)
	settings.ResponsibleMailbox = expandPlaceholders(settings.ResponsibleMailbox, values)
	return settings
}

func (m *Manager) enqueueZoneTx(ctx context.Context, tx *sql.Tx, zoneID int64, bulk bool) error {
	var revision int64
	serial, err := m.nextZoneSerialTx(ctx, tx, zoneID)
	if err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `UPDATE dns_zones SET desired_revision=desired_revision+1,serial=$2,status='pending',
last_error='',updated_at=now() WHERE id=$1 RETURNING desired_revision`, zoneID, serial).Scan(&revision); err != nil {
		return err
	}
	if _, err := m.river.InsertTx(ctx, tx, provision.ConfigureDNSZoneArgs{
		ZoneID: zoneID, DesiredRevision: revision, Bulk: bulk,
	}, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func (m *Manager) refreshZoneTemplateStatusTx(ctx context.Context, tx *sql.Tx, zoneID int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE dns_zones zone
	SET template_status=CASE
    WHEN zone.soa_override IS NOT NULL OR zone.transfer_cidrs IS NOT NULL OR EXISTS (
        SELECT 1 FROM dns_records record
        WHERE record.zone_id=zone.id
          AND (record.origin='custom' OR (record.origin='template' AND record.locally_modified))
	    ) THEN 'customized'
	    WHEN COALESCE(zone.template_revision,0)=revision.revision THEN 'in_sync'
	    ELSE 'out_of_sync'
END,
updated_at=now()
FROM dns_template_state state
JOIN dns_template_revisions revision ON revision.id=state.active_revision_id
WHERE zone.id=$1`, zoneID)
	return err
}

func (m *Manager) nextZoneSerialTx(ctx context.Context, tx *sql.Tx, zoneID int64) (int64, error) {
	var previous int64
	var format string
	err := tx.QueryRowContext(ctx, `SELECT zone.serial,
COALESCE(zone.soa_override->>'serial_format',revision.serial_format)
FROM dns_zones zone
JOIN dns_template_revisions revision ON revision.revision=zone.template_revision
WHERE zone.id=$1`, zoneID).Scan(&previous, &format)
	if err != nil {
		return 0, err
	}
	return nextDNSSerial(m.now().UTC(), previous, format)
}

func nextDNSSerial(now time.Time, previous int64, format string) (int64, error) {
	var serial int64
	if format == "date-counter" {
		base, _ := strconv.ParseInt(now.Format("20060102")+"00", 10, 64)
		if previous >= base && previous < base+99 {
			serial = previous + 1
		} else if previous >= base+99 && previous < base+100 {
			return 0, errors.New("the DNS serial date counter is exhausted for today")
		} else if previous > base {
			serial = previous + 1
		} else {
			serial = base
		}
	} else {
		serial = now.Unix()
		if serial <= previous {
			serial = previous + 1
		}
	}
	if serial < 1 || serial > int64(^uint32(0)) {
		return 0, errors.New("the next DNS serial exceeds the RFC 1982 32-bit range")
	}
	return serial, nil
}

func sortRecords(records []types.DNSRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Host != records[j].Host {
			return records[i].Host < records[j].Host
		}
		if records[i].Type != records[j].Type {
			return records[i].Type < records[j].Type
		}
		return records[i].ID < records[j].ID
	})
}
