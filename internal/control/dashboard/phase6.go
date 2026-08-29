package dashboard

import (
	"context"
	"database/sql"
	"errors"

	"github.com/nakroteck/nakpanel/internal/types"
)

type SQLPhase6Store struct {
	db *sql.DB
}

func NewSQLPhase6Store(db *sql.DB) *SQLPhase6Store {
	return &SQLPhase6Store{db: db}
}

func (s *SQLPhase6Store) GetPhase6(ctx context.Context) (Phase6Data, error) {
	if s.db == nil {
		return Phase6Data{}, errors.New("phase6 database is not configured")
	}
	backups, err := s.listBackups(ctx)
	if err != nil {
		return Phase6Data{}, err
	}
	restores, err := s.listRestores(ctx)
	if err != nil {
		return Phase6Data{}, err
	}
	webmail, err := s.listWebmail(ctx)
	if err != nil {
		return Phase6Data{}, err
	}
	dns, err := s.listDNS(ctx)
	if err != nil {
		return Phase6Data{}, err
	}
	reconciliations, err := s.listReconciliations(ctx)
	if err != nil {
		return Phase6Data{}, err
	}
	records, err := s.listDNSRecords(ctx)
	if err != nil {
		return Phase6Data{}, err
	}
	return Phase6Data{Backups: backups, Restores: restores, WebmailHosts: webmail, DNSZones: dns, DNSRecords: records, Reconciliations: reconciliations}, nil
}

func (s *SQLPhase6Store) listBackups(ctx context.Context) ([]Backup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, target_name, status, archive_path, size_bytes, last_error, created_at, COALESCE(site_id,0), COALESCE(subscription_id,0) FROM backups ORDER BY created_at DESC, id DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var backups []Backup
	for rows.Next() {
		var backup Backup
		if err := rows.Scan(&backup.ID, &backup.TargetName, &backup.Status, &backup.ArchivePath, &backup.SizeBytes, &backup.LastError, &backup.CreatedAt, &backup.SiteID, &backup.SubscriptionID); err != nil {
			return nil, err
		}
		backups = append(backups, backup)
	}
	return backups, rows.Err()
}

func (s *SQLPhase6Store) listRestores(ctx context.Context) ([]RestoreRun, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, COALESCE(backup_id, 0), target_name, status, restored_at, last_error, created_at FROM restore_runs ORDER BY created_at DESC, id DESC LIMIT 10`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var restores []RestoreRun
	for rows.Next() {
		var run RestoreRun
		var restoredAt sql.NullTime
		if err := rows.Scan(&run.ID, &run.BackupID, &run.TargetName, &run.Status, &restoredAt, &run.LastError, &run.CreatedAt); err != nil {
			return nil, err
		}
		run.RestoredAt = NullableTime{Time: restoredAt.Time, Valid: restoredAt.Valid}
		restores = append(restores, run)
	}
	return restores, rows.Err()
}

func (s *SQLPhase6Store) listWebmail(ctx context.Context) ([]WebmailHost, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, hostname, status, config_path, last_error, created_at FROM webmail_hosts ORDER BY created_at DESC, id DESC LIMIT 10`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hosts []WebmailHost
	for rows.Next() {
		var host WebmailHost
		if err := rows.Scan(&host.ID, &host.Hostname, &host.Status, &host.ConfigPath, &host.LastError, &host.CreatedAt); err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	return hosts, rows.Err()
}

func (s *SQLPhase6Store) listDNS(ctx context.Context) ([]DNSZone, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT zone.id,zone.domain,zone.address,zone.ipv6_address,zone.serial,
zone.status,zone.zone_path,zone.last_error,zone.created_at,zone.site_id,COALESCE(zone.parent_zone_id,0),
zone.mode,array_to_string(zone.upstream_primaries,E'\n'),
array_to_string(COALESCE(zone.transfer_cidrs,revision.transfer_cidrs),E'\n'),
COALESCE(zone.template_revision,0),zone.template_status,zone.desired_revision,zone.applied_revision,
COALESCE(zone.soa_override->>'primary_nameserver',replace(revision.primary_nameserver,'<domain>',zone.domain)),
COALESCE(zone.soa_override->>'responsible_mailbox',replace(revision.responsible_mailbox,'<domain>',zone.domain)),
COALESCE(zone.soa_override->>'serial_format',revision.serial_format),
COALESCE((zone.soa_override->>'default_ttl')::int,revision.default_ttl),
COALESCE((zone.soa_override->>'refresh_seconds')::int,revision.refresh_seconds),
COALESCE((zone.soa_override->>'retry_seconds')::int,revision.retry_seconds),
COALESCE((zone.soa_override->>'expire_seconds')::int,revision.expire_seconds),
COALESCE((zone.soa_override->>'minimum_ttl')::int,revision.minimum_ttl)
FROM dns_zones zone
JOIN dns_template_revisions revision ON revision.revision=zone.template_revision
ORDER BY zone.created_at DESC,zone.id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var zones []DNSZone
	for rows.Next() {
		var zone DNSZone
		if err := rows.Scan(&zone.ID, &zone.Domain, &zone.Address, &zone.IPv6Address, &zone.Serial,
			&zone.Status, &zone.ZonePath, &zone.LastError, &zone.CreatedAt, &zone.SiteID,
			&zone.ParentZoneID, &zone.Mode, &zone.UpstreamPrimaries, &zone.TransferCIDRs,
			&zone.TemplateRevision, &zone.TemplateStatus, &zone.DesiredRevision, &zone.AppliedRevision,
			&zone.SOA.PrimaryNameserver, &zone.SOA.ResponsibleMailbox, &zone.SOA.SerialFormat,
			&zone.SOA.DefaultTTL, &zone.SOA.RefreshSeconds, &zone.SOA.RetrySeconds,
			&zone.SOA.ExpireSeconds, &zone.SOA.MinimumTTL); err != nil {
			return nil, err
		}
		zones = append(zones, zone)
	}
	return zones, rows.Err()
}

func (s *SQLPhase6Store) listDNSRecords(ctx context.Context) ([]types.DNSRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,zone_id,COALESCE(owner_site_id,0),host,record_type,value,
COALESCE(priority,0),COALESCE(weight,0),COALESCE(port,0),ttl,origin,
COALESCE(template_record_key,''),COALESCE(template_revision,0),locally_modified
FROM dns_records ORDER BY zone_id,host,record_type,id`)
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

func (s *SQLPhase6Store) listReconciliations(ctx context.Context) ([]ReconciliationRun, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, status, sites_total, sites_ok, last_error, created_at FROM reconciliation_runs ORDER BY created_at DESC, id DESC LIMIT 10`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []ReconciliationRun
	for rows.Next() {
		var run ReconciliationRun
		if err := rows.Scan(&run.ID, &run.Status, &run.SitesTotal, &run.SitesOK, &run.LastError, &run.CreatedAt); err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}
