package dashboard

import (
	"context"
	"database/sql"
	"errors"
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
	return Phase6Data{Backups: backups, Restores: restores, WebmailHosts: webmail, DNSZones: dns, Reconciliations: reconciliations}, nil
}

func (s *SQLPhase6Store) listBackups(ctx context.Context) ([]Backup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, target_name, status, archive_path, size_bytes, last_error, created_at FROM backups ORDER BY created_at DESC, id DESC LIMIT 10`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var backups []Backup
	for rows.Next() {
		var backup Backup
		if err := rows.Scan(&backup.ID, &backup.TargetName, &backup.Status, &backup.ArchivePath, &backup.SizeBytes, &backup.LastError, &backup.CreatedAt); err != nil {
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
	rows, err := s.db.QueryContext(ctx, `SELECT id, domain, address, serial, status, zone_path, last_error, created_at FROM dns_zones ORDER BY created_at DESC, id DESC LIMIT 10`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var zones []DNSZone
	for rows.Next() {
		var zone DNSZone
		if err := rows.Scan(&zone.ID, &zone.Domain, &zone.Address, &zone.Serial, &zone.Status, &zone.ZonePath, &zone.LastError, &zone.CreatedAt); err != nil {
			return nil, err
		}
		zones = append(zones, zone)
	}
	return zones, rows.Err()
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
