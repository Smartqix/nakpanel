package provision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type SQLPhase6Repository struct {
	db    *sql.DB
	river *river.Client[*sql.Tx]
	now   func() time.Time
}

func NewSQLPhase6Repository(db *sql.DB, riverClient *river.Client[*sql.Tx]) *SQLPhase6Repository {
	return &SQLPhase6Repository{db: db, river: riverClient, now: time.Now}
}

func (r *SQLPhase6Repository) CreateBackup(ctx context.Context, ownerID int64, req types.CreateBackupReq) (int64, error) {
	if r.db == nil {
		return 0, errors.New("database is not configured")
	}
	if r.river == nil {
		return 0, errors.New("river client is not configured")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin backup transaction: %w", err)
	}
	defer tx.Rollback()

	site, err := selectActiveSiteForUpdate(ctx, tx, ownerID, req.Domain)
	if err != nil {
		return 0, err
	}
	databases, err := selectActiveOwnerDatabases(ctx, tx, ownerID)
	if err != nil {
		return 0, err
	}
	var backupID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO backups (owner_user_id, site_id, subscription_id, target_kind, target_name, status)
VALUES ($1, $2, (SELECT id FROM subscriptions WHERE customer_user_id = $1 AND status = 'active' LIMIT 1), 'site', $3, 'pending')
RETURNING id`, ownerID, site.id, site.domain).Scan(&backupID); err != nil {
		return 0, fmt.Errorf("insert backup intent: %w", err)
	}
	_, err = r.river.InsertTx(ctx, tx, CreateBackupArgs{
		BackupID:  backupID,
		Domain:    site.domain,
		Username:  site.username,
		Docroot:   "/home/" + site.username + "/public_html",
		Databases: databases,
	}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue create_backup job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit backup transaction: %w", err)
	}
	return backupID, nil
}

func (r *SQLPhase6Repository) ConfigureWebmail(ctx context.Context, ownerID int64, domain string) (int64, error) {
	if r.db == nil {
		return 0, errors.New("database is not configured")
	}
	if r.river == nil {
		return 0, errors.New("river client is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin webmail transaction: %w", err)
	}
	defer tx.Rollback()

	site, err := selectActiveSiteForUpdate(ctx, tx, ownerID, domain)
	if err != nil {
		return 0, err
	}
	hostname := "webmail." + site.domain
	var id int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO webmail_hosts (owner_user_id, site_id, hostname, status, last_error)
VALUES ($1, $2, $3, 'pending', '')
ON CONFLICT (hostname) DO UPDATE SET status = 'pending', last_error = '', updated_at = now()
RETURNING id`, ownerID, site.id, hostname).Scan(&id); err != nil {
		return 0, fmt.Errorf("upsert webmail intent: %w", err)
	}
	_, err = r.river.InsertTx(ctx, tx, ConfigureWebmailArgs{WebmailID: id, Domain: site.domain, Hostname: hostname}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue configure_webmail job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit webmail transaction: %w", err)
	}
	return id, nil
}

func (r *SQLPhase6Repository) RestoreBackup(ctx context.Context, ownerID int64, backupID int64) (int64, error) {
	if backupID <= 0 {
		return 0, errors.New("backup id is required")
	}
	if r.db == nil {
		return 0, errors.New("database is not configured")
	}
	if r.river == nil {
		return 0, errors.New("river client is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin restore transaction: %w", err)
	}
	defer tx.Rollback()

	backup, err := selectRestorableBackupForUpdate(ctx, tx, ownerID, backupID)
	if err != nil {
		return 0, err
	}
	databases, err := selectActiveOwnerDatabases(ctx, tx, ownerID)
	if err != nil {
		return 0, err
	}
	var restoreID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO restore_runs (owner_user_id, backup_id, target_name, status)
VALUES ($1, $2, $3, 'pending')
RETURNING id`, ownerID, backupID, backup.domain).Scan(&restoreID); err != nil {
		return 0, fmt.Errorf("insert restore run: %w", err)
	}
	_, err = r.river.InsertTx(ctx, tx, RestoreBackupArgs{
		RestoreID:   restoreID,
		BackupID:    backupID,
		Domain:      backup.domain,
		Username:    backup.username,
		Docroot:     "/home/" + backup.username + "/public_html",
		ArchivePath: backup.archivePath,
		Databases:   databases,
	}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue restore_backup job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit restore transaction: %w", err)
	}
	return restoreID, nil
}

func (r *SQLPhase6Repository) ConfigureDNS(ctx context.Context, ownerID int64, domain string, address string) (int64, error) {
	if net.ParseIP(address) == nil {
		return 0, fmt.Errorf("invalid dns address %q", address)
	}
	if r.db == nil {
		return 0, errors.New("database is not configured")
	}
	if r.river == nil {
		return 0, errors.New("river client is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin dns transaction: %w", err)
	}
	defer tx.Rollback()

	site, err := selectActiveSiteForUpdate(ctx, tx, ownerID, domain)
	if err != nil {
		return 0, err
	}
	serial := r.now().UTC().Unix()
	var id int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO dns_zones (owner_user_id, site_id, domain, address, serial, status, last_error)
VALUES ($1, $2, $3, $4, $5, 'pending', '')
ON CONFLICT (domain) DO UPDATE SET address = EXCLUDED.address, serial = EXCLUDED.serial, status = 'pending', last_error = '', updated_at = now()
RETURNING id`, ownerID, site.id, site.domain, address, serial).Scan(&id); err != nil {
		return 0, fmt.Errorf("upsert dns intent: %w", err)
	}
	_, err = r.river.InsertTx(ctx, tx, ConfigureDNSZoneArgs{ZoneID: id, Domain: site.domain, Address: address, Serial: serial}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue configure_dns_zone job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit dns transaction: %w", err)
	}
	return id, nil
}

func (r *SQLPhase6Repository) ReconcileSystem(ctx context.Context, ownerID int64) (int64, error) {
	if r.db == nil {
		return 0, errors.New("database is not configured")
	}
	if r.river == nil {
		return 0, errors.New("river client is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin reconciliation transaction: %w", err)
	}
	defer tx.Rollback()

	sites, err := selectReconcileSites(ctx, tx)
	if err != nil {
		return 0, err
	}
	var runID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO reconciliation_runs (owner_user_id, status, sites_total)
VALUES ($1, 'pending', $2)
RETURNING id`, ownerID, len(sites)).Scan(&runID); err != nil {
		return 0, fmt.Errorf("insert reconciliation run: %w", err)
	}
	_, err = r.river.InsertTx(ctx, tx, ReconcileSystemArgs{RunID: runID, Sites: sites}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue reconcile_system job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit reconciliation transaction: %w", err)
	}
	return runID, nil
}

func (r *SQLPhase6Repository) CreateAdminerToken(ctx context.Context, ownerID int64) (types.AdminerSSO, error) {
	if r.db == nil {
		return types.AdminerSSO{}, errors.New("database is not configured")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return types.AdminerSSO{}, fmt.Errorf("generate adminer token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	hash := sha256.Sum256([]byte(token))
	expiresAt := r.now().UTC().Add(10 * time.Minute)
	if _, err := r.db.ExecContext(ctx, `INSERT INTO adminer_tokens (owner_user_id, token_hash, expires_at)
VALUES ($1, $2, $3)`, ownerID, hex.EncodeToString(hash[:]), expiresAt); err != nil {
		return types.AdminerSSO{}, fmt.Errorf("insert adminer token: %w", err)
	}
	return types.AdminerSSO{Token: token, ExpiresAtUnix: expiresAt.Unix()}, nil
}

type phase6Site struct {
	id         int64
	username   string
	domain     string
	phpVersion string
}

type restorableBackup struct {
	backupID    int64
	siteID      int64
	username    string
	domain      string
	archivePath string
}

func selectRestorableBackupForUpdate(ctx context.Context, tx *sql.Tx, ownerID int64, backupID int64) (restorableBackup, error) {
	var backup restorableBackup
	if err := tx.QueryRowContext(ctx, `SELECT b.id, s.id, s.username, s.domain, b.archive_path
FROM backups b
JOIN sites s ON s.id = b.site_id
WHERE b.owner_user_id = $1
  AND b.id = $2
  AND b.status = 'active'
  AND b.archive_path <> ''
  AND s.status = 'active'
FOR UPDATE`, ownerID, backupID).Scan(&backup.backupID, &backup.siteID, &backup.username, &backup.domain, &backup.archivePath); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return restorableBackup{}, fmt.Errorf("active backup %d was not found", backupID)
		}
		return restorableBackup{}, fmt.Errorf("select restorable backup: %w", err)
	}
	return backup, nil
}

func selectActiveSiteForUpdate(ctx context.Context, tx *sql.Tx, ownerID int64, domain string) (phase6Site, error) {
	var site phase6Site
	if err := tx.QueryRowContext(ctx, `SELECT id, username, domain, php_version
FROM sites
WHERE owner_user_id = $1 AND domain = $2 AND status = 'active'
FOR UPDATE`, ownerID, domain).Scan(&site.id, &site.username, &site.domain, &site.phpVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return phase6Site{}, fmt.Errorf("active site %q was not found", domain)
		}
		return phase6Site{}, fmt.Errorf("select active site: %w", err)
	}
	return site, nil
}

func selectActiveOwnerDatabases(ctx context.Context, tx *sql.Tx, ownerID int64) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT db_name FROM databases WHERE owner_user_id = $1 AND status = 'active' ORDER BY db_name`, ownerID)
	if err != nil {
		return nil, fmt.Errorf("select active databases: %w", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return names, nil
}

func selectReconcileSites(ctx context.Context, tx *sql.Tx) ([]types.ReconcileSiteReq, error) {
	rows, err := tx.QueryContext(ctx, `SELECT s.username, s.domain, s.php_version,
       COALESCE(w.status IN ('pending', 'active', 'failed'), false) AS enable_webmail,
       COALESCE(d.status IN ('pending', 'active', 'failed'), false) AS enable_dns,
       COALESCE(d.address, '') AS address
FROM sites s
LEFT JOIN webmail_hosts w ON w.site_id = s.id
LEFT JOIN dns_zones d ON d.site_id = s.id
WHERE s.status = 'active'
ORDER BY s.domain`)
	if err != nil {
		return nil, fmt.Errorf("select reconcile sites: %w", err)
	}
	defer rows.Close()
	var sites []types.ReconcileSiteReq
	for rows.Next() {
		var site types.ReconcileSiteReq
		if err := rows.Scan(&site.Username, &site.Domain, &site.PHPVersion, &site.EnableWebmail, &site.EnableDNS, &site.Address); err != nil {
			return nil, err
		}
		sites = append(sites, site)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sites, nil
}

type SQLPhase6StatusStore struct {
	db *sql.DB
}

func NewSQLPhase6StatusStore(db *sql.DB) *SQLPhase6StatusStore {
	return &SQLPhase6StatusStore{db: db}
}

func (s *SQLPhase6StatusStore) MarkBackupActive(ctx context.Context, id int64, result types.CreateBackupResult) error {
	_, err := s.db.ExecContext(ctx, `UPDATE backups SET status = 'active', archive_path = $2, size_bytes = $3, checksum_sha256 = $4, last_error = '', updated_at = now() WHERE id = $1`, id, result.ArchivePath, result.SizeBytes, result.SHA256)
	return err
}

func (s *SQLPhase6StatusStore) MarkBackupFailed(ctx context.Context, id int64, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE backups SET status = 'failed', last_error = $2, updated_at = now() WHERE id = $1`, id, message)
	return err
}

func (s *SQLPhase6StatusStore) MarkRestoreActive(ctx context.Context, id int64, result types.RestoreBackupResult) error {
	_, err := s.db.ExecContext(ctx, `UPDATE restore_runs SET status = 'active', restored_at = now(), last_error = '', updated_at = now() WHERE id = $1`, id)
	return err
}

func (s *SQLPhase6StatusStore) MarkRestoreFailed(ctx context.Context, id int64, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE restore_runs SET status = 'failed', last_error = $2, updated_at = now() WHERE id = $1`, id, message)
	return err
}

func (s *SQLPhase6StatusStore) MarkWebmailActive(ctx context.Context, id int64, result types.ConfigureWebmailResult) error {
	_, err := s.db.ExecContext(ctx, `UPDATE webmail_hosts SET status = 'active', config_path = $2, last_error = '', updated_at = now() WHERE id = $1`, id, result.ConfigPath)
	return err
}

func (s *SQLPhase6StatusStore) MarkWebmailFailed(ctx context.Context, id int64, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE webmail_hosts SET status = 'failed', last_error = $2, updated_at = now() WHERE id = $1`, id, message)
	return err
}

func (s *SQLPhase6StatusStore) MarkDNSActive(ctx context.Context, id int64, result types.ConfigureDNSZoneResult) error {
	_, err := s.db.ExecContext(ctx, `UPDATE dns_zones SET status = 'active', zone_path = $2, serial = $3, last_error = '', updated_at = now() WHERE id = $1`, id, result.ZonePath, result.Serial)
	return err
}

func (s *SQLPhase6StatusStore) MarkDNSFailed(ctx context.Context, id int64, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE dns_zones SET status = 'failed', last_error = $2, updated_at = now() WHERE id = $1`, id, message)
	return err
}

func (s *SQLPhase6StatusStore) MarkReconcileActive(ctx context.Context, id int64, result types.ReconcileSystemResult) error {
	_, err := s.db.ExecContext(ctx, `UPDATE reconciliation_runs SET status = 'active', sites_total = $2, sites_ok = $3, last_error = '', updated_at = now() WHERE id = $1`, id, result.SitesTotal, result.SitesOK)
	return err
}

func (s *SQLPhase6StatusStore) MarkReconcileFailed(ctx context.Context, id int64, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE reconciliation_runs SET status = 'failed', last_error = $2, updated_at = now() WHERE id = $1`, id, message)
	return err
}
