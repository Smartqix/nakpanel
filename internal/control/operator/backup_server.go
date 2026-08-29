package operator

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

// Server-level backup operations for panelctl. These wrap the serveradmin
// manager (available only when the secret keyring was loaded) and attribute
// audit events to the operator's --actor label.

var errBackupUnavailable = errors.New("server backups require the secret keyring; set NAKPANEL_SECRET_KEY_FILE or install /etc/nakpanel/secret-keys.json")

func (s *Service) backupManager() (*serveradmin.Manager, error) {
	if s == nil || s.serverAdmin == nil {
		return nil, errBackupUnavailable
	}
	return s.serverAdmin, nil
}

func (s *Service) BackupKeyInit(ctx context.Context, force bool) (encoded, fingerprint string, err error) {
	manager, err := s.backupManager()
	if err != nil {
		return "", "", err
	}
	return manager.InitBackupKey(ctx, 0, s.actorLabel, force)
}

func (s *Service) BackupKeyStatus(ctx context.Context) (string, bool) {
	manager, err := s.backupManager()
	if err != nil {
		return "", false
	}
	return manager.BackupKeyFingerprint(ctx)
}

func (s *Service) SaveBackupDestination(ctx context.Context, params serveradmin.SaveBackupDestinationParams) (serveradmin.BackupDestination, error) {
	manager, err := s.backupManager()
	if err != nil {
		return serveradmin.BackupDestination{}, err
	}
	params.ActorLabel = s.actorLabel
	return manager.SaveBackupDestination(ctx, params)
}

func (s *Service) DeleteBackupDestination(ctx context.Context, name string) error {
	manager, err := s.backupManager()
	if err != nil {
		return err
	}
	return manager.DeleteBackupDestination(ctx, name, 0, s.actorLabel)
}

func (s *Service) ListBackupDestinations(ctx context.Context) ([]serveradmin.BackupDestination, error) {
	manager, err := s.backupManager()
	if err != nil {
		return nil, err
	}
	return manager.ListBackupDestinations(ctx)
}

func (s *Service) TestBackupDestination(ctx context.Context, name string) (types.TestBackupDestinationResult, error) {
	manager, err := s.backupManager()
	if err != nil {
		return types.TestBackupDestinationResult{}, err
	}
	return manager.TestBackupDestinationByName(ctx, name)
}

func (s *Service) RunServerBackup(ctx context.Context, destination string) (int64, error) {
	manager, err := s.backupManager()
	if err != nil {
		return 0, err
	}
	return manager.QueueServerBackup(ctx, destination, 0, s.actorLabel, false)
}

func (s *Service) ListServerBackups(ctx context.Context, limit int) ([]serveradmin.ServerBackup, error) {
	manager, err := s.backupManager()
	if err != nil {
		return nil, err
	}
	return manager.ListServerBackups(ctx, limit)
}

// WaitServerBackup polls one backup row until it reaches a terminal state.
func (s *Service) WaitServerBackup(ctx context.Context, backupID int64, timeout time.Duration) (serveradmin.ServerBackup, error) {
	deadline := time.Now().Add(timeout)
	for {
		row := s.db.QueryRowContext(ctx, `SELECT status, archive_name, size_bytes, checksum_sha256, last_error,
			COALESCE(verify_detail::text,''), verified_at IS NOT NULL
			FROM server_backups WHERE id=$1`, backupID)
		var item serveradmin.ServerBackup
		var verifyDetail string
		var verified bool
		err := row.Scan(&item.Status, &item.ArchiveName, &item.SizeBytes, &item.ChecksumSHA256, &item.LastError, &verifyDetail, &verified)
		if errors.Is(err, sql.ErrNoRows) {
			return item, fmt.Errorf("server backup %d does not exist", backupID)
		}
		if err != nil {
			return item, err
		}
		item.ID = backupID
		if verifyDetail != "" {
			item.VerifyDetail = json.RawMessage(verifyDetail)
		}
		switch item.Status {
		case "active", "failed", "delete_failed":
			return item, nil
		}
		if time.Now().After(deadline) {
			return item, fmt.Errorf("timed out waiting for server backup %d (status %s)", backupID, item.Status)
		}
		select {
		case <-ctx.Done():
			return item, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// RestoreMariaDBCredentials recreates tenant MariaDB users and grants from
// restored intent plus the decrypted provisioning credentials — the step that
// makes databases usable again after a disaster-recovery restore.
func (s *Service) RestoreMariaDBCredentials(ctx context.Context) (restored []string, warnings []string, err error) {
	if s == nil || s.secrets == nil {
		return nil, nil, errBackupUnavailable
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, db_name, db_user FROM databases WHERE engine='mariadb' AND status='active' ORDER BY db_name`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	type entry struct {
		id     int64
		name   string
		dbUser string
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.id, &e.name, &e.dbUser); err != nil {
			return nil, nil, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		password, _, err := s.secrets.GetSecret(ctx, "database", fmt.Sprintf("provision-%d", e.id))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("database %s: credential unavailable (%v); reconcile will flag it", e.name, err))
			continue
		}
		response, err := s.agent.CreateDatabase(ctx, types.CreateDatabaseReq{
			Engine:   types.EngineMariaDB,
			DBName:   e.name,
			DBUser:   e.dbUser,
			Password: string(password),
		})
		if err != nil {
			return restored, warnings, fmt.Errorf("recreate database user %s: %w", e.dbUser, err)
		}
		if !response.OK {
			return restored, warnings, fmt.Errorf("recreate database user %s: %s", e.dbUser, response.Error)
		}
		restored = append(restored, e.name)
	}
	return restored, warnings, nil
}

// RecordRestoreAudit writes the disaster-recovery completion audit event.
func (s *Service) RecordRestoreAudit(ctx context.Context, metadata map[string]any) error {
	return s.audit(ctx, "server.restore_completed", "server", 0, metadata)
}
