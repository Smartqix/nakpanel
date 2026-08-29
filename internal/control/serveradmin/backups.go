package serveradmin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/backup"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/robfig/cron/v3"
)

// Server-level backup orchestration. The heavy lifting (dumps, archive
// assembly, upload, verification) happens in the root agent; the panel owns
// destination configuration, credential custody, scheduling, row lifecycle,
// retention, and notifications.

const (
	// BackupQueue serializes server backup work without blocking the system
	// queue's power/update operations.
	BackupQueue = "backup"

	backupSecretScope            = "backup"
	backupArchiveKeyName         = "archive-key"
	backupDestinationSecretScope = "backup_destination"
)

var backupDestinationNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

type serverBackupAgent interface {
	CreateServerBackup(context.Context, types.CreateServerBackupReq) (types.CreateServerBackupResult, error)
	VerifyServerBackup(context.Context, types.VerifyServerBackupReq) (types.VerifyServerBackupResult, error)
	PruneServerBackups(context.Context, types.PruneServerBackupsReq) (types.PruneServerBackupsResult, error)
	TestBackupDestination(context.Context, types.TestBackupDestinationReq) (types.TestBackupDestinationResult, error)
}

type BackupDestination struct {
	ID                   int64           `json:"id"`
	Name                 string          `json:"name"`
	Kind                 string          `json:"kind"`
	Enabled              bool            `json:"enabled"`
	Settings             json.RawMessage `json:"settings"`
	CredentialSecretName string          `json:"credential_secret_name,omitempty"`
	ScheduleCron         string          `json:"schedule_cron"`
	RetentionCount       int             `json:"retention_count"`
	RetentionDays        int             `json:"retention_days"`
	IncludeMailData      bool            `json:"include_mail_data"`
	NotifyEmail          string          `json:"notify_email,omitempty"`
	LastStartedAt        *time.Time      `json:"last_started_at,omitempty"`
	LastSucceededAt      *time.Time      `json:"last_succeeded_at,omitempty"`
	LastError            string          `json:"last_error,omitempty"`
	CreatedAt            time.Time       `json:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"`
}

type SaveBackupDestinationParams struct {
	Name            string
	Kind            string
	Enabled         bool
	Settings        json.RawMessage
	Credential      []byte // nil keeps the stored credential
	ScheduleCron    string
	RetentionCount  int
	RetentionDays   int
	IncludeMailData bool
	NotifyEmail     string
	ActorUserID     int64
	ActorLabel      string // used when there is no panel user (panelctl)
}

// backupAudit writes an audit event attributed to a panel user or, for CLI
// and scheduler callers, a label (the audit table requires one of the two).
func backupAudit(ctx context.Context, tx *sql.Tx, actorUserID int64, actorLabel, action, target string, metadata json.RawMessage) error {
	if actorUserID <= 0 && strings.TrimSpace(actorLabel) == "" {
		actorLabel = "system"
	}
	data, err := normalizedJSONObject(metadata)
	if err != nil {
		return fmt.Errorf("validate backup audit metadata: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO audit_events(actor_user_id,actor_label,action,target_type,target_id,metadata)
VALUES (NULLIF($1,0),NULLIF($2,''),$3,$4,NULL,$5::jsonb)`,
		actorUserID, strings.TrimSpace(actorLabel), action, target, data)
	if err != nil {
		return fmt.Errorf("write backup audit event: %w", err)
	}
	return nil
}

type ServerBackup struct {
	ID              int64           `json:"id"`
	DestinationID   int64           `json:"destination_id,omitempty"`
	DestinationName string          `json:"destination_name,omitempty"`
	OperationID     string          `json:"operation_id,omitempty"`
	Status          string          `json:"status"`
	ArchiveName     string          `json:"archive_name,omitempty"`
	SizeBytes       int64           `json:"size_bytes"`
	ChecksumSHA256  string          `json:"checksum_sha256,omitempty"`
	KeyFingerprint  string          `json:"key_fingerprint,omitempty"`
	Manifest        json.RawMessage `json:"manifest,omitempty"`
	VerifiedAt      *time.Time      `json:"verified_at,omitempty"`
	VerifyDetail    json.RawMessage `json:"verify_detail,omitempty"`
	Scheduled       bool            `json:"scheduled"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
	LastError       string          `json:"last_error,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
}

func (m *Manager) backupAgent() (serverBackupAgent, error) {
	if m == nil {
		return nil, errors.New("server backup manager is not configured")
	}
	agent, ok := any(m.agent).(serverBackupAgent)
	if !ok {
		return nil, errors.New("server backup agent is not configured")
	}
	return agent, nil
}

func validateDestinationConfig(kind string, settings json.RawMessage, credential []byte) error {
	_, err := backup.NewDestination(kind, settings, credential)
	return err
}

func (m *Manager) ListBackupDestinations(ctx context.Context) ([]BackupDestination, error) {
	if m == nil || m.store == nil {
		return nil, errors.New("server backup manager is not configured")
	}
	rows, err := m.store.db.QueryContext(ctx, `
SELECT id,name,kind,enabled,settings,credential_secret_name,schedule_cron,
       retention_count,retention_days,include_mail_data,notify_email,
       last_started_at,last_succeeded_at,last_error,created_at,updated_at
FROM server_backup_destinations ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list backup destinations: %w", err)
	}
	defer rows.Close()
	var result []BackupDestination
	for rows.Next() {
		item, err := scanBackupDestination(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanBackupDestination(row rowScanner) (BackupDestination, error) {
	var item BackupDestination
	var started, succeeded sql.NullTime
	var settings []byte
	err := row.Scan(&item.ID, &item.Name, &item.Kind, &item.Enabled, &settings,
		&item.CredentialSecretName, &item.ScheduleCron, &item.RetentionCount,
		&item.RetentionDays, &item.IncludeMailData, &item.NotifyEmail,
		&started, &succeeded, &item.LastError, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return item, fmt.Errorf("scan backup destination: %w", err)
	}
	item.Settings = json.RawMessage(settings)
	if started.Valid {
		item.LastStartedAt = &started.Time
	}
	if succeeded.Valid {
		item.LastSucceededAt = &succeeded.Time
	}
	return item, nil
}

func (m *Manager) GetBackupDestination(ctx context.Context, name string) (BackupDestination, error) {
	if m == nil || m.store == nil {
		return BackupDestination{}, errors.New("server backup manager is not configured")
	}
	row := m.store.db.QueryRowContext(ctx, `
SELECT id,name,kind,enabled,settings,credential_secret_name,schedule_cron,
       retention_count,retention_days,include_mail_data,notify_email,
       last_started_at,last_succeeded_at,last_error,created_at,updated_at
FROM server_backup_destinations WHERE name=$1`, strings.TrimSpace(name))
	return scanBackupDestination(row)
}

func (m *Manager) SaveBackupDestination(ctx context.Context, params SaveBackupDestinationParams) (BackupDestination, error) {
	if m == nil || m.store == nil {
		return BackupDestination{}, errors.New("server backup manager is not configured")
	}
	name := strings.TrimSpace(params.Name)
	if !backupDestinationNameRE.MatchString(name) {
		return BackupDestination{}, errors.New("destination name must be lowercase letters, digits, and dashes, starting with a letter")
	}
	kindValid := false
	for _, kind := range backup.DestinationKinds {
		if params.Kind == kind {
			kindValid = true
		}
	}
	if !kindValid {
		return BackupDestination{}, fmt.Errorf("destination kind must be one of %s", strings.Join(backup.DestinationKinds, ", "))
	}
	schedule := strings.TrimSpace(params.ScheduleCron)
	if schedule == "" {
		schedule = "0 2 * * *"
	}
	if _, err := cron.ParseStandard(schedule); err != nil {
		return BackupDestination{}, fmt.Errorf("invalid schedule: %w", err)
	}
	if params.RetentionCount < 1 {
		return BackupDestination{}, errors.New("retention count must be at least 1")
	}
	if params.RetentionDays < 0 {
		return BackupDestination{}, errors.New("retention days must not be negative")
	}
	settings := params.Settings
	if len(settings) == 0 {
		settings = json.RawMessage(`{}`)
	}

	// Validate the destination configuration with the credential that will
	// actually be stored alongside it.
	credential := params.Credential
	if credential == nil && params.Kind != "local" {
		existing, _, err := m.store.GetSecret(ctx, backupDestinationSecretScope, name)
		if err != nil {
			return BackupDestination{}, errors.New("a credential is required for this destination kind")
		}
		credential = existing
	}
	if err := validateDestinationConfig(params.Kind, settings, credential); err != nil {
		return BackupDestination{}, err
	}

	tx, err := m.store.db.BeginTx(ctx, nil)
	if err != nil {
		return BackupDestination{}, err
	}
	defer func() { _ = tx.Rollback() }()

	credentialSecretName := ""
	if params.Kind != "local" {
		credentialSecretName = name
	}
	row := tx.QueryRowContext(ctx, `
INSERT INTO server_backup_destinations
    (name,kind,enabled,settings,credential_secret_name,schedule_cron,
     retention_count,retention_days,include_mail_data,notify_email)
VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10)
ON CONFLICT (name) DO UPDATE SET
    kind=EXCLUDED.kind, enabled=EXCLUDED.enabled, settings=EXCLUDED.settings,
    credential_secret_name=EXCLUDED.credential_secret_name,
    schedule_cron=EXCLUDED.schedule_cron, retention_count=EXCLUDED.retention_count,
    retention_days=EXCLUDED.retention_days, include_mail_data=EXCLUDED.include_mail_data,
    notify_email=EXCLUDED.notify_email, updated_at=now()
RETURNING id,name,kind,enabled,settings,credential_secret_name,schedule_cron,
          retention_count,retention_days,include_mail_data,notify_email,
          last_started_at,last_succeeded_at,last_error,created_at,updated_at`,
		name, params.Kind, params.Enabled, string(settings), credentialSecretName,
		schedule, params.RetentionCount, params.RetentionDays, params.IncludeMailData,
		strings.TrimSpace(params.NotifyEmail))
	item, err := scanBackupDestination(row)
	if err != nil {
		return BackupDestination{}, err
	}
	if params.Credential != nil && params.Kind != "local" {
		if _, err := m.store.PutSecretTx(ctx, tx, PutSecretParams{
			Scope:       backupDestinationSecretScope,
			Name:        name,
			Plaintext:   params.Credential,
			ActorUserID: params.ActorUserID,
		}); err != nil {
			return BackupDestination{}, fmt.Errorf("store destination credential: %w", err)
		}
	}
	if err := backupAudit(ctx, tx, params.ActorUserID, params.ActorLabel,
		"server.backup_destination_saved", "server_backup_destination",
		mustJSONObject(map[string]any{"name": name, "kind": params.Kind, "enabled": params.Enabled})); err != nil {
		return BackupDestination{}, err
	}
	if err := tx.Commit(); err != nil {
		return BackupDestination{}, err
	}
	return item, nil
}

func (m *Manager) DeleteBackupDestination(ctx context.Context, name string, actorUserID int64, actorLabel string) error {
	if m == nil || m.store == nil {
		return errors.New("server backup manager is not configured")
	}
	name = strings.TrimSpace(name)
	tx, err := m.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM server_backup_destinations WHERE name=$1`, name)
	if err != nil {
		return fmt.Errorf("delete backup destination: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return fmt.Errorf("backup destination %q does not exist", name)
	}
	if backupDestinationNameRE.MatchString(name) {
		if err := m.store.DeleteSecretTx(ctx, tx, backupDestinationSecretScope, name); err != nil {
			return err
		}
	}
	if err := backupAudit(ctx, tx, actorUserID, actorLabel,
		"server.backup_destination_deleted", "server_backup_destination",
		mustJSONObject(map[string]any{"name": name})); err != nil {
		return err
	}
	return tx.Commit()
}

// destinationSpec assembles the agent-facing spec with the decrypted
// credential for a stored destination.
func (m *Manager) destinationSpec(ctx context.Context, dest BackupDestination) (types.BackupDestinationSpec, error) {
	spec := types.BackupDestinationSpec{Kind: dest.Kind, Settings: dest.Settings}
	if dest.CredentialSecretName != "" {
		credential, _, err := m.store.GetSecret(ctx, backupDestinationSecretScope, dest.CredentialSecretName)
		if err != nil {
			return spec, fmt.Errorf("load destination credential: %w", err)
		}
		spec.Credential = credential
	}
	return spec, nil
}

func (m *Manager) TestBackupDestinationByName(ctx context.Context, name string) (types.TestBackupDestinationResult, error) {
	agent, err := m.backupAgent()
	if err != nil {
		return types.TestBackupDestinationResult{}, err
	}
	dest, err := m.GetBackupDestination(ctx, name)
	if err != nil {
		return types.TestBackupDestinationResult{}, err
	}
	spec, err := m.destinationSpec(ctx, dest)
	if err != nil {
		return types.TestBackupDestinationResult{}, err
	}
	return agent.TestBackupDestination(ctx, types.TestBackupDestinationReq{Destination: spec})
}

// InitBackupKey generates the archive master key, stores it sealed, and
// returns the operator-custody encoding exactly once. An existing key is
// never silently replaced: rotating it would orphan every prior archive.
func (m *Manager) InitBackupKey(ctx context.Context, actorUserID int64, actorLabel string, force bool) (encoded, fingerprint string, err error) {
	if m == nil || m.store == nil {
		return "", "", errors.New("server backup manager is not configured")
	}
	if _, _, err := m.store.GetSecret(ctx, backupSecretScope, backupArchiveKeyName); err == nil && !force {
		return "", "", errors.New("a backup archive key already exists; pass force to replace it (existing archives stay readable only with the old key)")
	}
	key, err := backup.GenerateKey()
	if err != nil {
		return "", "", err
	}
	encoded, err = backup.EncodeKey(key)
	if err != nil {
		return "", "", err
	}
	fingerprint = backup.Fingerprint(key)
	tx, err := m.store.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := m.store.PutSecretTx(ctx, tx, PutSecretParams{
		Scope:       backupSecretScope,
		Name:        backupArchiveKeyName,
		Plaintext:   key,
		ActorUserID: actorUserID,
		Metadata:    mustJSONObject(map[string]any{"fingerprint": fingerprint}),
	}); err != nil {
		return "", "", fmt.Errorf("store archive key: %w", err)
	}
	if err := backupAudit(ctx, tx, actorUserID, actorLabel, "server.backup_key_initialized",
		"server_backup_key", mustJSONObject(map[string]any{"fingerprint": fingerprint})); err != nil {
		return "", "", err
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	return encoded, fingerprint, nil
}

// BackupKeyFingerprint reports whether an archive key exists.
func (m *Manager) BackupKeyFingerprint(ctx context.Context) (string, bool) {
	if m == nil || m.store == nil {
		return "", false
	}
	key, _, err := m.store.GetSecret(ctx, backupSecretScope, backupArchiveKeyName)
	if err != nil {
		return "", false
	}
	return backup.Fingerprint(key), true
}

func (m *Manager) archiveKey(ctx context.Context) ([]byte, error) {
	key, _, err := m.store.GetSecret(ctx, backupSecretScope, backupArchiveKeyName)
	if err != nil {
		return nil, errors.New("backup archive key is not initialized; run backup-server key init")
	}
	if len(key) != backup.KeySize {
		return nil, errors.New("stored backup archive key is malformed")
	}
	return key, nil
}

// QueueServerBackup creates the backup row and its job atomically.
func (m *Manager) QueueServerBackup(ctx context.Context, destinationName string, actorUserID int64, actorLabel string, scheduled bool) (int64, error) {
	if m == nil || m.store == nil || m.river == nil {
		return 0, errors.New("server backup queue is not configured")
	}
	if _, err := m.backupAgent(); err != nil {
		return 0, err
	}
	if _, err := m.archiveKey(ctx); err != nil {
		return 0, err
	}
	dest, err := m.GetBackupDestination(ctx, destinationName)
	if err != nil {
		return 0, fmt.Errorf("backup destination %q: %w", destinationName, err)
	}
	tx, err := m.store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var inFlight int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM server_backups
		WHERE destination_id=$1 AND status IN ('pending','running','uploading','verifying')`, dest.ID).Scan(&inFlight); err != nil {
		return 0, err
	}
	if inFlight > 0 {
		return 0, fmt.Errorf("a backup for destination %q is already in flight", destinationName)
	}
	var backupID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO server_backups (destination_id,status,scheduled)
		VALUES ($1,'pending',$2) RETURNING id`, dest.ID, scheduled).Scan(&backupID); err != nil {
		return 0, fmt.Errorf("create server backup row: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE server_backup_destinations SET last_started_at=now(), updated_at=now() WHERE id=$1`, dest.ID); err != nil {
		return 0, err
	}
	if err := backupAudit(ctx, tx, actorUserID, actorLabel, "server.backup_requested",
		"server_backup", mustJSONObject(map[string]any{"backup_id": backupID, "destination": dest.Name, "scheduled": scheduled})); err != nil {
		return 0, err
	}
	if _, err := m.river.InsertTx(ctx, tx, ServerBackupArgs{ServerBackupID: backupID}, nil); err != nil {
		return 0, fmt.Errorf("queue server backup: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return backupID, nil
}

func (m *Manager) ListServerBackups(ctx context.Context, limit int) ([]ServerBackup, error) {
	if m == nil || m.store == nil {
		return nil, errors.New("server backup manager is not configured")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := m.store.db.QueryContext(ctx, `
SELECT b.id,COALESCE(b.destination_id,0),COALESCE(d.name,''),b.operation_id,b.status,
       b.archive_name,b.size_bytes,b.checksum_sha256,b.key_fingerprint,b.manifest,
       b.verified_at,b.verify_detail,b.scheduled,b.started_at,b.completed_at,
       b.last_error,b.created_at
FROM server_backups b
LEFT JOIN server_backup_destinations d ON d.id=b.destination_id
ORDER BY b.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list server backups: %w", err)
	}
	defer rows.Close()
	var result []ServerBackup
	for rows.Next() {
		var item ServerBackup
		var verifiedAt, startedAt, completedAt sql.NullTime
		var manifest, verifyDetail []byte
		if err := rows.Scan(&item.ID, &item.DestinationID, &item.DestinationName, &item.OperationID,
			&item.Status, &item.ArchiveName, &item.SizeBytes, &item.ChecksumSHA256, &item.KeyFingerprint,
			&manifest, &verifiedAt, &verifyDetail, &item.Scheduled, &startedAt, &completedAt,
			&item.LastError, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan server backup: %w", err)
		}
		item.Manifest = json.RawMessage(manifest)
		if len(verifyDetail) > 0 {
			item.VerifyDetail = json.RawMessage(verifyDetail)
		}
		if verifiedAt.Valid {
			item.VerifiedAt = &verifiedAt.Time
		}
		if startedAt.Valid {
			item.StartedAt = &startedAt.Time
		}
		if completedAt.Valid {
			item.CompletedAt = &completedAt.Time
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
