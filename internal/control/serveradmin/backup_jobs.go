package serveradmin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/nakroteck/nakpanel/internal/version"
	"github.com/riverqueue/river"
	"github.com/robfig/cron/v3"
)

type ServerBackupArgs struct {
	ServerBackupID int64 `json:"server_backup_id" river:"unique"`
}

func (ServerBackupArgs) Kind() string { return "server_backup" }

func (ServerBackupArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       BackupQueue,
		MaxAttempts: 2,
		UniqueOpts: river.UniqueOpts{
			ByArgs:  true,
			ByState: activeJobStates,
		},
	}
}

type PruneServerBackupsArgs struct {
	DestinationID int64 `json:"destination_id" river:"unique"`
}

func (PruneServerBackupsArgs) Kind() string { return "server_backup_prune" }

func (PruneServerBackupsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       BackupQueue,
		MaxAttempts: 2,
		UniqueOpts: river.UniqueOpts{
			ByArgs:  true,
			ByState: activeJobStates,
		},
	}
}

type ServerBackupSweepArgs struct{}

func (ServerBackupSweepArgs) Kind() string { return "server_backup_sweep" }

func (ServerBackupSweepArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       BackupQueue,
		MaxAttempts: 1,
		UniqueOpts: river.UniqueOpts{
			ByArgs:  true,
			ByState: activeJobStates,
		},
	}
}

// ServerBackupSweepWorker turns stored cron schedules into backup runs. It
// runs every minute, so schedule edits take effect without a panel restart.
type ServerBackupSweepWorker struct {
	river.WorkerDefaults[ServerBackupSweepArgs]
	manager *Manager
}

func NewServerBackupSweepWorker(manager *Manager) *ServerBackupSweepWorker {
	return &ServerBackupSweepWorker{manager: manager}
}

func (w *ServerBackupSweepWorker) Work(ctx context.Context, job *river.Job[ServerBackupSweepArgs]) error {
	m := w.manager
	if m == nil || m.store == nil {
		return errors.New("server backup sweep is not configured")
	}
	destinations, err := m.ListBackupDestinations(ctx)
	if err != nil {
		return err
	}
	if len(destinations) == 0 {
		return nil
	}
	if _, ok := m.BackupKeyFingerprint(ctx); !ok {
		// Nothing can run without the archive key; stay quiet rather than
		// filling the log every minute.
		return nil
	}
	// Reset rows abandoned in a non-terminal state (panel killed mid-backup,
	// worker context cancelled before it could record the failure). Without
	// this the in-flight guard in QueueServerBackup blocks every future run
	// for that destination permanently, and the only symptom is that backups
	// silently stop happening.
	if _, err := m.store.db.ExecContext(ctx, `UPDATE server_backups
		SET status='failed',
		    last_error=CASE WHEN last_error='' THEN 'abandoned while '||status||'; reset by sweep' ELSE last_error END,
		    completed_at=now(), updated_at=now()
		WHERE status IN ('pending','running','uploading','verifying','deleting')
		  AND updated_at < now() - interval '13 hours'`); err != nil {
		log.Printf("server backup sweep: reset abandoned rows: %v", err)
	}

	now := m.now()
	for _, dest := range destinations {
		if !dest.Enabled {
			continue
		}
		schedule, err := cron.ParseStandard(dest.ScheduleCron)
		if err != nil {
			continue
		}
		anchor := dest.CreatedAt
		if dest.LastStartedAt != nil {
			anchor = *dest.LastStartedAt
		}
		if schedule.Next(anchor).After(now) {
			continue
		}
		if _, err := m.QueueServerBackup(ctx, dest.Name, 0, "scheduler", true); err != nil {
			if strings.Contains(err.Error(), "already in flight") {
				continue
			}
			log.Printf("server backup sweep: queue %s: %v", dest.Name, err)
			_, _ = m.store.db.ExecContext(ctx,
				`UPDATE server_backup_destinations SET last_error=$2, updated_at=now() WHERE id=$1`,
				dest.ID, err.Error())
		}
	}
	return nil
}

type ServerBackupWorker struct {
	river.WorkerDefaults[ServerBackupArgs]
	manager *Manager
}

func NewServerBackupWorker(manager *Manager) *ServerBackupWorker {
	return &ServerBackupWorker{manager: manager}
}

// Timeout overrides River's one-minute default: a full-server archive plus a
// remote upload and verification pass can legitimately run for hours.
func (w *ServerBackupWorker) Timeout(job *river.Job[ServerBackupArgs]) time.Duration {
	return 12 * time.Hour
}

func (w *ServerBackupWorker) Work(ctx context.Context, job *river.Job[ServerBackupArgs]) error {
	m := w.manager
	if m == nil || m.store == nil {
		return errors.New("server backup worker is not configured")
	}
	agent, err := m.backupAgent()
	if err != nil {
		return err
	}
	backupID := job.Args.ServerBackupID

	var status string
	var destinationID sql.NullInt64
	var existingArchiveName string
	err = m.store.db.QueryRowContext(ctx,
		`SELECT status, destination_id, archive_name FROM server_backups WHERE id=$1`,
		backupID).Scan(&status, &destinationID, &existingArchiveName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if status != "pending" && status != "running" {
		return nil
	}
	if !destinationID.Valid {
		return w.fail(ctx, backupID, BackupDestination{}, errors.New("backup destination was deleted"), true)
	}
	var dest BackupDestination
	row := m.store.db.QueryRowContext(ctx, `
SELECT id,name,kind,enabled,settings,credential_secret_name,schedule_cron,
       retention_count,retention_days,include_mail_data,notify_email,
       last_started_at,last_succeeded_at,last_error,created_at,updated_at
FROM server_backup_destinations WHERE id=$1`, destinationID.Int64)
	dest, err = scanBackupDestination(row)
	if err != nil {
		return w.fail(ctx, backupID, BackupDestination{}, err, true)
	}

	finalAttempt := job.Attempt >= job.MaxAttempts

	spec, err := m.destinationSpec(ctx, dest)
	if err != nil {
		return w.fail(ctx, backupID, dest, err, finalAttempt)
	}
	key, err := m.archiveKey(ctx)
	if err != nil {
		return w.fail(ctx, backupID, dest, err, finalAttempt)
	}

	tenantDBs, err := listStrings(ctx, m.store.db,
		`SELECT db_name FROM databases WHERE engine='mariadb' AND status='active' ORDER BY db_name`)
	if err != nil {
		return w.fail(ctx, backupID, dest, err, finalAttempt)
	}
	systemUsers, err := listStrings(ctx, m.store.db,
		`SELECT username FROM subscription_system_accounts ORDER BY username`)
	if err != nil {
		return w.fail(ctx, backupID, dest, err, finalAttempt)
	}
	var gooseVersion int64
	if err := m.store.db.QueryRowContext(ctx,
		`SELECT COALESCE(max(version_id),0) FROM goose_db_version`).Scan(&gooseVersion); err != nil {
		return w.fail(ctx, backupID, dest, err, finalAttempt)
	}

	// Includes the attempt number: the agent dispatcher caches responses by
	// RPC ID *including errors*, so a stable ID would make River's retry
	// replay the cached failure instead of actually retrying. Within one
	// attempt the ID is still stable, which is what makes a lost response
	// replay-safe rather than re-archiving.
	operationID := fmt.Sprintf("server-backup-%d-%d", backupID, job.Attempt)
	if _, err := m.store.db.ExecContext(ctx, `UPDATE server_backups
		SET status='running', operation_id=$2, started_at=COALESCE(started_at, now()), updated_at=now()
		WHERE id=$1`, backupID, operationID); err != nil {
		return err
	}

	// A deterministic name means a retry (e.g. after a verify failure)
	// overwrites the same object instead of leaving the first upload orphaned
	// at the destination, where nothing would ever prune it.
	archiveName := existingArchiveName
	if archiveName == "" {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "server"
		}
		archiveName = fmt.Sprintf("nakpanel-%s-%d-%s.nkbk", hostname, backupID,
			m.now().UTC().Format("20060102T150405Z"))
	}
	created, err := agent.CreateServerBackup(ctx, types.CreateServerBackupReq{
		Destination:     spec,
		ArchiveKey:      key,
		ArchiveName:     archiveName,
		IncludeMailData: dest.IncludeMailData,
		TenantDatabases: tenantDBs,
		SystemUsers:     systemUsers,
		PanelVersion:    version.String(),
		GooseVersion:    gooseVersion,
		OperationID:     operationID,
	})
	if err != nil {
		return w.fail(ctx, backupID, dest, fmt.Errorf("create archive: %w", err), finalAttempt)
	}
	manifestSummary, _ := json.Marshal(created)
	if _, err := m.store.db.ExecContext(ctx, `UPDATE server_backups
		SET status='verifying', archive_name=$2, remote_path=$2, size_bytes=$3,
		    checksum_sha256=$4, key_fingerprint=$5, manifest=$6::jsonb, updated_at=now()
		WHERE id=$1`, backupID, created.ArchiveName, created.SizeBytes,
		created.SHA256, created.KeyFingerprint, string(manifestSummary)); err != nil {
		return err
	}

	verified, err := agent.VerifyServerBackup(ctx, types.VerifyServerBackupReq{
		Destination:    spec,
		ArchiveKey:     key,
		ArchiveName:    created.ArchiveName,
		ExpectedSHA256: created.SHA256,
	})
	if err != nil {
		return w.fail(ctx, backupID, dest, fmt.Errorf("verify archive: %w", err), finalAttempt)
	}
	verifyDetail, _ := json.Marshal(verified)
	if _, err := m.store.db.ExecContext(ctx, `UPDATE server_backups
		SET status='active', verified_at=now(), verify_detail=$2::jsonb,
		    completed_at=now(), last_error='', updated_at=now()
		WHERE id=$1`, backupID, string(verifyDetail)); err != nil {
		return err
	}
	if _, err := m.store.db.ExecContext(ctx, `UPDATE server_backup_destinations
		SET last_succeeded_at=now(), last_error='', updated_at=now() WHERE id=$1`, dest.ID); err != nil {
		return err
	}
	if err := resolveBackupFailureNotification(ctx, m.store.db, dest.Name); err != nil {
		return err
	}
	if err := func() error {
		tx, err := m.store.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := m.river.InsertTx(ctx, tx, PruneServerBackupsArgs{DestinationID: dest.ID}, nil); err != nil {
			return err
		}
		return tx.Commit()
	}(); err != nil {
		// The next successful backup enqueues pruning again; losing one
		// enqueue is not fatal.
		log.Printf("server backup %d: enqueue prune: %v", backupID, err)
	}
	return nil
}

func (w *ServerBackupWorker) fail(ctx context.Context, backupID int64, dest BackupDestination, workErr error, terminal bool) error {
	db := w.manager.store.db
	status := "pending"
	if terminal {
		status = "failed"
	}
	if _, err := db.ExecContext(ctx, `UPDATE server_backups
		SET status=$2, last_error=$3, completed_at=CASE WHEN $2='failed' THEN now() ELSE completed_at END, updated_at=now()
		WHERE id=$1`, backupID, status, workErr.Error()); err != nil {
		return errors.Join(workErr, err)
	}
	if dest.ID > 0 {
		if _, err := db.ExecContext(ctx, `UPDATE server_backup_destinations
			SET last_error=$2, updated_at=now() WHERE id=$1`, dest.ID, workErr.Error()); err != nil {
			return errors.Join(workErr, err)
		}
	}
	if terminal {
		if err := recordBackupFailureNotification(ctx, db, dest, workErr.Error()); err != nil {
			return errors.Join(workErr, err)
		}
	}
	return workErr
}

func listStrings(ctx context.Context, db *sql.DB, query string) ([]string, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

// recordBackupFailureNotification creates (or refreshes) the open failure
// notification for a destination and queues SMTP deliveries to the configured
// address or, when unset, every active administrator.
func recordBackupFailureNotification(ctx context.Context, db *sql.DB, dest BackupDestination, message string) error {
	destName := dest.Name
	if destName == "" {
		destName = "unknown"
	}
	dedupeKey := "server-backup:" + destName
	title := "Server backup failed"
	body := fmt.Sprintf("The server backup to destination %q failed: %s", destName, message)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var notificationID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO notifications(kind,severity,title,body,dedupe_key)
		VALUES('server_backup_failed','critical',$1,$2,$3)
		ON CONFLICT(dedupe_key) WHERE resolved_at IS NULL
		DO UPDATE SET body=EXCLUDED.body, updated_at=now()
		RETURNING id`, title, body, dedupeKey).Scan(&notificationID); err != nil {
		return fmt.Errorf("record backup failure notification: %w", err)
	}
	recipients := []string{}
	if email := strings.TrimSpace(dest.NotifyEmail); email != "" {
		recipients = append(recipients, email)
	} else {
		rows, err := tx.QueryContext(ctx,
			`SELECT email FROM users WHERE role='admin' AND NOT login_disabled ORDER BY email`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var email string
			if err := rows.Scan(&email); err != nil {
				rows.Close()
				return err
			}
			recipients = append(recipients, email)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	for _, recipient := range recipients {
		if _, err := tx.ExecContext(ctx, `INSERT INTO notification_deliveries(notification_id,channel,recipient)
			VALUES($1,'smtp',$2) ON CONFLICT(notification_id,channel,recipient) DO NOTHING`,
			notificationID, recipient); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func resolveBackupFailureNotification(ctx context.Context, db *sql.DB, destName string) error {
	_, err := db.ExecContext(ctx, `UPDATE notifications SET resolved_at=now(), updated_at=now()
		WHERE dedupe_key=$1 AND resolved_at IS NULL`, "server-backup:"+destName)
	return err
}

type PruneServerBackupsWorker struct {
	river.WorkerDefaults[PruneServerBackupsArgs]
	manager *Manager
}

func NewPruneServerBackupsWorker(manager *Manager) *PruneServerBackupsWorker {
	return &PruneServerBackupsWorker{manager: manager}
}

func (w *PruneServerBackupsWorker) Timeout(job *river.Job[PruneServerBackupsArgs]) time.Duration {
	return time.Hour
}

func (w *PruneServerBackupsWorker) Work(ctx context.Context, job *river.Job[PruneServerBackupsArgs]) error {
	m := w.manager
	if m == nil || m.store == nil {
		return errors.New("server backup prune worker is not configured")
	}
	agent, err := m.backupAgent()
	if err != nil {
		return err
	}
	row := m.store.db.QueryRowContext(ctx, `
SELECT id,name,kind,enabled,settings,credential_secret_name,schedule_cron,
       retention_count,retention_days,include_mail_data,notify_email,
       last_started_at,last_succeeded_at,last_error,created_at,updated_at
FROM server_backup_destinations WHERE id=$1`, job.Args.DestinationID)
	dest, err := scanBackupDestination(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := m.store.db.QueryContext(ctx, `
WITH ranked AS (
    SELECT id, archive_name, created_at,
           row_number() OVER (ORDER BY created_at DESC) AS position
    FROM server_backups WHERE destination_id=$1 AND status='active'
)
SELECT id, archive_name FROM ranked
WHERE position > $2 OR ($3 > 0 AND created_at < now() - make_interval(days => $3))`,
		dest.ID, dest.RetentionCount, dest.RetentionDays)
	if err != nil {
		return err
	}
	type victim struct {
		id   int64
		name string
	}
	var victims []victim
	for rows.Next() {
		var v victim
		if err := rows.Scan(&v.id, &v.name); err != nil {
			rows.Close()
			return err
		}
		victims = append(victims, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(victims) == 0 {
		return nil
	}
	spec, err := m.destinationSpec(ctx, dest)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(victims))
	ids := make([]int64, 0, len(victims))
	for _, v := range victims {
		if v.name == "" {
			continue
		}
		names = append(names, v.name)
		ids = append(ids, v.id)
	}
	if _, err := m.store.db.ExecContext(ctx,
		`UPDATE server_backups SET status='deleting', updated_at=now() WHERE id = ANY($1::bigint[])`, int64Array(ids)); err != nil {
		return err
	}
	if _, err := agent.PruneServerBackups(ctx, types.PruneServerBackupsReq{Destination: spec, Delete: names}); err != nil {
		_, _ = m.store.db.ExecContext(ctx,
			`UPDATE server_backups SET status='delete_failed', last_error=$2, updated_at=now() WHERE id = ANY($1::bigint[])`,
			int64Array(ids), err.Error())
		return err
	}
	if _, err := m.store.db.ExecContext(ctx,
		`DELETE FROM server_backups WHERE id = ANY($1::bigint[])`, int64Array(ids)); err != nil {
		return err
	}
	return nil
}

func int64Array(values []int64) any {
	// lib/pq-style array literal keeps this driver-agnostic for pgx stdlib.
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return "{" + strings.Join(parts, ",") + "}"
}
