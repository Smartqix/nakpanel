package provision

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/lib/pq"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

var ErrBackupBusy = errors.New("a selected backup is in use or is still processing")
var ErrBackupPreviewChanged = errors.New("the selected recovery points changed; review removal again")

type DeleteBackupArgs struct {
	BackupID   int64 `json:"backup_id" river:"unique"`
	ApprovalID int64 `json:"approval_id" river:"unique"`
}

func (DeleteBackupArgs) Kind() string { return "maintenance_delete_backup" }
func (DeleteBackupArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "maintenance", MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled}}}
}

func normalizeBackupSelection(ids []int64) ([]int64, error) {
	if len(ids) == 0 || len(ids) > 50 {
		return nil, errors.New("select between 1 and 50 recovery points")
	}
	result := slices.Clone(ids)
	slices.Sort(result)
	for _, id := range result {
		if id <= 0 {
			return nil, errors.New("invalid recovery point selection")
		}
	}
	return slices.Compact(result), nil
}

func (m *Manager) backupRemovalAccess(ctx context.Context, actor auth.SessionUser, subscriptionID int64, ids []int64) error {
	if actor.ID <= 0 || subscriptionID <= 0 || (actor.Role != auth.RoleAdmin && actor.Role != auth.RoleClient && actor.Role != auth.RoleReseller) {
		return ErrForbidden
	}
	if err := m.canManageSubscription(ctx, actor, subscriptionID); err != nil {
		return err
	}
	for _, id := range ids {
		if err := m.canManageBackup(ctx, actor, id); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) PreviewBackupRemovalFor(ctx context.Context, actor auth.SessionUser, subscriptionID int64, ids []int64) (types.BackupRemovalPreview, error) {
	var empty types.BackupRemovalPreview
	ids, err := normalizeBackupSelection(ids)
	if err != nil {
		return empty, err
	}
	if err = m.backupRemovalAccess(ctx, actor, subscriptionID, ids); err != nil {
		return empty, err
	}
	r, ok := m.phase6Repo.(*SQLPhase6Repository)
	if !ok || r.db == nil {
		return empty, errors.New("backup management is unavailable")
	}
	return loadBackupRemoval(ctx, r.db, subscriptionID, ids, false)
}

func (m *Manager) RemoveBackupsFor(ctx context.Context, actor auth.SessionUser, subscriptionID int64, ids []int64, digest string, confirmed bool) error {
	if !confirmed {
		return errors.New("confirm permanent removal of the selected backups")
	}
	ids, err := normalizeBackupSelection(ids)
	if err != nil {
		return err
	}
	if err = m.backupRemovalAccess(ctx, actor, subscriptionID, ids); err != nil {
		return err
	}
	r, ok := m.phase6Repo.(*SQLPhase6Repository)
	if !ok || r.db == nil || r.river == nil {
		return errors.New("backup management is unavailable")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = controlquota.LockSubscriptionMutationTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	if err = m.backupRemovalAccess(ctx, actor, subscriptionID, ids); err != nil {
		return err
	}
	p, err := loadBackupRemoval(ctx, tx, subscriptionID, ids, true)
	if err != nil {
		return err
	}
	if digest == "" || p.Digest != digest {
		return ErrBackupPreviewChanged
	}
	for _, item := range p.Items {
		metadata, _ := json.Marshal(map[string]any{"domain": item.Domain, "size_bytes": item.SizeBytes, "source": "backup-manager", "confirmed": true})
		var approval int64
		if err = tx.QueryRowContext(ctx, `INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'backup.deletion_requested','backup',$4,$5::jsonb) RETURNING id`, actor.ID, p.CustomerID, subscriptionID, item.ID, metadata).Scan(&approval); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE backups SET status='deleting',last_error='',updated_at=now() WHERE id=$1`, item.ID); err != nil {
			return err
		}
		if _, err = r.river.InsertTx(ctx, tx, DeleteBackupArgs{BackupID: item.ID, ApprovalID: approval}, nil); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type backupRemovalQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadBackupRemoval(ctx context.Context, q backupRemovalQuerier, subscriptionID int64, ids []int64, lock bool) (types.BackupRemovalPreview, error) {
	p := types.BackupRemovalPreview{SubscriptionID: subscriptionID}
	query := `SELECT b.id,b.customer_id,b.target_name,b.size_bytes,b.created_at,b.status,b.site_id IS NULL,b.archive_path,b.checksum_sha256,
 EXISTS(SELECT 1 FROM restore_runs restore WHERE restore.backup_id=b.id AND restore.status='pending')
 OR EXISTS(SELECT 1 FROM wordpress_operations operation WHERE operation.backup_id=b.id)
 OR EXISTS(SELECT 1 FROM river_job job WHERE job.kind IN('restore_backup','create_backup') AND job.args->>'backup_id'=b.id::text AND job.state IN('available','pending','retryable','running','scheduled'))
 OR EXISTS(SELECT 1 FROM site_removal_operations operation WHERE operation.state<>'completed' AND operation.snapshot->'backups' @> jsonb_build_array(jsonb_build_object('id',b.id)))
 OR COALESCE(site.removal_state,'none')<>'none'
 FROM backups b LEFT JOIN sites site ON site.id=b.site_id WHERE b.subscription_id=$1 AND b.id=ANY($2) ORDER BY b.id`
	if lock {
		query += " FOR UPDATE OF b"
	}
	rows, err := q.QueryContext(ctx, query, subscriptionID, pq.Array(ids))
	if err != nil {
		return p, err
	}
	defer rows.Close()
	digest := sha256.New()
	for rows.Next() {
		var item types.BackupRemovalItem
		var path, checksum string
		var customer int64
		var busy bool
		if err = rows.Scan(&item.ID, &customer, &item.Domain, &item.SizeBytes, &item.CreatedAt, &item.Status, &item.Retained, &path, &checksum, &busy); err != nil {
			return p, err
		}
		if busy || (item.Status != "active" && item.Status != "failed" && item.Status != "delete_failed") {
			return p, ErrBackupBusy
		}
		if p.CustomerID != 0 && p.CustomerID != customer {
			return p, ErrForbidden
		}
		p.CustomerID = customer
		encoded, _ := json.Marshal([]any{subscriptionID, customer, item, path, checksum})
		digest.Write(encoded)
		p.Items = append(p.Items, item)
		p.SizeBytes += item.SizeBytes
	}
	if err = rows.Err(); err != nil {
		return p, err
	}
	if len(p.Items) != len(ids) {
		return p, ErrForbidden
	}
	p.Digest = hex.EncodeToString(digest.Sum(nil))
	return p, nil
}

// PendingBackupWork keeps automatic refresh scoped to selected subscriptions;
// it never exposes archive paths or another customer's inventory.
func (m *Manager) BackupStatusFor(ctx context.Context, actor auth.SessionUser, subscriptionID int64) (map[int64]string, error) {
	if err := m.backupRemovalAccess(ctx, actor, subscriptionID, nil); err != nil {
		return nil, err
	}
	r, ok := m.phase6Repo.(*SQLPhase6Repository)
	if !ok || r.db == nil {
		return nil, fmt.Errorf("backup management is unavailable")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,status FROM backups WHERE subscription_id=$1 ORDER BY id`, subscriptionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[int64]string)
	for rows.Next() {
		var id int64
		var status string
		if err = rows.Scan(&id, &status); err != nil {
			return nil, err
		}
		result[id] = status
	}
	return result, rows.Err()
}
