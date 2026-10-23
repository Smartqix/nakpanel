package provision

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"github.com/riverqueue/river"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var ErrRecoveryUnverified = errors.New("recovery has not been independently verified")

type OperationsManager struct {
	*operations.Store
	db    *sql.DB
	queue *river.Client[*sql.Tx]
	agent OperationsAgent
}

func NewOperationsManager(db *sql.DB, queue *river.Client[*sql.Tx], agent OperationsAgent) *OperationsManager {
	return &OperationsManager{Store: operations.NewStore(db), db: db, queue: queue, agent: agent}
}

type RecoveryCheck struct {
	Label  string `json:"label"`
	Passed bool   `json:"passed"`
}
type RecoveryPreflight struct {
	IssueID      int64                     `json:"issue_id"`
	Allowed      bool                      `json:"allowed"`
	Action       operations.RecoveryAction `json:"action,omitempty"`
	Target       string                    `json:"target"`
	Reason       string                    `json:"reason,omitempty"`
	Confirmation string                    `json:"confirmation,omitempty"`
	Checks       []RecoveryCheck           `json:"checks"`
}
type RecoveryStarted struct {
	OperationID int64 `json:"operation_id"`
	JobID       int64 `json:"-"`
}

func (m *OperationsManager) prepareRecoveryTx(ctx context.Context, tx *sql.Tx, actor auth.SessionUser, id int64) (operations.Issue, operationIntent, error) {
	var role string
	var disabled bool
	if err := tx.QueryRowContext(ctx, `SELECT role,login_disabled FROM users WHERE id=$1 FOR SHARE`, actor.ID).Scan(&role, &disabled); err != nil || disabled || role != "admin" || actor.Role != auth.RoleAdmin {
		return operations.Issue{}, operationIntent{}, operations.ErrNotFound
	}
	initial, err := m.Store.Issue(ctx, actor, id)
	if err != nil {
		return initial, operationIntent{}, err
	}
	in, err := m.snapshotOperationIntentTx(ctx, tx, initial.Resource)
	if err != nil {
		return initial, in, err
	}
	if initial.OperationID > 0 {
		var opID int64
		if err = tx.QueryRowContext(ctx, `SELECT id FROM operations WHERE id=$1 FOR UPDATE`, initial.OperationID).Scan(&opID); err != nil {
			return initial, in, err
		}
	}
	i, err := m.Store.IssueForUpdateTx(ctx, tx, id)
	if err != nil {
		return i, in, err
	}
	if i.ResolvedAt != nil || i.Resource != initial.Resource {
		return i, in, operations.ErrConflict
	}
	if i.Kind != "backup" || i.Resource.Kind != operations.ResourceSite {
		return i, in, operations.ErrInvalid
	}
	if !in.Policy.Permissions.Backups || !in.Policy.Backups.Enabled {
		return i, in, operations.ErrConflict
	}
	if err = guardBackupIntentTx(ctx, tx, in.SubscriptionID, in.Domain); err != nil {
		return i, in, err
	}
	var busy bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM river_job WHERE kind='create_backup' AND state IN ('available','pending','running','retryable','scheduled') AND args->>'site_id'=$1::bigint::text)`, in.SiteID).Scan(&busy); err != nil {
		return i, in, err
	}
	if busy {
		return i, in, operations.ErrConflict
	}
	return i, in, nil
}
func recoveryConfirmation(i operations.Issue, in operationIntent, actorID, epoch int64) string {
	data, _ := json.Marshal([]any{i.ID, i.Generation, i.LatestEventID, i.OperationID, in.Hash, actorID, "retry_backup", epoch})
	sum := sha256.Sum256(data)
	return strconv.FormatInt(epoch, 10) + "." + hex.EncodeToString(sum[:])
}
func (m *OperationsManager) Preflight(ctx context.Context, actor auth.SessionUser, id int64) (RecoveryPreflight, error) {
	p := RecoveryPreflight{IssueID: id, Checks: []RecoveryCheck{}}
	if actor.Role != auth.RoleAdmin {
		return p, operations.ErrNotFound
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	i, in, err := m.prepareRecoveryTx(ctx, tx, actor, id)
	if err != nil {
		if errors.Is(err, operations.ErrNotFound) {
			return p, err
		}
		p.Reason = "Current resource state, backup permissions, limits or queued work prevents this retry. Review the resource settings and check again."
		return p, nil
	}
	p.Action = operations.RecoveryRetryBackup
	p.Target = in.Domain
	p.Checks = append(p.Checks, RecoveryCheck{"Current ownership and active resource", true}, RecoveryCheck{"Backup permission and quota", true}, RecoveryCheck{"No conflicting backup operation", true})
	if err = tx.Commit(); err != nil {
		return p, err
	}
	if m.agent == nil {
		p.Reason = "The agent is unavailable."
		return p, nil
	}
	response, err := m.agent.Ping(ctx)
	if err != nil || !response.OK {
		p.Reason = "The agent could not be reached."
		return p, nil
	}
	p.Checks = append(p.Checks, RecoveryCheck{"Agent reachable", true})
	inventory, err := m.agent.InspectServer(ctx)
	if err != nil || !strings.HasPrefix(inventory.OperatingSystem, "Ubuntu 26.04") || !freshOperationTime(inventory.CheckedAt) {
		p.Reason = "The supported server OS and current storage capacity could not be confirmed."
		return p, nil
	}
	mountLength := -1
	available := int64(0)
	for _, fs := range inventory.Filesystems {
		mount := filepath.Clean(fs.Mountpoint)
		if (mount == "/" || strings.HasPrefix("/var/lib/nakpanel/backups/", mount+"/")) && len(mount) > mountLength {
			mountLength = len(mount)
			available = fs.AvailableBytes
		}
	}
	if mountLength < 0 || available < 64<<20 {
		p.Reason = "Backup storage has less than 64 MB of confirmed free space. Free space and check again."
		return p, nil
	}
	p.Checks = append(p.Checks, RecoveryCheck{"At least 64 MB of backup storage is available", true})
	p.Allowed = true
	p.Confirmation = recoveryConfirmation(i, in, actor.ID, time.Now().Unix()/300)
	return p, nil
}
func (m *OperationsManager) Recover(ctx context.Context, actor auth.SessionUser, id int64, confirmation string) (RecoveryStarted, error) {
	var result RecoveryStarted
	epochText, _, ok := strings.Cut(confirmation, ".")
	epoch, err := strconv.ParseInt(epochText, 10, 64)
	currentEpoch := time.Now().Unix() / 300
	if !ok || err != nil || epoch < currentEpoch-1 || epoch > currentEpoch {
		return result, operations.ErrConflict
	}
	p, err := m.Preflight(ctx, actor, id)
	if err != nil {
		return result, err
	}
	if !p.Allowed {
		return result, operations.ErrConflict
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	i, in, err := m.prepareRecoveryTx(ctx, tx, actor, id)
	if err != nil {
		return result, operations.ErrConflict
	}
	expected := recoveryConfirmation(i, in, actor.ID, epoch)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(confirmation)) != 1 {
		return result, operations.ErrConflict
	}
	opID := i.OperationID
	if opID == 0 {
		if err = tx.QueryRowContext(ctx, `INSERT INTO operations(operation_key,kind,resource_kind,resource_id,title,trigger,intent_revision) VALUES($1,'create_backup','site',$2,'Create backup','recovery',$3) RETURNING id`, fmt.Sprintf("recovery:%d:%d", i.ID, i.Generation), in.SiteID, in.Revision).Scan(&opID); err != nil {
			return result, err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE operations SET intent_revision=$2 WHERE id=$1`, opID, in.Revision); err != nil {
		return result, err
	}
	var backupID int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO backups(owner_user_id,customer_id,subscription_id,site_id,target_kind,target_name,status) VALUES($1,$2,$3,$4,'site',$5,'pending') RETURNING id`, in.OwnerID, in.CustomerID, in.SubscriptionID, in.SiteID, in.Domain).Scan(&backupID); err != nil {
		return result, err
	}
	databases, err := selectActiveSubscriptionDatabases(ctx, tx, in.SubscriptionID)
	if err != nil {
		return result, err
	}
	metadata, _ := json.Marshal(map[string]int64{"nakpanel_operation_id": opID})
	if m.queue == nil {
		return result, operations.ErrConflict
	}
	queued, err := m.queue.InsertTx(ctx, tx, CreateBackupArgs{BackupID: backupID, SiteID: in.SiteID, SubscriptionID: in.SubscriptionID, CustomerID: in.CustomerID, ActorUserID: actor.ID, Domain: in.Domain, Username: in.Username, Docroot: in.Docroot, Databases: databases}, &river.InsertOpts{Metadata: metadata})
	if err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE issues SET operation_id=$2,intent_revision=$3,updated_at=now() WHERE id=$1`, i.ID, opID, in.Revision); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'operations.recovery_requested','issue',$4,jsonb_build_object('operation_id',$5::bigint,'action','retry_backup'))`, actor.ID, in.CustomerID, in.SubscriptionID, i.ID, opID); err != nil {
		return result, err
	}
	result = RecoveryStarted{OperationID: opID, JobID: queued.Job.ID}
	return result, tx.Commit()
}

func (m *OperationsManager) VerifyIssue(ctx context.Context, id int64) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var resource operations.Resource
	var operationID int64
	if err = tx.QueryRowContext(ctx, `SELECT resource_kind,resource_id,COALESCE(operation_id,0) FROM issues WHERE id=$1 AND resolved_at IS NULL`, id).Scan(&resource.Kind, &resource.ID, &operationID); errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	in, err := m.snapshotOperationIntentTx(ctx, tx, resource)
	if err != nil {
		return err
	}
	if operationID > 0 {
		var active bool
		if err = tx.QueryRowContext(ctx, `SELECT state IN ('queued','running','waiting_retry') FROM operations WHERE id=$1 FOR UPDATE`, operationID).Scan(&active); err != nil {
			return err
		}
		if active {
			return operations.ErrConflict
		}
	}
	i, err := m.Store.IssueForUpdateTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if i.ResolvedAt != nil {
		return nil
	}
	token, err := m.Store.SetCheckingTx(ctx, tx, i, in.Revision)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	receipt, probeErr := m.probeOperation(probeCtx, i, in)
	receipt.Token = token
	end, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer end.Rollback()
	current, err := m.snapshotOperationIntentTx(ctx, end, resource)
	if err != nil {
		_ = m.Store.VerificationFailedTx(ctx, end, token)
		_ = end.Commit()
		return err
	}
	if probeErr != nil {
		if err = m.Store.VerificationFailedTx(ctx, end, token); err != nil {
			return err
		}
		if err = end.Commit(); err != nil {
			return err
		}
		return fmt.Errorf("%w: independent probe did not establish recovery", ErrRecoveryUnverified)
	}
	if err = m.Store.ResolveVerifiedTx(ctx, end, receipt, current.Hash, current.Revision); err != nil {
		_ = m.Store.VerificationFailedTx(ctx, end, token)
		_ = end.Commit()
		return err
	}
	if receipt.Source == "archive_checksum" {
		if _, err = end.ExecContext(ctx, `INSERT INTO backup_readiness_checks(backup_id,checksum,size_bytes,verified_at,data_scope_hash,last_check_status,last_checked_at) VALUES($1,$2,$3,$4,$5,'verified',$4) ON CONFLICT(backup_id) DO UPDATE SET checksum=EXCLUDED.checksum,size_bytes=EXCLUDED.size_bytes,verified_at=EXCLUDED.verified_at,data_scope_hash=EXCLUDED.data_scope_hash,last_check_status='verified',last_checked_at=EXCLUDED.last_checked_at`, receipt.SourceID, receipt.Checksum, receipt.SizeBytes, receipt.ObservedAt, current.DataScopeHash); err != nil {
			return err
		}
	}
	return end.Commit()
}
