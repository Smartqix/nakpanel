package provision

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/lib/pq"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

var ErrRemovalPreviewChanged = errors.New("website removal preview changed; review its current impact before confirming")
var removalRequestIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type RemoveSiteArgs struct {
	OperationID int64 `json:"operation_id" river:"unique"`
	Revision    int64 `json:"revision" river:"unique"`
}

func (RemoveSiteArgs) Kind() string { return "remove_site" }
func (RemoveSiteArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: quota.HeavyQueue, MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning, rivertype.JobStateRetryable, rivertype.JobStateScheduled}}}
}

const removalOperationColumns = `id,request_id,site_id,subscription_id,customer_id,COALESCE(actor_user_id,0),actor_label,domain,COALESCE(parent_site_id,0),snapshot,delete_database_ids,revision,state,stage,checkpoints,last_error,created_at,updated_at,completed_at`

func readRemoval(row *sql.Row) (types.SiteRemovalOperation, error) {
	var op types.SiteRemovalOperation
	var snapshot []byte
	var completed sql.NullTime
	err := row.Scan(&op.ID, &op.RequestID, &op.SiteID, &op.SubscriptionID, &op.CustomerID, &op.ActorUserID, &op.ActorLabel, &op.Domain, &op.ParentSiteID, &snapshot, pq.Array(&op.DeleteDatabaseIDs), &op.Revision, &op.State, &op.Stage, pq.Array(&op.Checkpoints), &op.LastError, &op.CreatedAt, &op.UpdatedAt, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return op, ErrForbidden
	}
	if err != nil {
		return op, err
	}
	if err = json.Unmarshal(snapshot, &op.Snapshot); err != nil {
		return op, errors.New("website removal inventory is invalid")
	}
	if completed.Valid {
		op.CompletedAt = &completed.Time
	}
	return op, nil
}

func (s *SiteRemovalService) SiteRemovalFor(ctx context.Context, actor auth.SessionUser, id int64) (types.SiteRemovalOperation, error) {
	if s == nil || s.db == nil || s.access == nil {
		return types.SiteRemovalOperation{}, errors.New("website removal is not configured")
	}
	op, err := readRemoval(s.db.QueryRowContext(ctx, "SELECT "+removalOperationColumns+" FROM site_removal_operations WHERE id=$1", id))
	if err != nil {
		return op, err
	}
	return s.authorizeOperation(ctx, actor, op)
}
func (s *SiteRemovalService) SiteRemovalByRequestFor(ctx context.Context, actor auth.SessionUser, requestID string) (types.SiteRemovalOperation, error) {
	if s == nil || s.db == nil || s.access == nil {
		return types.SiteRemovalOperation{}, errors.New("website removal is not configured")
	}
	if !removalRequestIDPattern.MatchString(requestID) {
		return types.SiteRemovalOperation{}, ErrForbidden
	}
	op, err := readRemoval(s.db.QueryRowContext(ctx, "SELECT "+removalOperationColumns+" FROM site_removal_operations WHERE request_id=$1", requestID))
	if err != nil {
		return op, err
	}
	return s.authorizeOperation(ctx, actor, op)
}
func (s *SiteRemovalService) authorizeOperation(ctx context.Context, actor auth.SessionUser, op types.SiteRemovalOperation) (types.SiteRemovalOperation, error) {
	allowed, err := s.access.CanManageSubscription(ctx, actor, op.SubscriptionID)
	if err != nil {
		return types.SiteRemovalOperation{}, err
	}
	if !allowed {
		return types.SiteRemovalOperation{}, ErrForbidden
	}
	return op, nil
}

func (s *SiteRemovalService) RemoveSiteFor(ctx context.Context, actor auth.SessionUser, req types.RemoveSiteReq) (types.SiteRemovalOperation, error) {
	if s == nil || s.db == nil || s.river == nil || s.access == nil {
		return types.SiteRemovalOperation{}, errors.New("website removal is not configured")
	}
	if !removalRequestIDPattern.MatchString(req.RequestID) || req.SiteID <= 0 {
		return types.SiteRemovalOperation{}, errors.New("valid removal request identity is required")
	}
	if !req.AcknowledgePermanent {
		return types.SiteRemovalOperation{}, errors.New("acknowledge that website removal is permanent")
	}
	// Lookup before live-site authorization also recovers a lost response after completion.
	existing, err := s.SiteRemovalByRequestFor(ctx, actor, req.RequestID)
	if err == nil {
		return sameRemovalRequest(existing, req)
	}
	if !errors.Is(err, ErrForbidden) {
		return types.SiteRemovalOperation{}, err
	}
	if err = s.authorizeSite(ctx, actor, req.SiteID); err != nil {
		return types.SiteRemovalOperation{}, err
	}
	var subscriptionID int64
	if err = s.db.QueryRowContext(ctx, "SELECT subscription_id FROM sites WHERE id=$1", req.SiteID).Scan(&subscriptionID); err != nil {
		return types.SiteRemovalOperation{}, ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.SiteRemovalOperation{}, err
	}
	defer tx.Rollback()
	if err = quota.LockSubscriptionMutationTx(ctx, tx, subscriptionID); err != nil {
		return types.SiteRemovalOperation{}, err
	}
	// Another request with this nonce may have committed while this one waited.
	existing, err = readRemoval(tx.QueryRowContext(ctx, "SELECT "+removalOperationColumns+" FROM site_removal_operations WHERE request_id=$1", req.RequestID))
	if err == nil {
		return sameRemovalRequest(existing, req)
	}
	if !errors.Is(err, ErrForbidden) {
		return types.SiteRemovalOperation{}, err
	}
	allowed, err := s.access.CanRemoveSiteTx(ctx, tx, actor, req.SiteID)
	if err != nil {
		return types.SiteRemovalOperation{}, err
	}
	if !allowed {
		return types.SiteRemovalOperation{}, ErrForbidden
	}
	preview, err := s.preview(ctx, tx, req.SiteID)
	if err != nil {
		return types.SiteRemovalOperation{}, err
	}
	if preview.SubscriptionID != subscriptionID {
		return types.SiteRemovalOperation{}, ErrRemovalPreviewChanged
	}
	if !preview.Allowed {
		return types.SiteRemovalOperation{}, errors.New(strings.Join(preview.BlockedReasons, " "))
	}
	if preview.Digest != req.PreviewDigest {
		return types.SiteRemovalOperation{}, ErrRemovalPreviewChanged
	}
	if req.ConfirmDomain != preview.Domain {
		return types.SiteRemovalOperation{}, fmt.Errorf("type %s to confirm permanent removal", preview.Domain)
	}
	if len(preview.Snapshot.Sites) > 1 && !req.IncludeChildren {
		return types.SiteRemovalOperation{}, errors.New("acknowledge removal of the listed child domains")
	}
	selected := append([]int64{}, req.DeleteDatabaseIDs...)
	slices.Sort(selected)
	for i, id := range selected {
		if id <= 0 || (i > 0 && id == selected[i-1]) {
			return types.SiteRemovalOperation{}, errors.New("invalid database removal selection")
		}
		eligible := false
		for _, database := range preview.Snapshot.Databases {
			if database.ID == id && database.DeletionEligible {
				eligible = true
				break
			}
		}
		if !eligible {
			return types.SiteRemovalOperation{}, errors.New("selected database must be retained")
		}
	}
	snapshot, err := json.Marshal(preview.Snapshot)
	if err != nil {
		return types.SiteRemovalOperation{}, err
	}
	label := strings.TrimSpace(actor.Email)
	if label == "" {
		label = fmt.Sprintf("user:%d", actor.ID)
	}
	op, err := readRemoval(tx.QueryRowContext(ctx, `INSERT INTO site_removal_operations(request_id,site_id,subscription_id,customer_id,actor_user_id,actor_label,domain,parent_site_id,snapshot,preview_digest,delete_database_ids)
 VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,0),$9,$10,$11) RETURNING `+removalOperationColumns, req.RequestID, preview.SiteID, subscriptionID, preview.CustomerID, actor.ID, label, preview.Domain, preview.ParentSiteID, snapshot, preview.Digest, pq.Array(selected)))
	if err != nil {
		return types.SiteRemovalOperation{}, err
	}
	if _, err = tx.ExecContext(ctx, "SELECT set_config('nakpanel.site_removal_operation',$1,true)", fmt.Sprint(op.ID)); err != nil {
		return types.SiteRemovalOperation{}, err
	}
	ids := make([]int64, 0, len(preview.Snapshot.Sites))
	for _, item := range preview.Snapshot.Sites {
		ids = append(ids, item.SiteID)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if _, err = tx.ExecContext(ctx, "INSERT INTO site_removal_targets(operation_id,site_id) VALUES($1,$2)", op.ID, id); err != nil {
			return types.SiteRemovalOperation{}, err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE sites SET removal_state='queued',removal_revision=$2 WHERE id=$1 AND removal_state='none'", id, op.Revision); err != nil {
			return types.SiteRemovalOperation{}, err
		}
	}
	if _, err = s.river.InsertTx(ctx, tx, RemoveSiteArgs{OperationID: op.ID, Revision: op.Revision}, nil); err != nil {
		return types.SiteRemovalOperation{}, err
	}
	metadata, _ := json.Marshal(map[string]any{"sites": len(ids), "databases_deleted": len(selected), "databases_retained": len(preview.Snapshot.Databases) - len(selected), "backups_retained": len(preview.Snapshot.Backups)})
	if err = removalAudit(ctx, tx, actor, op, "site.removal_requested", metadata); err != nil {
		return types.SiteRemovalOperation{}, err
	}
	if err = tx.Commit(); err != nil {
		return types.SiteRemovalOperation{}, err
	}
	return op, nil
}
func sameRemovalRequest(op types.SiteRemovalOperation, req types.RemoveSiteReq) (types.SiteRemovalOperation, error) {
	selected := append([]int64(nil), req.DeleteDatabaseIDs...)
	slices.Sort(selected)
	if op.SiteID != req.SiteID || op.Domain != req.ConfirmDomain || !slices.Equal(selected, op.DeleteDatabaseIDs) || (len(op.Snapshot.Sites) > 1 && !req.IncludeChildren) {
		return types.SiteRemovalOperation{}, errors.New("removal request identity is already bound to another approved choice")
	}
	return op, nil
}
func removalAudit(ctx context.Context, tx *sql.Tx, actor auth.SessionUser, op types.SiteRemovalOperation, action string, metadata []byte) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,actor_label,customer_id,subscription_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,$4,$5,'site_removal',$6,$7)`, actor.ID, actor.Email, op.CustomerID, op.SubscriptionID, action, op.ID, metadata)
	return err
}
func (s *SiteRemovalService) RetrySiteRemovalFor(ctx context.Context, actor auth.SessionUser, id int64) (types.SiteRemovalOperation, error) {
	op, err := s.SiteRemovalFor(ctx, actor, id)
	if err != nil {
		return op, err
	}
	if op.State == "completed" {
		return op, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.SiteRemovalOperation{}, err
	}
	defer tx.Rollback()
	if err = quota.LockSubscriptionMutationTx(ctx, tx, op.SubscriptionID); err != nil {
		return types.SiteRemovalOperation{}, err
	}
	op, err = readRemoval(tx.QueryRowContext(ctx, "SELECT "+removalOperationColumns+" FROM site_removal_operations WHERE id=$1 FOR UPDATE", id))
	if err != nil {
		return op, err
	}
	if op.State == "completed" {
		return op, nil
	}
	allowed, err := s.access.CanRemoveSiteTx(ctx, tx, actor, op.SiteID)
	if err != nil {
		return types.SiteRemovalOperation{}, err
	}
	if !allowed {
		return types.SiteRemovalOperation{}, ErrForbidden
	}
	if op.State != "failed" {
		return op, errors.New("only failed website removals can be retried")
	}
	op, err = readRemoval(tx.QueryRowContext(ctx, "UPDATE site_removal_operations SET state='queued',revision=revision+1,last_error='',updated_at=now() WHERE id=$1 RETURNING "+removalOperationColumns, id))
	if err != nil {
		return op, err
	}
	if _, err = tx.ExecContext(ctx, "SELECT set_config('nakpanel.site_removal_operation',$1,true)", fmt.Sprint(op.ID)); err != nil {
		return op, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE sites SET removal_state='queued',removal_revision=$2 WHERE id IN (SELECT site_id FROM site_removal_targets WHERE operation_id=$1 AND NOT released)", op.ID, op.Revision); err != nil {
		return op, err
	}
	if _, err = s.river.InsertTx(ctx, tx, RemoveSiteArgs{OperationID: op.ID, Revision: op.Revision}, nil); err != nil {
		return op, err
	}
	if err = removalAudit(ctx, tx, actor, op, "site.removal_retried", []byte(`{}`)); err != nil {
		return op, err
	}
	if err = tx.Commit(); err != nil {
		return op, err
	}
	return op, nil
}

func (m *Manager) RemoveSiteFor(ctx context.Context, actor auth.SessionUser, req types.RemoveSiteReq) (types.SiteRemovalOperation, error) {
	return m.siteRemoval.RemoveSiteFor(ctx, actor, req)
}
func (m *Manager) RetrySiteRemovalFor(ctx context.Context, actor auth.SessionUser, id int64) (types.SiteRemovalOperation, error) {
	return m.siteRemoval.RetrySiteRemovalFor(ctx, actor, id)
}
func (m *Manager) SiteRemovalFor(ctx context.Context, actor auth.SessionUser, id int64) (types.SiteRemovalOperation, error) {
	return m.siteRemoval.SiteRemovalFor(ctx, actor, id)
}
func (m *Manager) SiteRemovalByRequestFor(ctx context.Context, actor auth.SessionUser, id string) (types.SiteRemovalOperation, error) {
	return m.siteRemoval.SiteRemovalByRequestFor(ctx, actor, id)
}
