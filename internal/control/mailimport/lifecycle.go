package mailimport

import (
	"context"
	"errors"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

func (m *Manager) Transition(ctx context.Context, actor auth.SessionUser, id, action string) (types.MailImport, error) {
	item, err := m.Status(ctx, actor, id)
	if err != nil {
		return item, err
	}
	store, ok := m.store.(interface {
		Transition(context.Context, auth.SessionUser, string, string) (types.MailImport, error)
	})
	if !ok {
		return item, errors.New("mail import controls unavailable")
	}
	if action != "pause" && action != "resume" && action != "cancel" {
		return item, errors.New("invalid mail import action")
	}
	if action == "resume" {
		box, err := m.authorize(ctx, actor, item.MailboxID)
		if err != nil {
			return item, err
		}
		if !box.Active {
			return item, ErrInactive
		}
	}
	return store.Transition(ctx, actor, id, action)
}
func (m *Manager) Pause(ctx context.Context, actor auth.SessionUser, id string) (types.MailImport, error) {
	return m.Transition(ctx, actor, id, "pause")
}
func (m *Manager) Resume(ctx context.Context, actor auth.SessionUser, id string) (types.MailImport, error) {
	return m.Transition(ctx, actor, id, "resume")
}
func (m *Manager) Cancel(ctx context.Context, actor auth.SessionUser, id string) (types.MailImport, error) {
	return m.Transition(ctx, actor, id, "cancel")
}

func (s *SQLStore) Transition(ctx context.Context, actor auth.SessionUser, id, action string) (types.MailImport, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.MailImport{}, err
	}
	defer tx.Rollback()
	item, err := scanImport(tx.QueryRowContext(ctx, importSQL+` FOR UPDATE`, id))
	if err != nil {
		return item, err
	}
	if err = authorizeTx(ctx, tx, actor, item.SubscriptionID); err != nil {
		return item, err
	}
	state := ""
	switch action {
	case "pause":
		if item.State == "queued" || item.State == "discovering" || item.State == "copying" || item.State == "verifying" {
			state = "paused"
		}
	case "resume":
		if item.State == "paused" || item.State == "attention_required" || item.State == "failed" {
			state = "queued"
			if _, err = s.lockMailbox(ctx, tx, item.MailboxID); err != nil {
				return item, err
			}
		}
	case "cancel":
		if item.State != "complete" && item.State != "cancelled" {
			state = "cancelled"
		}
	}
	if state == "" {
		return item, errors.New("that action is not available for the current import state")
	}
	item.Revision++
	item.State = state
	if _, err = tx.ExecContext(ctx, `UPDATE mail_imports SET state=$2,desired_revision=$3,last_error='',updated_at=now() WHERE id=$1`, id, state, item.Revision); err != nil {
		return item, err
	}
	if state == "queued" {
		if s.queue == nil {
			return item, errors.New("mail worker unavailable")
		}
		if _, err = s.queue.InsertTx(ctx, tx, ImportArgs{id, item.Revision}, &river.InsertOpts{MaxAttempts: 3}); err != nil {
			return item, err
		}
	}
	if state == "cancelled" {
		if _, err = tx.ExecContext(ctx, `DELETE FROM service_secrets WHERE scope='mail-import' AND metadata->>'import_id'=$1`, id); err != nil {
			return item, err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,subscription_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'mailbox',$4,jsonb_build_object('import_id',$5::text))`, actor.ID, item.SubscriptionID, "mail_import."+action, item.MailboxID, id); err != nil {
		return item, err
	}
	return item, tx.Commit()
}
