package mailimport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	transport "github.com/nakroteck/nakpanel/internal/mailimport"
)

func (s *SQLStore) Lock(ctx context.Context, id string) (func(), error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	var ok bool
	err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended('nakpanel:mail-import:'||$1,0))`, id).Scan(&ok)
	if err != nil || !ok {
		conn.Close()
		return nil, errors.New("mail import is already running")
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock(hashtextextended('nakpanel:mail-import:'||$1,0))`, id)
		_ = conn.Close()
	}, nil
}
func (s *SQLStore) Job(ctx context.Context, id string) (Job, error) {
	var j Job
	err := s.db.QueryRowContext(ctx, `SELECT i.id,i.mailbox_id,i.subscription_id,i.desired_revision,mb.local_part||'@'||md.domain,i.source_kind,i.source_host,i.source_user,i.staging_id,i.manifest_sha256,i.source_secret_id,i.target_secret_id FROM mail_imports i JOIN mailboxes mb ON mb.id=i.mailbox_id JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE i.id=$1`, id).Scan(&j.ID, &j.MailboxID, &j.SubscriptionID, &j.Revision, &j.Address, &j.SourceKind, &j.SourceHost, &j.SourceUser, &j.StagingID, &j.ManifestSHA256, &j.SourceSecretID, &j.TargetSecretID)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return j, err
}
func (s *SQLStore) Current(ctx context.Context, id string, revision int64) (bool, error) {
	var ok bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mail_imports i JOIN mailboxes mb ON mb.id=i.mailbox_id JOIN mail_domains md ON md.id=mb.mail_domain_id JOIN subscriptions sub ON sub.id=i.subscription_id JOIN customers c ON c.id=sub.customer_id JOIN users actor ON actor.id=i.actor_user_id JOIN subscription_entitlements ent ON ent.subscription_id=sub.id WHERE i.id=$1 AND i.desired_revision=$2 AND i.state IN ('queued','discovering','copying','verifying') AND mb.enabled AND md.effective_enabled AND NOT md.delete_requested AND sub.status='active' AND c.status='active' AND COALESCE((ent.hosting_policy#>>'{permissions,mail}')::boolean,false) AND COALESCE((ent.hosting_policy#>>'{mail,enabled}')::boolean,false) AND (actor.role='admin' OR (actor.role='reseller' AND EXISTS(SELECT 1 FROM reseller_accounts ra WHERE ra.id=c.reseller_id AND ra.login_user_id=actor.id AND ra.status='active'))))`, id, revision).Scan(&ok)
	return ok, err
}
func (s *SQLStore) SetState(ctx context.Context, id string, revision int64, state, message string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous string
	if err = tx.QueryRowContext(ctx, `SELECT state FROM mail_imports WHERE id=$1 FOR UPDATE`, id).Scan(&previous); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE mail_imports SET state=$3,last_error=$4,updated_at=now(),applied_revision=CASE WHEN $3='complete' THEN desired_revision ELSE applied_revision END WHERE id=$1 AND desired_revision=$2 AND state NOT IN ('paused','cancelled') AND ($3<>'complete' OR NOT EXISTS(SELECT 1 FROM mail_import_messages m JOIN mail_import_folders f ON f.id=m.folder_id WHERE f.import_id=$1 AND m.state NOT IN ('verified','excluded')))`, id, revision, state, message)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrSuperseded
	}
	if previous != state && (state == "complete" || state == "attention_required" || state == "failed") {
		if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,subscription_id,action,target_type,target_id,metadata) SELECT actor_user_id,subscription_id,$2,'mailbox',mailbox_id,jsonb_build_object('import_id',id,'state',state) FROM mail_imports WHERE id=$1`, id, "mail_import."+state); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *SQLStore) Discover(ctx context.Context, id string, folders []transport.Folder) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, folder := range folders {
		var folderID int64
		var approved bool
		target := folder.Name
		if folder.Delimiter != "" && folder.Delimiter != "/" {
			target = strings.ReplaceAll(target, folder.Delimiter, "/")
		}
		err = tx.QueryRowContext(ctx, `INSERT INTO mail_import_folders(import_id,source_name,target_name,uid_validity,special_use) VALUES($1,$2,$5,$3,$4) ON CONFLICT(import_id,source_name) DO UPDATE SET source_name=EXCLUDED.source_name WHERE mail_import_folders.uid_validity=EXCLUDED.uid_validity RETURNING id,approved`, id, folder.Name, folder.UIDValidity, folder.SpecialUse, target).Scan(&folderID, &approved)
		if errors.Is(err, sql.ErrNoRows) {
			return transport.ErrSourceChanged
		}
		if err != nil {
			return err
		}
		for _, m := range folder.Messages {
			flags, _ := json.Marshal(m.Flags)
			if m.Flags == nil {
				flags = []byte("[]")
			}
			hash := ""
			if m.Body != nil {
				hash = transport.ContentHash(m.Body)
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO mail_import_messages(folder_id,source_identity,source_uid,sha256,byte_size,internal_date,flags,receipt_token,source_key,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,CASE WHEN $10 THEN 'pending' ELSE 'excluded' END) ON CONFLICT(folder_id,source_identity) DO NOTHING`, folderID, m.Identity.String(), m.Identity.UID, hash, m.Size, m.InternalDate, flags, transport.ReceiptToken(id, m.Identity.String()), m.Identity.Key, approved)
			if err != nil {
				return err
			}
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mail_imports SET discovered=(SELECT count(*) FROM mail_import_messages m JOIN mail_import_folders f ON f.id=m.folder_id WHERE f.import_id=$1),updated_at=now() WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *SQLStore) Messages(ctx context.Context, id string) ([]MessageRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT m.id,f.source_name,f.uid_validity,m.source_uid,m.source_key,m.sha256,m.byte_size,m.internal_date,m.flags,m.receipt_token,m.state,m.target_uid,m.target_uid_validity,m.last_error,f.target_name FROM mail_import_messages m JOIN mail_import_folders f ON f.id=m.folder_id WHERE f.import_id=$1 ORDER BY m.id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MessageRecord{}
	for rows.Next() {
		var r MessageRecord
		var flags []byte
		var key string
		if err = rows.Scan(&r.ID, &r.Message.Identity.Folder, &r.Message.Identity.UIDValidity, &r.Message.Identity.UID, &key, &r.Hash, &r.Message.Size, &r.Message.InternalDate, &flags, &r.Token, &r.State, &r.Receipt.UID, &r.Receipt.UIDValidity, &r.Error, &r.Receipt.Folder); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(flags, &r.Message.Flags); err != nil {
			return nil, err
		}
		r.Message.Identity.Key = key
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *SQLStore) Checkpoint(ctx context.Context, id string, r MessageRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `UPDATE mail_import_messages SET state=$3,sha256=$4,target_uid=$5,target_uid_validity=$6,last_error=$7 WHERE id=$2 AND folder_id IN (SELECT id FROM mail_import_folders WHERE import_id=$1)`, id, r.ID, r.State, r.Hash, r.Receipt.UID, r.Receipt.UIDValidity, r.Error)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE mail_imports SET copied=(SELECT count(*) FROM mail_import_messages m JOIN mail_import_folders f ON f.id=m.folder_id WHERE f.import_id=$1 AND m.state IN ('copied','verified')),verified=(SELECT count(*) FROM mail_import_messages m JOIN mail_import_folders f ON f.id=m.folder_id WHERE f.import_id=$1 AND m.state='verified'),failed=(SELECT count(*) FROM mail_import_messages m JOIN mail_import_folders f ON f.id=m.folder_id WHERE f.import_id=$1 AND m.state='failed'),uncertain=(SELECT count(*) FROM mail_import_messages m JOIN mail_import_folders f ON f.id=m.folder_id WHERE f.import_id=$1 AND m.state IN ('appending','uncertain')),updated_at=now() WHERE id=$1`, id)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *SQLStore) Retire(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM service_secrets WHERE scope='mail-import' AND metadata->>'import_id'=$1 AND EXISTS(SELECT 1 FROM mail_imports WHERE id=$1 AND state IN ('complete','cancelled'))`, id)
	return err
}
func (s *SQLStore) Prepared(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mail_imports SET prepared=true WHERE id=$1 AND state='preview'`, id)
	return err
}
