package mailimport

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type Queue interface {
	InsertTx(context.Context, *sql.Tx, river.JobArgs, *river.InsertOpts) (*rivertype.JobInsertResult, error)
}
type SQLStore struct {
	db      *sql.DB
	queue   Queue
	secrets SecretStore
}

type SecretStore interface {
	PutSecretTx(context.Context, *sql.Tx, serveradmin.PutSecretParams) (serveradmin.SecretReference, error)
	GetSecret(context.Context, string, string) ([]byte, serveradmin.SecretReference, error)
}

func NewSQLStore(db *sql.DB, q Queue, secrets ...SecretStore) *SQLStore {
	s := &SQLStore{db: db, queue: q}
	if len(secrets) > 0 {
		s.secrets = secrets[0]
	}
	return s
}
func (s *SQLStore) SetQueue(q Queue) { s.queue = q }

const mailboxSQL = `SELECT mb.id,md.subscription_id,mb.local_part||'@'||md.domain,
 mb.enabled AND md.enabled AND md.effective_enabled AND NOT md.delete_requested
 AND sub.status='active' AND customer.status='active'
 AND COALESCE((ent.hosting_policy#>>'{permissions,mail}')::boolean,false)
 AND COALESCE((ent.hosting_policy#>>'{mail,enabled}')::boolean,false)
 AND (customer.reseller_id IS NULL OR EXISTS (SELECT 1 FROM reseller_accounts ra JOIN reseller_subscriptions rs ON rs.reseller_id=ra.id AND rs.status='active' WHERE ra.id=customer.reseller_id AND ra.status='active'))
 FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id
 JOIN subscriptions sub ON sub.id=md.subscription_id JOIN customers customer ON customer.id=sub.customer_id
 JOIN subscription_entitlements ent ON ent.subscription_id=sub.id WHERE mb.id=$1`

type row interface{ Scan(...any) error }

func scanMailbox(r row) (Mailbox, error) {
	var v Mailbox
	err := r.Scan(&v.ID, &v.SubscriptionID, &v.Address, &v.Active)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}
func (s *SQLStore) Mailbox(ctx context.Context, id int64) (Mailbox, error) {
	return scanMailbox(s.db.QueryRowContext(ctx, mailboxSQL, id))
}
func (s *SQLStore) lockMailbox(ctx context.Context, tx *sql.Tx, id int64) (Mailbox, error) {
	box, err := scanMailbox(tx.QueryRowContext(ctx, mailboxSQL, id))
	if err != nil {
		return box, err
	}
	if err = quota.LockSubscriptionMutationTx(ctx, tx, box.SubscriptionID); err != nil {
		return box, err
	}
	box, err = scanMailbox(tx.QueryRowContext(ctx, mailboxSQL+` FOR SHARE OF mb,md,sub,customer`, id))
	if err != nil {
		return box, err
	}
	if !box.Active {
		return box, ErrInactive
	}
	return box, nil
}
func (s *SQLStore) Preview(ctx context.Context, actor auth.SessionUser, req types.MailImportRequest) (types.MailImportPreview, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.MailImportPreview{}, err
	}
	defer tx.Rollback()
	box, err := s.lockMailbox(ctx, tx, req.MailboxID)
	if err != nil {
		return types.MailImportPreview{}, err
	}
	if err = authorizeTx(ctx, tx, actor, box.SubscriptionID); err != nil {
		return types.MailImportPreview{}, err
	}
	b := make([]byte, 24)
	if _, err = rand.Read(b); err != nil {
		return types.MailImportPreview{}, err
	}
	id := "imp_" + hex.EncodeToString(b)
	for _, secret := range []struct {
		name      string
		value     *string
		reference *string
	}{{"source", &req.SourcePassword, &req.SourceSecretID}, {"target", &req.TargetPassword, &req.TargetSecretID}} {
		if *secret.value == "" {
			continue
		}
		if s.secrets == nil {
			return types.MailImportPreview{}, errors.New("encrypted mail import credentials are unavailable")
		}
		metadata, _ := json.Marshal(map[string]string{"import_id": id})
		ref, err := s.secrets.PutSecretTx(ctx, tx, serveradmin.PutSecretParams{Scope: "mail-import", Name: id + "-" + secret.name, Plaintext: []byte(*secret.value), Metadata: metadata, ActorUserID: actor.ID})
		if err != nil {
			return types.MailImportPreview{}, err
		}
		*secret.reference = ref.SecretID
		*secret.value = ""
	}
	preview := types.MailImportPreview{ID: id, Request: req}
	if req.SourcePort == 0 {
		req.SourcePort = 993
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO mail_imports(id,mailbox_id,subscription_id,actor_user_id,source_kind,source_host,source_port,source_user,staging_id,source_secret_id,target_secret_id,manifest_sha256)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING expires_at`, id, box.ID, box.SubscriptionID, actor.ID, req.SourceKind, req.SourceHost, req.SourcePort, req.SourceUser, req.StagingID, req.SourceSecretID, req.TargetSecretID, req.ManifestSHA256).Scan(&preview.ExpiresAt)
	if err != nil {
		return types.MailImportPreview{}, err
	}
	return preview, tx.Commit()
}

const importSQL = `SELECT id,mailbox_id,subscription_id,state,desired_revision,discovered,copied,verified,failed,uncertain,last_error,created_at,(SELECT count(*) FROM mail_import_messages m JOIN mail_import_folders f ON f.id=m.folder_id WHERE f.import_id=mail_imports.id AND m.state='excluded') FROM mail_imports WHERE id=$1`

func scanImport(r row) (types.MailImport, error) {
	var v types.MailImport
	err := r.Scan(&v.ID, &v.MailboxID, &v.SubscriptionID, &v.State, &v.Revision, &v.Discovered, &v.Copied, &v.Verified, &v.Failed, &v.Uncertain, &v.LastError, &v.CreatedAt, &v.Excluded)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}
func (s *SQLStore) Load(ctx context.Context, id string) (types.MailImport, error) {
	return scanImport(s.db.QueryRowContext(ctx, importSQL, id))
}
func (s *SQLStore) Start(ctx context.Context, actor auth.SessionUser, id string) (types.MailImport, error) {
	if s.queue == nil {
		return types.MailImport{}, errors.New("mail import worker is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.MailImport{}, err
	}
	defer tx.Rollback()
	item, err := scanImport(tx.QueryRowContext(ctx, importSQL, id))
	if err != nil {
		return item, err
	}
	if _, err = s.lockMailbox(ctx, tx, item.MailboxID); err != nil {
		return types.MailImport{}, err
	}
	if err = authorizeTx(ctx, tx, actor, item.SubscriptionID); err != nil {
		return item, err
	}
	item, err = scanImport(tx.QueryRowContext(ctx, importSQL+` FOR UPDATE`, id))
	if err != nil {
		return item, err
	}
	var valid bool
	if err = tx.QueryRowContext(ctx, `SELECT actor_user_id=$2 AND expires_at>now() AND state='preview' AND prepared FROM mail_imports WHERE id=$1`, id, actor.ID).Scan(&valid); err != nil {
		return item, err
	}
	if !valid {
		return item, errors.New("import preview expired or was already started")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mail_imports SET state='queued',updated_at=now() WHERE id=$1`, id); err != nil {
		return item, err
	}
	if _, err = s.queue.InsertTx(ctx, tx, ImportArgs{item.ID, item.Revision}, &river.InsertOpts{MaxAttempts: 3}); err != nil {
		return types.MailImport{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,subscription_id,action,target_type,target_id,metadata) VALUES($1,$2,'mail_import.started','mailbox',$3,jsonb_build_object('import_id',$4::text))`, actor.ID, item.SubscriptionID, item.MailboxID, id); err != nil {
		return types.MailImport{}, fmt.Errorf("record import audit: %w", err)
	}
	item.State = "queued"
	return item, tx.Commit()
}

func authorizeTx(ctx context.Context, tx *sql.Tx, actor auth.SessionUser, subscriptionID int64) error {
	if actor.Role != auth.RoleAdmin && actor.Role != auth.RoleReseller {
		return ErrForbidden
	}
	var allowed bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM subscriptions s JOIN customers c ON c.id=s.customer_id JOIN users u ON u.id=$2 WHERE s.id=$1 AND (u.role='admin' OR (u.role='reseller' AND EXISTS(SELECT 1 FROM reseller_accounts ra WHERE ra.id=c.reseller_id AND ra.login_user_id=u.id AND ra.status='active'))))`, subscriptionID, actor.ID).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrNotFound
	}
	return nil
}
