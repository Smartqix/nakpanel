package mailimport

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	transport "github.com/nakroteck/nakpanel/internal/mailimport"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

func fixtureMailbox(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	var id int64
	if err := db.QueryRow(`INSERT INTO mail_domains(subscription_id,domain,enabled,effective_enabled,convergence_status) VALUES(1,'secrets.test',true,true,'in_sync') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO mailboxes(mail_domain_id,local_part,password_hash) VALUES($1,'import','hash') RETURNING id`, id).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
func TestMailImportEncryptionAndCancellation(t *testing.T) {
	db := removaldb.New(t, "")
	ctx := context.Background()
	keyring, err := serveradmin.NewKeyring(1, map[int][]byte{1: bytes.Repeat([]byte{17}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	secrets := serveradmin.NewStore(db, keyring)
	store := NewSQLStore(db, acceptingQueue{}, secrets)
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	preview, err := store.Preview(ctx, actor, types.MailImportRequest{MailboxID: fixtureMailbox(t, db), SourceKind: "imap", SourceHost: "mail.example.com", SourceUser: "user", SourcePassword: "source-plaintext", TargetPassword: "target-plaintext"})
	if err != nil {
		t.Fatal(err)
	}
	var body string
	if err = db.QueryRow(`SELECT row_to_json(i)::text FROM mail_imports i WHERE id=$1`, preview.ID).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "plaintext") {
		t.Fatal("secret persisted in intent")
	}
	job, err := store.Job(ctx, preview.ID)
	if err != nil {
		t.Fatal(err)
	}
	factory := RuntimeFactory{DB: db, Secrets: secrets}
	password, err := factory.secret(ctx, job.ID, job.TargetSecretID)
	if err != nil || string(password) != "target-plaintext" {
		t.Fatal("encrypted credential not recoverable")
	}
	clear(password)
	if _, err = store.Start(ctx, actor, job.ID); err == nil {
		t.Fatal("started without a reviewed discovery")
	}
	if err = store.Prepared(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Start(ctx, actor, job.ID); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"pause", "resume", "cancel"} {
		if _, err = store.Transition(ctx, actor, job.ID, action); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM service_secrets WHERE scope='mail-import'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cancel retained credentials: %d %v", count, err)
	}
}

func TestMailImportPlanDisabledBeforeStart(t *testing.T) {
	db := removaldb.New(t, "")
	store := NewSQLStore(db, acceptingQueue{})
	ctx := context.Background()
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	preview, err := store.Preview(ctx, actor, types.MailImportRequest{MailboxID: fixtureMailbox(t, db), SourceKind: "imap", SourceHost: "mail.example.com", SourceUser: "user", SourceSecretID: "secret", TargetSecretID: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Prepared(ctx, preview.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{permissions,mail}','false') WHERE subscription_id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Start(ctx, actor, preview.ID); !errors.Is(err, ErrInactive) {
		t.Fatalf("plan gate bypass: %v", err)
	}
}

func TestMailImportMappingIsReviewedAndScoped(t *testing.T) {
	db := removaldb.New(t, "")
	ctx := context.Background()
	store := NewSQLStore(db, acceptingQueue{})
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	preview, err := store.Preview(ctx, actor, types.MailImportRequest{MailboxID: fixtureMailbox(t, db), SourceKind: "imap", SourceHost: "mail.example.com", SourceSecretID: "source", TargetSecretID: "target"})
	if err != nil {
		t.Fatal(err)
	}
	engine := Engine{Store: store, Factory: memoryFactory{&memorySource{messages: []transport.Message{testMessage("one")}}, &memoryTarget{receipts: map[string]transport.Message{}}}}
	if err = engine.Prepare(ctx, preview.ID); err != nil {
		t.Fatal(err)
	}
	folders, err := store.Folders(ctx, preview.ID)
	if err != nil || len(folders) != 1 {
		t.Fatalf("folders %v %v", folders, err)
	}
	if err = store.MapFolders(ctx, actor, preview.ID, []types.MailImportMapping{{FolderID: folders[0].ID + 1, Target: "Other", Include: true}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign mapping: %v", err)
	}
	if err = store.MapFolders(ctx, actor, preview.ID, []types.MailImportMapping{{FolderID: folders[0].ID, Target: "Imported", Include: false}}); err != nil {
		t.Fatal(err)
	}
	item, err := store.Start(ctx, actor, preview.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Run(ctx, item.ID, item.Revision); err != nil {
		t.Fatal(err)
	}
	item, err = store.Load(ctx, item.ID)
	if err != nil || item.State != "complete" || item.Verified != 0 || item.Excluded != 1 {
		t.Fatalf("excluded scope: %+v %v", item, err)
	}
}

type failingQueue struct{}

func (failingQueue) InsertTx(context.Context, *sql.Tx, river.JobArgs, *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	return nil, errors.New("queue unavailable")
}

type acceptingQueue struct{}

func (acceptingQueue) InsertTx(context.Context, *sql.Tx, river.JobArgs, *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	return &rivertype.JobInsertResult{}, nil
}

func TestMailImportSQLWorkerIdentityAndIdempotency(t *testing.T) {
	db := removaldb.New(t, "")
	ctx := context.Background()
	var domainID, boxID int64
	if err := db.QueryRow(`INSERT INTO mail_domains(subscription_id,domain,enabled,effective_enabled,convergence_status) VALUES(1,'worker.test',true,true,'in_sync') RETURNING id`).Scan(&domainID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO mailboxes(mail_domain_id,local_part,password_hash) VALUES($1,'import','hash') RETURNING id`, domainID).Scan(&boxID); err != nil {
		t.Fatal(err)
	}
	store := NewSQLStore(db, acceptingQueue{})
	preview, err := store.Preview(ctx, auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, types.MailImportRequest{MailboxID: boxID, SourceKind: "imap", SourceHost: "mail.example.com", SourcePort: 993, SourceUser: "source@example.com", SourceSecretID: "sec_source", TargetSecretID: "sec_target"})
	if err != nil {
		t.Fatal(err)
	}
	source := &memorySource{messages: []transport.Message{testMessage("one")}, catchup: true}
	target := &memoryTarget{receipts: map[string]transport.Message{}}
	engine := Engine{Store: store, Factory: memoryFactory{source, target}}
	if err = engine.Prepare(ctx, preview.ID); err != nil {
		t.Fatal(err)
	}
	item, err := store.Start(ctx, auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, preview.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Run(ctx, item.ID, item.Revision); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(ctx, item.ID)
	if err != nil || got.State != "complete" || got.Verified != 2 {
		t.Fatalf("import did not converge: %+v %v", got, err)
	}
	if err = engine.Run(ctx, item.ID, item.Revision); err != nil {
		t.Fatal(err)
	}
	if target.appends != 2 {
		t.Fatal("repeated worker duplicated messages")
	}
}

func TestMailImportCheckpointPreservesCopiedMetadata(t *testing.T) {
	db := removaldb.New(t, "")
	ctx := context.Background()
	store := NewSQLStore(db, acceptingQueue{})
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	preview, err := store.Preview(ctx, actor, types.MailImportRequest{MailboxID: fixtureMailbox(t, db), SourceKind: "imap", SourceHost: "mail.example.com", SourceSecretID: "source", TargetSecretID: "target"})
	if err != nil {
		t.Fatal(err)
	}
	message := testMessage("metadata")
	message.Flags = []string{`\Seen`}
	source := &memorySource{messages: []transport.Message{message}}
	target := &memoryTarget{receipts: map[string]transport.Message{}}
	engine := Engine{Store: store, Factory: memoryFactory{source, target}}
	if err = engine.Prepare(ctx, preview.ID); err != nil {
		t.Fatal(err)
	}
	// The source user marks it unread after preview, before the actual copy.
	source.messages[0].Flags = nil
	item, err := store.Start(ctx, actor, preview.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Run(ctx, item.ID, item.Revision); err != nil {
		t.Fatal(err)
	}
	item, err = store.Load(ctx, item.ID)
	if err != nil || item.State != "complete" || item.Verified != 1 {
		t.Fatalf("fresh verification used stale preview metadata: %+v %v", item, err)
	}
	records, err := store.Messages(ctx, item.ID)
	if err != nil || len(records) != 1 || len(records[0].Message.Flags) != 0 {
		t.Fatalf("copied flags not persisted: %+v %v", records, err)
	}
}

func TestMailImportWorkerUsesDesiredLifecycleGate(t *testing.T) {
	for _, change := range []string{"domain-disabled", "reseller-suspended", "reseller-allocation-suspended"} {
		t.Run(change, func(t *testing.T) {
			db := removaldb.New(t, "")
			ctx := context.Background()
			store := NewSQLStore(db, acceptingQueue{})
			actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
			preview, err := store.Preview(ctx, actor, types.MailImportRequest{MailboxID: fixtureMailbox(t, db), SourceKind: "imap", SourceHost: "mail.example.com", SourceSecretID: "source", TargetSecretID: "target"})
			if err != nil {
				t.Fatal(err)
			}
			source := &memorySource{messages: []transport.Message{testMessage("one")}}
			target := &memoryTarget{receipts: map[string]transport.Message{}}
			engine := Engine{Store: store, Factory: memoryFactory{source, target}}
			if err = engine.Prepare(ctx, preview.ID); err != nil {
				t.Fatal(err)
			}
			item, err := store.Start(ctx, actor, preview.ID)
			if err != nil {
				t.Fatal(err)
			}
			if change == "domain-disabled" {
				_, err = db.Exec(`UPDATE mail_domains SET enabled=false`)
			} else {
				_, err = db.Exec(`INSERT INTO users(email,password_hash,role) VALUES('provider@test.invalid','hash','reseller');
INSERT INTO reseller_accounts(login_user_id,email) SELECT id,email FROM users WHERE email='provider@test.invalid';
INSERT INTO reseller_subscriptions(reseller_id,reseller_plan_id) SELECT id,(SELECT id FROM reseller_plans LIMIT 1) FROM reseller_accounts WHERE email='provider@test.invalid';
UPDATE customers SET reseller_id=(SELECT id FROM reseller_accounts WHERE email='provider@test.invalid') WHERE id=(SELECT customer_id FROM subscriptions WHERE id=1)`)
				if err == nil && change == "reseller-suspended" {
					_, err = db.Exec(`UPDATE reseller_accounts SET status='suspended' WHERE email='provider@test.invalid'`)
				} else if err == nil {
					_, err = db.Exec(`UPDATE reseller_subscriptions SET status='suspended'`)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = engine.Run(ctx, item.ID, item.Revision); err != nil {
				t.Fatal(err)
			}
			if target.appends != 0 {
				t.Fatal("worker copied mail after desired service/provider suspension")
			}
		})
	}
}

func TestMailImportTerminalCleanupRetries(t *testing.T) {
	for _, stage := range []string{"retire", "cleanup"} {
		t.Run(stage, func(t *testing.T) {
			db := removaldb.New(t, "")
			ctx := context.Background()
			store := &retryRetirementStore{SQLStore: NewSQLStore(db, acceptingQueue{}), failOnce: stage == "retire"}
			actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
			preview, err := store.Preview(ctx, actor, types.MailImportRequest{MailboxID: fixtureMailbox(t, db), SourceKind: "imap", SourceHost: "mail.example.com", SourceSecretID: "source", TargetSecretID: "target"})
			if err != nil {
				t.Fatal(err)
			}
			target := &memoryTarget{receipts: map[string]transport.Message{}}
			factory := &retryCleanupFactory{memoryFactory: memoryFactory{&memorySource{messages: []transport.Message{testMessage("one")}}, target}, failOnce: stage == "cleanup"}
			engine := Engine{Store: store, Factory: factory}
			if err = engine.Prepare(ctx, preview.ID); err != nil {
				t.Fatal(err)
			}
			item, err := store.Start(ctx, actor, preview.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err = engine.Run(ctx, item.ID, item.Revision); err == nil {
				t.Fatal("transient cleanup failure was hidden")
			}
			opens := factory.opens
			if err = engine.Run(ctx, item.ID, item.Revision); err != nil {
				t.Fatal(err)
			}
			if store.retireCalls != 2 || factory.cleanupCalls == 0 || factory.failOnce {
				t.Fatalf("terminal cleanup not retried: retire=%d cleanup=%d", store.retireCalls, factory.cleanupCalls)
			}
			if factory.opens != opens || target.appends != 1 {
				t.Fatal("cleanup retry reopened credentials or copied messages again")
			}
		})
	}
}

func TestMailImportResumesWithOriginalAppendMetadata(t *testing.T) {
	db := removaldb.New(t, "")
	ctx := context.Background()
	store := NewSQLStore(db, acceptingQueue{})
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	preview, err := store.Preview(ctx, actor, types.MailImportRequest{MailboxID: fixtureMailbox(t, db), SourceKind: "imap", SourceHost: "mail.example.com", SourceSecretID: "source", TargetSecretID: "target"})
	if err != nil {
		t.Fatal(err)
	}
	message := testMessage("resume-metadata")
	message.Flags = []string{`\Seen`}
	source := &memorySource{messages: []transport.Message{message}}
	target := &memoryTarget{receipts: map[string]transport.Message{}}
	engine := Engine{Store: store, Factory: memoryFactory{source, target}}
	if err = engine.Prepare(ctx, preview.ID); err != nil {
		t.Fatal(err)
	}
	item, err := store.Start(ctx, actor, preview.ID)
	if err != nil {
		t.Fatal(err)
	}
	records, err := store.Messages(ctx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	record := records[0]
	record.State, record.Hash = "appending", transport.ContentHash(message.Body)
	if err = store.Checkpoint(ctx, item.ID, record); err != nil {
		t.Fatal(err)
	}
	message.Identity.UID = 1
	target.receipts[record.Token] = message
	source.messages[0].Flags = nil
	if err = engine.Run(ctx, item.ID, item.Revision); err != nil {
		t.Fatal(err)
	}
	item, err = store.Load(ctx, item.ID)
	if err != nil || item.State != "complete" || target.appends != 0 {
		t.Fatalf("receipt recovery replaced the original append metadata: %+v appends=%d %v", item, target.appends, err)
	}
}

func TestMailImportCancellationQueuesCleanup(t *testing.T) {
	db := removaldb.New(t, "")
	queue := &countingImportQueue{}
	store := NewSQLStore(db, queue)
	ctx := context.Background()
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	preview, err := store.Preview(ctx, actor, types.MailImportRequest{MailboxID: fixtureMailbox(t, db), SourceKind: "imap", SourceHost: "mail.example.com", SourceSecretID: "source", TargetSecretID: "target"})
	if err != nil {
		t.Fatal(err)
	}
	item, err := store.Transition(ctx, actor, preview.ID, "cancel")
	if err != nil {
		t.Fatal(err)
	}
	if len(queue.args) != 1 || queue.args[0].ImportID != item.ID || queue.args[0].Revision != item.Revision {
		t.Fatalf("cancelled preview has no durable cleanup job: %+v", queue.args)
	}
}

type countingImportQueue struct{ args []ImportArgs }

func (q *countingImportQueue) InsertTx(_ context.Context, _ *sql.Tx, args river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	q.args = append(q.args, args.(ImportArgs))
	return &rivertype.JobInsertResult{}, nil
}

func TestExpiredMailImportPreviewRetiresSecretsAndQueuesCleanup(t *testing.T) {
	db := removaldb.New(t, "")
	ctx := context.Background()
	keyring, err := serveradmin.NewKeyring(1, map[int][]byte{1: bytes.Repeat([]byte{23}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	queue := &countingImportQueue{}
	store := NewSQLStore(db, queue, serveradmin.NewStore(db, keyring))
	sweeper, ok := any(store).(interface{ ExpirePreviews(context.Context) error })
	if !ok {
		t.Fatal("expired previews have no cleanup sweep")
	}
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	box := fixtureMailbox(t, db)
	preview, err := store.Preview(ctx, actor, types.MailImportRequest{MailboxID: box, SourceKind: "imap", SourceHost: "mail.example.com", SourcePassword: "source-secret", TargetPassword: "target-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE mail_imports SET expires_at=now()-interval '1 minute' WHERE id=$1`, preview.ID); err != nil {
		t.Fatal(err)
	}
	if err = sweeper.ExpirePreviews(ctx); err != nil {
		t.Fatal(err)
	}
	item, err := store.Load(ctx, preview.ID)
	if err != nil || item.State != "cancelled" || item.LastError == "" || len(queue.args) != 1 || queue.args[0].Revision != item.Revision {
		t.Fatalf("expired preview was not retired durably: %+v jobs=%+v %v", item, queue.args, err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM service_secrets WHERE scope='mail-import'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expired credentials retained: %d %v", count, err)
	}
	if err = sweeper.ExpirePreviews(ctx); err != nil || len(queue.args) != 1 {
		t.Fatal("expiry is not idempotent", err)
	}
}

func TestPreviewExpiryPreservesResumableImportsAndRollsBackQueueFailure(t *testing.T) {
	for _, state := range []string{"preview", "paused", "copying"} {
		t.Run(state, func(t *testing.T) {
			db := removaldb.New(t, "")
			ctx := context.Background()
			keyring, err := serveradmin.NewKeyring(1, map[int][]byte{1: bytes.Repeat([]byte{24}, 32)})
			if err != nil {
				t.Fatal(err)
			}
			store := NewSQLStore(db, failingQueue{}, serveradmin.NewStore(db, keyring))
			sweeper, ok := any(store).(interface{ ExpirePreviews(context.Context) error })
			if !ok {
				t.Fatal("expired previews have no cleanup sweep")
			}
			preview, err := store.Preview(ctx, auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, types.MailImportRequest{MailboxID: fixtureMailbox(t, db), SourceKind: "imap", SourceHost: "mail.example.com", SourcePassword: "source-secret", TargetPassword: "target-secret"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`UPDATE mail_imports SET expires_at=now()-interval '1 minute',state=$2 WHERE id=$1`, preview.ID, state); err != nil {
				t.Fatal(err)
			}
			err = sweeper.ExpirePreviews(ctx)
			if (state == "preview") != (err != nil) {
				t.Fatalf("unexpected expiry outcome for %s: %v", state, err)
			}
			item, err := store.Load(ctx, preview.ID)
			if err != nil || item.State != state {
				t.Fatalf("expiry changed preserved or unqueued state: %+v %v", item, err)
			}
			var secrets, audits int
			if err = db.QueryRow(`SELECT count(*) FROM service_secrets WHERE scope='mail-import'`).Scan(&secrets); err != nil || secrets != 2 {
				t.Fatalf("resumable credentials were retired: %d %v", secrets, err)
			}
			if err = db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='mail_import.expire'`).Scan(&audits); err != nil || audits != 0 {
				t.Fatalf("uncommitted expiry was audited: %d %v", audits, err)
			}
		})
	}
}

type retryRetirementStore struct {
	*SQLStore
	failOnce    bool
	retireCalls int
}

func (s *retryRetirementStore) Retire(ctx context.Context, id string) error {
	s.retireCalls++
	if s.failOnce {
		s.failOnce = false
		return errors.New("transient retirement failure")
	}
	return s.SQLStore.Retire(ctx, id)
}

type retryCleanupFactory struct {
	memoryFactory
	failOnce            bool
	cleanupCalls, opens int
}

func (f *retryCleanupFactory) Open(ctx context.Context, job Job) (Source, Target, error) {
	f.opens++
	return f.memoryFactory.Open(ctx, job)
}

func (f *retryCleanupFactory) Cleanup(context.Context, Job) error {
	f.cleanupCalls++
	if f.failOnce {
		f.failOnce = false
		return errors.New("transient staging cleanup failure")
	}
	return nil
}
func TestMailImportStartRollsBackOnEnqueueFailure(t *testing.T) {
	db := removaldb.New(t, "")
	ctx := context.Background()
	var box int64
	err := db.QueryRow(`INSERT INTO mail_domains(subscription_id,domain,enabled,effective_enabled,convergence_status) VALUES(1,'import.test',true,true,'in_sync') RETURNING id`).Scan(&box)
	if err != nil {
		t.Fatal(err)
	}
	err = db.QueryRow(`INSERT INTO mailboxes(mail_domain_id,local_part,password_hash) VALUES($1,'import','hash') RETURNING id`, box).Scan(&box)
	if err != nil {
		t.Fatal(err)
	}
	store := NewSQLStore(db, failingQueue{})
	preview, err := store.Preview(ctx, auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, types.MailImportRequest{MailboxID: box, SourceKind: "imap", SourceHost: "mail.example.com", SourcePort: 993, SourceUser: "source@example.com", SourceSecretID: "sec_source", TargetSecretID: "sec_target"})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Prepared(ctx, preview.ID); err != nil {
		t.Fatal(err)
	}
	_, err = store.Start(ctx, auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, preview.ID)
	if err == nil || err.Error() != "queue unavailable" {
		t.Fatal("accepted failed enqueue")
	}
	item, err := store.Load(ctx, preview.ID)
	if err != nil || item.State != "preview" {
		t.Fatalf("state changed despite rollback: %+v %v", item, err)
	}
}
func TestMailImportMigrationRoundTrip(t *testing.T) {
	db := removaldb.New(t, "20261015000054")
	data, err := os.ReadFile("../../../migrations/20261015000054_mail_import.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(data), "-- +goose Down", 2)
	for i := 0; i < 2; i++ {
		if _, err = db.Exec(parts[0]); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(parts[1]); err != nil {
			t.Fatal(err)
		}
	}
}
