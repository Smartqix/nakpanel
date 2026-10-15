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
