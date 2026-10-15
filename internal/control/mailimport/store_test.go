package mailimport

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type failingQueue struct{}

func (failingQueue) InsertTx(context.Context, *sql.Tx, river.JobArgs, *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	return nil, errors.New("queue unavailable")
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
	_, err = store.Start(ctx, auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, preview.ID)
	if err == nil {
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
