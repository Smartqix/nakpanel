package maintenance

import (
	"context"
	"database/sql"
	"errors"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
	"strings"
	"testing"
)

func confirmedBackupFixture(t *testing.T) (*sql.DB, int64, int64) {
	t.Helper()
	db := removaldb.New(t, "")
	migrator, err := rivermigrate.New(riverdatabasesql.New(db), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = migrator.Migrate(context.Background(), rivermigrate.DirectionUp, nil); err != nil {
		t.Fatal(err)
	}
	var id, approval int64
	if err = db.QueryRow(`INSERT INTO backups(owner_user_id,customer_id,subscription_id,target_kind,target_name,status,archive_path,size_bytes) SELECT customer_user_id,customer_id,id,'site','retained.test','deleting','/var/lib/nakpanel/backups/retained.tar.gz',123 FROM subscriptions WHERE id=1 RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata) SELECT 1,customer_id,1,'backup.deletion_requested','backup',id,'{"confirmed":true,"source":"backup-manager"}' FROM backups WHERE id=$1 RETURNING id`, id).Scan(&approval); err != nil {
		t.Fatal(err)
	}
	return db, id, approval
}

func TestBackupManagerWorkerRetainedDeletionFailureAndRecovery(t *testing.T) {
	for _, scenario := range []string{"success", "failure", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			db, id, approval := confirmedBackupFixture(t)
			agent := &deleteAgent{response: types.Response{OK: true}}
			service := NewService(db, nil, agent)
			if scenario == "failure" {
				agent.err = errors.New("private-sentinel-path /var/lib/nakpanel/backups/private.tar.gz")
			}
			if scenario == "cancelled" {
				if err := service.enqueuePrunes(context.Background(), 0); err != nil {
					t.Fatal(err)
				}
				var status string
				if err := db.QueryRow(`SELECT status FROM backups WHERE id=$1`, id).Scan(&status); err != nil || status != "delete_failed" {
					t.Fatal(status, err)
				}
				if len(agent.calls) != 0 {
					t.Fatal("repair deleted archive")
				}
				return
			}
			err := service.deleteBackup(context.Background(), id, approval)
			if scenario == "success" {
				if err != nil {
					t.Fatal(err)
				}
				if err = service.deleteBackup(context.Background(), id, approval); err != nil {
					t.Fatal("not idempotent", err)
				}
				var count int
				if err = db.QueryRow(`SELECT count(*) FROM backups WHERE id=$1`, id).Scan(&count); err != nil || count != 0 {
					t.Fatal(count, err)
				}
			} else {
				if err == nil || strings.Contains(err.Error(), "private-sentinel") {
					t.Fatal("unredacted failure", err)
				}
				var status string
				if err = db.QueryRow(`SELECT status FROM backups WHERE id=$1`, id).Scan(&status); err != nil || status != "delete_failed" {
					t.Fatal(status, err)
				}
				var leaks int
				if err = db.QueryRow(`SELECT count(*) FROM audit_events WHERE metadata::text LIKE '%private-sentinel%'`).Scan(&leaks); err != nil || leaks != 0 {
					t.Fatal("audit leaked path", leaks, err)
				}
			}
		})
	}
}
