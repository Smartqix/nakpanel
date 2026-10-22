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

func TestBackupManagerSharedLegacyArchivePreservesUnselectedReference(t *testing.T) {
	db, first, approval := confirmedBackupFixture(t)
	var subscription, second int64
	if err := db.QueryRow(`INSERT INTO subscriptions(customer_user_id,customer_id,plan_id,name,status,sync_mode) SELECT customer_user_id,customer_id,plan_id,'legacy archive scope','active','synced' FROM subscriptions WHERE id=1 RETURNING id`).Scan(&subscription); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO backups(owner_user_id,customer_id,subscription_id,target_kind,target_name,status,archive_path,size_bytes) SELECT owner_user_id,customer_id,$2,'site','sibling.test','active',archive_path,size_bytes FROM backups WHERE id=$1 RETURNING id`, first, subscription).Scan(&second); err != nil {
		t.Fatal(err)
	}
	agent := &deleteAgent{response: types.Response{OK: true}}
	service := NewService(db, nil, agent)
	if err := service.deleteBackup(context.Background(), first, approval); err != nil {
		t.Fatal(err)
	}
	if len(agent.calls) != 0 {
		t.Fatal("unselected sibling's archive was deleted")
	}
	var secondApproval int64
	if _, err := db.Exec(`UPDATE backups SET status='deleting' WHERE id=$1`, second); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata) SELECT 1,customer_id,subscription_id,'backup.deletion_requested','backup',id,'{"confirmed":true,"source":"backup-manager"}' FROM backups WHERE id=$1 RETURNING id`, second).Scan(&secondApproval); err != nil {
		t.Fatal(err)
	}
	if err := service.deleteBackup(context.Background(), second, secondApproval); err != nil {
		t.Fatal(err)
	}
	if len(agent.calls) != 1 {
		t.Fatal("last confirmed reference did not remove its archive", len(agent.calls))
	}
}

func TestBackupManagerWorkerProtectsWordPressBeforeArchiveDeletion(t *testing.T) {
	for _, status := range []string{"waiting_backup", "succeeded"} {
		t.Run(status, func(t *testing.T) {
			db, backup, approval := confirmedBackupFixture(t)
			site := removaldb.Site(t, db, 1, "wordpress-safety.test", nil)
			var instance int64
			if err := db.QueryRow(`INSERT INTO wordpress_instances(subscription_id,site_id) VALUES(1,$1) RETURNING id`, site).Scan(&instance); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO wordpress_operations(subscription_id,instance_id,kind,backup_id,status) VALUES(1,$1,'update',$2,$3)`, instance, backup, status); err != nil {
				t.Fatal(err)
			}
			agent := &deleteAgent{response: types.Response{OK: true}}
			service := NewService(db, nil, agent)
			if err := service.deleteBackup(context.Background(), backup, approval); err == nil {
				t.Fatal("referenced WordPress backup was accepted for deletion")
			}
			if len(agent.calls) != 0 {
				t.Fatal("archive was removed before its WordPress reference was checked")
			}
			var path string
			if err := db.QueryRow(`SELECT archive_path FROM backups WHERE id=$1`, backup).Scan(&path); err != nil || path == "" {
				t.Fatalf("WordPress safety backup not preserved: %q %v", path, err)
			}
		})
	}
}
