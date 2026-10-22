package provision

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/workspace"
)

func backupManagerFixture(t *testing.T) (*sql.DB, *Manager, auth.SessionUser, int64, int64) {
	t.Helper()
	db, s, actor, _ := removalServiceFixture(t)
	var site int64
	if err := db.QueryRow(`SELECT id FROM sites WHERE domain='primary.test'`).Scan(&site); err != nil {
		t.Fatal(err)
	}
	var live, retained int64
	for i, target := range []string{"primary.test", "removed.test"} {
		var id int64
		var ownerSite any = site
		if i == 1 {
			ownerSite = nil
		}
		if err := db.QueryRow(`INSERT INTO backups(owner_user_id,customer_id,subscription_id,site_id,target_kind,target_name,status,archive_path,size_bytes,checksum_sha256) SELECT customer_user_id,customer_id,id,$1,'site',$2,'active','/var/lib/nakpanel/backups/'||$2||'.tar.gz',123,repeat('a',64) FROM subscriptions WHERE id=1 RETURNING id`, ownerSite, target).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			live = id
		} else {
			retained = id
		}
	}
	m := NewManager(nil, WithPhase6Repository(NewSQLPhase6Repository(db, s.river)), WithAccessPolicy(workspace.NewStore(db)))
	return db, m, actor, live, retained
}

func TestBackupManagerConfirmedRetainedRemovalIsAtomicAndSecretFree(t *testing.T) {
	db, m, actor, live, retained := backupManagerFixture(t)
	p, err := m.PreviewBackupRemovalFor(context.Background(), actor, 1, []int64{retained, live})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Items) != 2 || p.SizeBytes != 246 || !p.Items[1].Retained {
		t.Fatal(p)
	}
	if err = m.RemoveBackupsFor(context.Background(), actor, 1, []int64{live, retained}, p.Digest, false); err == nil {
		t.Fatal("confirmation not enforced")
	}
	var n int
	if err = db.QueryRow(`SELECT count(*) FROM backups WHERE status='active'`).Scan(&n); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if err = m.RemoveBackupsFor(context.Background(), actor, 1, []int64{live, retained}, p.Digest, true); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM backups WHERE status='deleting'`).Scan(&n); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	usage, err := controlquota.NewSQLStore(db).GetUsageForSubscription(context.Background(), 1)
	if err != nil || usage.BackupStorageBytes != 246 {
		t.Fatalf("queued deletion released storage: %+v %v", usage, err)
	}
	rows, err := db.Query(`SELECT args FROM river_job WHERE kind='maintenance_delete_backup' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var args DeleteBackupArgs
		if err = rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &args); err != nil || args.ApprovalID <= 0 {
			t.Fatal(string(raw), err)
		}
		var approved bool
		if err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM audit_events WHERE id=$1 AND actor_user_id=$2 AND target_id=$3 AND action='backup.deletion_requested')`, args.ApprovalID, actor.ID, args.BackupID).Scan(&approved); err != nil || !approved {
			t.Fatal(approved, err)
		}
		var values map[string]any
		json.Unmarshal(raw, &values)
		if len(values) != 2 {
			t.Fatalf("job contains more than IDs: %s", raw)
		}
	}
}

func TestBackupManagerRejectsStaleBusyAndMixedSelectionsWithoutIntent(t *testing.T) {
	for _, reason := range []string{"stale", "restore", "creation", "foreign", "enqueue", "audit"} {
		t.Run(reason, func(t *testing.T) {
			db, m, actor, live, _ := backupManagerFixture(t)
			p, err := m.PreviewBackupRemovalFor(context.Background(), actor, 1, []int64{live})
			if err != nil {
				t.Fatal(err)
			}
			ids := []int64{live}
			switch reason {
			case "stale":
				_, err = db.Exec(`UPDATE backups SET size_bytes=124 WHERE id=$1`, live)
			case "restore":
				_, err = db.Exec(`INSERT INTO restore_runs(owner_user_id,backup_id,target_name,status) VALUES(1,$1,'primary.test','pending')`, live)
			case "creation":
				_, err = db.Exec(`UPDATE backups SET status='failed' WHERE id=$1`, live)
				if err == nil {
					_, err = db.Exec(`INSERT INTO river_job(kind,args,state,queue,max_attempts) VALUES('create_backup',jsonb_build_object('backup_id',$1::bigint),'retryable','default',3)`, live)
				}
			case "foreign":
				ids = append(ids, 999999)
			default:
				table := "river_job"
				if reason == "audit" {
					table = "audit_events"
				}
				_, err = db.Exec(`CREATE FUNCTION reject_backup_removal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test failure'; END $$; CREATE TRIGGER reject_backup_removal BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_backup_removal()`)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = m.RemoveBackupsFor(context.Background(), actor, 1, ids, p.Digest, true)
			if err == nil {
				t.Fatal("unsafe removal accepted")
			}
			if (reason == "restore" || reason == "creation") && !errors.Is(err, ErrBackupBusy) {
				t.Fatal(err)
			}
			for _, query := range []string{`SELECT count(*) FROM backups WHERE status='deleting'`, `SELECT count(*) FROM river_job`, `SELECT count(*) FROM audit_events`} {
				var n int
				want := 0
				if reason == "creation" && query == `SELECT count(*) FROM river_job` {
					want = 1
				}
				if e := db.QueryRow(query).Scan(&n); e != nil || n != want {
					t.Fatal(query, n, e)
				}
			}
		})
	}
}

func TestBackupManagerRejectsRevivedCreationAfterRemoval(t *testing.T) {
	db, m, actor, live, _ := backupManagerFixture(t)
	var jobID int64
	if err := db.QueryRow(`INSERT INTO river_job(kind,args,state,queue,max_attempts,finalized_at) VALUES('create_backup',jsonb_build_object('backup_id',$1::bigint),'discarded','default',3,now()) RETURNING id`, live).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	p, err := m.PreviewBackupRemovalFor(context.Background(), actor, 1, []int64{live})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.RemoveBackupsFor(context.Background(), actor, 1, []int64{live}, p.Digest, true); err != nil {
		t.Fatal(err)
	}
	if err = (&SQLJobRetryStore{db: db}).RetryDiscardedProvisioningJob(context.Background(), jobID); !errors.Is(err, ErrJobNotRetryable) {
		t.Fatal("revived stale creation", err)
	}
	allowed, err := (&SQLPhase6StatusStore{db: db}).BackupJobAllowed(context.Background(), live)
	if err != nil || allowed {
		t.Fatal("stale creation reaches archive", allowed, err)
	}
}

func TestBackupManagerProtectsWordPressSafetyBackups(t *testing.T) {
	for _, status := range []string{"waiting_backup", "succeeded"} {
		t.Run(status, func(t *testing.T) {
			db, m, actor, live, _ := backupManagerFixture(t)
			preview, err := m.PreviewBackupRemovalFor(context.Background(), actor, 1, []int64{live})
			if err != nil {
				t.Fatal(err)
			}
			var instance int64
			if err = db.QueryRow(`INSERT INTO wordpress_instances(subscription_id,site_id) SELECT subscription_id,site_id FROM backups WHERE id=$1 RETURNING id`, live).Scan(&instance); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`INSERT INTO wordpress_operations(subscription_id,instance_id,kind,backup_id,status) VALUES(1,$1,'update',$2,$3)`, instance, live, status); err != nil {
				t.Fatal(err)
			}
			if _, err = m.PreviewBackupRemovalFor(context.Background(), actor, 1, []int64{live}); !errors.Is(err, ErrBackupBusy) {
				t.Fatalf("referenced backup preview must be protected: %v", err)
			}
			if err = m.RemoveBackupsFor(context.Background(), actor, 1, []int64{live}, preview.Digest, true); !errors.Is(err, ErrBackupBusy) {
				t.Fatalf("WordPress reference added after preview must prevent removal: %v", err)
			}
			var state string
			if err = db.QueryRow(`SELECT status FROM backups WHERE id=$1`, live).Scan(&state); err != nil || state != "active" {
				t.Fatalf("protected backup changed: %q %v", state, err)
			}
			var jobs int
			if err = db.QueryRow(`SELECT count(*) FROM river_job WHERE kind='maintenance_delete_backup'`).Scan(&jobs); err != nil || jobs != 0 {
				t.Fatalf("protected backup queued archive removal: %d %v", jobs, err)
			}
		})
	}
}
