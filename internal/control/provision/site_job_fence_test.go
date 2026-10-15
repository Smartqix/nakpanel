package provision

import (
	"context"
	"encoding/json"
	"github.com/riverqueue/river/rivertype"
	"testing"
	"time"
)

func TestRemovalFenceStopsWorkBeforeAgent(t *testing.T) {
	db, s, actor, req := removalServiceFixture(t)
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	guard := NewSiteJobFence(db)
	called := false
	args, _ := json.Marshal(CreateSiteArgs{SiteID: op.SiteID, Domain: op.Domain})
	err = guard.Work(context.Background(), &rivertype.JobRow{Kind: "create_site", EncodedArgs: args}, func(context.Context) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("removing site worker reached agent", err)
	}
	args, _ = json.Marshal(CreateSiteArgs{SiteID: 1, Domain: "primary.test"})
	called = false
	if err = guard.Work(context.Background(), &rivertype.JobRow{Kind: "create_site", EncodedArgs: args}, func(context.Context) error { called = true; return nil }); err != nil || !called {
		t.Fatal("sibling work blocked", err)
	}
}

func TestRemovalFenceDoesNotCancelSharedJobs(t *testing.T) {
	db, _, _, _ := removalServiceFixture(t)
	called := false
	if err := NewSiteJobFence(db).Work(context.Background(), &rivertype.JobRow{Kind: "configure_mail"}, func(context.Context) error { called = true; return nil }); err != nil || !called {
		t.Fatal("shared job cancelled", err)
	}
}

func TestRemovalFenceClassifiesEveryTargetKind(t *testing.T) {
	args := removalFenceArgs{SiteID: 1, ApplicationID: 1, InstanceID: 1, ZoneID: 1, WebmailID: 1, BackupID: 1, DatabaseID: 1, RunID: 1, OperationID: json.RawMessage("1"), ImportID: "imp_fixture"}
	for kind, class := range removalJobClassification {
		if class == "target" {
			query, id := removalFenceQuery(kind, args)
			var expected any = int64(1)
			if kind == "mail_import" {
				expected = "imp_fixture"
			}
			if query == "" || id != expected {
				t.Errorf("target kind lacks scoped worker guard: %s", kind)
			}
		}
	}
}

func TestRemovalFenceDoesNotSubstituteDomainForMissingResourceID(t *testing.T) {
	db, _, _, _ := removalServiceFixture(t)
	called := false
	args := []byte(`{"database_id":0,"domain":"primary.test"}`)
	err := NewSiteJobFence(db).Work(context.Background(), &rivertype.JobRow{Kind: "create_database", EncodedArgs: args}, func(context.Context) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("resource identity replaced by unrelated domain", err)
	}
}

func TestRemovalFenceServerBackupExcludesPhysicalRemoval(t *testing.T) {
	db, _, _, _ := removalServiceFixture(t)
	ctx := context.Background()
	backup, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	if _, err = backup.ExecContext(ctx, `SELECT pg_advisory_lock(hashtextextended('nakpanel:server-snapshot',0))`); err != nil {
		t.Fatal(err)
	}
	defer backup.ExecContext(ctx, `SELECT pg_advisory_unlock(hashtextextended('nakpanel:server-snapshot',0))`)
	worker, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	deadline, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if err = acquireServerSnapshotGate(deadline, worker, true); err == nil {
		releaseServerSnapshotGate(worker, true)
		t.Fatal("physical removal can overlap a server intent/state backup")
	}
}
