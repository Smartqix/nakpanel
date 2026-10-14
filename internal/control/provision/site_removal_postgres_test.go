package provision

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/workspace"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
)

func removalServiceFixture(t *testing.T) (*sql.DB, *SiteRemovalService, auth.SessionUser, types.RemoveSiteReq) {
	t.Helper()
	db := removaldb.New(t, "")
	driver := riverdatabasesql.New(db)
	migrator, err := rivermigrate.New(driver, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = migrator.Migrate(context.Background(), rivermigrate.DirectionUp, nil); err != nil {
		t.Fatal(err)
	}
	client, err := river.NewClient(driver, &river.Config{})
	if err != nil {
		t.Fatal(err)
	}
	removaldb.Site(t, db, 1, "primary.test", nil)
	addon := removaldb.Site(t, db, 1, "addon.test", nil)
	removaldb.Site(t, db, 1, "child.addon.test", addon)
	service := NewSiteRemovalService(db, client, workspace.NewStore(db), SiteRemovalOptions{})
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin, Email: "admin@nakpanel.test"}
	preview, err := service.PreviewSiteRemoval(context.Background(), actor, addon)
	if err != nil {
		t.Fatal(err)
	}
	req := types.RemoveSiteReq{SiteID: addon, RequestID: strings.Repeat("a", 32), PreviewDigest: preview.Digest, ConfirmDomain: preview.Domain, AcknowledgePermanent: true, IncludeChildren: true}
	return db, service, actor, req
}

func TestSiteRemovalReservationAtomicPostgreSQL(t *testing.T) {
	for _, failure := range []string{"", "enqueue", "audit"} {
		t.Run(failure, func(t *testing.T) {
			db, service, actor, req := removalServiceFixture(t)
			if failure != "" {
				table := "river_job"
				if failure == "audit" {
					table = "audit_events"
				}
				if _, err := db.Exec("CREATE FUNCTION reject_removal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected failure'; END $$; CREATE TRIGGER reject_removal BEFORE INSERT ON " + table + " FOR EACH ROW EXECUTE FUNCTION reject_removal()"); err != nil {
					t.Fatal(err)
				}
			}
			op, err := service.RemoveSiteFor(context.Background(), actor, req)
			expected := 1
			if failure != "" {
				expected = 0
				if err == nil {
					t.Fatal("injected failure committed")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			for _, table := range []string{"site_removal_operations", "river_job", "audit_events"} {
				var count int
				if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != expected {
					t.Fatalf("%s count=%d err=%v", table, count, err)
				}
			}
			var marked int
			if err := db.QueryRow("SELECT count(*) FROM sites WHERE removal_state<>'none'").Scan(&marked); err != nil || marked != expected*2 {
				t.Fatalf("markers=%d %v", marked, err)
			}
			if failure == "" {
				var args string
				if err := db.QueryRow("SELECT args::text FROM river_job WHERE kind='remove_site'").Scan(&args); err != nil {
					t.Fatal(err)
				}
				var fields map[string]any
				json.Unmarshal([]byte(args), &fields)
				if len(fields) != 2 || fields["operation_id"] != float64(op.ID) || fields["revision"] != float64(1) {
					t.Fatalf("non-ID arguments: %s", args)
				}
			}
		})
	}
}

func TestSiteRemovalPreviewChangedPostgreSQL(t *testing.T) {
	db, service, actor, req := removalServiceFixture(t)
	removaldb.Site(t, db, 1, "new.addon.test", req.SiteID)
	if _, err := service.RemoveSiteFor(context.Background(), actor, req); err == nil {
		t.Fatal("changed preview accepted")
	}
	var count int
	db.QueryRow("SELECT count(*) FROM site_removal_operations").Scan(&count)
	if count != 0 {
		t.Fatal("partial operation")
	}
}

func TestSiteRemovalDuplicateRequestPostgreSQL(t *testing.T) {
	db, service, actor, req := removalServiceFixture(t)
	first, err := service.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	again, err := service.RemoveSiteFor(context.Background(), actor, req)
	if err != nil || first.ID != again.ID {
		t.Fatalf("duplicate: %#v %v", again, err)
	}
	preview, err := service.PreviewSiteRemoval(context.Background(), actor, req.SiteID)
	if err != nil || preview.Allowed || preview.Operation == nil || preview.Operation.ID != first.ID {
		t.Fatalf("pending preview lost operation: %#v %v", preview, err)
	}
	req.SiteID = removaldb.Site(t, db, 1, "other.test", nil)
	if _, err := service.RemoveSiteFor(context.Background(), actor, req); err == nil {
		t.Fatal("nonce reused for different site")
	}
	var count int
	db.QueryRow("SELECT count(*) FROM river_job").Scan(&count)
	if count != 1 {
		t.Fatal("duplicate jobs")
	}
}

func TestSiteRemovalConcurrentReservationsPostgreSQL(t *testing.T) {
	db, service, actor, req := removalServiceFixture(t)
	if db.Stats().MaxOpenConnections < 2 {
		t.Fatal("concurrency fixture uses only one database connection")
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, nonce := range []string{"b", "c"} {
		wg.Add(1)
		go func(nonce string) {
			defer wg.Done()
			request := req
			request.RequestID = strings.Repeat(nonce, 32)
			_, err := service.RemoveSiteFor(context.Background(), actor, request)
			results <- err
		}(nonce)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successful reservations=%d", success)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM site_removal_targets WHERE NOT released").Scan(&count); err != nil || count != 2 {
		t.Fatalf("targets=%d %v", count, err)
	}
}

func TestSiteRemovalRetryAndHistoricalScopePostgreSQL(t *testing.T) {
	db, service, actor, req := removalServiceFixture(t)
	op, err := service.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	changed := req
	changed.DeleteDatabaseIDs = []int64{999}
	if _, err := service.RemoveSiteFor(context.Background(), actor, changed); err == nil {
		t.Fatal("replayed request expanded approved database choices")
	}
	if _, err := db.Exec("UPDATE site_removal_operations SET state='failed',checkpoints=ARRAY['stopped'],last_error='safe failure' WHERE id=$1", op.ID); err != nil {
		t.Fatal(err)
	}
	retry, err := service.RetrySiteRemovalFor(context.Background(), actor, op.ID)
	if err != nil || retry.Revision != 2 || len(retry.Checkpoints) != 1 || retry.Domain != op.Domain {
		t.Fatalf("retry=%#v %v", retry, err)
	}
	if _, err := service.SiteRemovalFor(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, op.ID); err == nil {
		t.Fatal("foreign history visible")
	}
	result, err := service.SiteRemovalByRequestFor(context.Background(), actor, req.RequestID)
	if err != nil || result.ID != op.ID {
		t.Fatalf("request recovery=%#v %v", result, err)
	}
	if _, err := db.Exec("UPDATE site_removal_operations SET state='completed',stage='completed',completed_at=now() WHERE id=$1", op.ID); err != nil {
		t.Fatal(err)
	}
	finished, err := service.RetrySiteRemovalFor(context.Background(), actor, op.ID)
	if err != nil || finished.Revision != 2 || finished.State != "completed" {
		t.Fatalf("completed retry=%#v %v", finished, err)
	}
}
