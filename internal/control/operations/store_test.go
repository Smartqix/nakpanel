package operations_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"github.com/nakroteck/nakpanel/internal/control/quota"
)

func isolatedDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("NAKPANEL_OPERATIONS_TEST_DSN")
	if dsn == "" {
		t.Skip("set NAKPANEL_OPERATIONS_TEST_DSN to a dedicated local test database")
	}
	c, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test database configuration")
	}
	if !strings.HasPrefix(c.Database, "nakpanel_operations_") {
		t.Fatal("requires a dedicated nakpanel_operations_ test database")
	}
	local := func(h string) bool {
		return h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasPrefix(h, "/")
	}
	if !local(c.Host) {
		t.Fatal("operations tests require local PostgreSQL")
	}
	for _, f := range c.Fallbacks {
		if !local(f.Host) {
			t.Fatal("remote test fallback is forbidden")
		}
	}
	admin := stdlib.OpenDB(*c)
	schema := fmt.Sprintf("operations_%d", time.Now().UnixNano())
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	c.RuntimeParams["search_path"] = schema
	c.RuntimeParams["statement_timeout"] = "5s"
	db := stdlib.OpenDB(*c)
	db.SetMaxOpenConns(12)
	t.Cleanup(func() { db.Close(); _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); admin.Close() })
	return db
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db := isolatedDB(t)
	_, err := db.Exec(`CREATE TABLE users(id bigint PRIMARY KEY,role text,email text);
 CREATE TABLE reseller_accounts(id bigint PRIMARY KEY,login_user_id bigint,status text DEFAULT 'active');
 CREATE TABLE customers(id bigint PRIMARY KEY,login_user_id bigint,reseller_id bigint,status text DEFAULT 'active',display_name text DEFAULT 'Example customer');
 CREATE TABLE subscriptions(id bigint PRIMARY KEY,customer_id bigint,status text DEFAULT 'active',name text DEFAULT 'Example subscription');
 CREATE TABLE sites(id bigint PRIMARY KEY,subscription_id bigint,status text DEFAULT 'active',domain text DEFAULT 'example.test');
 CREATE TABLE backups(id bigserial PRIMARY KEY);
 CREATE TABLE security_settings(id boolean PRIMARY KEY,alert_email text);
 CREATE TABLE notifications(id bigserial PRIMARY KEY,recipient_user_id bigint,customer_id bigint,reseller_id bigint,subscription_id bigint,kind text,severity text,title text,body text,dedupe_key text,read_at timestamptz,resolved_at timestamptz,created_at timestamptz DEFAULT now(),updated_at timestamptz DEFAULT now());
 CREATE UNIQUE INDEX notifications_open_dedupe_idx ON notifications(dedupe_key) WHERE resolved_at IS NULL;
 ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check CHECK(kind IS NOT NULL);
 INSERT INTO users VALUES(1,'admin','admin@example.test'),(2,'admin','second@example.test'),(11,'client','one@example.test'),(22,'client','two@example.test'),(100,'reseller','provider@example.test'),(200,'reseller','other@example.test');
 INSERT INTO reseller_accounts(id,login_user_id) VALUES(7,100),(8,200);
 INSERT INTO customers(id,login_user_id,reseller_id) VALUES(10,11,7),(20,22,8);
 INSERT INTO subscriptions(id,customer_id) VALUES(42,10),(99,20);
 INSERT INTO sites(id,subscription_id) VALUES(51,42),(52,42),(91,99);
 ALTER TABLE users ADD COLUMN login_disabled boolean NOT NULL DEFAULT false;`)
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("../../../migrations/202610230000*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(strings.SplitN(string(data), "-- +goose Down", 2)[0]); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	return db
}

func TestCurrentMigrationAppliesToCompleteSchemaAndRollsBack(t *testing.T) {
	db := isolatedDB(t)
	files, err := filepath.Glob("../../../migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(strings.SplitN(string(data), "-- +goose Down", 2)[0]); err != nil {
			t.Fatalf("%s: %v", filepath.Base(path), err)
		}
	}
	var oldReadColumn bool
	if err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='notifications' AND column_name='read_at')`).Scan(&oldReadColumn); err != nil || oldReadColumn {
		t.Fatalf("shared read state remains: %v %v", oldReadColumn, err)
	}
	if _, err = db.Exec(`SELECT user_id,read_at FROM notification_receipts LIMIT 0`); err != nil {
		t.Fatal(err)
	}
	for index := len(files) - 1; index >= 0; index-- {
		if filepath.Base(files[index]) < "20261023000057" {
			break
		}
		data, err := os.ReadFile(files[index])
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(strings.SplitN(string(data), "-- +goose Down", 2)[1]); err != nil {
			t.Fatalf("rollback %s: %v", files[index], err)
		}
	}
}

func TestDatabaseRejectsInvalidResourceIdentity(t *testing.T) {
	db := testDB(t)
	if _, err := db.Exec(`INSERT INTO operations(operation_key,kind,resource_kind,resource_id,title,trigger) VALUES('invalid-server','health','server',42,'Health','system')`); err == nil {
		t.Fatal("database accepted a fabricated server resource ID")
	}
}

var ctx = context.Background()
var admin = auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
var client = auth.SessionUser{ID: 11, Role: auth.RoleClient}

func observation(key string, site int64) operations.Observation {
	return operations.Observation{EventKey: key, Resource: operations.Resource{Kind: operations.ResourceSite, ID: site}, Kind: "backup", Condition: "daily", Severity: "critical", Title: "Backup is overdue", Summary: "No verified fresh archive", IntentRevision: 3, ObservedAt: time.Now().UTC()}
}

func TestIncidentIdentityAndDuplicateEvents(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	a, err := s.ObserveIssue(ctx, observation("first", 51))
	if err != nil {
		t.Fatal(err)
	}
	same, err := s.ObserveIssue(ctx, observation("first", 51))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.ObserveIssue(ctx, observation("second", 51))
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.ObserveIssue(ctx, observation("other-resource", 52))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != same.ID || same.Occurrences != 1 || b.ID != a.ID || b.Occurrences != 2 || b.Generation != 2 || other.ID == a.ID {
		t.Fatalf("incident dedupe failed: %#v %#v %#v %#v", a, same, b, other)
	}
	var events int
	if err = db.QueryRow(`SELECT count(*) FROM operation_events`).Scan(&events); err != nil || events != 3 {
		t.Fatalf("events=%d err=%v", events, err)
	}
	if _, err = s.ObserveIssue(ctx, observation("first", 91)); !errors.Is(err, operations.ErrConflict) {
		t.Fatalf("event identity reused for another resource: %v", err)
	}
}

func TestIncidentAndEventRollbackTogether(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ObserveIssueTx(ctx, tx, observation("rolled-back", 51)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT count(*) FROM issues`).Scan(&n)
	if n != 0 {
		t.Fatal("incident survived rollback")
	}
	db.QueryRow(`SELECT count(*) FROM operation_events`).Scan(&n)
	if n != 0 {
		t.Fatal("outbox event survived rollback")
	}
}

func TestConcurrentIncidentDedupe(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.ObserveIssue(ctx, observation(fmt.Sprintf("sample-%d", i), 51))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var rows, occ int
	err := db.QueryRow(`SELECT count(*),sum(occurrences) FROM issues`).Scan(&rows, &occ)
	if err != nil || rows != 1 || occ != 12 {
		t.Fatalf("rows=%d occurrences=%d err=%v", rows, occ, err)
	}
}

func TestNotificationReadStateIsPersonalAndDoesNotResolve(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	var id int64
	err := db.QueryRow(`INSERT INTO notifications(subscription_id,kind,severity,title,body,dedupe_key) VALUES(42,'threshold','warning','Disk usage','Usage is high','usage:42') RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.MarkNotificationRead(ctx, client, id); err != nil {
		t.Fatal(err)
	}
	if err = s.MarkNotificationRead(ctx, client, id); err != nil {
		t.Fatal(err)
	}
	var receipts, resolved int
	db.QueryRow(`SELECT count(*) FROM notification_receipts WHERE notification_id=$1`, id).Scan(&receipts)
	db.QueryRow(`SELECT count(*) FROM notifications WHERE resolved_at IS NOT NULL`).Scan(&resolved)
	if receipts != 1 || resolved != 0 {
		t.Fatalf("receipts=%d resolved=%d", receipts, resolved)
	}
	if err = s.MarkNotificationRead(ctx, auth.SessionUser{ID: 22, Role: auth.RoleClient}, id); !errors.Is(err, operations.ErrNotFound) {
		t.Fatalf("cross tenant read allowed: %v", err)
	}
	if err = s.MarkNotificationRead(ctx, admin, id); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(`SELECT count(*) FROM notification_receipts WHERE notification_id=$1`, id).Scan(&receipts)
	if receipts != 2 {
		t.Fatal("users share receipt state")
	}
}

func TestQuotaAlertsUseViewerReceiptAndFailClosed(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	var id int64
	if err := db.QueryRow(`INSERT INTO notifications(subscription_id,kind,severity,title,body,dedupe_key) VALUES(42,'threshold','warning','Usage','Usage is high','usage:42') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkNotificationRead(ctx, client, id); err != nil {
		t.Fatal(err)
	}
	q := quota.NewSQLStore(db)
	own, err := q.ListUsageAlerts(ctx, client, 50)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := q.ListUsageAlerts(ctx, admin, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(own) != 1 || own[0].ReadAt.IsZero() || len(provider) != 1 || !provider[0].ReadAt.IsZero() {
		t.Fatalf("receipt leaked between viewers: %#v %#v", own, provider)
	}
	denied, err := q.ListUsageAlerts(ctx, auth.SessionUser{ID: 22, Role: auth.RoleClient}, 50)
	if err != nil || len(denied) != 0 {
		t.Fatalf("cross tenant alerts: %#v %v", denied, err)
	}
	denied, err = q.ListUsageAlerts(ctx, auth.SessionUser{ID: 11, Role: auth.RoleAdmin}, 50)
	if err != nil || len(denied) != 0 {
		t.Fatalf("stale role alerts: %#v %v", denied, err)
	}
}

func TestAcknowledgementLeavesIssueOpenAndRechecksOwnership(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	issue, err := s.ObserveIssue(ctx, observation("failure", 51))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AcknowledgeIssue(ctx, client, issue.ID); err != nil {
		t.Fatal(err)
	}
	var by int64
	var resolved sql.NullTime
	db.QueryRow(`SELECT acknowledged_by,resolved_at FROM issues WHERE id=$1`, issue.ID).Scan(&by, &resolved)
	if by != 11 || resolved.Valid {
		t.Fatal("acknowledgement resolved the issue")
	}
	if _, err = db.Exec(`UPDATE subscriptions SET customer_id=20 WHERE id=42`); err != nil {
		t.Fatal(err)
	}
	if err = s.AcknowledgeIssue(ctx, client, issue.ID); !errors.Is(err, operations.ErrNotFound) {
		t.Fatalf("former owner acknowledged: %v", err)
	}
}

func TestAttemptOutcomesCannotBeRewritten(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	op, err := s.CreateOperation(ctx, operations.NewOperation{Key: "backup:one", Kind: "create_backup", Resource: operations.Resource{Kind: operations.ResourceSite, ID: 51}, Title: "Create backup", Trigger: "manual", IntentRevision: 3})
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.StartAttempt(ctx, op.ID, 900)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FinishAttempt(ctx, a.ID, operations.StateFailed, "archive_unavailable"); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishAttempt(ctx, a.ID, operations.StateSucceeded, ""); !errors.Is(err, operations.ErrConflict) {
		t.Fatalf("original failure overwritten: %v", err)
	}
	b, err := s.StartAttempt(ctx, op.ID, 901)
	if err != nil {
		t.Fatal(err)
	}
	if b.Number != 2 || a.ID == b.ID {
		t.Fatal("retry reused the failed attempt")
	}
	if err = s.FinishAttempt(ctx, b.ID, operations.StateSucceeded, ""); err != nil {
		t.Fatal(err)
	}
	var state string
	db.QueryRow(`SELECT state FROM operation_attempts WHERE id=$1`, a.ID).Scan(&state)
	if state != "failed" {
		t.Fatal("recovery rewrote failure")
	}
}
