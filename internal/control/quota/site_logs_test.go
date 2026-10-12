package quota

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nakroteck/nakpanel/internal/types"
)

func taskLogPostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("NAKPANEL_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		t.Skipf("local test PostgreSQL unavailable: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TEMP TABLE sites(id BIGINT,subscription_id BIGINT);
CREATE TEMP TABLE scheduled_tasks(id BIGINT,site_id BIGINT,subscription_id BIGINT,name TEXT);
CREATE TEMP TABLE scheduled_task_runs(id BIGINT,task_id BIGINT,status TEXT,output TEXT,finished_at TIMESTAMPTZ);
INSERT INTO sites VALUES(7,4),(99,5);
INSERT INTO scheduled_tasks VALUES(3,7,4,'runner'),(4,99,5,'foreign'),(5,7,5,'wrong owner');
INSERT INTO scheduled_task_runs VALUES(1,3,'succeeded',E'first\nsecond','2026-01-01T00:00:00Z'),(2,4,'succeeded','foreign secret','2026-01-01T00:00:01Z'),(3,5,'succeeded','wrong owner secret','2026-01-01T00:00:02Z'),(4,3,'running','unfinished',NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestPostgresTaskLogReadsCompletedRunsWithStableByteCursor(t *testing.T) {
	db := taskLogPostgres(t)
	s := NewSQLStore(db)
	req := types.SiteLogRequest{Source: types.SiteLogTask, LineLimit: 1, ByteLimit: 4096}
	result, err := s.ReadScheduledTaskLog(context.Background(), 7, req)
	header := "Task 3 run 1 [succeeded]"
	if err != nil || len(result.Lines) != 1 || result.Lines[0] != header || result.NextCursor != int64(len(header)+1) || !result.Truncated {
		t.Fatalf("first page=%#v err=%v", result, err)
	}
	req.Cursor = result.NextCursor
	result, err = s.ReadScheduledTaskLog(context.Background(), 7, req)
	if err != nil || len(result.Lines) != 1 || result.Lines[0] != "first" {
		t.Fatalf("second page=%#v err=%v", result, err)
	}
	req.Cursor = 0
	req.LineLimit = 20
	req.Search = "second"
	result, err = s.ReadScheduledTaskLog(context.Background(), 7, req)
	if err != nil || len(result.Lines) != 1 || result.Lines[0] != "second" || result.Truncated {
		t.Fatalf("filtered log=%#v err=%v", result, err)
	}
	req.Search = ""
	req.Cursor = 99999
	result, err = s.ReadScheduledTaskLog(context.Background(), 7, req)
	if err != nil || !result.Rotated || strings.Contains(strings.Join(result.Lines, "\n"), "secret") || strings.Contains(strings.Join(result.Lines, "\n"), "unfinished") {
		t.Fatalf("rotated log=%#v err=%v", result, err)
	}
}

func TestPostgresTaskLogEmptyAndOversizedOutputAreBounded(t *testing.T) {
	db := taskLogPostgres(t)
	s := NewSQLStore(db)
	req := types.SiteLogRequest{Source: types.SiteLogTask, LineLimit: 20, ByteLimit: 1024}
	empty, err := s.ReadScheduledTaskLog(context.Background(), 100, req)
	if err != nil || empty.Lines == nil || len(empty.Lines) != 0 || empty.NextCursor != 0 {
		t.Fatalf("empty=%#v err=%v", empty, err)
	}
	if _, err := db.Exec(`INSERT INTO scheduled_task_runs VALUES(5,3,'failed',$1,'2026-01-01T00:00:03Z')`, strings.Repeat("x", 10000)); err != nil {
		t.Fatal(err)
	}
	result, err := s.ReadScheduledTaskLog(context.Background(), 7, req)
	if err != nil || result.NextCursor != 1024 || !result.Truncated || len(result.Lines) > 20 || len(strings.Join(result.Lines, "\n")) > 1024 {
		t.Fatalf("bounded=%#v err=%v", result, err)
	}
	for _, bad := range []types.SiteLogRequest{{Source: types.SiteLogTask, Cursor: -1}, {Source: types.SiteLogTask, LineLimit: 1001}, {Source: types.SiteLogTask, ByteLimit: 1}} {
		if _, err := s.ReadScheduledTaskLog(context.Background(), 7, bad); err == nil {
			t.Fatal("invalid log bounds accepted")
		}
	}
}

func TestPostgresTaskLogCursorSurvivesOutOfOrderCompletion(t *testing.T) {
	db := taskLogPostgres(t)
	_, err := db.Exec(`DELETE FROM scheduled_task_runs;
INSERT INTO scheduled_task_runs VALUES(1,3,'running','older started run',NULL),(2,3,'succeeded','second run completed first','2026-01-01T00:00:00Z');`)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSQLStore(db)
	req := types.SiteLogRequest{Source: types.SiteLogTask, LineLimit: 20, ByteLimit: 4096}
	first, err := s.ReadScheduledTaskLog(context.Background(), 7, req)
	if err != nil || !strings.Contains(strings.Join(first.Lines, "\n"), "second run completed first") {
		t.Fatalf("initial log=%#v err=%v", first, err)
	}
	if _, err := db.Exec(`UPDATE scheduled_task_runs SET status='succeeded',output='older run finished later',finished_at='2026-01-01T00:00:01Z' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	req.Cursor = first.NextCursor
	if _, err := db.Exec(`UPDATE scheduled_tasks SET name='renamed task with a different header length' WHERE id=3`); err != nil {
		t.Fatal(err)
	}
	resumed, err := s.ReadScheduledTaskLog(context.Background(), 7, req)
	text := strings.Join(resumed.Lines, "\n")
	if err != nil || !strings.Contains(text, "older run finished later") || strings.Contains(text, "second run completed first") {
		t.Fatalf("completion moved old byte offsets: %#v err=%v", resumed, err)
	}
}

func TestPostgresTaskLogRedactsSiteRegisteredSecrets(t *testing.T) {
	db := taskLogPostgres(t)
	_, err := db.Exec(`CREATE TEMP TABLE php_applications(id BIGINT,site_id BIGINT);
CREATE TEMP TABLE service_secrets(id BIGINT,scope TEXT,name TEXT);
CREATE TEMP TABLE php_environment_bindings(application_id BIGINT,secret_id BIGINT,secret_scope TEXT);
INSERT INTO php_applications VALUES(31,7);
INSERT INTO service_secrets VALUES(5,'php.application.31','env.APP_KEY');
INSERT INTO php_environment_bindings VALUES(31,5,'php.application.31');
UPDATE scheduled_task_runs SET output='echoed very-secret-value' WHERE id=1;`)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSQLStore(db)
	s.phpLogSecrets = fakePHPLogSecretReader{value: "very-secret-value"}
	result, err := s.ReadScheduledTaskLog(context.Background(), 7, types.SiteLogRequest{Source: types.SiteLogTask})
	if err != nil {
		t.Fatal(err)
	}
	cursor := result.NextCursor
	result.Lines, err = s.RedactPHPEnvironmentSecrets(context.Background(), 7, result.Lines)
	if err != nil || strings.Contains(strings.Join(result.Lines, "\n"), "very-secret-value") || !strings.Contains(strings.Join(result.Lines, "\n"), "[REDACTED]") || result.NextCursor != cursor {
		t.Fatalf("registered secret not redacted: %#v err=%v", result, err)
	}
}
