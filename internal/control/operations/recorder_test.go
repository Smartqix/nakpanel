package operations_test

import (
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
	"testing"
)

type trackedBackupArgs struct {
	SiteID int64  `json:"site_id"`
	Domain string `json:"domain"`
}

func (trackedBackupArgs) Kind() string { return "create_backup" }

func TestRecorderKeepsAutomaticAttemptsAndTerminalEvents(t *testing.T) {
	db := testDB(t)
	driver := riverdatabasesql.New(db)
	m, err := rivermigrate.New(driver, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		t.Fatal(err)
	}
	if err = operations.InstallRecorder(ctx, db); err != nil {
		t.Fatal(err)
	}
	queue, err := river.NewClient(driver, &river.Config{})
	if err != nil {
		t.Fatal(err)
	}
	row, err := queue.Insert(ctx, trackedBackupArgs{SiteID: 51, Domain: "example.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	update := func(query string) {
		t.Helper()
		if _, err := db.Exec(query, row.Job.ID); err != nil {
			t.Fatal(err)
		}
	}
	update(`UPDATE river_job SET state='running',attempt=1,attempted_at=now() WHERE id=$1`)
	update(`UPDATE river_job SET state='retryable' WHERE id=$1`)
	update(`UPDATE river_job SET state='running',attempt=2,attempted_at=now() WHERE id=$1`)
	update(`UPDATE river_job SET state='discarded',finalized_at=now() WHERE id=$1`)
	// A repeated terminal write is not another occurrence or attempt.
	update(`UPDATE river_job SET state='discarded' WHERE id=$1`)
	s := operations.NewStore(db)
	p, err := s.Page(ctx, client, "issues", operations.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Issues) != 1 || p.Issues[0].Occurrences != 1 || p.Issues[0].OperationID == 0 {
		t.Fatalf("terminal dedupe: %#v", p)
	}
	d, err := s.Operation(ctx, client, p.Issues[0].OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Attempts) != 2 || d.Attempts[0].State != operations.StateFailed || d.Attempts[1].State != operations.StateFailed {
		t.Fatalf("automatic retry rewrote attempts: %#v", d)
	}
	if _, err = s.Dispatch(ctx, 100); err != nil {
		t.Fatal(err)
	}
	feed, err := s.Feed(ctx, client, 0, operations.Filter{})
	if err != nil || len(feed.Events) < 4 {
		t.Fatalf("missing transitions: %#v %v", feed, err)
	}
	var n int
	if err = db.QueryRow(`SELECT count(*) FROM notifications WHERE issue_id=$1`, p.Issues[0].ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("incident inbox dedupe: %d %v", n, err)
	}
}

func TestRecorderAndSourceTransitionRollbackTogether(t *testing.T) {
	db := testDB(t)
	driver := riverdatabasesql.New(db)
	m, err := rivermigrate.New(driver, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		t.Fatal(err)
	}
	if err = operations.InstallRecorder(ctx, db); err != nil {
		t.Fatal(err)
	}
	queue, err := river.NewClient(driver, &river.Config{})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = queue.InsertTx(ctx, tx, trackedBackupArgs{SiteID: 51, Domain: "example.test"}, nil); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = db.QueryRow(`SELECT count(*) FROM operations`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("operation survived source rollback: %d %v", n, err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM operation_events`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("event survived source rollback: %d %v", n, err)
	}
}

type trackedScheduledArgs struct {
	RunID int64 `json:"run_id"`
}

func (trackedScheduledArgs) Kind() string { return "run_scheduled_task" }
func TestRecorderUsesScheduledCommandOutcomeInsteadOfSuccessfulQueueCompletion(t *testing.T) {
	db := testDB(t)
	if _, err := db.Exec(`CREATE TABLE scheduled_tasks(id bigint PRIMARY KEY,site_id bigint,subscription_id bigint);CREATE TABLE scheduled_task_runs(id bigint PRIMARY KEY,task_id bigint,status text);INSERT INTO scheduled_tasks VALUES(10,51,42);INSERT INTO scheduled_task_runs VALUES(20,10,'failed')`); err != nil {
		t.Fatal(err)
	}
	driver := riverdatabasesql.New(db)
	m, err := rivermigrate.New(driver, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		t.Fatal(err)
	}
	if err = operations.InstallRecorder(ctx, db); err != nil {
		t.Fatal(err)
	}
	q, err := river.NewClient(driver, &river.Config{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := q.Insert(ctx, trackedScheduledArgs{RunID: 20}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE river_job SET state='completed',attempt=1,finalized_at=now() WHERE id=$1`, job.Job.ID); err != nil {
		t.Fatal(err)
	}
	p, err := operations.NewStore(db).Page(ctx, client, "tasks", operations.Filter{})
	if err != nil || len(p.Tasks) != 1 || p.Tasks[0].State != operations.StateFailed || p.Counts.OpenIssues != 1 {
		t.Fatalf("failed command reported success: %#v %v", p, err)
	}
}
