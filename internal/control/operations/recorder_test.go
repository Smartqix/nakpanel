package operations_test

import (
	"database/sql"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
	"testing"
)

func recorderQueue(t *testing.T, db *sql.DB) *river.Client[*sql.Tx] {
	t.Helper()
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
	return q
}

type trackedServerBackupArgs struct {
	ID int64 `json:"server_backup_id"`
}

func (trackedServerBackupArgs) Kind() string { return "server_backup" }

type trackedCertArgs struct {
	SiteID            int64 `json:"site_id"`
	AfterProvisioning bool  `json:"after_provisioning"`
}

func (trackedCertArgs) Kind() string { return "issue_cert" }

func TestRecorderSeparatesTasksAndBackupDestinationsWithinOneScope(t *testing.T) {
	db := testDB(t)
	if _, err := db.Exec(`CREATE TABLE scheduled_tasks(id bigint PRIMARY KEY,site_id bigint,subscription_id bigint);CREATE TABLE scheduled_task_runs(id bigint PRIMARY KEY,task_id bigint,status text);INSERT INTO scheduled_tasks VALUES(10,51,42),(11,51,42);INSERT INTO scheduled_task_runs VALUES(20,10,'failed'),(21,11,'failed'),(22,10,'failed');CREATE TABLE server_backups(id bigint PRIMARY KEY,destination_id bigint);INSERT INTO server_backups VALUES(30,7),(31,8),(32,7)`); err != nil {
		t.Fatal(err)
	}
	q := recorderQueue(t, db)
	for _, args := range []river.JobArgs{trackedScheduledArgs{20}, trackedScheduledArgs{21}, trackedScheduledArgs{22}, trackedServerBackupArgs{30}, trackedServerBackupArgs{31}, trackedServerBackupArgs{32}} {
		job, err := q.Insert(ctx, args, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`UPDATE river_job SET state='discarded',attempt=1,finalized_at=now() WHERE id=$1`, job.Job.ID); err != nil {
			t.Fatal(err)
		}
	}
	p, err := operations.NewStore(db).Page(ctx, admin, "issues", operations.Filter{})
	if err != nil || len(p.Issues) != 4 {
		t.Fatalf("independent tasks/destinations merged: %#v %v", p, err)
	}
	var recurring int
	for _, i := range p.Issues {
		if i.Occurrences == 2 {
			recurring++
		}
	}
	if recurring != 2 {
		t.Fatalf("same resource failed to recur: %#v", p)
	}
}

func TestRecorderRecognizesPersistedCertificateFailureOnCancellation(t *testing.T) {
	db := testDB(t)
	if _, err := db.Exec(`ALTER TABLE sites ADD COLUMN tls_status text DEFAULT 'none';ALTER TABLE sites ADD COLUMN updated_at timestamptz DEFAULT now()`); err != nil {
		t.Fatal(err)
	}
	q := recorderQueue(t, db)
	for n, id := range []int64{51, 52, 52} {
		if n == 2 {
			if _, err := db.Exec(`UPDATE sites SET tls_status='failed',updated_at=now()-interval '1 hour' WHERE id=$1`, id); err != nil {
				t.Fatal(err)
			}
		}
		job, err := q.Insert(ctx, trackedCertArgs{SiteID: id, AfterProvisioning: true}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if id == 51 {
			if _, err = db.Exec(`UPDATE sites SET tls_status='failed',updated_at=now() WHERE id=$1`, id); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = db.Exec(`UPDATE river_job SET state='cancelled',attempt=1,attempted_at=now()-interval '1 second',finalized_at=now() WHERE id=$1`, job.Job.ID); err != nil {
			t.Fatal(err)
		}
	}
	p, err := operations.NewStore(db).Page(ctx, client, "issues", operations.Filter{})
	if err != nil || len(p.Issues) != 1 || p.Issues[0].Kind != "tls" || p.Issues[0].Resource.ID != 51 {
		t.Fatalf("SSL failure lost or genuine cancellation became failure: %#v %v", p, err)
	}
	d, err := operations.NewStore(db).Operation(ctx, client, p.Issues[0].OperationID)
	if err != nil || d.Operation.State != operations.StateFailed || len(d.Attempts) != 1 || d.Attempts[0].State != operations.StateFailed {
		t.Fatalf("SSL failure mislabeled: %#v %v", d, err)
	}
}

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
