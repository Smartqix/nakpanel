package operations_test

import (
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
	"testing"
)

func TestDispatcherCanRunAgainAfterACompletedTick(t *testing.T) {
	db := testDB(t)
	driver := riverdatabasesql.New(db)
	migrator, err := rivermigrate.New(driver, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = migrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		t.Fatal(err)
	}
	queueClient, err := river.NewClient(driver, &river.Config{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := queueClient.Insert(ctx, operations.DispatchArgs{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE river_job SET state='completed',finalized_at=now() WHERE id=$1`, first.Job.ID); err != nil {
		t.Fatal(err)
	}
	second, err := queueClient.Insert(ctx, operations.DispatchArgs{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.Job.ID == first.Job.ID || second.UniqueSkippedAsDuplicate {
		t.Fatal("completed dispatcher tick prevented all future publication")
	}
	s := operations.NewStore(db)
	if _, err = s.ObserveIssue(ctx, observation("worker-replay", 51)); err != nil {
		t.Fatal(err)
	}
	worker := &operations.DispatchWorker{Store: s}
	if err = worker.Work(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err = worker.Work(ctx, nil); err != nil {
		t.Fatal(err)
	}
	feed, err := s.Feed(ctx, client, 0, operations.Filter{})
	if err != nil || len(feed.Events) != 1 {
		t.Fatalf("worker replay: %#v %v", feed, err)
	}
}
