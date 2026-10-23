package provision

import (
	"context"
	"encoding/json"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"testing"
)

type manualTaskStore struct{ fakeMailServiceStore }

type manualTaskRepo struct {
	fakeSiteRepository
	queued bool
}

func TestManualScheduledTaskQueueRecordsAtomicallyAndRechecksSuspension(t *testing.T) {
	db, m, _, actor, site := operationsFixture(t)
	ctx := context.Background()
	if err := controlquota.NewSQLStore(db).SetSubscriptionPolicy(ctx, 1, actor.ID, json.RawMessage(`{"permissions":{"scheduled_tasks":true},"resources":{"max_scheduled_tasks":4}}`), true); err != nil {
		t.Fatal(err)
	}
	var taskID int64
	if err := db.QueryRow(`INSERT INTO scheduled_tasks(subscription_id,site_id,name,schedule,command,enabled) VALUES(1,$1,'manual test','0 0 1 1 *','/bin/true',true) RETURNING id`, site).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	repo := &SQLSiteRepository{db: db, river: m.queue}
	runID, err := repo.EnqueueManualScheduledTask(ctx, actor, 1, taskID)
	if err != nil {
		t.Fatal(err)
	}
	var state string
	if err = db.QueryRow(`SELECT status FROM scheduled_task_runs WHERE id=$1`, runID).Scan(&state); err != nil || state != "pending" {
		t.Fatal(state, err)
	}
	page, err := m.Store.Page(ctx, actor, "tasks", operations.Filter{})
	if err != nil || len(page.Tasks) != 1 || page.Tasks[0].Kind != "run_scheduled_task" {
		t.Fatalf("Run Now missing from Tasks: %#v %v", page, err)
	}
	if _, err = db.Exec(`UPDATE sites SET desired_status='suspended' WHERE id=$1`, site); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.EnqueueManualScheduledTask(ctx, actor, 1, taskID); err == nil {
		t.Fatal("suspended site queued a new run")
	}
	var runs int
	if err = db.QueryRow(`SELECT count(*) FROM scheduled_task_runs WHERE task_id=$1`, taskID).Scan(&runs); err != nil || runs != 1 {
		t.Fatalf("denied request left a run: %d %v", runs, err)
	}
}

func (r *manualTaskRepo) EnqueueManualScheduledTask(context.Context, auth.SessionUser, int64, int64) (int64, error) {
	r.queued = true
	return 9, nil
}

func TestRunNowUsesDurableQueueInsteadOfUntrackedSynchronousExecution(t *testing.T) {
	repo := &manualTaskRepo{}
	m := NewManager(repo, WithQuotaStore(&manualTaskStore{}), WithAccessPolicy(fakeAccessPolicy{allow: true}))
	run, err := m.RunScheduledTask(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, 1, 7)
	if err != nil || !repo.queued || run.ID != 9 || run.Status != "pending" {
		t.Fatalf("Run Now bypassed the durable worker: %#v queued=%v err=%v", run, repo.queued, err)
	}
}
