package provision

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"testing"
)

type manualTaskStore struct{ fakeMailServiceStore }

type manualTaskRepo struct {
	fakeSiteRepository
	queued bool
}

type failedManualTaskAgent struct{}

func (failedManualTaskAgent) RunScheduledTask(context.Context, types.RunScheduledTaskReq) (types.RunScheduledTaskResult, error) {
	return types.RunScheduledTaskResult{Status: "failed", ExitCode: 1, Output: "owned fixture failure"}, nil
}

func TestRepeatedManualFailuresPublishOneIncidentNotification(t *testing.T) {
	for _, timing := range []string{"delayed_dispatch", "between_runs", "before_second_worker"} {
		t.Run(timing, func(t *testing.T) {
			db, m, _, actor, site := operationsFixture(t)
			ctx := context.Background()
			if err := controlquota.NewSQLStore(db).SetSubscriptionPolicy(ctx, 1, actor.ID, json.RawMessage(`{"permissions":{"scheduled_tasks":true}}`), true); err != nil {
				t.Fatal(err)
			}
			var task int64
			if err := db.QueryRow(`INSERT INTO scheduled_tasks(subscription_id,site_id,name,schedule,command,enabled) VALUES(1,$1,'failure','0 0 1 1 *','/bin/false',true) RETURNING id`, site).Scan(&task); err != nil {
				t.Fatal(err)
			}
			repo := &SQLSiteRepository{db: db, river: m.queue}
			for n := 0; n < 2; n++ {
				run, err := repo.EnqueueManualScheduledTask(ctx, actor, 1, task)
				if err != nil {
					t.Fatal(err)
				}
				if timing == "before_second_worker" && n == 1 {
					if _, err = m.Dispatch(ctx, 100); err != nil {
						t.Fatal(err)
					}
				}
				var jobID int64
				if err = db.QueryRow(`SELECT id FROM river_job WHERE kind='run_scheduled_task' AND args->>'run_id'=$1::bigint::text`, run).Scan(&jobID); err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(`UPDATE river_job SET state='running',attempt=1,attempted_at=now() WHERE id=$1`, jobID); err != nil {
					t.Fatal(err)
				}
				err = (&operations.JobContextMiddleware{}).Work(ctx, &rivertype.JobRow{ID: jobID}, func(workCtx context.Context) error {
					return controlquota.NewRunScheduledTaskWorker(db, failedManualTaskAgent{}).Work(workCtx, &river.Job[controlquota.RunScheduledTaskArgs]{Args: controlquota.RunScheduledTaskArgs{RunID: run}})
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(`UPDATE river_job SET state='completed',finalized_at=now() WHERE id=$1`, jobID); err != nil {
					t.Fatal(err)
				}
				if timing == "between_runs" {
					if _, err = m.Dispatch(ctx, 100); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := m.Dispatch(ctx, 100); err != nil {
				t.Fatal(err)
			}
			var notices, occurrences int
			if err := db.QueryRow(`SELECT count(*),max(i.occurrences) FROM notifications n JOIN issues i ON i.id=n.issue_id WHERE i.condition=$1`, "run_scheduled_task:task:"+fmt.Sprint(task)).Scan(&notices, &occurrences); err != nil {
				t.Fatal(err)
			}
			if notices != 1 || occurrences != 2 {
				t.Fatalf("repeated failure notices=%d occurrences=%d; want one notice with two occurrences", notices, occurrences)
			}
		})
	}
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
