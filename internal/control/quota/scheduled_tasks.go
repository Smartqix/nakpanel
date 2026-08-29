package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/robfig/cron/v3"
)

type SweepScheduledTasksArgs struct{}

func (SweepScheduledTasksArgs) Kind() string { return "sweep_scheduled_tasks" }
func (SweepScheduledTasksArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

type RunScheduledTaskArgs struct {
	RunID int64 `json:"run_id" river:"unique"`
}

func (RunScheduledTaskArgs) Kind() string { return "run_scheduled_task" }
func (RunScheduledTaskArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       HeavyQueue,
		MaxAttempts: 1,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		}},
	}
}

type SweepScheduledTasksWorker struct {
	river.WorkerDefaults[SweepScheduledTasksArgs]
	db    *sql.DB
	river *river.Client[*sql.Tx]
	now   func() time.Time
}

func NewSweepScheduledTasksWorker(db *sql.DB) *SweepScheduledTasksWorker {
	return &SweepScheduledTasksWorker{db: db, now: time.Now}
}

func (w *SweepScheduledTasksWorker) SetRiverClient(client *river.Client[*sql.Tx]) { w.river = client }

func (w *SweepScheduledTasksWorker) Work(ctx context.Context, _ *river.Job[SweepScheduledTasksArgs]) error {
	if w == nil || w.db == nil || w.river == nil {
		return errors.New("scheduled task sweep is not configured")
	}
	rows, err := w.db.QueryContext(ctx, `SELECT task.id,task.subscription_id,task.schedule,task.timezone
FROM scheduled_tasks task
JOIN subscriptions subscription ON subscription.id=task.subscription_id
JOIN customers customer ON customer.id=subscription.customer_id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
LEFT JOIN reseller_subscriptions reseller_subscription
  ON reseller_subscription.reseller_id=reseller.id AND reseller_subscription.status='active'
WHERE task.enabled AND task.site_id IS NOT NULL
  AND subscription.status='active' AND customer.status='active'
  AND (customer.reseller_id IS NULL OR (reseller.status='active' AND reseller_subscription.id IS NOT NULL))
ORDER BY task.id`)
	if err != nil {
		return err
	}
	type candidateTask struct {
		id             int64
		subscriptionID int64
		expression     string
		timezone       string
	}
	var candidates []candidateTask
	for rows.Next() {
		var candidate candidateTask
		if err := rows.Scan(&candidate.id, &candidate.subscriptionID, &candidate.expression, &candidate.timezone); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	type dueTask struct {
		id           int64
		scheduledFor time.Time
	}
	var due []dueTask
	now := w.now().UTC()
	policyStore := NewSQLStore(w.db)
	policyCache := make(map[int64]bool)
	for _, candidate := range candidates {
		permitted, ok := policyCache[candidate.subscriptionID]
		if !ok {
			policy, policyErr := policyStore.EffectiveSubscriptionPolicy(ctx, candidate.subscriptionID)
			if policyErr != nil {
				return policyErr
			}
			permitted = scheduledTasksAllowed(policy)
			policyCache[candidate.subscriptionID] = permitted
		}
		if !permitted {
			continue
		}
		next, isDue := scheduledOccurrence(candidate.expression, candidate.timezone, now)
		if !isDue {
			continue
		}
		due = append(due, dueTask{id: candidate.id, scheduledFor: next.UTC()})
	}
	for _, task := range due {
		tx, err := w.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var runID int64
		err = tx.QueryRowContext(ctx, `INSERT INTO scheduled_task_runs(task_id,status,scheduled_for)
VALUES($1,'pending',$2) ON CONFLICT(task_id,scheduled_for) WHERE scheduled_for IS NOT NULL DO NOTHING
RETURNING id`, task.id, task.scheduledFor).Scan(&runID)
		if errors.Is(err, sql.ErrNoRows) {
			_ = tx.Rollback()
			continue
		}
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = w.river.InsertTx(ctx, tx, RunScheduledTaskArgs{RunID: runID}, nil); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func scheduledOccurrence(expression, timezone string, now time.Time) (time.Time, bool) {
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return time.Time{}, false
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(expression)
	if err != nil {
		return time.Time{}, false
	}
	minute := now.In(location).Truncate(time.Minute)
	next := schedule.Next(minute.Add(-time.Second))
	if next.After(minute) {
		return time.Time{}, false
	}
	return next.UTC(), true
}

type ScheduledTaskAgent interface {
	RunScheduledTask(context.Context, types.RunScheduledTaskReq) (types.RunScheduledTaskResult, error)
}

type RunScheduledTaskWorker struct {
	river.WorkerDefaults[RunScheduledTaskArgs]
	db    *sql.DB
	agent ScheduledTaskAgent
}

func NewRunScheduledTaskWorker(db *sql.DB, agent ScheduledTaskAgent) *RunScheduledTaskWorker {
	return &RunScheduledTaskWorker{db: db, agent: agent}
}

func (w *RunScheduledTaskWorker) Work(ctx context.Context, job *river.Job[RunScheduledTaskArgs]) error {
	if w == nil || w.db == nil || w.agent == nil {
		return errors.New("scheduled task worker is not configured")
	}
	req, subscriptionID, taskName, scheduledFor, err := loadScheduledTaskRun(ctx, w.db, job.Args.RunID)
	if err != nil {
		if errors.Is(err, ErrExceeded) {
			_, updateErr := w.db.ExecContext(ctx, `UPDATE scheduled_task_runs
SET status='failed',output='Scheduled tasks are disabled by the subscription policy.',finished_at=now()
WHERE id=$1 AND status IN ('pending','running')`, job.Args.RunID)
			return updateErr
		}
		return err
	}
	if _, err = w.db.ExecContext(ctx, `UPDATE scheduled_task_runs SET status='running',started_at=now() WHERE id=$1 AND status='pending'`, job.Args.RunID); err != nil {
		return err
	}
	result, runErr := w.agent.RunScheduledTask(ctx, req)
	if runErr != nil {
		result = types.RunScheduledTaskResult{Status: "failed", ExitCode: -1, Output: truncateError(runErr)}
	}
	if result.Status == "" {
		result.Status = "failed"
	}
	if _, err = w.db.ExecContext(ctx, `UPDATE scheduled_task_runs
SET status=$2,exit_code=$3,output=$4,finished_at=now() WHERE id=$1`,
		job.Args.RunID, result.Status, result.ExitCode, result.Output); err != nil {
		return errors.Join(runErr, err)
	}
	if result.Status == "failed" || result.Status == "timed_out" {
		key := "scheduled-task:" + strconv.FormatInt(req.TaskID, 10) + ":" + scheduledFor.UTC().Format(time.RFC3339)
		if err = recordSubscriptionNotification(ctx, w.db, subscriptionID, "scheduled_task_failed", "warning",
			"Scheduled task failed", fmt.Sprintf("%s: %s", taskName, truncateError(errors.New(result.Output))), key); err != nil {
			return errors.Join(runErr, err)
		}
	}
	return nil
}

func loadScheduledTaskRun(ctx context.Context, db *sql.DB, runID int64) (types.RunScheduledTaskReq, int64, string, time.Time, error) {
	var req types.RunScheduledTaskReq
	var taskName string
	var scheduledFor sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT task.id,task.subscription_id,task.site_id,account.username,
site.domain,site.php_version,task.kind,task.command,task.url,task.script_path,task.timeout_seconds,task.working_directory,
task.name,run.scheduled_for
FROM scheduled_task_runs run
JOIN scheduled_tasks task ON task.id=run.task_id
JOIN sites site ON site.id=task.site_id AND site.subscription_id=task.subscription_id
JOIN subscription_system_accounts account ON account.subscription_id=task.subscription_id
JOIN subscriptions subscription ON subscription.id=task.subscription_id
JOIN customers customer ON customer.id=subscription.customer_id
WHERE run.id=$1 AND run.status IN ('pending','running') AND task.enabled
  AND subscription.status='active' AND customer.status='active'
  AND (customer.reseller_id IS NULL OR EXISTS (
      SELECT 1 FROM reseller_accounts reseller
      JOIN reseller_subscriptions allocation ON allocation.reseller_id=reseller.id AND allocation.status='active'
      WHERE reseller.id=customer.reseller_id AND reseller.status='active'
  ))`,
		runID,
	).Scan(&req.TaskID, &req.SubscriptionID, &req.SiteID, &req.Username, &req.Domain, &req.PHPVersion, &req.Kind,
		&req.Command, &req.URL, &req.Script, &req.TimeoutSeconds, &req.WorkingDirectory, &taskName, &scheduledFor)
	if err != nil {
		return types.RunScheduledTaskReq{}, 0, "", time.Time{}, err
	}
	policy, err := NewSQLStore(db).EffectiveSubscriptionPolicy(ctx, req.SubscriptionID)
	if err != nil {
		return types.RunScheduledTaskReq{}, 0, "", time.Time{}, err
	}
	if !scheduledTasksAllowed(policy) {
		return types.RunScheduledTaskReq{}, 0, "", time.Time{}, fmt.Errorf("%w: scheduled tasks are disabled", ErrExceeded)
	}
	return req, req.SubscriptionID, taskName, scheduledFor.Time, nil
}

func scheduledTasksAllowed(policy types.HostingPolicy) bool {
	return policy.Permissions.ScheduledTasks
}
