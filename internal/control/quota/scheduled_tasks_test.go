package quota

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type forbiddenScheduledTaskAgent struct{ t *testing.T }

func (a forbiddenScheduledTaskAgent) RunScheduledTask(context.Context, types.RunScheduledTaskReq) (types.RunScheduledTaskResult, error) {
	a.t.Fatal("ineligible task reached the agent")
	return types.RunScheduledTaskResult{}, nil
}

func TestScheduledTaskWorkerSettlesDisabledOrSuspendedRun(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT task.id`).WithArgs(int64(21)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`(?s)UPDATE scheduled_task_runs.*status='failed'.*finished_at=now\(\)`).WithArgs(int64(21)).WillReturnResult(sqlmock.NewResult(0, 1))
	w := NewRunScheduledTaskWorker(db, forbiddenScheduledTaskAgent{t})
	if err := w.Work(context.Background(), &river.Job[RunScheduledTaskArgs]{Args: RunScheduledTaskArgs{RunID: 21}}); err != nil {
		t.Fatalf("ineligible run was not settled: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestScheduledTaskSweepGatesSuspendedSites(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`(?s)SELECT task.id.*JOIN sites site.*site.desired_status='active'`).WillReturnRows(sqlmock.NewRows([]string{"id", "subscription_id", "schedule", "timezone"}))
	w := NewSweepScheduledTasksWorker(db)
	w.SetRiverClient(&river.Client[*sql.Tx]{})
	if err := w.Work(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestScheduledTaskExecutionQueriesGateSiteSuspension(t *testing.T) {
	for _, manual := range []bool{false, true} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectQuery(`(?s)SELECT task.id.*site.desired_status='active'`).WillReturnError(sql.ErrNoRows)
		if manual {
			_, err = NewSQLStore(db).ScheduledTaskRunRequest(context.Background(), 4, 21)
		} else {
			_, _, _, _, err = loadScheduledTaskRun(context.Background(), db, 21)
		}
		if err != sql.ErrNoRows {
			t.Errorf("manual=%v: expected ineligible site, got %v", manual, err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		db.Close()
	}
}

func TestScheduledOccurrenceUsesTaskTimezone(t *testing.T) {
	now := time.Date(2026, time.July, 23, 14, 30, 42, 0, time.UTC)
	got, due := scheduledOccurrence("30 10 * * *", "America/New_York", now)
	if !due {
		t.Fatal("expected 10:30 America/New_York to be due")
	}
	if !got.Equal(time.Date(2026, time.July, 23, 14, 30, 0, 0, time.UTC)) {
		t.Fatalf("scheduled time = %s", got)
	}
	if _, due = scheduledOccurrence("31 10 * * *", "America/New_York", now); due {
		t.Fatal("future schedule reported due")
	}
}

func TestScheduledTasksAllowedFailsClosedOnPolicyRevocation(t *testing.T) {
	var policy types.HostingPolicy
	if scheduledTasksAllowed(policy) {
		t.Fatal("scheduled tasks remained runnable without an entitlement")
	}
	policy.Permissions.ScheduledTasks = true
	if !scheduledTasksAllowed(policy) {
		t.Fatal("scheduled tasks were blocked despite an explicit entitlement")
	}
}

func TestScheduledOccurrenceRejectsInvalidInput(t *testing.T) {
	now := time.Now()
	if _, due := scheduledOccurrence("not cron", "UTC", now); due {
		t.Fatal("invalid cron reported due")
	}
	if _, due := scheduledOccurrence("* * * * *", "Mars/Olympus", now); due {
		t.Fatal("invalid timezone reported due")
	}
}
