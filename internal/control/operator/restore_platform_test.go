package operator

import (
	"context"
	"github.com/DATA-DOG/go-sqlmock"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"strings"
	"testing"
	"time"
)

func TestRestoreConvergenceRequiresCompletedJobsAndNoAttention(t *testing.T) {
	for _, tc := range []struct {
		name, status, job, errText            string
		total, ok, pending, failed, attention int
	}{
		{name: "complete", status: "active", job: "completed", total: 2, ok: 2},
		{name: "detected only database", status: "active", job: "completed", total: 2, ok: 2, attention: 1, errText: "attention"},
		{name: "failed run", status: "failed", job: "retryable", errText: "failed"},
		{name: "partial sites", status: "active", job: "completed", total: 2, ok: 1, errText: "sites"},
		{name: "failed PHP worker", status: "active", job: "completed", failed: 1, errText: "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, m, e := sqlmock.New()
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			s := &Service{db: db}
			m.ExpectQuery(`SELECT r.status`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"status", "sites_total", "sites_ok", "last_error", "job_state"}).AddRow(tc.status, tc.total, tc.ok, "", tc.job))
			if tc.status != "failed" && tc.total == tc.ok {
				m.ExpectQuery(`SELECT`).WithArgs(int64(7), "[]").WillReturnRows(sqlmock.NewRows([]string{"pending", "failed", "attention"}).AddRow(tc.pending, tc.failed, tc.attention))
			}
			e = s.WaitRestoreConvergence(context.Background(), 7, time.Second)
			if tc.errText == "" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil || !strings.Contains(e.Error(), tc.errText) {
				t.Fatalf("err=%v want %s", e, tc.errText)
			}
			if e = m.ExpectationsWereMet(); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestRestoreConvergenceDoesNotTreatQueuedReconciliationAsSuccess(t *testing.T) {
	db, m, e := sqlmock.New()
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s := &Service{db: db}
	m.ExpectQuery(`SELECT r.status`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"status", "sites_total", "sites_ok", "last_error", "job_state"}).AddRow("pending", 2, 0, "", "available"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if e = s.WaitRestoreConvergence(ctx, 7, time.Second); e == nil {
		t.Fatal("queued run passed")
	}
}

func TestRestoreResourceJobsPreserveDesiredRevisions(t *testing.T) {
	jobs := restoreResourceJobs([]restoreAccountRevision{{SubscriptionID: 42, Revision: 7}})
	if len(jobs) != 2 {
		t.Fatalf("jobs=%d", len(jobs))
	}
	args, ok := jobs[0].(controlquota.ConvergeSubscriptionArgs)
	if !ok || args.SubscriptionID != 42 || args.Revision != 7 {
		t.Fatalf("wrong restored intent %+v", jobs[0])
	}
	if jobs[1].Kind() != "reconcile_applications" {
		t.Fatalf("container observation missing: %s", jobs[1].Kind())
	}
}

func TestRestoreConvergenceIncludesDeduplicatedResourceJobs(t *testing.T) {
	db, m, e := sqlmock.New()
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s := &Service{db: db}
	m.ExpectQuery(`SELECT r.status`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"status", "sites_total", "sites_ok", "last_error", "job_state"}).AddRow("active", 0, 0, "", "completed"))
	m.ExpectQuery(`SELECT`).WithArgs(int64(7), "[8]").WillReturnRows(sqlmock.NewRows([]string{"pending", "failed", "attention"}).AddRow(1, 0, 0))
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if e = s.WaitRestoreConvergence(ctx, 7, time.Second, 8); e == nil {
		t.Fatal("deduplicated pending job was skipped")
	}
	if e = m.ExpectationsWereMet(); e != nil {
		t.Fatal(e)
	}
}
