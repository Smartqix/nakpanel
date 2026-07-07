package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSQLJobStoreListsRecentProvisioningJobs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	createdAt := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	scheduledAt := createdAt.Add(time.Minute)
	attemptedAt := createdAt.Add(2 * time.Minute)
	finalizedAt := createdAt.Add(3 * time.Minute)

	mock.ExpectQuery(`(?s)SELECT id, kind, state::text, queue, attempt, max_attempts.*errors\[array_length\(errors, 1\)\]->>'error'.*WHERE kind IN \('create_site', 'create_database', 'issue_cert', 'create_backup', 'restore_backup', 'configure_webmail', 'configure_dns_zone', 'reconcile_system'\).*ORDER BY created_at DESC, id DESC.*LIMIT \$1`).
		WithArgs(5).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"kind",
			"state",
			"queue",
			"attempt",
			"max_attempts",
			"args",
			"last_error",
			"created_at",
			"scheduled_at",
			"attempted_at",
			"finalized_at",
		}).AddRow(
			int64(41),
			"issue_cert",
			"discarded",
			"default",
			int16(2),
			int16(3),
			[]byte(`{"domain":"example.test"}`),
			"acme failed",
			createdAt,
			scheduledAt,
			sql.NullTime{Time: attemptedAt, Valid: true},
			sql.NullTime{Time: finalizedAt, Valid: true},
		))

	jobs, err := NewSQLJobStore(db).ListRecentJobs(context.Background(), 5)
	if err != nil {
		t.Fatalf("ListRecentJobs returned error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("jobs length = %d, want 1", len(jobs))
	}
	job := jobs[0]
	if job.ID != 41 || job.Kind != "issue_cert" || job.State != "discarded" || job.Queue != "default" {
		t.Fatalf("job identity = %#v, want mapped identity", job)
	}
	if job.Attempt != 2 || job.MaxAttempts != 3 || job.Target != "example.test" || job.LastError != "acme failed" {
		t.Fatalf("job details = %#v, want attempts/target/error", job)
	}
	if !job.CreatedAt.Equal(createdAt) || !job.ScheduledAt.Equal(scheduledAt) {
		t.Fatalf("job timestamps = %#v, want created/scheduled", job)
	}
	if !job.AttemptedAt.Valid || !job.AttemptedAt.Time.Equal(attemptedAt) {
		t.Fatalf("attempted_at = %#v, want %v", job.AttemptedAt, attemptedAt)
	}
	if !job.FinalizedAt.Valid || !job.FinalizedAt.Time.Equal(finalizedAt) {
		t.Fatalf("finalized_at = %#v, want %v", job.FinalizedAt, finalizedAt)
	}
}

func TestExtractJobTarget(t *testing.T) {
	tests := []struct {
		name string
		kind string
		args map[string]string
		want string
	}{
		{name: "site domain", kind: "create_site", args: map[string]string{"domain": "example.test"}, want: "example.test"},
		{name: "certificate domain", kind: "issue_cert", args: map[string]string{"domain": "tls.test"}, want: "tls.test"},
		{name: "database name", kind: "create_database", args: map[string]string{"db_name": "np_demo"}, want: "np_demo"},
		{name: "backup domain", kind: "create_backup", args: map[string]string{"domain": "backup.test"}, want: "backup.test"},
		{name: "restore domain", kind: "restore_backup", args: map[string]string{"domain": "restored.test"}, want: "restored.test"},
		{name: "webmail domain", kind: "configure_webmail", args: map[string]string{"domain": "mail.test"}, want: "mail.test"},
		{name: "dns domain", kind: "configure_dns_zone", args: map[string]string{"domain": "dns.test"}, want: "dns.test"},
		{name: "reconcile system", kind: "reconcile_system", args: map[string]string{}, want: "system"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.args)
			if err != nil {
				t.Fatalf("marshal args: %v", err)
			}
			if got := extractJobTarget(tt.kind, data); got != tt.want {
				t.Fatalf("extractJobTarget() = %q, want %q", got, tt.want)
			}
		})
	}
}
