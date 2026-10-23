package dashboard

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestActiveJobStates(t *testing.T) {
	jobs := []Job{}
	for _, state := range []string{"available", "scheduled", "running", "retryable", "pending", "completed", "cancelled", "discarded", "failed"} {
		jobs = append(jobs, Job{State: state})
	}
	if got := ActiveJobs(jobs); got != 5 {
		t.Fatalf("active=%d", got)
	}
}
func TestSQLActiveCountUsesSameKindsAndAllNonterminalStates(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`(?s)SELECT count\(\*\) FROM river_job WHERE kind IN \('create_site', 'create_database', 'issue_cert', 'create_backup', 'restore_backup', 'configure_webmail', 'configure_dns_zone', 'reconcile_system'\) AND state IN \('available', 'scheduled', 'running', 'retryable', 'pending'\)`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(101))
	count, err := NewSQLJobStore(db).CountActiveJobs(context.Background())
	if err != nil || count != 101 {
		t.Fatalf("count=%d %v", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
