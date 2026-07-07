package provision

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/riverqueue/river/rivertype"
)

type fakeJobRetryStore struct {
	job            jobRetryRecord
	getErr         error
	retryErr       error
	retriedJobID   int64
	retryCallCount int
}

func (s *fakeJobRetryStore) GetJob(ctx context.Context, id int64) (jobRetryRecord, error) {
	if s.getErr != nil {
		return jobRetryRecord{}, s.getErr
	}
	return s.job, nil
}

func (s *fakeJobRetryStore) RetryDiscardedProvisioningJob(ctx context.Context, id int64) error {
	s.retriedJobID = id
	s.retryCallCount++
	if s.retryErr != nil {
		return s.retryErr
	}
	return nil
}

func TestJobRetrierRetriesDiscardedProvisioningJob(t *testing.T) {
	for _, kind := range []string{"create_site", "restore_backup"} {
		t.Run(kind, func(t *testing.T) {
			store := &fakeJobRetryStore{
				job: jobRetryRecord{
					Kind:  kind,
					State: rivertype.JobStateDiscarded,
				},
			}
			retrier := NewJobRetrier(store)

			if err := retrier.RetryProvisioningJob(context.Background(), 41); err != nil {
				t.Fatalf("RetryProvisioningJob returned error: %v", err)
			}
			if store.retryCallCount != 1 || store.retriedJobID != 41 {
				t.Fatalf("retry calls=%d id=%d, want one call with 41", store.retryCallCount, store.retriedJobID)
			}
		})
	}
}

func TestJobRetrierRejectsNonDiscardedJobs(t *testing.T) {
	for _, state := range []rivertype.JobState{
		rivertype.JobStateAvailable,
		rivertype.JobStateCompleted,
		rivertype.JobStateRetryable,
		rivertype.JobStateRunning,
		rivertype.JobStateScheduled,
	} {
		t.Run(string(state), func(t *testing.T) {
			store := &fakeJobRetryStore{
				job: jobRetryRecord{
					Kind:  "create_site",
					State: state,
				},
			}
			retrier := NewJobRetrier(store)

			err := retrier.RetryProvisioningJob(context.Background(), 41)
			if !errors.Is(err, ErrJobNotRetryable) {
				t.Fatalf("RetryProvisioningJob error = %v, want ErrJobNotRetryable", err)
			}
			if store.retryCallCount != 0 {
				t.Fatalf("retry was called for state %s", state)
			}
		})
	}
}

func TestJobRetrierRejectsUnsupportedKind(t *testing.T) {
	store := &fakeJobRetryStore{
		job: jobRetryRecord{
			Kind:  "send_email",
			State: rivertype.JobStateDiscarded,
		},
	}
	retrier := NewJobRetrier(store)

	err := retrier.RetryProvisioningJob(context.Background(), 41)
	if !errors.Is(err, ErrUnsupportedJobKind) {
		t.Fatalf("RetryProvisioningJob error = %v, want ErrUnsupportedJobKind", err)
	}
	if store.retryCallCount != 0 {
		t.Fatal("retry was called for unsupported job kind")
	}
}

func TestJobRetrierRejectsInvalidJobID(t *testing.T) {
	store := &fakeJobRetryStore{}
	retrier := NewJobRetrier(store)

	err := retrier.RetryProvisioningJob(context.Background(), 0)
	if !errors.Is(err, ErrJobNotRetryable) {
		t.Fatalf("RetryProvisioningJob error = %v, want ErrJobNotRetryable", err)
	}
	if store.retryCallCount != 0 {
		t.Fatal("retry was called for invalid job id")
	}
}

func TestJobRetrierPropagatesRetryErrors(t *testing.T) {
	wantErr := errors.New("retry failed")
	store := &fakeJobRetryStore{
		job: jobRetryRecord{
			Kind:  "issue_cert",
			State: rivertype.JobStateDiscarded,
		},
		retryErr: wantErr,
	}
	retrier := NewJobRetrier(store)

	err := retrier.RetryProvisioningJob(context.Background(), 41)
	if !errors.Is(err, wantErr) {
		t.Fatalf("RetryProvisioningJob error = %v, want %v", err, wantErr)
	}
	if store.retryCallCount != 1 {
		t.Fatalf("retry calls = %d, want 1", store.retryCallCount)
	}
}

func TestSQLJobRetryStoreGetsJob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta(getJobForRetrySQL)).
		WithArgs(int64(41)).
		WillReturnRows(sqlmock.NewRows([]string{"kind", "state"}).AddRow("create_site", "discarded"))

	store := &SQLJobRetryStore{db: db}
	job, err := store.GetJob(context.Background(), 41)
	if err != nil {
		t.Fatalf("GetJob returned error: %v", err)
	}
	if job.Kind != "create_site" || job.State != rivertype.JobStateDiscarded {
		t.Fatalf("job = %#v, want create_site discarded", job)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestSQLJobRetryStoreRetriesOnlyDiscardedProvisioningJob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(regexp.QuoteMeta(retryDiscardedProvisioningJobSQL)).
		WithArgs(int64(41)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	store := &SQLJobRetryStore{db: db}
	if err := store.RetryDiscardedProvisioningJob(context.Background(), 41); err != nil {
		t.Fatalf("RetryDiscardedProvisioningJob returned error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestSQLJobRetryStoreRejectsUnchangedRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(regexp.QuoteMeta(retryDiscardedProvisioningJobSQL)).
		WithArgs(int64(41)).
		WillReturnResult(sqlmock.NewResult(0, 0))

	store := &SQLJobRetryStore{db: db}
	err = store.RetryDiscardedProvisioningJob(context.Background(), 41)
	if !errors.Is(err, ErrJobNotRetryable) {
		t.Fatalf("RetryDiscardedProvisioningJob error = %v, want ErrJobNotRetryable", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}
