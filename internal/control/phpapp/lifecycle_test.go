package phpapp

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type lifecycleRiverInserter struct {
	args []river.JobArgs
}

func (r *lifecycleRiverInserter) InsertTx(_ context.Context, _ *sql.Tx, args river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	r.args = append(r.args, args)
	return nil, nil
}

func TestReconcileSiteApplicationQueuesCurrentRevisionWithoutMutatingIntent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id,desired_revision FROM php_applications WHERE site_id=\$1 FOR UPDATE`).
		WithArgs(int64(42)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "desired_revision"}).AddRow(int64(7), int64(13)))
	mock.ExpectCommit()

	inserter := &lifecycleRiverInserter{}
	store := NewSQLStore(db, inserter, nil)
	if err = store.ReconcileSiteApplication(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	if len(inserter.args) != 1 {
		t.Fatalf("queued jobs = %d, want 1", len(inserter.args))
	}
	job, ok := inserter.args[0].(ReconcilePHPApplicationArgs)
	if !ok {
		t.Fatalf("queued job type = %T, want ReconcilePHPApplicationArgs", inserter.args[0])
	}
	if job.ApplicationID != 7 || job.DesiredRevision != 13 {
		t.Fatalf("queued job = %#v, want application 7 revision 13", job)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
