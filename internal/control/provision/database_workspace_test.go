package provision

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/control/store"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

func expectDatabaseSubscription(mock sqlmock.Sqlmock) {
	expectMutableSubscription(mock, 7)
	mock.ExpectQuery(`SELECT e.max_sites`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"max_sites", "max_subdomains", "max_databases", "max_backups", "backup_storage_mb", "overuse_policy", "hosting_enabled", "allow_backups"}).AddRow(2, 2, 2, 2, 128, "block", true, true))
}

func TestDatabaseCreateReplayIsPayloadBound(t *testing.T) {
	for _, test := range []struct {
		name, fingerprint string
		conflict          bool
	}{{"same", "payload", false}, {"changed", "other", true}} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repo := NewSQLDatabaseRepository(db, store.New(db), nil)
			mock.ExpectBegin()
			expectDatabaseSubscription(mock)
			mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs("session-scope", "request-key").WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery(`SELECT database_id,payload_hash`).WithArgs("session-scope", "request-key").WillReturnRows(sqlmock.NewRows([]string{"database_id", "payload_hash"}).AddRow(30, "payload"))
			mock.ExpectRollback()
			id, err := repo.LookupDatabaseCreate(context.Background(), types.CreateDatabaseReq{SubscriptionID: 7, IdempotencyScope: "session-scope", IdempotencyKey: "request-key", IdempotencyFingerprint: test.fingerprint})
			if test.conflict {
				if !errors.Is(err, ErrDatabaseIdempotencyConflict) {
					t.Fatalf("error=%v", err)
				}
			} else if err != nil || id != 30 {
				t.Fatalf("id=%d err=%v", id, err)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDatabaseCreateDuplicateDoesNotReplaceCredentials(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewSQLDatabaseRepository(db, store.New(db), new(river.Client[*sql.Tx]), new(serveradmin.Store))
	mock.ExpectBegin()
	expectDatabaseSubscription(mock)
	mock.ExpectQuery(`SELECT subscription_id FROM databases`).WithArgs("existing").WillReturnRows(sqlmock.NewRows([]string{"subscription_id"}).AddRow(7))
	mock.ExpectQuery(`SELECT id FROM databases`).WithArgs("existing").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(30))
	mock.ExpectRollback()
	_, err = repo.CreateDatabase(context.Background(), 1, types.CreateDatabaseReq{SubscriptionID: 7, DBName: "existing", Password: "MustNeverBeStored"})
	if !errors.Is(err, ErrDatabaseExists) {
		t.Fatalf("error=%v", err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseRetryRejectsActiveAndForeignDatabase(t *testing.T) {
	for _, state := range []string{"active", "pending", "foreign"} {
		t.Run(state, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repo := NewSQLDatabaseRepository(db, store.New(db), new(river.Client[*sql.Tx]), new(serveradmin.Store))
			mock.ExpectBegin()
			expectDatabaseSubscription(mock)
			query := mock.ExpectQuery(`SELECT status,engine,db_name,db_user FROM databases`).WithArgs(int64(30), int64(7))
			if state == "foreign" {
				query.WillReturnError(sql.ErrNoRows)
			} else {
				query.WillReturnRows(sqlmock.NewRows([]string{"status", "engine", "db_name", "db_user"}).AddRow(state, "mariadb", "existing", "existing_user"))
			}
			mock.ExpectRollback()
			if err = repo.RetryDatabase(context.Background(), 30, 7); err == nil {
				t.Fatal("retry unexpectedly allowed")
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDatabaseRetryReusesActiveJobWithoutCredentialMutation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewSQLDatabaseRepository(db, store.New(db), new(river.Client[*sql.Tx]), new(serveradmin.Store))
	mock.ExpectBegin()
	expectDatabaseSubscription(mock)
	mock.ExpectQuery(`SELECT status,engine,db_name,db_user FROM databases`).WithArgs(int64(30), int64(7)).WillReturnRows(sqlmock.NewRows([]string{"status", "engine", "db_name", "db_user"}).AddRow("failed", "mariadb", "existing", "existing_user"))
	mock.ExpectQuery(`SELECT COUNT`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(int64(30)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec(`UPDATE databases SET status='pending'`).WithArgs(int64(30)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err = repo.RetryDatabase(context.Background(), 30, 7); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
