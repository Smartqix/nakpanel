package provision

import (
	"context"
	"database/sql"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"strings"
	"testing"
	"time"
)

func TestDatabaseManagerScopeHasTenantAndRotationGates(t *testing.T) {
	for _, predicate := range []string{"c.login_user_id=$3", "ra.login_user_id=$3", "c.status='active'", "s.status='active'", "d.status='active'", "rotate_password", "awaiting_confirmation", "sec.name='provision-'"} {
		if !strings.Contains(managerDatabaseScope, predicate) {
			t.Errorf("missing gate %q", predicate)
		}
	}
}

func TestDatabaseManagerCredentialRevisionInvalidatesGrant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT u.role FROM sessions").WithArgs(auth.TokenHash("session"), int64(5)).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("client"))
	mock.ExpectQuery("SELECT database_id,credential_revision,consumed_at FROM database_manager_grants").WithArgs(auth.TokenHash("grant"), auth.TokenHash("session"), int64(5)).WillReturnRows(sqlmock.NewRows([]string{"database_id", "credential_revision", "consumed_at"}).AddRow(17, "old", time.Now()))
	mock.ExpectQuery("SELECT d.db_name").WithArgs(int64(17), "client", int64(5)).WillReturnRows(sqlmock.NewRows([]string{"db_name", "db_user", "revision"}).AddRow("test", "testuser", "new"))
	_, err = NewSQLDatabaseManager(db, serveradmin.NewStore(db, nil)).Access(context.Background(), auth.SessionUser{ID: 5}, "session", "grant")
	if err != ErrDatabaseManagerDenied {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseManagerExpiredOrWrongSessionGrantDenied(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT u.role FROM sessions").WithArgs(auth.TokenHash("other-session"), int64(5)).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("client"))
	mock.ExpectQuery("SELECT database_id,credential_revision,consumed_at FROM database_manager_grants").WithArgs(auth.TokenHash("grant"), auth.TokenHash("other-session"), int64(5)).WillReturnError(sql.ErrNoRows)
	_, err = NewSQLDatabaseManager(db, serveradmin.NewStore(db, nil)).Access(context.Background(), auth.SessionUser{ID: 5}, "other-session", "grant")
	if err != ErrDatabaseManagerDenied {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestDatabaseManagerRevokedSessionCannotAccessGrant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT u.role FROM sessions").WithArgs(auth.TokenHash("session"), int64(5)).WillReturnError(sql.ErrNoRows)
	_, err = NewSQLDatabaseManager(db, serveradmin.NewStore(db, nil)).Access(context.Background(), auth.SessionUser{ID: 5}, "session", "grant")
	if err != ErrDatabaseManagerDenied {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestDatabaseManagerLaunchCrossTenantReturnsNoGrant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT d.db_name").WithArgs(int64(17), "client", int64(5)).WillReturnError(sql.ErrNoRows)
	token, err := NewSQLDatabaseManager(db, serveradmin.NewStore(db, nil)).Launch(context.Background(), auth.SessionUser{ID: 5, Role: auth.RoleClient}, "session", 17)
	if err != ErrDatabaseManagerDenied || token != "" {
		t.Fatalf("%q %v", token, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
