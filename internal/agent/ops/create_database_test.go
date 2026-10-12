package ops

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type recordingSQLExecutor struct {
	db    *sql.DB
	calls []sqlExecCall
	err   error
}

func (e *recordingSQLExecutor) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return e.db.QueryRowContext(ctx, query, args...)
}

type sqlExecCall struct {
	query string
	args  []any
}

func (e *recordingSQLExecutor) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	e.calls = append(e.calls, sqlExecCall{query: query, args: append([]any(nil), args...)})
	if e.err != nil {
		return nil, e.err
	}
	return driver.RowsAffected(1), nil
}

func TestValidateCreateDatabaseRequestRejectsUnsafeInputs(t *testing.T) {
	tests := []struct {
		name string
		req  types.CreateDatabaseReq
	}{
		{
			name: "unknown engine",
			req:  types.CreateDatabaseReq{Engine: "sqlite", DBName: "np_demo", DBUser: "np_demo_user", Password: "secret-password"},
		},
		{
			name: "database name with dash",
			req:  types.CreateDatabaseReq{Engine: types.EngineMariaDB, DBName: "np-demo", DBUser: "np_demo_user", Password: "secret-password"},
		},
		{
			name: "database name path traversal",
			req:  types.CreateDatabaseReq{Engine: types.EngineMariaDB, DBName: "../mysql", DBUser: "np_demo_user", Password: "secret-password"},
		},
		{
			name: "user shell metacharacter",
			req:  types.CreateDatabaseReq{Engine: types.EngineMariaDB, DBName: "np_demo", DBUser: "np_demo_user;drop", Password: "secret-password"},
		},
		{
			name: "password required",
			req:  types.CreateDatabaseReq{Engine: types.EngineMariaDB, DBName: "np_demo", DBUser: "np_demo_user"},
		},
		{
			name: "password with unsafe quote",
			req:  types.CreateDatabaseReq{Engine: types.EngineMariaDB, DBName: "np_demo", DBUser: "np_demo_user", Password: "unsafe'password"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateCreateDatabaseRequest(tt.req); err == nil {
				t.Fatal("ValidateCreateDatabaseRequest returned nil error")
			}
		})
	}
}

func TestDatabaseProvisionerRejectsUnconfiguredFutureEngines(t *testing.T) {
	provisioner := NewDatabaseProvisioner(map[types.DBEngine]DatabaseEngine{
		types.EngineMariaDB: NewMariaDBEngine(&recordingSQLExecutor{}),
	})

	for _, engine := range []types.DBEngine{types.EngineMySQL, types.EnginePgSQL} {
		t.Run(string(engine), func(t *testing.T) {
			err := provisioner.CreateDatabase(context.Background(), types.CreateDatabaseReq{
				Engine:   engine,
				DBName:   "np_demo",
				DBUser:   "np_demo_user",
				Password: "secret-password",
			})
			if !errors.Is(err, ErrEngineNotImplemented) {
				t.Fatalf("CreateDatabase error = %v, want ErrEngineNotImplemented", err)
			}
		})
	}
}

func TestMariaDBEngineUsesScopedGrantAndPasswordHash(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT COUNT").WithArgs("np_demo").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT COUNT").WithArgs("np_demo_user").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	exec := &recordingSQLExecutor{db: db}
	engine := NewMariaDBEngine(exec)
	engine.ownershipDir = filepath.Join(t.TempDir(), "ownership")
	if err := os.Chmod(filepath.Dir(engine.ownershipDir), 0700); err != nil {
		t.Fatal(err)
	}
	engine.ownerUID = uint32(os.Getuid())

	req := types.CreateDatabaseReq{
		DatabaseID: 7,
		Engine:     types.EngineMariaDB,
		DBName:     "np_demo",
		DBUser:     "np_demo_user",
		Password:   "super-secret-password",
	}
	if err := engine.CreateDatabase(context.Background(), req); err != nil {
		t.Fatalf("CreateDatabase returned error: %v", err)
	}

	wantQueries := []string{
		"CREATE DATABASE IF NOT EXISTS `np_demo` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
		"CREATE USER IF NOT EXISTS 'np_demo_user'@'localhost' ACCOUNT LOCK",
		"ALTER USER 'np_demo_user'@'localhost' IDENTIFIED BY PASSWORD '*AB71DDEC03C2ABA51CA5E1A0A91DEAE2216590E3'",
		"ALTER USER 'np_demo_user'@'localhost' ACCOUNT UNLOCK",
		"GRANT ALL PRIVILEGES ON `np\\_demo`.* TO 'np_demo_user'@'localhost'",
	}
	if len(exec.calls) != len(wantQueries) {
		t.Fatalf("ExecContext call count = %d, want %d: %#v", len(exec.calls), len(wantQueries), exec.calls)
	}
	for i, want := range wantQueries {
		if got := exec.calls[i].query; got != want {
			t.Fatalf("query[%d] = %q, want %q", i, got, want)
		}
		if strings.Contains(exec.calls[i].query, req.Password) {
			t.Fatalf("query[%d] contains plaintext password: %q", i, exec.calls[i].query)
		}
	}

	for i := range exec.calls {
		if len(exec.calls[i].args) != 0 {
			t.Fatalf("args[%d] = %#v, want no args", i, exec.calls[i].args)
		}
	}
}
