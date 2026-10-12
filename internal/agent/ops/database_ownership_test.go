package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestDatabaseCreationRejectsSystemNamesBeforeSQL(t *testing.T) {
	for _, name := range []string{"root", "mysql", "information_schema", "performance_schema", "sys", "nakpanel", "nakpanel_service", "mysql_sys", "phpmyadmin"} {
		for _, principal := range []bool{false, true} {
			exec := &recordingSQLExecutor{}
			req := types.CreateDatabaseReq{DatabaseID: 7, Engine: types.EngineMariaDB, DBName: "tenant_db", DBUser: "tenant_user", Password: "desired_password_2026"}
			if principal {
				req.DBUser = name
			} else {
				req.DBName = name
			}
			if err := NewMariaDBEngine(exec).CreateDatabase(context.Background(), req); err == nil {
				t.Fatalf("accepted reserved name %q", name)
			}
			if len(exec.calls) != 0 {
				t.Fatal("reserved target caused SQL mutation")
			}
		}
	}
}

func TestDatabaseCreationRejectsExistingUnownedResources(t *testing.T) {
	for _, counts := range [][2]int{{1, 0}, {0, 1}, {1, 1}} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		exec := &recordingSQLExecutor{db: db}
		engine := NewMariaDBEngine(exec)
		root := t.TempDir()
		if err := os.Chmod(root, 0700); err != nil {
			t.Fatal(err)
		}
		engine.ownershipDir = filepath.Join(root, "ownership")
		engine.ownerUID = uint32(os.Getuid())
		mock.ExpectQuery("SELECT COUNT.*SCHEMATA").WithArgs("tenant_db").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(counts[0]))
		mock.ExpectQuery("SELECT COUNT.*mysql.user WHERE User = ").WithArgs("untracked_user").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(counts[1]))
		req := types.CreateDatabaseReq{DatabaseID: 7, Engine: types.EngineMariaDB, DBName: "tenant_db", DBUser: "untracked_user", Password: "desired_password_2026"}
		if err := engine.CreateDatabase(context.Background(), req); err == nil {
			t.Fatal("unowned existing resource accepted")
		}
		if len(exec.calls) != 0 {
			t.Fatal("unowned resource mutated")
		}
		if _, err := os.Stat(filepath.Join(engine.ownershipDir, "7.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unowned target acquired marker")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
}

func TestDatabaseOwnedIntentRetriesAfterPartialApplyAndRejectsChangedBinding(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := &recordingSQLExecutor{db: db, err: errors.New("interrupted DDL")}
	engine := NewMariaDBEngine(exec)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	engine.ownershipDir = filepath.Join(root, "ownership")
	engine.ownerUID = uint32(os.Getuid())
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	req := types.CreateDatabaseReq{DatabaseID: 7, Engine: types.EngineMariaDB, DBName: "tenant_db", DBUser: "tenant_user", Password: "desired_password_2026"}
	if err := engine.CreateDatabase(context.Background(), req); err == nil {
		t.Fatal("expected interruption")
	}
	// The marker predates DDL; a new engine can resume the same immutable intent.
	restarted := NewMariaDBEngine(exec)
	restarted.ownershipDir = engine.ownershipDir
	restarted.ownerUID = engine.ownerUID
	exec.err = nil
	if err := restarted.CreateDatabase(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	count := len(exec.calls)
	req.DBUser = "other_user"
	if err := restarted.CreateDatabase(context.Background(), req); err == nil {
		t.Fatal("changed principal accepted")
	}
	if len(exec.calls) != count {
		t.Fatal("mismatched intent mutated SQL")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseOwnershipRejectsMissingIDAndUnsafeMarkers(t *testing.T) {
	for _, mode := range []string{"missing_id", "symlink", "public_marker", "wrong_owner"} {
		t.Run(mode, func(t *testing.T) {
			db, _, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exec := &recordingSQLExecutor{db: db}
			engine := NewMariaDBEngine(exec)
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			engine.ownershipDir = filepath.Join(root, "ownership")
			engine.ownerUID = uint32(os.Getuid())
			if err := os.Mkdir(engine.ownershipDir, 0700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(engine.ownershipDir, "7.json")
			payload := []byte(`{"database_id":7,"name":"tenant_db","principal":"tenant_user"}`)
			req := types.CreateDatabaseReq{DatabaseID: 7, Engine: types.EngineMariaDB, DBName: "tenant_db", DBUser: "tenant_user", Password: "desired_password_2026"}
			switch mode {
			case "missing_id":
				req.DatabaseID = 0
			case "symlink":
				target := filepath.Join(root, "target")
				if err := os.WriteFile(target, payload, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, marker); err != nil {
					t.Fatal(err)
				}
			case "public_marker":
				if err := os.WriteFile(marker, payload, 0644); err != nil {
					t.Fatal(err)
				}
			case "wrong_owner":
				engine.ownerUID++
			}
			if err := engine.CreateDatabase(context.Background(), req); err == nil {
				t.Fatal("unsafe ownership accepted")
			}
			if len(exec.calls) != 0 {
				t.Fatal("unsafe marker allowed mutation")
			}
		})
	}
}

func TestTrustedRestoreAdoptsImportedSchemaButNeverUnownedPrincipal(t *testing.T) {
	for _, principals := range []int{0, 1} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		exec := &recordingSQLExecutor{db: db}
		engine := NewMariaDBEngine(exec)
		root := t.TempDir()
		if err := os.Chmod(root, 0700); err != nil {
			t.Fatal(err)
		}
		engine.ownershipDir = filepath.Join(root, "ownership")
		engine.ownerUID = uint32(os.Getuid())
		mock.ExpectQuery("SELECT COUNT.*SCHEMATA").WithArgs("restored_db").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
		mock.ExpectQuery("SELECT COUNT.*mysql.user").WithArgs("restored_user").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(principals))
		req := types.CreateDatabaseReq{DatabaseID: 7, Engine: types.EngineMariaDB, DBName: "restored_db", DBUser: "restored_user", Password: "desired_password_2026"}
		release, err := engine.claimDatabaseOwnershipMode(context.Background(), exec, req, true)
		if principals == 1 {
			if err == nil {
				release()
				t.Fatal("trusted restore adopted an unowned existing principal")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			release()
			if err := engine.CreateDatabase(context.Background(), req); err != nil {
				t.Fatalf("adopted restore cannot recreate credentials: %v", err)
			}
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
}
