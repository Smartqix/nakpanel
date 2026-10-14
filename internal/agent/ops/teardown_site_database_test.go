package ops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

func removalDatabaseFixture(t *testing.T, owned bool) (*MariaDBEngine, sqlmock.Sqlmock, types.SiteRemovalDatabase) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	parent := t.TempDir()
	os.Chmod(parent, 0700)
	directory := filepath.Join(parent, "ownership")
	os.Mkdir(directory, 0700)
	engine := NewMariaDBEngine(db)
	engine.ownershipDir = directory
	engine.ownerUID = uint32(os.Geteuid())
	target := types.SiteRemovalDatabase{ID: 50, SiteID: 2, SubscriptionID: 2, Name: "np2_fixture", Principal: "np2_principal", DeletionEligible: true}
	if owned {
		data, _ := json.Marshal(databaseOwnership{DatabaseID: target.ID, Name: target.Name, Principal: target.Principal})
		if err := os.WriteFile(filepath.Join(directory, "50.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return engine, mock, target
}
func TestTeardownSiteDatabaseOwnershipAndReplay(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "exclusive", true: "shared"}[shared], func(t *testing.T) {
			engine, mock, target := removalDatabaseFixture(t, true)
			mock.ExpectQuery("information_schema.SCHEMATA").WithArgs(target.Name).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
			mock.ExpectQuery("mysql.user").WithArgs(target.Principal).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
			count := 0
			if shared {
				count = 1
			}
			mock.ExpectQuery(regexp.QuoteMeta(databaseSharedPrincipalSQL)).WithArgs(target.Principal, `np2\_fixture`, target.Principal, target.Name, target.Principal, target.Name, target.Principal, target.Name, quoteMariaDBAccount(target.Principal), target.Principal).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(count))
			mock.ExpectExec(regexp.QuoteMeta("DROP DATABASE IF EXISTS `np2_fixture`")).WillReturnResult(sqlmock.NewResult(0, 1))
			if !shared {
				mock.ExpectExec(regexp.QuoteMeta("DROP USER IF EXISTS 'np2_principal'@'localhost'")).WillReturnResult(sqlmock.NewResult(0, 1))
			}
			removed, err := engine.RemoveOwnedDatabase(context.Background(), 10, target)
			if err != nil || removed == shared {
				t.Fatalf("principal removed=%v err=%v", removed, err)
			}
			// Retired intent returns without looking up or dropping a replacement schema.
			again, err := engine.RemoveOwnedDatabase(context.Background(), 10, target)
			if err != nil || again != removed {
				t.Fatalf("replay=%v %v", again, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestTeardownSiteUnownedDatabaseCannotBeDropped(t *testing.T) {
	engine, mock, target := removalDatabaseFixture(t, false)
	if _, err := engine.RemoveOwnedDatabase(context.Background(), 10, target); err == nil {
		t.Fatal("unowned database dropped")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestTeardownSiteRetiredDatabaseRejectsStaleCreate(t *testing.T) {
	engine, mock, target := removalDatabaseFixture(t, true)
	state := databaseRemovalOwnership{OperationID: 10, Database: databaseOwnership{DatabaseID: 50, Name: target.Name, Principal: target.Principal}, Complete: true, PrincipalRemoved: true}
	data, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(engine.ownershipDir, "50.removed.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.claimDatabaseOwnership(context.Background(), engine.exec, types.CreateDatabaseReq{DatabaseID: 50, DBName: target.Name, DBUser: target.Principal}); err == nil {
		t.Fatal("stale create accepted retired ID")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestTeardownSiteDatabaseProofIsAvailableBeforeConfirmation(t *testing.T) {
	engine, _, target := removalDatabaseFixture(t, true)
	admin := newMariaDBAdministrationWithDB(nil)
	admin.ownershipDir = engine.ownershipDir
	admin.ownershipUID = engine.ownerUID
	proof := admin.databaseOwnershipVerified(types.DatabaseAdminTarget{DatabaseID: target.ID, Name: target.Name, Principal: target.Principal})
	if !proof {
		t.Fatal("owned database has no safe preview proof")
	}
	target.Principal = "another_principal"
	if admin.databaseOwnershipVerified(types.DatabaseAdminTarget{DatabaseID: target.ID, Name: target.Name, Principal: target.Principal}) {
		t.Fatal("mismatched principal proof accepted")
	}
}

func TestTeardownSiteToolkitRecoveryProofRequired(t *testing.T) {
	f := newSiteTeardownFixture(t)
	engine, _, _ := removalDatabaseFixture(t, true)
	f.opts.MariaDB = engine
	f.request.Snapshot.Databases[0].Provenance = "wordpress_toolkit"
	f.request.Snapshot.Databases[0].RecoveryBackupID = 70
	f.request.DeleteDatabaseIDs = []int64{50}
	if _, err := NewSiteTeardownProvisioner(f.opts).TeardownSite(context.Background(), f.request); err == nil {
		t.Fatal("Toolkit database deletion without verified archive")
	}
	if len(f.runner.calls) != 0 {
		t.Fatal("service stopped before recovery proof")
	}
}

func TestTeardownSiteToolkitRecoveryArchiveCoverage(t *testing.T) {
	f := newSiteTeardownFixture(t)
	f.opts.BackupRoot = filepath.Join(f.opts.Paths.HomeRoot, "../backups")
	backup, err := NewBackupProvisioner(BackupProvisionerOptions{OutputDir: f.opts.BackupRoot, HomeRoot: f.opts.Paths.HomeRoot, DatabaseDumper: &fakeDatabaseDumper{}}).CreateBackup(context.Background(), types.CreateBackupReq{Domain: "addon.test", Username: "nps2", Docroot: f.target.Docroot, Databases: []string{"np2_fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	proof := types.SiteRemovalResource{ID: 70, Kind: "backup", Name: "addon.test", SiteID: 2, ParentID: 2, Mode: "active", ArchivePath: backup.ArchivePath, SHA256: backup.SHA256, DatabaseNames: []string{"np2_fixture"}}
	p := NewSiteTeardownProvisioner(f.opts)
	if err = p.verifyRemovalRecoveryArchive(context.Background(), proof, "np2_fixture"); err != nil {
		t.Fatal("valid recovery archive", err)
	}
	if err = p.verifyRemovalRecoveryArchive(context.Background(), proof, "missing_schema"); err == nil {
		t.Fatal("missing dump accepted")
	}
	proof.SHA256 = strings.Repeat("0", 64)
	if err = p.verifyRemovalRecoveryArchive(context.Background(), proof, "np2_fixture"); err == nil {
		t.Fatal("changed archive accepted")
	}
}
