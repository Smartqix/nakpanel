package operator

import (
	"context"
	"database/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"os"
	"testing"
)

// This integration test executes the removal guard's actual PostgreSQL JSONB
// predicates. Temporary tables shadow live tables only in one isolated session.
func TestRuntimeProviderRemovalPostgresRetainedAndDesiredReferences(t *testing.T) {
	dsn := os.Getenv("NAKPANEL_REMOVAL_TEST_DSN")
	if dsn == "" {
		t.Skip("requires isolated nakpanel_removal_test PostgreSQL")
	}
	if err := removaldb.ValidateDSN(dsn); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var database string
	if err := db.QueryRow("SELECT current_database()").Scan(&database); err != nil || database != "nakpanel_removal_test" {
		t.Fatalf("isolated database required: %s %v", database, err)
	}
	for _, query := range []string{
		"CREATE TEMP TABLE sites(php_version text,desired_php_version text)",
		"CREATE TEMP TABLE php_applications(php_version text)",
		"CREATE TEMP TABLE site_removal_operations(state text,snapshot jsonb)",
		"CREATE TEMP TABLE server_backups(status text,manifest jsonb)",
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, insert string
		used         bool
	}{
		{"unused", "", false},
		{"current site", `INSERT INTO sites VALUES('8.4','8.5')`, true},
		{"desired site", `INSERT INTO sites VALUES('8.5','8.4')`, true},
		{"managed app", `INSERT INTO php_applications VALUES('8.4')`, true},
		{"retained removal", `INSERT INTO site_removal_operations VALUES('failed','{"sites":[{"php_version":"8.4"}]}')`, true},
		{"retained desired", `INSERT INTO site_removal_operations VALUES('waiting','{"sites":[{"desired_php_version":"8.4"}]}')`, true},
		{"completed deletion", `INSERT INTO site_removal_operations VALUES('completed','{"sites":[{"php_version":"8.4"}]}')`, false},
		{"restorable backup", `INSERT INTO server_backups VALUES('active','{"platform":{"required_php_versions":["8.4"],"php_inventory_complete":true}}')`, true},
		{"unrelated backup", `INSERT INTO server_backups VALUES('active','{"platform":{"required_php_versions":["8.5"],"php_inventory_complete":true}}')`, false},
		{"legacy unknown backup", `INSERT INTO server_backups VALUES('active','{}')`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.Exec("TRUNCATE pg_temp.sites,pg_temp.php_applications,pg_temp.site_removal_operations,pg_temp.server_backups"); err != nil {
				t.Fatal(err)
			}
			if tc.insert != "" {
				if _, err := db.Exec(tc.insert); err != nil {
					t.Fatal(err)
				}
			}
			used, err := (&Service{db: db}).RuntimeProviderInUse(context.Background(), "nakpanel", "8.4", "8.5")
			if err != nil || used != tc.used {
				t.Fatalf("used=%v err=%v want %v", used, err, tc.used)
			}
		})
	}
}
