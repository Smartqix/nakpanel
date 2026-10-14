package removaldb

import (
	"database/sql"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// New creates a disposable schema in the explicitly named test database.
func New(t *testing.T, before string) *sql.DB {
	t.Helper()
	dsn := os.Getenv("NAKPANEL_REMOVAL_TEST_DSN")
	if dsn == "" {
		t.Skip("requires nakpanel_removal_test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	var name string
	if err = db.QueryRow("SELECT current_database()").Scan(&name); err != nil || name != "nakpanel_removal_test" {
		db.Close()
		t.Fatalf("isolated removal database required: %q %v", name, err)
	}
	schema := fmt.Sprintf("removal_service_%d", time.Now().UnixNano())
	if _, err = db.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	admin := db
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = schema
	db = stdlib.OpenDB(*config)
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { db.Close(); _, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE"); admin.Close() })
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err = os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("repository root not found")
		}
		directory = parent
	}
	files, err := filepath.Glob(filepath.Join(directory, "migrations", "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if before != "" && filepath.Base(path) >= before {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(strings.SplitN(string(data), "-- +goose Down", 2)[0]); err != nil {
			t.Fatalf("%s: %v", filepath.Base(path), err)
		}
	}
	return db
}

func Site(t *testing.T, db *sql.DB, subscriptionID int64, domain string, parent any) int64 {
	t.Helper()
	var id int64
	if err := db.QueryRow(`INSERT INTO sites(owner_user_id,subscription_id,customer_id,system_account_id,username,document_root,domain,php_version,desired_php_version,parent_site_id,status)
 SELECT s.customer_user_id,s.id,s.customer_id,a.id,a.username,a.home_path||'/domains/'||$2||'/public_html',$2,'8.4','8.4',$3,'active'
 FROM subscriptions s JOIN subscription_system_accounts a ON a.subscription_id=s.id WHERE s.id=$1 RETURNING id`, subscriptionID, domain, parent).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
