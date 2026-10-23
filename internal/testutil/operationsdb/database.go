// Package operationsdb creates complete current-design disposable local schemas.
package operationsdb

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

func New(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("NAKPANEL_OPERATIONS_TEST_DSN")
	if dsn == "" {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatal("CI requires NAKPANEL_OPERATIONS_TEST_DSN for current Operations regression tests")
		}
		t.Skip("requires dedicated local operations test database")
	}
	c, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(c.Database, "nakpanel_operations_") {
		t.Fatal("requires dedicated nakpanel_operations_ test database")
	}
	local := func(h string) bool {
		return h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasPrefix(h, "/")
	}
	if !local(c.Host) {
		t.Fatal("remote operations tests are forbidden")
	}
	for _, f := range c.Fallbacks {
		if !local(f.Host) {
			t.Fatal("remote fallback is forbidden")
		}
	}
	admin := stdlib.OpenDB(*c)
	schema := fmt.Sprintf("operations_full_%d", time.Now().UnixNano())
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	c.RuntimeParams["search_path"] = schema
	c.RuntimeParams["statement_timeout"] = "10s"
	db := stdlib.OpenDB(*c)
	db.SetMaxOpenConns(8)
	t.Cleanup(func() { db.Close(); _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); admin.Close() })
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
