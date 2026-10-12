package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func siteIntentSource(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("queries/sites.sql")
	if err != nil {
		t.Fatal(err)
	}
	return strings.SplitN(string(data), "\n\n-- name:", 2)[0]
}

func TestSiteIntentInitializesBothPHPVersions(t *testing.T) {
	for name, query := range map[string]string{"source": siteIntentSource(t), "generated": upsertSiteIntent} {
		t.Run(name, func(t *testing.T) {
			if !regexp.MustCompile(`php_version,\s*desired_php_version,`).MatchString(query) {
				t.Fatal("site insert leaves desired PHP at its schema default")
			}
			argument := `sqlc\.arg\(php_version\)`
			if name == "generated" {
				argument = `\$3`
			}
			if !regexp.MustCompile(argument + `,\s*` + argument + `,\s*'pending'`).MatchString(query) {
				t.Fatal("insert PHP fields do not use the same requested version")
			}
			if !strings.Contains(query, "desired_php_version = EXCLUDED.desired_php_version,") {
				t.Fatal("retry upsert does not preserve the requested desired PHP version")
			}
		})
	}
}

func TestSiteIntentGeneratedQueryMatchesSource(t *testing.T) {
	arguments := map[string]int{}
	pattern := regexp.MustCompile(`sqlc\.arg\(([a-z_]+)\)`)
	source := pattern.ReplaceAllStringFunc(siteIntentSource(t), func(match string) string {
		name := pattern.FindStringSubmatch(match)[1]
		if arguments[name] == 0 {
			arguments[name] = len(arguments) + 1
		}
		return fmt.Sprintf("$%d", arguments[name])
	})
	source = strings.TrimSuffix(strings.TrimSpace(source), ";")
	if source != strings.TrimSpace(upsertSiteIntent) {
		t.Fatal("generated site-intent query has drifted from its SQL source; run sqlc-generate")
	}
}

func TestSiteIntentUsesRequestedPHPArgumentForBothColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`(?s)INSERT INTO sites.*php_version,\s*desired_php_version,.*\$3,\s*\$3,.*desired_php_version = EXCLUDED.desired_php_version`).WithArgs(int64(2), "new.test", "8.4", int64(42)).WillReturnError(sql.ErrNoRows)
	_, err = New(db).UpsertSiteIntent(context.Background(), UpsertSiteIntentParams{OwnerUserID: 2, Domain: "new.test", PhpVersion: "8.4", SubscriptionID: 42})
	if err != sql.ErrNoRows {
		t.Fatalf("site intent failed to use requested PHP: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
