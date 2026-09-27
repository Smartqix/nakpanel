package wordpress

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestWordPressUsageCountIgnoresFailedEmptyPlaceholdersAndExcludesCurrent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(regexp.QuoteMeta(wordpressUsageCountSQL)).
		WithArgs(int64(20), int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	used, err := countWordPressUsage(context.Background(), tx, 20, 7)
	if err != nil || used != 2 {
		t.Fatalf("countWordPressUsage = %d, %v; want 2", used, err)
	}
	for _, required := range []string{
		"id<>$2",
		"observed_state<>'removed'",
		"database_id IS NULL",
		"installed_version=''",
		"observed_state='failed'",
		"convergence_status='failed'",
	} {
		if !regexp.MustCompile(regexp.QuoteMeta(required)).MatchString(wordpressUsageCountSQL) {
			t.Errorf("WordPress usage SQL is missing %q", required)
		}
	}
	mock.ExpectRollback()
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
