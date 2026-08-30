package phpapp

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestPHPRuntimeSweepResolvesLegacyNotificationKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT DISTINCT application.subscription_id`).
		WillReturnRows(sqlmock.NewRows([]string{"subscription_id", "customer_id", "php_version"}).AddRow(3, 5, "8.4"))
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT dedupe_key FROM notifications`).WillReturnRows(sqlmock.NewRows([]string{"dedupe_key"}).
		AddRow("php:runtime-missing:3:8.3").
		AddRow("php:end-of-support:3:8.3"))
	for _, key := range []string{"php:runtime-missing:3:8.3", "php:end-of-support:3:8.3"} {
		mock.ExpectExec(`UPDATE notifications SET resolved_at=now\(\),updated_at=now\(\) WHERE dedupe_key=\$1`).
			WithArgs(key).WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectExec(`UPDATE notifications SET resolved_at=now\(\),updated_at=now\(\) WHERE dedupe_key=\$1`).
		WithArgs("php:runtime:3:8.4").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE notifications SET resolved_at=now\(\),updated_at=now\(\) WHERE dedupe_key=\$1`).
		WithArgs("php:runtime-missing:3:8.4").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE notifications SET resolved_at=now\(\),updated_at=now\(\) WHERE dedupe_key=\$1`).
		WithArgs("php:end-of-support:3:8.4").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	worker := NewSweepPHPRuntimesWorker(&SQLStore{db: db}, fakeCapabilities{value: types.RuntimeCapabilities{
		PHPRuntimes: []types.PHPRuntimeCapability{{Version: "8.4", Ready: true, SupportStatus: types.PHPSupportActive}},
	}})
	if err := worker.Work(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
