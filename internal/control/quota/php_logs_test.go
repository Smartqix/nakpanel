package quota

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
)

type fakePHPLogSecretReader struct{}

func (fakePHPLogSecretReader) GetSecret(context.Context, string, string) ([]byte, serveradmin.SecretReference, error) {
	return []byte("very-secret-value"), serveradmin.SecretReference{}, nil
}

func TestRedactPHPEnvironmentSecretsFailsClosedOnReferenceReadError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows := sqlmock.NewRows([]string{"scope", "name"}).
		AddRow("php.application.31", "environment-abcd").
		AddRow("php.application.31", "environment-efgh").
		RowError(1, errors.New("reference read failed"))
	mock.ExpectQuery(`SELECT secret.scope,secret.name`).WithArgs(int64(7)).WillReturnRows(rows)
	store := &SQLStore{db: db, phpLogSecrets: fakePHPLogSecretReader{}}
	lines, err := store.RedactPHPEnvironmentSecrets(context.Background(), 7, []string{"value=very-secret-value"})
	if err == nil || lines != nil {
		t.Fatalf("reference read failure returned lines %#v, error %v", lines, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRedactPHPEnvironmentSecretsLoadsOnlyReferencedSiteSecrets(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT secret.scope,secret.name`).WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"scope", "name"}).AddRow("php.application.31", "environment-abcd"))
	store := &SQLStore{db: db, phpLogSecrets: fakePHPLogSecretReader{}}
	lines, err := store.RedactPHPEnvironmentSecrets(context.Background(), 7, []string{"value=very-secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "value=[REDACTED]" {
		t.Fatalf("redacted lines = %#v", lines)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
