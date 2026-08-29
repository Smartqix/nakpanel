package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
)

type fakeMigrationSecretStore struct {
	values map[string][]byte
	txPuts []serveradmin.PutSecretParams
	getErr error
}

func (s *fakeMigrationSecretStore) PutSecret(_ context.Context, params serveradmin.PutSecretParams) (serveradmin.SecretReference, error) {
	if s.values == nil {
		s.values = make(map[string][]byte)
	}
	s.values[params.Scope+"/"+params.Name] = append([]byte(nil), params.Plaintext...)
	return serveradmin.SecretReference{Scope: params.Scope, Name: params.Name}, nil
}

func (s *fakeMigrationSecretStore) GetSecret(_ context.Context, scope, name string) ([]byte, serveradmin.SecretReference, error) {
	if s.getErr != nil {
		return nil, serveradmin.SecretReference{}, s.getErr
	}
	value, ok := s.values[scope+"/"+name]
	if !ok {
		return nil, serveradmin.SecretReference{}, sql.ErrNoRows
	}
	return append([]byte(nil), value...), serveradmin.SecretReference{Scope: scope, Name: name}, nil
}

func (s *fakeMigrationSecretStore) PutSecretTx(_ context.Context, _ *sql.Tx, params serveradmin.PutSecretParams) (serveradmin.SecretReference, error) {
	params.Plaintext = append([]byte(nil), params.Plaintext...)
	params.Metadata = append([]byte(nil), params.Metadata...)
	s.txPuts = append(s.txPuts, params)
	return serveradmin.SecretReference{Scope: params.Scope, Name: params.Name}, nil
}

func TestMigrateLegacySecretsEncryptsActiveJobsAndClearsPlaintext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	secrets := &fakeMigrationSecretStore{}
	mock.ExpectQuery("SELECT smarthost_host,smarthost_password FROM mail_settings").
		WillReturnRows(sqlmock.NewRows([]string{"smarthost_host", "smarthost_password"}).
			AddRow("relay.example.test", "relay-password"))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id,state,args").
		WillReturnRows(sqlmock.NewRows([]string{"id", "state", "args"}).
			AddRow(int64(10), "available", []byte(`{"database_id":7,"db_name":"app","password":"database-password"}`)).
			AddRow(int64(11), "completed", []byte(`{"database_id":8,"password":"terminal-password"}`)))
	mock.ExpectExec("UPDATE river_job").
		WithArgs(int64(10), "provision-7").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE river_job").
		WithArgs(int64(11)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE mail_settings").
		WithArgs("relay-password").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT count\\(\\*\\)").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(0)))
	mock.ExpectCommit()

	result, err := migrateLegacySecrets(context.Background(), db, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if result.encryptedCredentials != 2 || result.migratedJobs != 1 || result.scrubbedJobs != 1 {
		t.Fatalf("migration result = %+v", result)
	}
	if got := string(secrets.values["mail/smarthost"]); got != "relay-password" {
		t.Fatalf("encrypted relay value = %q", got)
	}
	if len(secrets.txPuts) != 1 || secrets.txPuts[0].Scope != "database" ||
		secrets.txPuts[0].Name != "provision-7" ||
		string(secrets.txPuts[0].Plaintext) != "database-password" {
		t.Fatalf("database credential writes = %#v", secrets.txPuts)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateLegacySecretsRollsBackUnsupportedActiveJob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	secrets := &fakeMigrationSecretStore{}
	mock.ExpectQuery("SELECT smarthost_host,smarthost_password FROM mail_settings").
		WillReturnRows(sqlmock.NewRows([]string{"smarthost_host", "smarthost_password"}).AddRow("", ""))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id,state,args").
		WillReturnRows(sqlmock.NewRows([]string{"id", "state", "args"}).
			AddRow(int64(44), "retryable", []byte(`{"database_id":0,"password":"must-not-be-lost"}`)))
	mock.ExpectRollback()

	_, err = migrateLegacySecrets(context.Background(), db, secrets)
	if err == nil || !strings.Contains(err.Error(), "job 44") {
		t.Fatalf("migration error = %v, want actionable job identity", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateLegacySecretsFailsClosedWhenEncryptedRelayCannotBeVerified(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	secrets := &fakeMigrationSecretStore{getErr: errors.New("key unavailable")}
	mock.ExpectQuery("SELECT smarthost_host,smarthost_password FROM mail_settings").
		WillReturnRows(sqlmock.NewRows([]string{"smarthost_host", "smarthost_password"}).
			AddRow("relay.example.test", "relay-password"))

	_, err = migrateLegacySecrets(context.Background(), db, secrets)
	if err == nil || !strings.Contains(err.Error(), "verify encrypted relay credential") {
		t.Fatalf("migration error = %v, want verification failure", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateLegacySecretsPostgreSQL(t *testing.T) {
	dsn := os.Getenv("NAKPANEL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NAKPANEL_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
	CREATE TEMP TABLE mail_settings (
		id BOOLEAN PRIMARY KEY CHECK (id),
		smarthost_host TEXT NOT NULL,
		smarthost_password TEXT NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
	);
CREATE TEMP TABLE river_job (
	id BIGINT PRIMARY KEY,
	state TEXT NOT NULL,
	kind TEXT NOT NULL,
	args JSONB NOT NULL
);
INSERT INTO mail_settings(id,smarthost_host,smarthost_password)
VALUES (true,'relay.example.test','relay-password');
INSERT INTO river_job(id,state,kind,args)
VALUES (10,'available','create_database','{"database_id":7,"password":"database-password"}');
`); err != nil {
		t.Fatal(err)
	}

	result, err := migrateLegacySecrets(context.Background(), db, &fakeMigrationSecretStore{})
	if err != nil {
		t.Fatal(err)
	}
	if result.migratedJobs != 1 {
		t.Fatalf("migration result = %+v", result)
	}
	var relayPassword, credentialRef string
	var hasPassword bool
	if err := db.QueryRow(`SELECT smarthost_password FROM mail_settings WHERE id`).Scan(&relayPassword); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`
SELECT args ? 'password',args->>'credential_ref'
FROM river_job WHERE id=10`).Scan(&hasPassword, &credentialRef); err != nil {
		t.Fatal(err)
	}
	if relayPassword != "" || hasPassword || credentialRef != "provision-7" {
		t.Fatalf("plaintext remains: relay=%q has_job_password=%v credential_ref=%q", relayPassword, hasPassword, credentialRef)
	}
}
