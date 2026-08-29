package quota

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
)

func TestUpdateMailSettingsDoesNotTouchSecretWhenBeginFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyring, err := serveradmin.NewKeyring(1, map[int][]byte{1: mailTestKey(0x61)})
	if err != nil {
		t.Fatal(err)
	}
	store := NewSQLStore(db)
	store.SetServiceSecretStore(serveradmin.NewStore(db, keyring))
	beginErr := errors.New("database unavailable")
	mock.ExpectBegin().WillReturnError(beginErr)

	err = store.UpdateMailSettings(context.Background(), validMailSettings("new-secret"))
	if !errors.Is(err, beginErr) {
		t.Fatalf("UpdateMailSettings error = %v, want %v", err, beginErr)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateMailSettingsRollsBackEncryptedSecretWithSettings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyring, err := serveradmin.NewKeyring(2, map[int][]byte{2: mailTestKey(0x62)})
	if err != nil {
		t.Fatal(err)
	}
	store := NewSQLStore(db)
	store.SetServiceSecretStore(serveradmin.NewStore(db, keyring))
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	updateErr := errors.New("settings update failed")

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO service_secrets")).
		WithArgs(
			sqlmock.AnyArg(), "mail", "smarthost", serveradmin.EnvelopeAlgorithm, 2,
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			[]byte(`{}`), int64(0),
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "secret_id", "scope", "name", "key_version", "metadata",
			"updated_by_user_id", "created_at", "updated_at",
		}).AddRow(
			int64(1), "sec_12345678901234567890123456789012", "mail", "smarthost", 2,
			[]byte(`{}`), nil, now, now,
		))
	settings := validMailSettings("new-secret")
	mock.ExpectExec(regexp.QuoteMeta("UPDATE mail_settings SET mail_hostname=$1")).
		WithArgs(
			settings.MailHostname, settings.SmarthostHost, settings.SmarthostPort,
			settings.SmarthostUsername, "", settings.OutboundRateLimit,
			settings.QueueAlertThreshold,
		).
		WillReturnError(updateErr)
	mock.ExpectRollback()

	err = store.UpdateMailSettings(context.Background(), settings)
	if !errors.Is(err, updateErr) {
		t.Fatalf("UpdateMailSettings error = %v, want %v", err, updateErr)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateMailSettingsRollsBackSecretDeletionWithSettings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyring, err := serveradmin.NewKeyring(1, map[int][]byte{1: mailTestKey(0x63)})
	if err != nil {
		t.Fatal(err)
	}
	store := NewSQLStore(db)
	store.SetServiceSecretStore(serveradmin.NewStore(db, keyring))
	updateErr := errors.New("settings update failed")
	settings := validMailSettings("")
	settings.SmarthostHost = ""
	settings.SmarthostPort = 0
	settings.SmarthostUsername = ""

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM service_secrets WHERE scope=$1 AND name=$2")).
		WithArgs("mail", "smarthost").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE mail_settings SET mail_hostname=$1")).
		WithArgs(
			settings.MailHostname, "", 0, "", "", settings.OutboundRateLimit,
			settings.QueueAlertThreshold,
		).
		WillReturnError(updateErr)
	mock.ExpectRollback()

	err = store.UpdateMailSettings(context.Background(), settings)
	if !errors.Is(err, updateErr) {
		t.Fatalf("UpdateMailSettings error = %v, want %v", err, updateErr)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReadMailSettingsFailsClosedWhenEncryptedRelayIsUnavailable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyring, err := serveradmin.NewKeyring(1, map[int][]byte{1: mailTestKey(0x64)})
	if err != nil {
		t.Fatal(err)
	}
	secrets := serveradmin.NewStore(db, keyring)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT mail_hostname,smarthost_host,smarthost_port,smarthost_username,smarthost_password,outbound_rate_limit,queue_alert_threshold FROM mail_settings WHERE id")).
		WillReturnRows(sqlmock.NewRows([]string{
			"mail_hostname", "smarthost_host", "smarthost_port", "smarthost_username",
			"smarthost_password", "outbound_rate_limit", "queue_alert_threshold",
		}).AddRow("mail.example.test", "relay.example.test", 587, "relay", "legacy-plaintext", "200/1h", 50))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id,secret_id,scope,name,algorithm,key_version,wrapped_key_nonce")).
		WithArgs("mail", "smarthost").
		WillReturnError(errors.New("encrypted store unavailable"))

	_, err = ReadMailSettings(context.Background(), db, secrets)
	if err == nil || !strings.Contains(err.Error(), "read encrypted smarthost credential") {
		t.Fatalf("ReadMailSettings error = %v, want fail-closed encrypted-secret error", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReadMailSettingsAllowsCredentialFreeRelayWithoutSecret(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyring, err := serveradmin.NewKeyring(1, map[int][]byte{1: mailTestKey(0x65)})
	if err != nil {
		t.Fatal(err)
	}
	secrets := serveradmin.NewStore(db, keyring)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT mail_hostname,smarthost_host,smarthost_port,smarthost_username,smarthost_password,outbound_rate_limit,queue_alert_threshold FROM mail_settings WHERE id")).
		WillReturnRows(sqlmock.NewRows([]string{
			"mail_hostname", "smarthost_host", "smarthost_port", "smarthost_username",
			"smarthost_password", "outbound_rate_limit", "queue_alert_threshold",
		}).AddRow("mail.example.test", "127.0.0.1", 2525, "", "", "200/1h", 50))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id,secret_id,scope,name,algorithm,key_version,wrapped_key_nonce")).
		WithArgs("mail", "smarthost").
		WillReturnError(sql.ErrNoRows)

	settings, err := ReadMailSettings(context.Background(), db, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if settings.SmarthostHost != "127.0.0.1" || settings.SmarthostPassword != "" {
		t.Fatalf("ReadMailSettings = %#v, want credential-free relay", settings)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func validMailSettings(password string) MailSettings {
	return MailSettings{
		MailHostname:        "mail.example.test",
		SmarthostHost:       "relay.example.test",
		SmarthostPort:       587,
		SmarthostUsername:   "relay",
		SmarthostPassword:   password,
		OutboundRateLimit:   "200/1h",
		QueueAlertThreshold: 50,
	}
}

func mailTestKey(fill byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	return key
}
