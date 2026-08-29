package serveradmin

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSaveDesiredSettingUsesOptimisticRevision(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{
		"category", "desired", "applied", "desired_revision", "applied_revision",
		"convergence_status", "last_good_config_hash", "last_error",
		"updated_by_user_id", "created_at", "updated_at",
	}).AddRow(
		"general", []byte(`{"timezone":"UTC"}`), []byte(`{}`), int64(1), int64(0),
		"pending", nil, "", int64(7), now, now,
	)
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO server_settings")).
		WithArgs("general", json.RawMessage(`{"timezone":"UTC"}`), int64(0), int64(7)).
		WillReturnRows(rows)

	store := NewStore(db, nil)
	setting, err := store.SaveDesiredSetting(context.Background(), SaveDesiredSettingParams{
		Category:         "general",
		ExpectedRevision: 0,
		Desired:          json.RawMessage(`{"timezone":"UTC"}`),
		ActorUserID:      7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if setting.DesiredRevision != 1 || setting.ConvergenceStatus != ConvergencePending {
		t.Fatalf("setting = %+v", setting)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSaveDesiredSettingMapsStaleRevision(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO server_settings")).
		WithArgs("security", json.RawMessage(`{"firewall":true}`), int64(3), int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{
			"category", "desired", "applied", "desired_revision", "applied_revision",
			"convergence_status", "last_good_config_hash", "last_error",
			"updated_by_user_id", "created_at", "updated_at",
		}))

	_, err = NewStore(db, nil).SaveDesiredSetting(context.Background(), SaveDesiredSettingParams{
		Category:         "security",
		ExpectedRevision: 3,
		Desired:          json.RawMessage(`{"firewall":true}`),
		ActorUserID:      7,
	})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("SaveDesiredSetting error = %v, want ErrRevisionConflict", err)
	}
}

type excludesPlaintext struct{ value string }

func (m excludesPlaintext) Match(value driver.Value) bool {
	switch typed := value.(type) {
	case []byte:
		return !strings.Contains(string(typed), m.value)
	case string:
		return !strings.Contains(typed, m.value)
	default:
		return true
	}
}

func TestPutSecretNeverPassesPlaintextToPostgres(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyring, err := NewKeyring(4, map[int][]byte{4: testKey(0x71)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	plaintext := "relay-secret-value"

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO service_secrets")).
		WithArgs(
			sqlmock.AnyArg(), "mail", "smarthost", EnvelopeAlgorithm, 4,
			excludesPlaintext{plaintext}, excludesPlaintext{plaintext},
			excludesPlaintext{plaintext}, excludesPlaintext{plaintext},
			json.RawMessage(`{"host":"relay.test"}`), int64(7),
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "secret_id", "scope", "name", "key_version", "metadata",
			"updated_by_user_id", "created_at", "updated_at",
		}).AddRow(
			int64(12), "sec_12345678901234567890123456789012", "mail", "smarthost", 4,
			[]byte(`{"host":"relay.test"}`), int64(7), now, now,
		))

	reference, err := NewStore(db, keyring).PutSecret(context.Background(), PutSecretParams{
		Scope:       "mail",
		Name:        "smarthost",
		Plaintext:   []byte(plaintext),
		Metadata:    json.RawMessage(`{"host":"relay.test"}`),
		ActorUserID: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if reference.KeyVersion != 4 || reference.Scope != "mail" {
		t.Fatalf("reference = %+v", reference)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestGetSecretDecryptsPersistedEnvelope(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyring, err := NewKeyring(1, map[int][]byte{1: testKey(0x72)})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := keyring.Seal([]byte("registry-token"), secretAAD("registry", "dockerhub"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id,secret_id,scope,name,algorithm,key_version,wrapped_key_nonce,")).
		WithArgs("registry", "dockerhub").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "secret_id", "scope", "name", "algorithm", "key_version",
			"wrapped_key_nonce", "wrapped_data_key", "value_nonce", "ciphertext",
			"metadata", "updated_by_user_id", "created_at", "updated_at",
		}).AddRow(
			int64(10), "sec_12345678901234567890123456789012", "registry", "dockerhub",
			envelope.Algorithm, envelope.KeyVersion, envelope.WrappedKeyNonce,
			envelope.WrappedDataKey, envelope.ValueNonce, envelope.Ciphertext,
			[]byte(`{}`), nil, now, now,
		))

	plaintext, reference, err := NewStore(db, keyring).GetSecret(context.Background(), "registry", "dockerhub")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	if string(plaintext) != "registry-token" || reference.SecretID == "" {
		t.Fatalf("GetSecret = %q, %+v", plaintext, reference)
	}
}

func TestInventoryRequiresFreshnessWindow(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	_, err = NewStore(db, nil).UpsertInventory(context.Background(), UpsertInventoryParams{
		Kind:         "service",
		ResourceKey:  "nginx",
		HealthStatus: HealthHealthy,
		CheckedAt:    now,
		ExpiresAt:    now.Add(-time.Second),
	})
	if err == nil || !strings.Contains(err.Error(), "freshness") {
		t.Fatalf("UpsertInventory error = %v", err)
	}
}

func TestFinishOperationCommitsTerminalStateAndAuditTogether(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const operationID = "op_12345678901234567890"
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta("UPDATE server_operations")).
		WithArgs(operationID, OperationSucceeded, json.RawMessage(`{"changed":true}`), "",
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(operationTestRows(now).AddRow(
			int64(1), operationID, "services", "restart", "server_service", "web",
			[]byte(`{"action":"restart"}`), []byte(`{"changed":true}`), "succeeded",
			nil, operationID, nil, nil, "", int64(7), now, now, now, now,
		))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_events(")).
		WithArgs(int64(7), "server.service_restart_succeeded", "server_service", json.RawMessage(`{"service_id":"web"}`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	operation, err := NewStore(db, nil).FinishOperation(context.Background(), FinishOperationParams{
		UpdateOperationParams: UpdateOperationParams{
			OperationID: operationID,
			Status:      OperationSucceeded,
			Result:      json.RawMessage(`{"changed":true}`),
			StartedAt:   sql.NullTime{Time: now, Valid: true},
			CompletedAt: sql.NullTime{Time: now, Valid: true},
		},
		AuditAction: "server.service_restart_succeeded",
		AuditTarget: "server_service",
		AuditData:   json.RawMessage(`{"service_id":"web"}`),
	})
	if err != nil {
		t.Fatalf("FinishOperation error = %v", err)
	}
	if operation.Status != OperationSucceeded {
		t.Fatalf("operation status = %q", operation.Status)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizedJSONObjectRejectsNonObjectAndTrailingData(t *testing.T) {
	for _, value := range []json.RawMessage{
		json.RawMessage(`[]`),
		json.RawMessage(`null`),
		json.RawMessage(`{} {}`),
	} {
		if _, err := normalizedJSONObject(value); err == nil {
			t.Fatalf("normalizedJSONObject(%q) unexpectedly succeeded", value)
		}
	}
}

func TestPhase26MigrationContainsFoundationAndNoCredentialBackfill(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/20260723000028_phase26_tools_settings_foundation.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration := string(payload)
	for _, marker := range []string{
		"CREATE TABLE server_settings",
		"CREATE TABLE server_inventory",
		"CREATE TABLE server_operations",
		"CREATE TABLE service_secrets",
		"wrapped_data_key BYTEA",
		"authenticated_at TIMESTAMPTZ",
		"last_seen_at TIMESTAMPTZ",
		"revoked_at TIMESTAMPTZ",
		"cannot roll back Phase 26: restore the legacy smarthost credential",
		"-- +goose Down",
	} {
		if !strings.Contains(migration, marker) {
			t.Errorf("Phase 26 migration missing %q", marker)
		}
	}
	for _, forbidden := range []string{
		"UPDATE mail_settings SET smarthost_password",
		"ALTER TABLE mail_settings DROP COLUMN smarthost_password",
	} {
		if strings.Contains(migration, forbidden) {
			t.Errorf("foundation migration performs unsafe credential migration %q", forbidden)
		}
	}

	hardening, err := os.ReadFile("../../../migrations/20260723000029_phase26_operation_hardening.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		"server_operations_active_host_action_idx",
		"server_operations_active_service_action_idx",
		"status IN ('pending', 'running', 'awaiting_confirmation')",
	} {
		if !strings.Contains(string(hardening), marker) {
			t.Errorf("Phase 26 operation hardening migration missing %q", marker)
		}
	}
}

func TestSecretMethodsRequireKeyring(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _, err = NewStore(db, nil).GetSecret(context.Background(), "mail", "smarthost")
	if !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("GetSecret error = %v, want ErrSecretUnavailable", err)
	}
}

func TestSecretTransactionMethodsRejectNilTransaction(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyring, err := NewKeyring(1, map[int][]byte{1: testKey(0x73)})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(db, keyring)
	if _, err := store.PutSecretTx(context.Background(), nil, PutSecretParams{
		Scope: "mail", Name: "smarthost", Plaintext: []byte("secret"),
	}); err == nil || !strings.Contains(err.Error(), "transaction") {
		t.Fatalf("PutSecretTx error = %v", err)
	}
	if err := store.DeleteSecretTx(context.Background(), nil, "mail", "smarthost"); err == nil || !strings.Contains(err.Error(), "transaction") {
		t.Fatalf("DeleteSecretTx error = %v", err)
	}
}
