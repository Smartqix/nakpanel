package databaseadmin

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
)

func TestPendingCredentialNamePersistsThroughRealSecretIdentityValidation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keyring, err := serveradmin.NewKeyring(1, map[int][]byte{1: bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	store := serveradmin.NewStore(db, keyring)
	const operationID = "op_MiXeD_Base64_-AbC0123456789"
	name := pendingCredentialName(operationID)
	if len(name) != 73 || name != strings.ToLower(name) || name == pendingCredentialName(strings.ToLower(operationID)) {
		t.Fatal("staged name must preserve full ID entropy in lowercase form")
	}
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO service_secrets").WithArgs(sqlmock.AnyArg(), pendingSecretScope, name, sqlmock.AnyArg(), 1, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), int64(7)).WillReturnRows(sqlmock.NewRows([]string{"id", "secret_id", "scope", "name", "key_version", "metadata", "updated_by_user_id", "created_at", "updated_at"}).AddRow(1, "sec_test", pendingSecretScope, name, 1, []byte(`{}`), 7, time.Now(), time.Now()))
	mock.ExpectRollback()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutSecretTx(context.Background(), tx, serveradmin.PutSecretParams{Scope: pendingSecretScope, Name: name, Plaintext: []byte("desired_password_2026"), ActorUserID: 7}); err != nil {
		t.Fatalf("real secret store rejected staged name: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
