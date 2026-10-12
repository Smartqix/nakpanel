package ops

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestPasswordRotationVerifiesRestrictedLoginAndReplaysSameCredential(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	admin := newMariaDBAdministrationWithDB(db)
	req := types.ManageDatabaseAdminReq{OperationID: "op_0123456789abcdef0123456789abcdef", Action: types.DatabaseAdminRotatePassword, Target: types.DatabaseAdminTarget{DatabaseID: 7, Name: "np_demo", Principal: "np_demo_user"}, Password: "desired_password_2026"}
	attempts := 0
	admin.verifyCredential = func(_ context.Context, credential types.CreateDatabaseReq) error {
		attempts++
		if credential.DBName != req.Target.Name || credential.DBUser != req.Target.Principal || credential.Password != req.Password {
			t.Fatal("verification did not use restricted desired credential")
		}
		if attempts == 1 {
			return errors.New("lost response " + req.Password)
		}
		return nil
	}
	for i := 0; i < 2; i++ {
		mock.ExpectPing()
		mock.ExpectExec("ALTER USER 'np_demo_user'@'localhost' IDENTIFIED BY PASSWORD").WillReturnResult(sqlmock.NewResult(0, 1))
		result, err := admin.ManageDatabaseAdmin(context.Background(), req)
		if i == 0 && (err == nil || strings.Contains(err.Error(), req.Password) || result.Changed) {
			t.Fatal("verification failure must be sanitized and not reported successful")
		}
		if i == 1 && (err != nil || !result.Changed) {
			t.Fatalf("reconciliation failed: %v", err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
