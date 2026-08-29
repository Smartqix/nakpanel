package ops

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestMariaDBAdministrationInspectsOnlyTypedTargets(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	admin := newMariaDBAdministrationWithDB(db)
	admin.now = func() time.Time { return time.Date(2026, 7, 23, 15, 0, 0, 0, time.UTC) }

	mock.ExpectPing()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT VERSION()")).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow("11.4.7-MariaDB"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM information_schema.PROCESSLIST")).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(4))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE COMMAND <> 'Sleep'")).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectQuery(regexp.QuoteMeta("SHOW GLOBAL STATUS LIKE 'Uptime'")).
		WillReturnRows(sqlmock.NewRows([]string{"name", "value"}).AddRow("Uptime", "7200"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?")).
		WithArgs("np_demo").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM mysql.user WHERE User = ? AND Host = 'localhost'")).
		WithArgs("np_demo_user").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	result, err := admin.InspectDatabaseAdmin(context.Background(), types.InspectDatabaseAdminReq{
		Targets: []types.DatabaseAdminTarget{{DatabaseID: 7, Name: "np_demo", Principal: "np_demo_user"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Server.Available || result.Server.Version != "11.4.7-MariaDB" ||
		result.Server.Uptime != 7200 || len(result.Databases) != 1 ||
		!result.Databases[0].DatabaseExists || !result.Databases[0].PrincipalExists {
		t.Fatalf("unexpected inspection result: %#v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMariaDBAdministrationAppliesOnlyAllowlistedRole(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	admin := newMariaDBAdministrationWithDB(db)

	mock.ExpectPing()
	mock.ExpectQuery(regexp.QuoteMeta("SHOW GRANTS FOR 'np_demo_user'@'localhost'")).
		WillReturnRows(sqlmock.NewRows([]string{"Grants for np_demo_user@localhost"}).
			AddRow("GRANT ALL PRIVILEGES ON `np_demo`.* TO `np_demo_user`@`localhost`"))
	mock.ExpectExec(regexp.QuoteMeta("REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'np_demo_user'@'localhost'")).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("GRANT SELECT, SHOW VIEW ON `np_demo`.* TO 'np_demo_user'@'localhost'")).
		WillReturnResult(sqlmock.NewResult(0, 0))

	result, err := admin.ManageDatabaseAdmin(context.Background(), types.ManageDatabaseAdminReq{
		OperationID: "op_0123456789abcdef0123456789abcdef",
		Action:      types.DatabaseAdminSetRole,
		Target:      types.DatabaseAdminTarget{DatabaseID: 7, Name: "np_demo", Principal: "np_demo_user"},
		Role:        types.DatabaseAdminRoleReadOnly,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Role != types.DatabaseAdminRoleReadOnly {
		t.Fatalf("unexpected role result: %#v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMariaDBAdministrationRestoresGrantsWhenRoleApplyFails(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	admin := newMariaDBAdministrationWithDB(db)
	previous := "GRANT SELECT, INSERT ON `np_demo`.* TO `np_demo_user`@`localhost`"

	mock.ExpectPing()
	mock.ExpectQuery(regexp.QuoteMeta("SHOW GRANTS FOR 'np_demo_user'@'localhost'")).
		WillReturnRows(sqlmock.NewRows([]string{"grant"}).AddRow(previous))
	mock.ExpectExec(regexp.QuoteMeta("REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'np_demo_user'@'localhost'")).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("GRANT SELECT, SHOW VIEW ON `np_demo`.* TO 'np_demo_user'@'localhost'")).
		WillReturnError(errors.New("grant rejected"))
	mock.ExpectExec(regexp.QuoteMeta(previous)).
		WillReturnResult(sqlmock.NewResult(0, 0))

	_, err = admin.ManageDatabaseAdmin(context.Background(), types.ManageDatabaseAdminReq{
		OperationID: "op_0123456789abcdef0123456789abcdef",
		Action:      types.DatabaseAdminSetRole,
		Target:      types.DatabaseAdminTarget{DatabaseID: 7, Name: "np_demo", Principal: "np_demo_user"},
		Role:        types.DatabaseAdminRoleReadOnly,
	})
	if err == nil {
		t.Fatal("expected role apply failure")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMariaDBAdministrationRejectsInjectionBeforeOpeningDatabase(t *testing.T) {
	admin := newMariaDBAdministrationWithDB(nil)
	for _, req := range []types.ManageDatabaseAdminReq{
		{
			OperationID: "op_0123456789abcdef0123456789abcdef",
			Action:      types.DatabaseAdminSetRole,
			Target:      types.DatabaseAdminTarget{DatabaseID: 1, Name: "np_demo; DROP DATABASE mysql", Principal: "np_user"},
			Role:        types.DatabaseAdminRoleReadOnly,
		},
		{
			OperationID: "op_0123456789abcdef0123456789abcdef",
			Action:      types.DatabaseAdminRotatePassword,
			Target:      types.DatabaseAdminTarget{DatabaseID: 1, Name: "np_demo", Principal: "np_user"},
			Password:    "not safe spaces",
		},
		{
			OperationID: "op_0123456789abcdef0123456789abcdef",
			Action:      types.DatabaseAdminSetRole,
			Target:      types.DatabaseAdminTarget{DatabaseID: 1, Name: "np_demo", Principal: "np_user"},
			Role:        "SUPER",
		},
	} {
		if _, err := admin.ManageDatabaseAdmin(context.Background(), req); err == nil {
			t.Fatalf("expected request rejection: %#v", req)
		}
	}
}
