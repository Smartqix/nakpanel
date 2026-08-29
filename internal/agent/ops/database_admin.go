package ops

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	dbvalidation "github.com/nakroteck/nakpanel/internal/database"
	"github.com/nakroteck/nakpanel/internal/types"
)

const maxDatabaseIntegrityTables = 5000

type databaseAdminDB interface {
	SQLExecutor
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
	PingContext(context.Context) error
	Close() error
}

type databaseAdminOpener func(context.Context) (databaseAdminDB, error)

type MariaDBAdministration struct {
	dsn    string
	db     databaseAdminDB
	opener databaseAdminOpener
	now    func() time.Time
}

func NewMariaDBAdministration(dsn string) *MariaDBAdministration {
	if strings.TrimSpace(dsn) == "" {
		dsn = DefaultMariaDBDSN()
	}
	return &MariaDBAdministration{
		dsn: dsn,
		opener: func(ctx context.Context) (databaseAdminDB, error) {
			db, err := sql.Open("mysql", dsn)
			if err != nil {
				return nil, fmt.Errorf("open MariaDB administration connection: %w", err)
			}
			if err := db.PingContext(ctx); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("ping MariaDB administration connection: %w", err)
			}
			return db, nil
		},
		now: time.Now,
	}
}

func newMariaDBAdministrationWithDB(db databaseAdminDB) *MariaDBAdministration {
	return &MariaDBAdministration{db: db, now: time.Now}
}

func (m *MariaDBAdministration) InspectDatabaseAdmin(ctx context.Context, req types.InspectDatabaseAdminReq) (types.DatabaseAdminSnapshot, error) {
	if len(req.Targets) > 10000 {
		return types.DatabaseAdminSnapshot{}, errors.New("database inspection target limit exceeded")
	}
	for _, target := range req.Targets {
		if err := validateDatabaseAdminTarget(target); err != nil {
			return types.DatabaseAdminSnapshot{}, err
		}
	}

	db, closeDB, err := m.open(ctx)
	if err != nil {
		return types.DatabaseAdminSnapshot{}, err
	}
	defer closeDB()

	checkedAt := m.now().UTC()
	result := types.DatabaseAdminSnapshot{
		Server: types.DatabaseServerHealth{
			Engine: "mariadb", Available: true, CheckedAt: checkedAt,
		},
		Databases: make([]types.TrackedDatabaseState, 0, len(req.Targets)),
		CheckedAt: checkedAt,
	}
	if err := db.QueryRowContext(ctx, `SELECT VERSION()`).Scan(&result.Server.Version); err != nil {
		return types.DatabaseAdminSnapshot{}, fmt.Errorf("inspect MariaDB version: %w", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.PROCESSLIST`).Scan(&result.Server.Threads); err != nil {
		return types.DatabaseAdminSnapshot{}, fmt.Errorf("inspect MariaDB threads: %w", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE COMMAND <> 'Sleep'`).Scan(&result.Server.Connections); err != nil {
		return types.DatabaseAdminSnapshot{}, fmt.Errorf("inspect MariaDB connections: %w", err)
	}
	var uptimeName, uptimeValue string
	if err := db.QueryRowContext(ctx, `SHOW GLOBAL STATUS LIKE 'Uptime'`).Scan(&uptimeName, &uptimeValue); err != nil {
		return types.DatabaseAdminSnapshot{}, fmt.Errorf("inspect MariaDB uptime: %w", err)
	}
	result.Server.Uptime, _ = strconv.ParseInt(uptimeValue, 10, 64)

	for _, target := range req.Targets {
		state := types.TrackedDatabaseState{
			DatabaseID: target.DatabaseID, Name: target.Name, Principal: target.Principal,
		}
		var databaseCount int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?`, target.Name).Scan(&databaseCount); err != nil {
			state.LastError = "database state could not be inspected"
			result.Databases = append(result.Databases, state)
			continue
		}
		state.DatabaseExists = databaseCount == 1
		var principalCount int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mysql.user WHERE User = ? AND Host = 'localhost'`, target.Principal).Scan(&principalCount); err != nil {
			state.LastError = "principal state could not be inspected"
		} else {
			state.PrincipalExists = principalCount == 1
		}
		result.Databases = append(result.Databases, state)
	}
	return result, nil
}

func (m *MariaDBAdministration) ManageDatabaseAdmin(ctx context.Context, req types.ManageDatabaseAdminReq) (types.ManageDatabaseAdminResult, error) {
	if !operationIDRE.MatchString(req.OperationID) {
		return types.ManageDatabaseAdminResult{}, errors.New("a valid operation id is required")
	}
	if err := validateDatabaseAdminTarget(req.Target); err != nil {
		return types.ManageDatabaseAdminResult{}, err
	}
	switch req.Action {
	case types.DatabaseAdminRotatePassword:
		if req.Role != "" {
			return types.ManageDatabaseAdminResult{}, errors.New("role is not valid for password rotation")
		}
		if err := validateDatabaseAdminPassword(req.Target, req.Password); err != nil {
			return types.ManageDatabaseAdminResult{}, err
		}
	case types.DatabaseAdminSetRole:
		if req.Password != "" {
			return types.ManageDatabaseAdminResult{}, errors.New("password is not valid for role changes")
		}
		if !validDatabaseAdminRole(req.Role) {
			return types.ManageDatabaseAdminResult{}, errors.New("database role is not allowed")
		}
	case types.DatabaseAdminCheck:
		if req.Password != "" || req.Role != "" {
			return types.ManageDatabaseAdminResult{}, errors.New("database checks do not accept role or password fields")
		}
	default:
		return types.ManageDatabaseAdminResult{}, errors.New("database administration action is not allowed")
	}

	db, closeDB, err := m.open(ctx)
	if err != nil {
		return types.ManageDatabaseAdminResult{}, err
	}
	defer closeDB()

	result := types.ManageDatabaseAdminResult{
		DatabaseID: req.Target.DatabaseID, Action: req.Action, Role: req.Role, CheckedAt: m.now().UTC(),
	}
	switch req.Action {
	case types.DatabaseAdminRotatePassword:
		hash := quoteMariaDBPasswordHash(mariaDBNativePasswordHash(req.Password))
		if _, err := db.ExecContext(ctx, fmt.Sprintf(
			"ALTER USER %s IDENTIFIED BY PASSWORD %s",
			quoteMariaDBAccount(req.Target.Principal), hash,
		)); err != nil {
			return types.ManageDatabaseAdminResult{}, fmt.Errorf("rotate tracked MariaDB principal password: %w", err)
		}
		result.Changed = true
	case types.DatabaseAdminSetRole:
		if err := applyDatabaseAdminRole(ctx, db, req.Target, req.Role); err != nil {
			return types.ManageDatabaseAdminResult{}, err
		}
		result.Changed = true
	case types.DatabaseAdminCheck:
		checks, err := checkDatabaseIntegrity(ctx, db, req.Target.Name)
		if err != nil {
			return types.ManageDatabaseAdminResult{}, err
		}
		result.Checks = checks
	}
	return result, nil
}

func (m *MariaDBAdministration) open(ctx context.Context) (databaseAdminDB, func(), error) {
	if m == nil {
		return nil, func() {}, errors.New("MariaDB administration is not configured")
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.db != nil {
		if err := m.db.PingContext(ctx); err != nil {
			return nil, func() {}, fmt.Errorf("ping MariaDB administration connection: %w", err)
		}
		return m.db, func() {}, nil
	}
	if m.opener == nil {
		return nil, func() {}, errors.New("MariaDB administration is not configured")
	}
	db, err := m.opener(ctx)
	if err != nil {
		return nil, func() {}, err
	}
	return db, func() { _ = db.Close() }, nil
}

func validateDatabaseAdminTarget(target types.DatabaseAdminTarget) error {
	if target.DatabaseID <= 0 {
		return errors.New("tracked database id is required")
	}
	req := types.CreateDatabaseReq{
		Engine: types.EngineMariaDB, DBName: target.Name, DBUser: target.Principal,
		Password: "validation_only_password",
	}
	if err := dbvalidation.ValidateCreateDatabaseRequest(req); err != nil {
		return fmt.Errorf("invalid tracked database target: %w", err)
	}
	return nil
}

func validateDatabaseAdminPassword(target types.DatabaseAdminTarget, password string) error {
	return dbvalidation.ValidateCreateDatabaseRequest(types.CreateDatabaseReq{
		Engine: types.EngineMariaDB, DBName: target.Name, DBUser: target.Principal, Password: password,
	})
}

func validDatabaseAdminRole(role types.DatabaseAdminRole) bool {
	switch role {
	case types.DatabaseAdminRoleReadOnly, types.DatabaseAdminRoleReadWrite, types.DatabaseAdminRoleSchemaManager:
		return true
	default:
		return false
	}
}

func applyDatabaseAdminRole(ctx context.Context, db databaseAdminDB, target types.DatabaseAdminTarget, role types.DatabaseAdminRole) error {
	var privileges string
	switch role {
	case types.DatabaseAdminRoleReadOnly:
		privileges = "SELECT, SHOW VIEW"
	case types.DatabaseAdminRoleReadWrite:
		privileges = "SELECT, INSERT, UPDATE, DELETE, EXECUTE, SHOW VIEW"
	case types.DatabaseAdminRoleSchemaManager:
		privileges = "SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, EXECUTE, CREATE VIEW, SHOW VIEW, TRIGGER"
	default:
		return errors.New("database role is not allowed")
	}
	database := quoteMariaDBIdentifier(target.Name)
	principal := quoteMariaDBAccount(target.Principal)
	previous, err := readMariaDBGrants(ctx, db, principal)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, fmt.Sprintf("REVOKE ALL PRIVILEGES, GRANT OPTION FROM %s", principal)); err != nil {
		return fmt.Errorf("reset tracked MariaDB principal grants: %w", err)
	}
	if _, err := db.ExecContext(ctx, fmt.Sprintf("GRANT %s ON %s.* TO %s", privileges, database, principal)); err != nil {
		rollbackErr := restoreMariaDBGrants(ctx, db, previous)
		if rollbackErr != nil {
			return fmt.Errorf("apply tracked MariaDB principal role: %w (restore previous grants: %v)", err, rollbackErr)
		}
		return fmt.Errorf("apply tracked MariaDB principal role: %w", err)
	}
	return nil
}

func readMariaDBGrants(ctx context.Context, db databaseAdminDB, principal string) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SHOW GRANTS FOR "+principal)
	if err != nil {
		return nil, fmt.Errorf("inspect tracked MariaDB principal grants: %w", err)
	}
	defer rows.Close()
	grants := make([]string, 0, 4)
	for rows.Next() {
		var statement string
		if err := rows.Scan(&statement); err != nil {
			return nil, fmt.Errorf("read tracked MariaDB principal grant: %w", err)
		}
		if len(statement) > 4096 || !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(statement)), "GRANT ") {
			return nil, errors.New("MariaDB returned an unsupported principal grant")
		}
		grants = append(grants, statement)
		if len(grants) > 128 {
			return nil, errors.New("tracked MariaDB principal grant limit exceeded")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read tracked MariaDB principal grants: %w", err)
	}
	if len(grants) == 0 {
		return nil, errors.New("tracked MariaDB principal has no grant state")
	}
	return grants, nil
}

func restoreMariaDBGrants(ctx context.Context, db SQLExecutor, grants []string) error {
	var failures []string
	for _, statement := range grants {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return errors.New(boundedText([]byte(strings.Join(failures, "; ")), 4096))
	}
	return nil
}

func checkDatabaseIntegrity(ctx context.Context, db databaseAdminDB, database string) ([]types.DatabaseIntegrityItem, error) {
	rows, err := db.QueryContext(ctx, `
SELECT TABLE_NAME
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'
ORDER BY TABLE_NAME
LIMIT ?`, database, maxDatabaseIntegrityTables+1)
	if err != nil {
		return nil, fmt.Errorf("list MariaDB tables for integrity check: %w", err)
	}
	defer rows.Close()

	names := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("read MariaDB integrity table: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list MariaDB integrity tables: %w", err)
	}
	if len(names) > maxDatabaseIntegrityTables {
		return nil, errors.New("database integrity table limit exceeded")
	}

	result := make([]types.DatabaseIntegrityItem, 0, len(names))
	for _, table := range names {
		checkRows, err := db.QueryContext(ctx, fmt.Sprintf(
			"CHECK TABLE %s.%s QUICK",
			quoteMariaDBIdentifier(database), quoteMariaDBIdentifier(table),
		))
		if err != nil {
			return nil, fmt.Errorf("check MariaDB table: %w", err)
		}
		var tableName, operation, messageType, messageText string
		for checkRows.Next() {
			if err := checkRows.Scan(&tableName, &operation, &messageType, &messageText); err != nil {
				_ = checkRows.Close()
				return nil, fmt.Errorf("read MariaDB table check: %w", err)
			}
			result = append(result, types.DatabaseIntegrityItem{
				Table: table, Status: strings.ToLower(messageType), Message: boundedText([]byte(messageText), 1024),
			})
		}
		if err := checkRows.Err(); err != nil {
			_ = checkRows.Close()
			return nil, fmt.Errorf("read MariaDB table check rows: %w", err)
		}
		_ = checkRows.Close()
	}
	return result, nil
}
