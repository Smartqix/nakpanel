package ops

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/go-sql-driver/mysql"
	dbvalidation "github.com/nakroteck/nakpanel/internal/database"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	ErrEngineNotImplemented = errors.New("database engine is not implemented")
)

type SQLExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type SQLDatabase interface {
	SQLExecutor
	Close() error
}

type SQLOpener func(ctx context.Context) (SQLDatabase, error)

type DatabaseEngine interface {
	CreateDatabase(ctx context.Context, req types.CreateDatabaseReq) error
}

type DatabaseProvisioner struct {
	engines map[types.DBEngine]DatabaseEngine
}

func NewDatabaseProvisioner(engines map[types.DBEngine]DatabaseEngine) *DatabaseProvisioner {
	copied := make(map[types.DBEngine]DatabaseEngine, len(engines))
	for engine, provisioner := range engines {
		copied[engine] = provisioner
	}
	return &DatabaseProvisioner{engines: copied}
}

func (p *DatabaseProvisioner) CreateDatabase(ctx context.Context, req types.CreateDatabaseReq) error {
	req = NormalizeCreateDatabaseRequest(req)
	if err := ValidateCreateDatabaseRequest(req); err != nil {
		return err
	}

	engine, ok := p.engines[req.Engine]
	if !ok || engine == nil {
		return fmt.Errorf("%w: %s", ErrEngineNotImplemented, req.Engine)
	}
	return engine.CreateDatabase(ctx, req)
}

type MariaDBEngine struct {
	exec        SQLExecutor
	opener      SQLOpener
	dsn         string
	verifyLogin bool
}

func NewMariaDBEngine(exec SQLExecutor) *MariaDBEngine {
	return &MariaDBEngine{exec: exec}
}

func NewLazyMariaDBEngine(dsn string) *MariaDBEngine {
	if dsn == "" {
		dsn = DefaultMariaDBDSN()
	}
	return &MariaDBEngine{
		dsn:         dsn,
		verifyLogin: true,
		opener: func(ctx context.Context) (SQLDatabase, error) {
			db, err := sql.Open("mysql", dsn)
			if err != nil {
				return nil, fmt.Errorf("open mariadb connection: %w", err)
			}
			if err := db.PingContext(ctx); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("ping mariadb connection: %w", err)
			}
			return db, nil
		},
	}
}

func DefaultMariaDBDSN() string {
	return "root@unix(/run/mysqld/mysqld.sock)/mysql?parseTime=true"
}

func (e *MariaDBEngine) CreateDatabase(ctx context.Context, req types.CreateDatabaseReq) error {
	req = NormalizeCreateDatabaseRequest(req)
	if err := ValidateCreateDatabaseRequest(req); err != nil {
		return err
	}
	if req.Engine != types.EngineMariaDB {
		return fmt.Errorf("%w: %s", ErrEngineNotImplemented, req.Engine)
	}

	exec := e.exec
	var closer interface{ Close() error }
	if exec == nil {
		if e.opener == nil {
			return errors.New("mariadb connection is not configured")
		}
		db, err := e.opener(ctx)
		if err != nil {
			return err
		}
		exec = db
		closer = db
	}
	if closer != nil {
		defer closer.Close()
	}

	quotedDB := quoteMariaDBIdentifier(req.DBName)
	quotedUser := quoteMariaDBAccount(req.DBUser)
	quotedPasswordHash := quoteMariaDBPasswordHash(mariaDBNativePasswordHash(req.Password))
	statements := []struct {
		query string
		args  []any
	}{
		{
			query: fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", quotedDB),
		},
		{
			query: fmt.Sprintf("CREATE USER IF NOT EXISTS %s ACCOUNT LOCK", quotedUser),
		},
		{
			query: fmt.Sprintf("ALTER USER %s IDENTIFIED BY PASSWORD %s", quotedUser, quotedPasswordHash),
		},
		{
			query: fmt.Sprintf("ALTER USER %s ACCOUNT UNLOCK", quotedUser),
		},
		{
			query: fmt.Sprintf("GRANT ALL PRIVILEGES ON %s.* TO %s", quotedDB, quotedUser),
		},
	}

	for _, stmt := range statements {
		if _, err := exec.ExecContext(ctx, stmt.query, stmt.args...); err != nil {
			return fmt.Errorf("run mariadb statement: %w", err)
		}
	}
	if e.verifyLogin {
		if err := e.verifyDatabaseLogin(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

func (e *MariaDBEngine) verifyDatabaseLogin(ctx context.Context, req types.CreateDatabaseReq) error {
	cfg, err := mysql.ParseDSN(e.dsn)
	if err != nil {
		return fmt.Errorf("parse mariadb dsn for verification: %w", err)
	}
	cfg.User = req.DBUser
	cfg.Passwd = req.Password
	cfg.DBName = req.DBName
	if cfg.Params == nil {
		cfg.Params = make(map[string]string)
	}
	cfg.Params["parseTime"] = "true"

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return fmt.Errorf("open mariadb verification connection: %w", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("verify mariadb database credentials: %w", err)
	}
	return nil
}

func NormalizeCreateDatabaseRequest(req types.CreateDatabaseReq) types.CreateDatabaseReq {
	return dbvalidation.NormalizeCreateDatabaseRequest(req)
}

func ValidateCreateDatabaseRequest(req types.CreateDatabaseReq) error {
	return dbvalidation.ValidateCreateDatabaseRequest(req)
}

func quoteMariaDBIdentifier(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

func quoteMariaDBAccount(user string) string {
	return "'" + strings.ReplaceAll(user, "'", "''") + "'@'localhost'"
}

func quoteMariaDBPasswordHash(hash string) string {
	return "'" + hash + "'"
}

func mariaDBNativePasswordHash(password string) string {
	first := sha1.Sum([]byte(password))
	second := sha1.Sum(first[:])
	return "*" + strings.ToUpper(hex.EncodeToString(second[:]))
}
