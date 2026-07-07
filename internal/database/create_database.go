package database

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,47}$`)
	passwordPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{12,256}$`)
)

func NormalizeCreateDatabaseRequest(req types.CreateDatabaseReq) types.CreateDatabaseReq {
	req.Engine = types.DBEngine(strings.ToLower(strings.TrimSpace(string(req.Engine))))
	req.DBName = strings.ToLower(strings.TrimSpace(req.DBName))
	req.DBUser = strings.ToLower(strings.TrimSpace(req.DBUser))
	return req
}

func ValidateCreateDatabaseRequest(req types.CreateDatabaseReq) error {
	req = NormalizeCreateDatabaseRequest(req)
	switch req.Engine {
	case types.EngineMariaDB, types.EngineMySQL, types.EnginePgSQL:
	default:
		return fmt.Errorf("unsupported database engine %q", req.Engine)
	}
	if !identifierPattern.MatchString(req.DBName) {
		return errors.New("database name must start with a lowercase letter and contain only lowercase letters, digits, and underscores")
	}
	if !identifierPattern.MatchString(req.DBUser) {
		return errors.New("database user must start with a lowercase letter and contain only lowercase letters, digits, and underscores")
	}
	if !passwordPattern.MatchString(req.Password) {
		return errors.New("database password must be 12-256 URL-safe characters")
	}
	return nil
}
