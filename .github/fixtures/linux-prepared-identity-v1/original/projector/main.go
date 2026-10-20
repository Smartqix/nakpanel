// Private no-connect configuration projector, never a database probe.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/jackc/pgx/v5"
)

const canonicalDSN = "postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable"

type projection struct {
	PGXVersion           string `json:"pgx_version"`
	Mode                 string `json:"mode"`
	ParserMode           string `json:"parser_mode"`
	NetworkOrSQLExecuted bool   `json:"network_or_sql_executed"`
}

func project(dsn string, parse func(string) (*pgx.ConnConfig, error)) (projection, error) {
	var empty projection
	if dsn != canonicalDSN {
		return empty, errors.New("configuration rejected")
	}
	cfg, err := parse(dsn)
	if err != nil || cfg == nil || cfg.DefaultQueryExecMode != pgx.QueryExecModeCacheStatement {
		return empty, errors.New("configuration rejected")
	}
	return projection{PGXVersion: "5.7.2", Mode: "cache_statement", ParserMode: cfg.DefaultQueryExecMode.String(), NetworkOrSQLExecuted: false}, nil
}

func execute() error {
	if len(os.Args) != 1 {
		return errors.New("arguments rejected")
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("build rejected")
	}
	found := false
	for _, dep := range info.Deps {
		if dep.Path == "github.com/jackc/pgx/v5" {
			found = dep.Version == "v5.7.2" && dep.Replace == nil
		}
	}
	if !found {
		return errors.New("build rejected")
	}
	os.Clearenv()
	if err := os.Setenv("PGPASSFILE", "/dev/null"); err != nil {
		return errors.New("environment rejected")
	}
	value, err := project(canonicalDSN, pgx.ParseConfig)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(value)
}

func main() {
	if execute() != nil {
		fmt.Fprintln(os.Stderr, "day0 query projection rejected")
		os.Exit(1)
	}
}
