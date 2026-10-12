package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	panelhttp "github.com/nakroteck/nakpanel/internal/control/http"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
)

func startDatabaseManager(ctx context.Context, db *sql.DB, secrets *serveradmin.Store) (*panelhttp.DatabaseManagerProxy, func(), error) {
	keyPath := os.Getenv("NAKPANEL_DATABASE_MANAGER_KEY_FILE")
	if keyPath == "" {
		keyPath = "/etc/nakpanel/database-manager.key"
	}
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, func() {}, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read database manager key: %w", err)
	}
	if len(strings.TrimSpace(string(key))) < 32 {
		return nil, nil, errors.New("database manager key is invalid")
	}
	group, err := user.LookupGroup("nakpanel-dbmgr")
	if err != nil {
		return nil, nil, errors.New("database manager runtime group is missing")
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return nil, nil, err
	}
	const socket = "/run/nakpanel-db-manager/bridge.sock"
	dir := filepath.Dir(socket)
	if err = os.MkdirAll(dir, 0750); err != nil {
		return nil, nil, err
	}
	if err = os.Chown(dir, -1, gid); err != nil {
		return nil, nil, err
	}
	if err = os.Chmod(dir, 0750); err != nil {
		return nil, nil, err
	}
	if info, statErr := os.Lstat(socket); statErr == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, nil, errors.New("database manager bridge is not a socket")
		}
		if err = os.Remove(socket); err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, nil, statErr
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return nil, nil, err
	}
	if err = os.Chown(socket, -1, gid); err != nil {
		listener.Close()
		return nil, nil, err
	}
	if err = os.Chmod(socket, 0660); err != nil {
		listener.Close()
		return nil, nil, err
	}
	proxy := panelhttp.NewDatabaseManagerProxy(provision.NewSQLDatabaseManager(db, secrets), string(key))
	srv := &http.Server{Handler: proxy.BridgeHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192}
	go func() { _ = srv.Serve(listener) }()
	close := func() { _ = srv.Close() }
	go func() { <-ctx.Done(); close() }()
	return proxy, close, nil
}
