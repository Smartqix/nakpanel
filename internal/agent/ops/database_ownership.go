package ops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/nakroteck/nakpanel/internal/types"
)

type databaseOwnership struct {
	DatabaseID int64  `json:"database_id"`
	Name       string `json:"name"`
	Principal  string `json:"principal"`
}

type databaseOwnershipInspector interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// A private, durable marker reserves a previously absent pair before any DDL.
// Partial application is replayable only by the same control-plane intent.
func (e *MariaDBEngine) claimDatabaseOwnership(ctx context.Context, exec SQLExecutor, req types.CreateDatabaseReq) (func(), error) {
	return e.claimDatabaseOwnershipMode(ctx, exec, req, false)
}

func (e *MariaDBEngine) claimDatabaseOwnershipMode(ctx context.Context, exec SQLExecutor, req types.CreateDatabaseReq, restoredSchema bool) (func(), error) {
	if req.DatabaseID <= 0 || e.ownershipDir == "" {
		return nil, errors.New("tracked database ownership is required")
	}
	inspector, ok := exec.(databaseOwnershipInspector)
	if !ok {
		return nil, errors.New("database ownership inspection is not configured")
	}
	if err := os.MkdirAll(e.ownershipDir, 0700); err != nil {
		return nil, errors.New("prepare database ownership directory failed")
	}
	for _, path := range []string{filepath.Dir(e.ownershipDir), e.ownershipDir} {
		if err := validateDatabaseOwnershipPath(path, e.ownerUID, true); err != nil {
			return nil, err
		}
	}
	lock, err := os.OpenFile(filepath.Join(e.ownershipDir, ".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("open database ownership lock failed")
	}
	release := func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() }
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, errors.New("lock database ownership failed")
	}
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	marker := filepath.Join(e.ownershipDir, strconv.FormatInt(req.DatabaseID, 10)+".json")
	want := databaseOwnership{DatabaseID: req.DatabaseID, Name: req.DBName, Principal: req.DBUser}
	if _, err := os.Lstat(marker); err == nil {
		if err := validateDatabaseOwnershipPath(marker, e.ownerUID, false); err != nil {
			return nil, err
		}
		payload, err := os.ReadFile(marker)
		if err != nil {
			return nil, errors.New("read database ownership failed")
		}
		var stored databaseOwnership
		if json.Unmarshal(payload, &stored) != nil || stored != want {
			return nil, errors.New("database ownership does not match tracked intent")
		}
		success = true
		return release, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect database ownership failed")
	}
	var databases, principals int
	if err := inspector.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?`, req.DBName).Scan(&databases); err != nil {
		return nil, errors.New("inspect existing database failed")
	}
	// Reject a principal at any host, not just localhost.
	if err := inspector.QueryRowContext(ctx, `SELECT COUNT(*) FROM mysql.user WHERE User = ?`, req.DBUser).Scan(&principals); err != nil {
		return nil, errors.New("inspect existing database principal failed")
	}
	if (!restoredSchema && databases != 0) || (restoredSchema && databases != 1) || principals != 0 {
		return nil, errors.New("database or principal already exists without verified ownership")
	}
	payload, _ := json.Marshal(want)
	if err := writeFileAtomic(marker, payload, 0600); err != nil {
		return nil, errors.New("persist database ownership failed")
	}
	success = true
	return release, nil
}

// AdoptRestoredDatabaseOwnership is only for the root disaster-recovery CLI,
// immediately after importing this schema from a verified full-server archive.
// It is deliberately not exposed as an agent operation or request option.
// Legacy existing principals require manual review; this never takes them over.
func AdoptRestoredDatabaseOwnership(ctx context.Context, target types.DatabaseAdminTarget) error {
	if os.Geteuid() != 0 {
		return errors.New("restored database ownership requires root")
	}
	if err := validateDatabaseAdminTarget(target); err != nil {
		return err
	}
	engine := NewLazyMariaDBEngine(DefaultMariaDBDSN())
	db, err := engine.opener(ctx)
	if err != nil {
		return errors.New("open restored database inspection failed")
	}
	defer db.Close()
	release, err := engine.claimDatabaseOwnershipMode(ctx, db, types.CreateDatabaseReq{DatabaseID: target.DatabaseID, DBName: target.Name, DBUser: target.Principal}, true)
	if err != nil {
		return err
	}
	release()
	return nil
}

func validateDatabaseOwnershipPath(path string, uid uint32, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("inspect database ownership path failed")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return errors.New("database ownership path is not private and agent-owned")
	}
	return nil
}
