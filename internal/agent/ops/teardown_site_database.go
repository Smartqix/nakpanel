package ops

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nakroteck/nakpanel/internal/types"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const databaseSharedPrincipalSQL = `SELECT
 (SELECT COUNT(*) FROM mysql.db WHERE User=? AND Db<>?) +
 (SELECT COUNT(*) FROM mysql.tables_priv WHERE User=? AND Db<>?) +
 (SELECT COUNT(*) FROM mysql.columns_priv WHERE User=? AND Db<>?) +
 (SELECT COUNT(*) FROM mysql.procs_priv WHERE User=? AND Db<>?) +
 (SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=? AND PRIVILEGE_TYPE<>'USAGE') +
 (SELECT COUNT(*) FROM mysql.user WHERE User=? AND Host<>'localhost')`

type databaseRemovalOwnership struct {
	OperationID      int64             `json:"operation_id"`
	Database         databaseOwnership `json:"database"`
	SchemaDropped    bool              `json:"schema_dropped"`
	PrincipalRemoved bool              `json:"principal_removed"`
	Complete         bool              `json:"complete"`
}

func (e *MariaDBEngine) lockDatabaseRemoval(ctx context.Context) (func(), error) {
	if e == nil || e.ownershipDir == "" {
		return nil, errors.New("database ownership inspection is not configured")
	}
	if err := os.MkdirAll(e.ownershipDir, 0700); err != nil {
		return nil, errors.New("database ownership directory is unavailable")
	}
	for _, path := range []string{filepath.Dir(e.ownershipDir), e.ownershipDir} {
		if err := validateDatabaseOwnershipPath(path, e.ownerUID, true); err != nil {
			return nil, err
		}
	}
	file, err := openSiteIdentityLock(filepath.Join(e.ownershipDir, ".lock"))
	if err != nil {
		return nil, errors.New("database ownership lock is unavailable")
	}
	for {
		err = lockSiteIdentityFile(file)
		if err == nil {
			break
		}
		if !siteIdentityLockBusy(err) {
			file.Close()
			return nil, errors.New("database ownership lock failed")
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return func() { unlockSiteIdentityFile(file); file.Close() }, nil
}
func (e *MariaDBEngine) readDatabaseRemoval(path string) (databaseRemovalOwnership, error) {
	var state databaseRemovalOwnership
	if err := validateDatabaseOwnershipPath(path, e.ownerUID, false); err != nil {
		if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
			return state, os.ErrNotExist
		}
		return state, err
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 65536 {
		return state, errors.New("database removal journal is unavailable")
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, errors.New("database removal journal is invalid")
	}
	return state, nil
}
func (e *MariaDBEngine) writeDatabaseRemoval(path string, state databaseRemovalOwnership) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err = writeFileAtomic(path, data, 0600); err != nil {
		return errors.New("database removal journal could not be persisted")
	}
	return nil
}

func (e *MariaDBEngine) verifiedDatabaseOwnership(target databaseOwnership) error {
	if e == nil || e.ownershipDir == "" {
		return errors.New("database ownership inspection is not configured")
	}
	for _, path := range []string{filepath.Dir(e.ownershipDir), e.ownershipDir} {
		if err := validateDatabaseOwnershipPath(path, e.ownerUID, true); err != nil {
			return err
		}
	}
	path := filepath.Join(e.ownershipDir, strconv.FormatInt(target.DatabaseID, 10)+".json")
	if err := validateDatabaseOwnershipPath(path, e.ownerUID, false); err != nil {
		return errors.New("selected database has no verified ownership marker")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 65536 {
		return errors.New("selected database ownership cannot be read")
	}
	var stored databaseOwnership
	if json.Unmarshal(data, &stored) != nil || stored != target {
		return errors.New("selected database ownership differs from its approved identity")
	}
	return nil
}

// The durable reservation prevents stale creates and checkpoint loss from
// dropping a subsequently recreated schema using the same name.
func (e *MariaDBEngine) RemoveOwnedDatabase(ctx context.Context, operationID int64, target types.SiteRemovalDatabase) (bool, error) {
	if operationID <= 0 || target.ID <= 0 || !databaseIdentifierRE.MatchString(target.Name) || !databaseIdentifierRE.MatchString(target.Principal) {
		return false, errors.New("valid database removal identity is required")
	}
	release, err := e.lockDatabaseRemoval(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	want := databaseOwnership{DatabaseID: target.ID, Name: target.Name, Principal: target.Principal}
	path := filepath.Join(e.ownershipDir, strconv.FormatInt(target.ID, 10)+".removed.json")
	state, err := e.readDatabaseRemoval(path)
	if errors.Is(err, os.ErrNotExist) {
		state = databaseRemovalOwnership{OperationID: operationID, Database: want}
	} else if err != nil {
		return false, err
	}
	if state.OperationID != operationID || state.Database != want {
		return false, errors.New("database removal does not match its durable reservation")
	}
	if state.Complete {
		return state.PrincipalRemoved, nil
	}
	if err = e.verifiedDatabaseOwnership(want); err != nil {
		return false, err
	}
	exec := e.exec
	if exec == nil {
		if e.opener == nil {
			return false, errors.New("database removal connection is unavailable")
		}
		db, err := e.opener(ctx)
		if err != nil {
			return false, errors.New("database removal connection is unavailable")
		}
		defer db.Close()
		exec = db
	}
	inspector, ok := exec.(databaseOwnershipInspector)
	if !ok {
		return false, errors.New("database removal inspection is unavailable")
	}
	var schemas, principals, shared int
	if err = inspector.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?`, target.Name).Scan(&schemas); err != nil {
		return false, errors.New("selected database cannot be inspected")
	}
	if err = inspector.QueryRowContext(ctx, `SELECT COUNT(*) FROM mysql.user WHERE User=? AND Host='localhost'`, target.Principal).Scan(&principals); err != nil {
		return false, errors.New("selected database principal cannot be inspected")
	}
	if shared, err = databasePrincipalDependencies(ctx, inspector, target.Name, target.Principal); err != nil {
		return false, errors.New("database principal dependencies cannot be inspected")
	}
	if schemas > 1 || principals > 1 {
		return false, errors.New("selected database has ambiguous ownership")
	}
	if err = e.writeDatabaseRemoval(path, state); err != nil {
		return false, err
	}
	if !state.SchemaDropped {
		if _, err = exec.ExecContext(ctx, "DROP DATABASE IF EXISTS "+quoteMariaDBIdentifier(target.Name)); err != nil {
			return false, errors.New("selected database could not be removed")
		}
		state.SchemaDropped = true
		if err = e.writeDatabaseRemoval(path, state); err != nil {
			return false, err
		}
	}
	if shared == 0 {
		if principals > 0 && !state.PrincipalRemoved {
			if _, err = exec.ExecContext(ctx, "DROP USER IF EXISTS "+quoteMariaDBAccount(target.Principal)); err != nil {
				return false, errors.New("selected database principal could not be removed")
			}
		}
		state.PrincipalRemoved = true
	}
	state.Complete = true
	if err = e.writeDatabaseRemoval(path, state); err != nil {
		return false, err
	}
	return state.PrincipalRemoved, nil
}

func databasePrincipalDependencies(ctx context.Context, inspector databaseOwnershipInspector, name, principal string) (int, error) {
	pattern := strings.NewReplacer(`\`, `\\`, `_`, `\_`, `%`, `\%`).Replace(name)
	var shared int
	err := inspector.QueryRowContext(ctx, databaseSharedPrincipalSQL, principal, pattern, principal, name, principal, name, principal, name, quoteMariaDBAccount(principal), principal).Scan(&shared)
	return shared, err
}

func (p *SiteTeardownProvisioner) validateSelectedDatabaseOwnership(req types.TeardownSiteReq) error {
	if len(req.DeleteDatabaseIDs) == 0 {
		return nil
	}
	if p.options.MariaDB == nil {
		return errors.New("selected database removal is not configured")
	}
	for _, id := range req.DeleteDatabaseIDs {
		for _, target := range req.Snapshot.Databases {
			if target.ID == id {
				if err := p.options.MariaDB.verifiedDatabaseOwnership(databaseOwnership{DatabaseID: id, Name: target.Name, Principal: target.Principal}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (e *MariaDBEngine) rejectRetiredDatabaseClaim(req types.CreateDatabaseReq) error {
	entries, err := os.ReadDir(e.ownershipDir)
	if err != nil {
		return errors.New("database removal reservations cannot be inspected")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".removed.json") {
			continue
		}
		state, err := e.readDatabaseRemoval(filepath.Join(e.ownershipDir, entry.Name()))
		if err != nil {
			return err
		}
		if state.Database.DatabaseID == req.DatabaseID || (!state.Complete && state.Database.Name == req.DBName) {
			return errors.New("database identity is retired or reserved for removal")
		}
	}
	return nil
}

func (p *SiteTeardownProvisioner) removeSelectedDatabases(ctx context.Context, req types.TeardownSiteReq, journalPath string, journal *siteRemovalJournal) error {
	if len(req.DeleteDatabaseIDs) == 0 {
		return nil
	}
	if p.options.MariaDB == nil {
		return errors.New("selected database removal is not configured")
	}
	for _, id := range req.DeleteDatabaseIDs {
		for _, database := range req.Snapshot.Databases {
			if database.ID != id {
				continue
			}
			if err := p.removalCheckpoint(journalPath, journal, "database-removed:"+siteRemovalID(id), func() error {
				removed, err := p.options.MariaDB.RemoveOwnedDatabase(ctx, req.OperationID, database)
				if err != nil {
					return err
				}
				flag := "database-principal-kept:"
				if removed {
					flag = "database-principal-removed:"
				}
				journal.Checkpoints = append(journal.Checkpoints, flag+siteRemovalID(id))
				return nil
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
