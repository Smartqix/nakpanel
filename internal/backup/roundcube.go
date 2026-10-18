package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// RoundcubeSQLiteDumpName holds a consistent SQLite online-backup snapshot,
// rather than a live database file or its independently changing WAL.
const RoundcubeSQLiteDumpName = "sqlite/roundcube.sqlite"
const NativeRoundcubeSQLitePath = "/var/lib/roundcube/roundcube.sqlite"

func IsRoundcubeSQLitePath(path string) bool {
	switch path {
	case NativeRoundcubeSQLitePath, "/var/lib/roundcube/db/roundcube", "/var/lib/dbconfig-common/sqlite3/roundcube/roundcube":
		return true
	}
	return false
}
func RoundcubeSQLiteDestination(source string, mode RestoreMode) (string, error) {
	if !IsRoundcubeSQLitePath(source) {
		return "", fmt.Errorf("unsupported Roundcube SQLite path %q", source)
	}
	if mode == RestoreForwardMigration {
		return NativeRoundcubeSQLitePath, nil
	}
	return source, nil
}

// CheckRoundcubeRestoreTarget verifies the actual SQLite import prerequisites
// without stopping FPM or replacing the installed database.
func CheckRoundcubeRestoreTarget(source Manifest, target PlatformProvenance, mode RestoreMode) error {
	if source.RoundcubeSQLitePath == "" {
		return nil
	}
	destination, err := RoundcubeSQLiteDestination(source.RoundcubeSQLitePath, mode)
	if err != nil {
		return err
	}
	if target.InternalPHPVersion == "" {
		return errors.New("Roundcube SQLite restore requires the observed target internal PHP version")
	}
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return errors.New("Roundcube SQLite restore requires the installed sqlite3 CLI")
	}
	if info, err := os.Lstat(destination); err != nil || !info.Mode().IsRegular() {
		return errors.New("Roundcube SQLite restore requires a regular database at the installed destination path")
	}
	return nil
}

// restoreRoundcubeSQLite is called with the target internal FPM stopped. Keep
// destination-native ownership/mode and discard its obsolete SQLite journals
// before the atomic database replacement, so WAL cannot replay stale state.
func restoreRoundcubeSQLite(ctx context.Context, snapshot, destination string) error {
	output, err := exec.CommandContext(ctx, "sqlite3", "-readonly", snapshot, "PRAGMA quick_check;").Output()
	if err != nil || strings.TrimSpace(string(output)) != "ok" {
		return errors.New("Roundcube SQLite snapshot integrity check failed")
	}
	info, err := os.Lstat(destination)
	if err != nil {
		return fmt.Errorf("inspect installed Roundcube SQLite destination: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("Roundcube SQLite destination must be a regular installed database")
	}
	input, err := os.Open(snapshot)
	if err != nil {
		return err
	}
	defer input.Close()
	temp, err := os.CreateTemp(filepath.Dir(destination), ".roundcube-restore-")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	ok := false
	defer func() {
		if !ok {
			temp.Close()
		}
	}()
	if _, err = io.Copy(temp, input); err != nil {
		return err
	}
	if err = temp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if stat, hasStat := info.Sys().(*syscall.Stat_t); hasStat && os.Geteuid() == 0 {
		if err = temp.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}
	}
	if err = temp.Sync(); err != nil {
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	ok = true
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err = os.Remove(destination + suffix); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("discard stale Roundcube SQLite journal: %w", err)
		}
	}
	return os.Rename(temp.Name(), destination)
}
