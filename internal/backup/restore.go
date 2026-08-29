package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RunRestore rebuilds a server from a backup archive. It expects a fresh
// installation (binaries, packages, and services present — the unified
// installer's --fresh path) and must run as root. All system interaction goes
// through the standard CLI tools so the engine works before the panel is up.

type RestoreOptions struct {
	// OpenArchive returns a fresh reader over the archive from the beginning.
	// It is called twice: once for the manifest preflight, once to extract.
	OpenArchive func() (io.ReadCloser, error)
	Key         []byte
	// PostgresDSN for pg_restore, run as the nakpanel role.
	PostgresDSN string
	// AllowSchemaMismatch proceeds when the archive's migration version is
	// older than the installed one (the operator must run goose up after).
	AllowSchemaMismatch bool
	Log                 func(format string, args ...any)
}

type RestoreSummary struct {
	Manifest         Manifest        `json:"manifest"`
	ExtractedEntries int             `json:"extracted_entries"`
	MariaDBRestored  []string        `json:"mariadb_restored,omitempty"`
	UsersCreated     []string        `json:"users_created,omitempty"`
	ServicesStarted  []string        `json:"services_started,omitempty"`
	SchemaMismatch   bool            `json:"schema_mismatch"`
	DurationMS       int64           `json:"duration_ms"`
	Identity         *SystemIdentity `json:"-"`
}

func (o *RestoreOptions) log(format string, args ...any) {
	if o.Log != nil {
		o.Log(format, args...)
	}
}

// restoreStopServices is stopped before touching state; postgres and mariadb
// stay up because the engine restores through them.
var restoreStopServices = []string{
	"nakpanel.service",
	"nakpanel-agent.service",
	"stalwart-mail.service",
	"nginx.service",
	"named.service",
	"nakpanel-proftpd.service",
}

var restoreUnitStartOrder = []string{
	"nakpanel-agent.service",
	"nakpanel.service",
	"nginx.service",
	"named.service",
	"stalwart-mail.service",
	"nakpanel-proftpd.service",
}

func RunRestore(ctx context.Context, opts RestoreOptions) (RestoreSummary, error) {
	summary := RestoreSummary{}
	started := time.Now()
	if os.Geteuid() != 0 {
		return summary, errors.New("restore-server must run as root")
	}
	if len(opts.Key) != KeySize {
		return summary, ErrBadKey
	}
	if opts.OpenArchive == nil {
		return summary, errors.New("archive source is required")
	}
	if opts.PostgresDSN == "" {
		opts.PostgresDSN = "postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable"
	}

	// --- Preflight -------------------------------------------------------
	opts.log("step: read archive manifest")
	source, err := opts.OpenArchive()
	if err != nil {
		return summary, err
	}
	manifest, err := ReadManifest(source, opts.Key)
	source.Close()
	if err != nil {
		return summary, fmt.Errorf("read manifest: %w", err)
	}
	summary.Manifest = manifest
	if manifest.KeyFingerprint != "" && manifest.KeyFingerprint != Fingerprint(opts.Key) {
		return summary, fmt.Errorf("archive was encrypted with a different key (archive fingerprint %s)", manifest.KeyFingerprint)
	}

	opts.log("step: check schema versions")
	installedGoose := currentGooseVersion(ctx)
	switch {
	case manifest.GooseVersion > installedGoose && installedGoose > 0:
		return summary, fmt.Errorf("archive schema version %d is newer than the installed migrations (%d); install matching or newer nakpanel binaries first", manifest.GooseVersion, installedGoose)
	case manifest.GooseVersion < installedGoose:
		summary.SchemaMismatch = true
		if !opts.AllowSchemaMismatch {
			return summary, fmt.Errorf("archive schema version %d is older than the installed migrations (%d); rerun with --allow-schema-mismatch and run migrations afterwards", manifest.GooseVersion, installedGoose)
		}
		opts.log("warning: archive schema (%d) is older than installed migrations (%d); run goose up after the restore", manifest.GooseVersion, installedGoose)
	}

	// --- Stop the world (except the database engines) --------------------
	opts.log("step: stop services")
	for _, unit := range restoreStopServices {
		_ = runQuiet(ctx, "systemctl", "stop", unit)
	}
	for _, unit := range enumerateInstanceUnits() {
		_ = runQuiet(ctx, "systemctl", "stop", unit)
	}

	workDir, err := os.MkdirTemp("/var/lib/nakpanel", ".restore-")
	if err != nil {
		return summary, err
	}
	defer os.RemoveAll(workDir)

	// --- Extraction pass --------------------------------------------------
	opts.log("step: extract archive")
	source, err = opts.OpenArchive()
	if err != nil {
		return summary, err
	}
	defer source.Close()
	reader, err := NewArchiveReader(source, opts.Key)
	if err != nil {
		return summary, err
	}
	var identity SystemIdentity
	var pgDumpPath string
	var mariaDumps []string
	identityApplied := false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return summary, fmt.Errorf("archive is corrupt: %w", err)
		}
		switch {
		case header.Name == ManifestName:
			if _, err := io.Copy(io.Discard, reader); err != nil {
				return summary, err
			}
		case header.Name == UsersEntryName:
			if err := json.NewDecoder(io.LimitReader(reader, 4<<20)).Decode(&identity); err != nil {
				return summary, fmt.Errorf("users.json is corrupt: %w", err)
			}
			created, err := applySystemIdentity(ctx, identity, opts.log)
			if err != nil {
				return summary, err
			}
			summary.UsersCreated = created
			summary.Identity = &identity
			identityApplied = true
		case header.Name == PostgresDumpName:
			pgDumpPath = filepath.Join(workDir, "nakpanel.dump")
			if err := writeFileFrom(reader, pgDumpPath, 0o600); err != nil {
				return summary, err
			}
		case strings.HasPrefix(header.Name, MariaDBPrefix):
			base := filepath.Base(header.Name)
			if !strings.HasSuffix(base, ".sql.gz") || strings.Contains(base, "..") {
				return summary, fmt.Errorf("unexpected mariadb entry %q", header.Name)
			}
			target := filepath.Join(workDir, "mariadb-"+base)
			if err := writeFileFrom(reader, target, 0o600); err != nil {
				return summary, err
			}
			mariaDumps = append(mariaDumps, target)
		case strings.HasPrefix(header.Name, TreePrefix):
			if !identityApplied && len(identity.Users) == 0 {
				// users.json is written before any tree; tolerate archives
				// without it (nothing to map).
				identityApplied = true
			}
			if err := extractTreeEntry(header, reader); err != nil {
				return summary, err
			}
			summary.ExtractedEntries++
		default:
			return summary, fmt.Errorf("unexpected archive entry %q", header.Name)
		}
	}
	// archive/tar stops at its zero blocks, so a corrupt or truncated
	// encryption stream would otherwise read as a clean EOF and we would
	// "successfully" restore a damaged archive.
	if err := reader.Finish(); err != nil {
		return summary, err
	}
	if pgDumpPath == "" {
		return summary, errors.New("archive has no postgres dump")
	}

	// --- Postgres ---------------------------------------------------------
	opts.log("step: restore panel database")
	if err := restorePostgres(ctx, opts.PostgresDSN, pgDumpPath); err != nil {
		return summary, err
	}
	opts.log("step: cancel stale queued jobs")
	if err := riverHygiene(ctx); err != nil {
		return summary, err
	}
	// The stalwart_directory role lives in the Postgres cluster, not in the
	// dumped database: realign its password with the restored credential file
	// so the mail server's SQL directory works on the rebuilt host.
	if err := realignStalwartRole(ctx); err != nil {
		opts.log("warning: %v", err)
	}

	// --- MariaDB ----------------------------------------------------------
	for _, dump := range mariaDumps {
		base := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(dump), "mariadb-"), ".sql.gz")
		opts.log("step: restore mariadb database %s", base)
		if err := restoreMariaDB(ctx, base, dump); err != nil {
			return summary, err
		}
		summary.MariaDBRestored = append(summary.MariaDBRestored, base)
	}

	// --- Services ---------------------------------------------------------
	opts.log("step: start services")
	if err := runQuiet(ctx, "systemctl", "daemon-reload"); err != nil {
		return summary, err
	}
	for _, unit := range restoreUnitStartOrder {
		if !unitFileExists(unit) {
			continue
		}
		if err := runQuiet(ctx, "systemctl", "start", unit); err != nil {
			opts.log("warning: start %s failed: %v", unit, err)
			continue
		}
		summary.ServicesStarted = append(summary.ServicesStarted, unit)
	}
	for _, unit := range enumerateInstanceUnits() {
		if err := runQuiet(ctx, "systemctl", "start", unit); err != nil {
			opts.log("warning: start %s failed: %v", unit, err)
			continue
		}
		summary.ServicesStarted = append(summary.ServicesStarted, unit)
	}

	summary.DurationMS = time.Since(started).Milliseconds()
	return summary, nil
}

func runQuiet(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

var (
	restoreIdentityRunQuiet        = runQuiet
	restoreIdentityLookupGroupGID  = lookupGroupGID
	restoreIdentityLookupUserUID   = lookupUserUID
	restoreIdentityLookupGroupName = lookupGroupNameByGID
	restoreIdentityLookupUserName  = lookupUserNameByUID
)

func psqlSuper(ctx context.Context, query string) (string, error) {
	cmd := exec.CommandContext(ctx, "runuser", "-u", "postgres", "--", "psql", "-Atq", "-d", "nakpanel", "-c", query)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("psql: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func currentGooseVersion(ctx context.Context) int64 {
	out, err := psqlSuper(ctx, "SELECT COALESCE(max(version_id),0) FROM goose_db_version")
	if err != nil {
		return 0
	}
	value, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func restorePostgres(ctx context.Context, dsn, dumpPath string) error {
	if err := runQuiet(ctx, "runuser", "-u", "postgres", "--", "dropdb", "--force", "--if-exists", "nakpanel"); err != nil {
		return err
	}
	if err := runQuiet(ctx, "runuser", "-u", "postgres", "--", "createdb", "-O", "nakpanel", "nakpanel"); err != nil {
		return err
	}
	// pg_restore runs as the nakpanel role, so hand it ownership rather than
	// widening the mode: this directory also holds every tenant MariaDB dump
	// and the panel dump contains password hashes and sealed secrets.
	if uid, gid, err := lookupUserIDs("nakpanel"); err == nil {
		_ = os.Chown(filepath.Dir(dumpPath), uid, gid)
		_ = os.Chown(dumpPath, uid, gid)
	} else {
		// Fall back to the previous behaviour only if the account is missing.
		if err := os.Chmod(dumpPath, 0o644); err != nil {
			return err
		}
		if err := os.Chmod(filepath.Dir(dumpPath), 0o755); err != nil {
			return err
		}
	}
	return runQuiet(ctx, "runuser", "-u", "nakpanel", "--", "pg_restore", "--exit-on-error", "-d", dsn, dumpPath)
}

func riverHygiene(ctx context.Context) error {
	// In-flight pre-disaster jobs are stale: periodic jobs re-arm when the
	// panel starts and reconciliation re-derives real work.
	if _, err := psqlSuper(ctx, `UPDATE river_job SET state='cancelled', finalized_at=now()
		WHERE state IN ('available','running','scheduled','retryable','pending')`); err != nil {
		return err
	}
	// Backups that were mid-flight when this archive was taken can never
	// complete on the restored server.
	if _, err := psqlSuper(ctx, `UPDATE server_backups SET status='failed',
		last_error='interrupted by disaster recovery restore', updated_at=now()
		WHERE status IN ('pending','running','uploading','verifying','deleting')`); err != nil {
		// An archive predating this table is expected and benign; anything
		// else (connection loss, permissions) must surface, because leaving
		// rows in a non-terminal state wedges scheduled backups silently.
		if strings.Contains(err.Error(), "server_backups") && strings.Contains(err.Error(), "does not exist") {
			return nil
		}
		return fmt.Errorf("clear interrupted server backups: %w", err)
	}
	return nil
}

// lookupUserIDs resolves a system account's numeric uid/gid.
func lookupUserIDs(name string) (int, int, error) {
	uid, err := lookupUserUID(name)
	if err != nil {
		return 0, 0, err
	}
	out, err := exec.Command("id", "-g", name).Output()
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

func realignStalwartRole(ctx context.Context) error {
	data, err := os.ReadFile("/etc/stalwart/pg-password")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read stalwart pg-password: %w", err)
	}
	password := strings.TrimSpace(string(data))
	if password == "" {
		return nil
	}
	var exists string
	exists, err = psqlSuper(ctx, "SELECT 1 FROM pg_roles WHERE rolname='stalwart_directory'")
	if err != nil || strings.TrimSpace(exists) != "1" {
		return nil
	}
	quoted := strings.ReplaceAll(password, "'", "''")
	if _, err := psqlSuper(ctx, fmt.Sprintf("ALTER ROLE stalwart_directory WITH LOGIN PASSWORD '%s'", quoted)); err != nil {
		return fmt.Errorf("realign stalwart_directory role: %w", err)
	}
	return nil
}

func restoreMariaDB(ctx context.Context, database, dumpPath string) error {
	if !regexpDBName.MatchString(database) {
		return fmt.Errorf("invalid mariadb database name %q", database)
	}
	if err := runQuiet(ctx, "mariadb", "-e", fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", database)); err != nil {
		return err
	}
	file, err := os.Open(dumpPath)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	cmd := exec.CommandContext(ctx, "mariadb")
	cmd.Stdin = gz
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mariadb import %s: %w: %s", database, err, strings.TrimSpace(string(out)))
	}
	return nil
}

var regexpDBName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func writeFileFrom(r io.Reader, path string, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, r); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// extractTreeEntry writes one files/ entry back to its absolute path with
// numeric ownership. Existing files are replaced, never written through.
func extractTreeEntry(header *tar.Header, r io.Reader) error {
	rel := strings.TrimPrefix(header.Name, TreePrefix)
	if rel == "" {
		return nil
	}
	// Reject traversal by path COMPONENT, before Clean collapses it. A
	// substring test would also reject legitimate names such as
	// "config..bak" and abort the whole recovery over one tenant file.
	for _, part := range strings.Split(rel, "/") {
		if part == ".." {
			return fmt.Errorf("unsafe archive path %q", header.Name)
		}
	}
	target := filepath.Clean("/" + rel)
	if target == "/" {
		return fmt.Errorf("unsafe archive path %q", header.Name)
	}
	switch header.Typeflag {
	case tar.TypeDir:
		if err := os.MkdirAll(target, os.FileMode(header.Mode).Perm()); err != nil {
			return err
		}
		if err := os.Chmod(target, os.FileMode(header.Mode).Perm()); err != nil {
			return err
		}
		return os.Chown(target, header.Uid, header.Gid)
	case tar.TypeReg:
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode).Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(file, r); err != nil {
			file.Close()
			return fmt.Errorf("extract %s: %w", target, err)
		}
		if err := file.Chmod(os.FileMode(header.Mode).Perm()); err != nil {
			file.Close()
			return err
		}
		if err := file.Chown(header.Uid, header.Gid); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if !header.ModTime.IsZero() {
			_ = os.Chtimes(target, header.ModTime, header.ModTime)
		}
		return nil
	case tar.TypeSymlink:
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Symlink(header.Linkname, target); err != nil {
			return err
		}
		return os.Lchown(target, header.Uid, header.Gid)
	default:
		return nil
	}
}

func applySystemIdentity(ctx context.Context, identity SystemIdentity, logf func(string, ...any)) ([]string, error) {
	var created []string
	if err := parkExistingIdentity(ctx, identity, logf); err != nil {
		return created, err
	}
	for _, group := range identity.Groups {
		if group.Name == "" || group.GID <= 0 {
			continue
		}
		if existingGID, err := restoreIdentityLookupGroupGID(group.Name); err == nil {
			if existingGID != group.GID {
				if err := restoreIdentityRunQuiet(ctx, "groupmod", "--gid", strconv.Itoa(group.GID), group.Name); err != nil {
					return created, fmt.Errorf("restore group %s to gid %d: %w", group.Name, group.GID, err)
				}
			}
			continue
		}
		if err := restoreIdentityRunQuiet(ctx, "groupadd", "--gid", strconv.Itoa(group.GID), group.Name); err != nil {
			return created, fmt.Errorf("recreate group %s: %w", group.Name, err)
		}
	}
	for _, user := range identity.Users {
		if user.Name == "" || user.UID < 0 {
			continue
		}
		existingUID, err := restoreIdentityLookupUserUID(user.Name)
		if err == nil {
			if existingUID != user.UID {
				if logf != nil {
					logf("remapping user %s from uid %d to archived uid %d", user.Name, existingUID, user.UID)
				}
				if err := restoreIdentityRunQuiet(ctx, "usermod", "--uid", strconv.Itoa(user.UID), user.Name); err != nil {
					return created, fmt.Errorf("restore user %s to uid %d: %w", user.Name, user.UID, err)
				}
			}
			if user.GID > 0 {
				if err := restoreIdentityRunQuiet(ctx, "usermod", "--gid", strconv.Itoa(user.GID), user.Name); err != nil {
					return created, fmt.Errorf("restore user %s to gid %d: %w", user.Name, user.GID, err)
				}
			}
		} else {
			args := []string{
				"--no-create-home", "--home-dir", user.Home, "--shell", user.Shell,
				"--uid", strconv.Itoa(user.UID), "--gid", strconv.Itoa(user.GID), user.Name,
			}
			if err := restoreIdentityRunQuiet(ctx, "useradd", args...); err != nil {
				return created, fmt.Errorf("recreate user %s: %w", user.Name, err)
			}
			created = append(created, user.Name)
		}
		for _, group := range user.Groups {
			if group == "" || group == user.Name {
				continue
			}
			if _, err := restoreIdentityLookupGroupGID(group); err != nil {
				continue
			}
			_ = restoreIdentityRunQuiet(ctx, "usermod", "-aG", group, user.Name)
		}
		if user.SubUIDSize > 0 {
			ensureSubIDLine("/etc/subuid", user.Name, user.SubUIDBase, user.SubUIDSize)
		}
		if user.SubGIDSize > 0 {
			ensureSubIDLine("/etc/subgid", user.Name, user.SubGIDBase, user.SubGIDSize)
		}
	}
	if logf != nil && len(created) > 0 {
		logf("recreated %d system accounts", len(created))
	}
	return created, nil
}

// parkExistingIdentity moves accounts already created by the fresh installer
// out of the archived numeric-ID range before exact identities are restored.
// Without this two archived accounts whose IDs shifted between installations
// can block each other even though both names are legitimate Nakpanel users.
func parkExistingIdentity(ctx context.Context, identity SystemIdentity, logf func(string, ...any)) error {
	groupTargets := make(map[int]struct{}, len(identity.Groups))
	for _, group := range identity.Groups {
		if group.GID > 0 {
			groupTargets[group.GID] = struct{}{}
		}
	}
	userTargets := make(map[int]struct{}, len(identity.Users))
	for _, user := range identity.Users {
		if user.UID >= 0 {
			userTargets[user.UID] = struct{}{}
		}
	}

	nextGroupID := 60000
	for _, group := range identity.Groups {
		current, err := restoreIdentityLookupGroupGID(group.Name)
		if err != nil || current == group.GID {
			continue
		}
		parked, err := nextRestoreParkingID(&nextGroupID, groupTargets, restoreIdentityLookupGroupName)
		if err != nil {
			return fmt.Errorf("park group %s: %w", group.Name, err)
		}
		if err := restoreIdentityRunQuiet(ctx, "groupmod", "--gid", strconv.Itoa(parked), group.Name); err != nil {
			return fmt.Errorf("park group %s at gid %d: %w", group.Name, parked, err)
		}
		if logf != nil {
			logf("temporarily parked group %s from gid %d at gid %d", group.Name, current, parked)
		}
	}

	nextUserID := 60000
	for _, user := range identity.Users {
		current, err := restoreIdentityLookupUserUID(user.Name)
		if err != nil || current == user.UID {
			continue
		}
		parked, err := nextRestoreParkingID(&nextUserID, userTargets, restoreIdentityLookupUserName)
		if err != nil {
			return fmt.Errorf("park user %s: %w", user.Name, err)
		}
		if err := restoreIdentityRunQuiet(ctx, "usermod", "--uid", strconv.Itoa(parked), user.Name); err != nil {
			return fmt.Errorf("park user %s at uid %d: %w", user.Name, parked, err)
		}
		if logf != nil {
			logf("temporarily parked user %s from uid %d at uid %d", user.Name, current, parked)
		}
	}
	return nil
}

func nextRestoreParkingID(next *int, reserved map[int]struct{}, lookup func(int) (string, error)) (int, error) {
	for *next >= 50000 {
		candidate := *next
		*next--
		if _, reserved := reserved[candidate]; reserved {
			continue
		}
		if _, err := lookup(candidate); err != nil {
			return candidate, nil
		}
	}
	return 0, errors.New("no temporary numeric identity is available")
}

func lookupUserUID(name string) (int, error) {
	out, err := exec.Command("id", "-u", name).Output()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

func lookupGroupGID(name string) (int, error) {
	out, err := exec.Command("getent", "group", name).Output()
	if err != nil {
		return 0, err
	}
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) < 3 {
		return 0, errors.New("malformed group entry")
	}
	return strconv.Atoi(fields[2])
}

func lookupUserNameByUID(uid int) (string, error) {
	out, err := exec.Command("getent", "passwd", strconv.Itoa(uid)).Output()
	if err != nil {
		return "", err
	}
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) < 3 {
		return "", errors.New("malformed passwd entry")
	}
	return fields[0], nil
}

func lookupGroupNameByGID(gid int) (string, error) {
	out, err := exec.Command("getent", "group", strconv.Itoa(gid)).Output()
	if err != nil {
		return "", err
	}
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) < 3 {
		return "", errors.New("malformed group entry")
	}
	return fields[0], nil
}

func ensureSubIDLine(path, name string, base, size int) {
	data, _ := os.ReadFile(path)
	prefix := name + ":"
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			return
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	// Without this, an existing file that does not end in a newline would have
	// the new range concatenated onto its last entry, corrupting both — and
	// rootless podman will not start without valid subordinate ranges.
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		fmt.Fprint(file, "\n")
	}
	fmt.Fprintf(file, "%s:%d:%d\n", name, base, size)
}

func unitFileExists(unit string) bool {
	_, err := os.Stat(filepath.Join("/etc/systemd/system", unit))
	if err == nil {
		return true
	}
	_, err = os.Stat(filepath.Join("/usr/lib/systemd/system", unit))
	if err == nil {
		return true
	}
	_, err = os.Stat(filepath.Join("/lib/systemd/system", unit))
	return err == nil
}

func enumerateInstanceUnits() []string {
	var units []string
	patterns := []string{
		"/etc/systemd/system/nakpanel-php-fpm@*.service",
		"/etc/systemd/system/nakpanel-valkey@*.service",
		"/etc/systemd/system/nakpanel-task-*.timer",
	}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			units = append(units, filepath.Base(match))
		}
	}
	return units
}
