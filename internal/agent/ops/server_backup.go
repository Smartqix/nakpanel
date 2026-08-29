package ops

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"syscall"
	"time"

	"github.com/nakroteck/nakpanel/internal/backup"
	"github.com/nakroteck/nakpanel/internal/types"
)

// ServerBackupProvisioner produces, verifies, and prunes whole-server backup
// archives. It runs as root inside the agent: pg_dump drops to the panel's
// database role, tenant MariaDB databases are dumped over the root socket,
// and the archive is assembled from the state trees disaster recovery needs.
type ServerBackupProvisioner struct {
	spoolDir    string
	postgresDSN string
	runner      CommandRunner
	now         func() time.Time
}

type ServerBackupProvisionerOptions struct {
	SpoolDir    string
	PostgresDSN string
	Runner      CommandRunner
	Now         func() time.Time
}

const defaultServerBackupSpool = "/var/lib/nakpanel/server-backups"

// serverBackupMinFreeBytes is the preflight free-space floor for the spool
// filesystem before an archive is attempted.
const serverBackupMinFreeBytes = int64(512) << 20

var serverBackupUsernameRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func NewServerBackupProvisioner(opts ServerBackupProvisionerOptions) *ServerBackupProvisioner {
	spool := opts.SpoolDir
	if spool == "" {
		spool = defaultServerBackupSpool
	}
	dsn := opts.PostgresDSN
	if dsn == "" {
		dsn = "postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable"
	}
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &ServerBackupProvisioner{spoolDir: spool, postgresDSN: dsn, runner: runner, now: now}
}

// serverBackupTrees are archived verbatim. Missing roots are skipped so the
// same inventory serves installs without optional components.
var serverBackupTrees = []string{
	"/etc/nakpanel",
	"/etc/stalwart",
	"/etc/nginx/sites-available",
	"/etc/nginx/sites-enabled",
	"/etc/nginx/nakpanel",
	"/etc/bind/nakpanel",
	"/home",
	"/var/lib/nakpanel/certs",
	"/var/lib/nakpanel/acme",
	"/var/lib/nakpanel/dkim",
	"/var/lib/nakpanel/tls",
	"/var/lib/nakpanel/git",
	"/var/lib/nakpanel/tasks",
	"/var/lib/nakpanel/system-users",
	"/var/lib/nakpanel/migrations",
	"/var/lib/nakpanel/roundcube-des-key",
	"/var/lib/nakpanel/containers",
	"/etc/roundcube",
}

// serverBackupExcluded documents what is deliberately absent.
var serverBackupExcluded = []string{
	"/var/lib/nakpanel/backups",
	"/var/lib/nakpanel/server-backups",
	"/var/lib/nakpanel/staging",
	"/var/lib/nakpanel/tls-staging",
	"/var/lib/nakpanel/security-stages",
	"**/containers/storage (rootless image layers; re-pulled from pinned digests)",
}

// serverBackupSkip prunes rootless container image storage. nakpanel runs
// podman with XDG_DATA_HOME under the subscription's own state directory (see
// application_runtime.go), so the graphroot is
// /var/lib/nakpanel/containers/sub-<id>/data/containers/storage — NOT the
// usual ~/.local/share/containers. Image layers are large, hardlink-heavy, and
// contain whiteout device nodes the archiver cannot represent; they are
// re-pulled from pinned digests on convergence instead.
func serverBackupSkip(path string) bool {
	return strings.Contains(path, "/containers/storage") ||
		strings.Contains(path, "/.local/share/containers")
}

const stalwartDataDir = "/var/lib/stalwart/data"

func (p *ServerBackupProvisioner) CreateServerBackup(ctx context.Context, req types.CreateServerBackupReq) (types.CreateServerBackupResult, error) {
	var result types.CreateServerBackupResult
	started := p.now()

	if len(req.ArchiveKey) != backup.KeySize {
		return result, errors.New("archive key must be 32 bytes")
	}
	name := strings.TrimSpace(req.ArchiveName)
	if name == "" {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "server"
		}
		name = fmt.Sprintf("nakpanel-%s-%s.nkbk", hostname, started.UTC().Format("20060102T150405Z"))
	}
	if !strings.HasSuffix(name, ".nkbk") || strings.ContainsAny(name, "/\\") {
		return result, errors.New("archive name must be a bare .nkbk file name")
	}
	destination, err := backup.NewDestination(req.Destination.Kind, req.Destination.Settings, req.Destination.Credential)
	if err != nil {
		return result, err
	}

	if err := os.MkdirAll(p.spoolDir, 0o700); err != nil {
		return result, err
	}
	if err := checkFreeSpace(p.spoolDir, serverBackupMinFreeBytes); err != nil {
		return result, err
	}
	workDir, err := os.MkdirTemp(p.spoolDir, ".work-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(workDir)

	// 1. Postgres dump (custom format) as the nakpanel role.
	pgDumpPath := filepath.Join(workDir, "nakpanel.dump")
	if err := p.dumpPostgres(ctx, pgDumpPath); err != nil {
		return result, err
	}

	// 2. Tenant MariaDB dumps.
	var dumpFiles []string
	for _, database := range req.TenantDatabases {
		normalized := strings.ToLower(strings.TrimSpace(database))
		if !phase6DBIdentifierRE.MatchString(normalized) {
			return result, fmt.Errorf("invalid tenant database name %q", database)
		}
		target := filepath.Join(workDir, "mariadb-"+normalized+".sql.gz")
		if err := p.dumpMariaDB(ctx, normalized, target); err != nil {
			return result, err
		}
		dumpFiles = append(dumpFiles, normalized)
	}

	// 3. System identities.
	identity, err := collectSystemIdentity(req.SystemUsers)
	if err != nil {
		return result, err
	}
	identityJSON, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return result, err
	}

	// 4. Mail data: pause Stalwart only for the local copy so RocksDB is
	// crash-consistent, then archive the copy under its original path.
	var stalwartCopy string
	var stalwartPaused time.Duration
	if req.IncludeMailData {
		stalwartCopy, stalwartPaused, err = p.copyStalwartData(ctx, workDir)
		if err != nil {
			return result, err
		}
	}

	units, err := collectNakpanelUnits()
	if err != nil {
		return result, err
	}

	manifest := backup.Manifest{
		FormatVersion:    1,
		CreatedAt:        started.UTC(),
		PanelVersion:     req.PanelVersion,
		GooseVersion:     req.GooseVersion,
		KeyFingerprint:   backup.Fingerprint(req.ArchiveKey),
		TenantDatabases:  dumpFiles,
		Trees:            serverBackupTrees,
		SystemdUnits:     units,
		IncludeMailData:  req.IncludeMailData,
		StalwartPausedMS: stalwartPaused.Milliseconds(),
		Excluded:         serverBackupExcluded,
	}
	manifest.Hostname, _ = os.Hostname()
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return result, err
	}

	// 5. Assemble the encrypted archive in the work dir, then publish.
	spoolPath := filepath.Join(workDir, name)
	spoolFile, err := os.OpenFile(spoolPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return result, err
	}
	hasher := sha256.New()
	writer, err := backup.NewArchiveWriter(io.MultiWriter(spoolFile, hasher), req.ArchiveKey)
	if err != nil {
		spoolFile.Close()
		return result, err
	}

	buildErr := func() error {
		if err := writer.AddBytes(backup.ManifestName, manifestJSON, 0o600); err != nil {
			return err
		}
		if err := writer.AddBytes(backup.UsersEntryName, identityJSON, 0o600); err != nil {
			return err
		}
		if err := writer.AddFileFrom(backup.PostgresDumpName, pgDumpPath); err != nil {
			return err
		}
		for _, database := range dumpFiles {
			if err := writer.AddFileFrom(backup.MariaDBPrefix+database+".sql.gz", filepath.Join(workDir, "mariadb-"+database+".sql.gz")); err != nil {
				return err
			}
		}
		for _, tree := range serverBackupTrees {
			if err := writer.AddTreeMapped(tree, tree, serverBackupSkip); err != nil {
				return fmt.Errorf("archive %s: %w", tree, err)
			}
		}
		for _, unit := range units {
			if err := writer.AddTreeMapped(unit, unit, nil); err != nil {
				return fmt.Errorf("archive %s: %w", unit, err)
			}
		}
		if stalwartCopy != "" {
			if err := writer.AddTreeMapped(stalwartCopy, stalwartDataDir, nil); err != nil {
				return fmt.Errorf("archive stalwart data: %w", err)
			}
		}
		return writer.Close()
	}()
	if buildErr != nil {
		spoolFile.Close()
		return result, buildErr
	}
	if err := spoolFile.Sync(); err != nil {
		spoolFile.Close()
		return result, err
	}
	if err := spoolFile.Close(); err != nil {
		return result, err
	}

	info, err := os.Stat(spoolPath)
	if err != nil {
		return result, err
	}
	source, err := os.Open(spoolPath)
	if err != nil {
		return result, err
	}
	uploadErr := destination.Put(ctx, name, bufio.NewReaderSize(source, 1<<20), info.Size())
	source.Close()
	if uploadErr != nil {
		return result, fmt.Errorf("upload archive: %w", uploadErr)
	}

	result = types.CreateServerBackupResult{
		ArchiveName:      name,
		SizeBytes:        info.Size(),
		SHA256:           hex.EncodeToString(hasher.Sum(nil)),
		KeyFingerprint:   manifest.KeyFingerprint,
		Entries:          writer.Entries(),
		StalwartPausedMS: stalwartPaused.Milliseconds(),
		DurationMS:       time.Since(started).Milliseconds(),
	}
	return result, nil
}

func (p *ServerBackupProvisioner) dumpPostgres(ctx context.Context, target string) error {
	file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	cmd := exec.CommandContext(ctx, "runuser", "-u", "nakpanel", "--", "pg_dump", "--format=custom", p.postgresDSN)
	cmd.Stdout = file
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_dump: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return file.Sync()
}

func (p *ServerBackupProvisioner) dumpMariaDB(ctx context.Context, database, target string) error {
	file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	gz := gzip.NewWriter(file)
	cmd := exec.CommandContext(ctx, "mariadb-dump", "--single-transaction", "--databases", database)
	cmd.Stdout = gz
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("mariadb-dump %s: %w: %s", database, err, strings.TrimSpace(stderr.String()))
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return file.Sync()
}

func (p *ServerBackupProvisioner) copyStalwartData(ctx context.Context, workDir string) (string, time.Duration, error) {
	if _, err := os.Stat(stalwartDataDir); errors.Is(err, os.ErrNotExist) {
		return "", 0, nil
	}
	copyDir := filepath.Join(workDir, "stalwart-data")
	wasActive := serviceIsActive(ctx, "stalwart-mail.service")
	start := p.now()
	if wasActive {
		if out, err := exec.CommandContext(ctx, "systemctl", "stop", "stalwart-mail.service").CombinedOutput(); err != nil {
			return "", 0, fmt.Errorf("stop stalwart-mail: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	copyErr := func() error {
		out, err := exec.CommandContext(ctx, "cp", "-a", stalwartDataDir, copyDir).CombinedOutput()
		if err != nil {
			return fmt.Errorf("copy stalwart data: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}()
	if wasActive {
		// Deliberately detached from ctx: if the backup was cancelled mid-copy
		// the same ctx would refuse to run systemctl, leaving mail down with
		// no error mentioning it. The restart error is always surfaced, even
		// when the copy already failed, because a stopped mail server is the
		// more serious of the two.
		restartCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if out, err := exec.CommandContext(restartCtx, "systemctl", "start", "stalwart-mail.service").CombinedOutput(); err != nil {
			restartErr := fmt.Errorf("restart stalwart-mail: %w: %s", err, strings.TrimSpace(string(out)))
			if copyErr == nil {
				copyErr = restartErr
			} else {
				copyErr = fmt.Errorf("%w (additionally: %v)", copyErr, restartErr)
			}
		}
	}
	paused := p.now().Sub(start)
	if copyErr != nil {
		return "", paused, copyErr
	}
	return copyDir, paused, nil
}

func serviceIsActive(ctx context.Context, unit string) bool {
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run() == nil
}

func collectNakpanelUnits() ([]string, error) {
	var units []string
	patterns := []string{
		"/etc/systemd/system/nakpanel-php-fpm@*.service",
		"/etc/systemd/system/nakpanel-valkey@*.service",
		"/etc/systemd/system/nakpanel-task-*.service",
		"/etc/systemd/system/nakpanel-task-*.timer",
		"/etc/systemd/system/nakpanel-proftpd.service",
		"/etc/systemd/system/multi-user.target.wants/nakpanel-*",
		"/etc/systemd/system/timers.target.wants/nakpanel-task-*",
	}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		units = append(units, matches...)
	}
	return units, nil
}

// collectSystemIdentity captures numeric ids and subordinate ranges for the
// panel-managed accounts so restore recreates identities that match archived
// numeric ownership.
func collectSystemIdentity(usernames []string) (backup.SystemIdentity, error) {
	var identity backup.SystemIdentity
	wanted := map[string]bool{"nakpanel": true}
	for _, username := range usernames {
		username = strings.TrimSpace(username)
		if username == "" {
			continue
		}
		if !serverBackupUsernameRE.MatchString(username) {
			return identity, fmt.Errorf("invalid system username %q", username)
		}
		wanted[username] = true
	}

	passwd, err := parseColonFile("/etc/passwd")
	if err != nil {
		return identity, err
	}
	groups, err := parseColonFile("/etc/group")
	if err != nil {
		return identity, err
	}
	subuid := parseSubIDFile("/etc/subuid")
	subgid := parseSubIDFile("/etc/subgid")

	gidNames := map[int]string{}
	memberOf := map[string][]string{}
	for _, fields := range groups {
		if len(fields) < 4 {
			continue
		}
		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		gidNames[gid] = fields[0]
		for _, member := range strings.Split(fields[3], ",") {
			if member = strings.TrimSpace(member); member != "" {
				memberOf[member] = append(memberOf[member], fields[0])
			}
		}
	}

	seenGroups := map[string]bool{}
	for _, fields := range passwd {
		if len(fields) < 7 || !wanted[fields[0]] {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			continue
		}
		user := backup.SystemUser{
			Name:   fields[0],
			UID:    uid,
			GID:    gid,
			Home:   fields[5],
			Shell:  fields[6],
			Groups: memberOf[fields[0]],
		}
		if sub, ok := subuid[fields[0]]; ok {
			user.SubUIDBase, user.SubUIDSize = sub[0], sub[1]
		}
		if sub, ok := subgid[fields[0]]; ok {
			user.SubGIDBase, user.SubGIDSize = sub[0], sub[1]
		}
		identity.Users = append(identity.Users, user)
		if groupName, ok := gidNames[gid]; ok && !seenGroups[groupName] {
			identity.Groups = append(identity.Groups, backup.SystemGroup{Name: groupName, GID: gid})
			seenGroups[groupName] = true
		}
	}
	return identity, nil
}

func parseColonFile(path string) ([][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rows [][]string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rows = append(rows, strings.Split(line, ":"))
	}
	return rows, nil
}

func parseSubIDFile(path string) map[string][2]int {
	result := map[string][2]int{}
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) != 3 {
			continue
		}
		base, err1 := strconv.Atoi(fields[1])
		size, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			continue
		}
		// First range wins; nakpanel provisions a single range per account.
		if _, ok := result[fields[0]]; !ok {
			result[fields[0]] = [2]int{base, size}
		}
	}
	return result
}

func checkFreeSpace(dir string, minBytes int64) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return fmt.Errorf("statfs %s: %w", dir, err)
	}
	free := int64(stat.Bavail) * int64(stat.Bsize)
	if free < minBytes {
		return fmt.Errorf("insufficient free space in %s: %d bytes available, need at least %d", dir, free, minBytes)
	}
	return nil
}

func (p *ServerBackupProvisioner) VerifyServerBackup(ctx context.Context, req types.VerifyServerBackupReq) (types.VerifyServerBackupResult, error) {
	var result types.VerifyServerBackupResult
	started := p.now()
	if len(req.ArchiveKey) != backup.KeySize {
		return result, errors.New("archive key must be 32 bytes")
	}
	destination, err := backup.NewDestination(req.Destination.Kind, req.Destination.Settings, req.Destination.Credential)
	if err != nil {
		return result, err
	}
	source, _, err := destination.Open(ctx, req.ArchiveName)
	if err != nil {
		return result, fmt.Errorf("open archive at destination: %w", err)
	}
	defer source.Close()

	hasher := sha256.New()
	counter := &countingReader{r: io.TeeReader(bufio.NewReaderSize(source, 1<<20), hasher)}
	reader, err := backup.NewArchiveReader(counter, req.ArchiveKey)
	if err != nil {
		return result, err
	}

	if err := os.MkdirAll(p.spoolDir, 0o700); err != nil {
		return result, err
	}
	scratch, err := os.CreateTemp(p.spoolDir, ".verify-*.dump")
	if err != nil {
		return result, err
	}
	scratchPath := scratch.Name()
	defer func() {
		scratch.Close()
		os.Remove(scratchPath)
	}()

	entries := 0
	sawManifest := false
	sawPGDump := false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, fmt.Errorf("archive is corrupt: %w", err)
		}
		entries++
		switch header.Name {
		case backup.ManifestName:
			sawManifest = true
			var manifest backup.Manifest
			if err := json.NewDecoder(io.LimitReader(reader, 1<<20)).Decode(&manifest); err != nil {
				return result, fmt.Errorf("manifest is corrupt: %w", err)
			}
			if manifest.KeyFingerprint != backup.Fingerprint(req.ArchiveKey) {
				return result, errors.New("archive key fingerprint mismatch")
			}
		case backup.PostgresDumpName:
			sawPGDump = true
			if _, err := io.Copy(scratch, reader); err != nil {
				return result, fmt.Errorf("extract postgres dump: %w", err)
			}
		default:
			// Every byte still flows through the AEAD, which is the actual
			// integrity check; just drain the entry.
			if _, err := io.Copy(io.Discard, reader); err != nil {
				return result, fmt.Errorf("archive is corrupt at %s: %w", header.Name, err)
			}
		}
	}
	// Force the encryption stream's remaining chunks, its final-chunk
	// authentication, and the gzip trailer to be checked. archive/tar stops at
	// its zero blocks, so without this a corrupt tail reads as a clean EOF.
	if err := reader.Finish(); err != nil {
		return result, err
	}
	// Then drain any raw trailing bytes so the sha256 covers the whole file.
	if _, err := io.Copy(io.Discard, counter); err != nil && !errors.Is(err, io.EOF) {
		return result, fmt.Errorf("archive trailer: %w", err)
	}
	if !sawManifest {
		return result, errors.New("archive has no manifest entry")
	}
	if !sawPGDump {
		return result, errors.New("archive has no postgres dump entry")
	}
	if req.ExpectedSHA256 != "" {
		actual := hex.EncodeToString(hasher.Sum(nil))
		if actual != strings.ToLower(strings.TrimSpace(req.ExpectedSHA256)) {
			return result, fmt.Errorf("archive checksum mismatch: got %s", actual)
		}
	}

	if err := scratch.Sync(); err != nil {
		return result, err
	}
	if out, err := exec.CommandContext(ctx, "pg_restore", "--list", scratchPath).CombinedOutput(); err != nil {
		return result, fmt.Errorf("pg_restore --list failed: %s", strings.TrimSpace(string(out)))
	}
	const listOK = true
	result = types.VerifyServerBackupResult{
		Entries:         entries,
		Bytes:           counter.n,
		PgRestoreListOK: listOK,
		DurationMS:      time.Since(started).Milliseconds(),
	}
	return result, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (p *ServerBackupProvisioner) PruneServerBackups(ctx context.Context, req types.PruneServerBackupsReq) (types.PruneServerBackupsResult, error) {
	var result types.PruneServerBackupsResult
	destination, err := backup.NewDestination(req.Destination.Kind, req.Destination.Settings, req.Destination.Credential)
	if err != nil {
		return result, err
	}
	for _, name := range req.Delete {
		if err := destination.Delete(ctx, name); err != nil {
			return result, fmt.Errorf("delete %s: %w", name, err)
		}
		result.Deleted = append(result.Deleted, name)
	}
	remote, err := destination.List(ctx)
	if err != nil {
		return result, fmt.Errorf("list destination: %w", err)
	}
	for _, item := range remote {
		result.Remote = append(result.Remote, item.Name)
	}
	return result, nil
}

func (p *ServerBackupProvisioner) TestBackupDestination(ctx context.Context, req types.TestBackupDestinationReq) (types.TestBackupDestinationResult, error) {
	destination, err := backup.NewDestination(req.Destination.Kind, req.Destination.Settings, req.Destination.Credential)
	if err != nil {
		return types.TestBackupDestinationResult{}, err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result := types.TestBackupDestinationResult{}
	if err := destination.Probe(probeCtx); err != nil {
		result.Detail = err.Error()
	} else {
		result.OK = true
	}
	if observer, ok := destination.(interface{ ObservedHostKey() string }); ok {
		result.ObservedHostKey = observer.ObservedHostKey()
	}
	if !result.OK {
		return result, nil
	}
	return result, nil
}
