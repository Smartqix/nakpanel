package ops

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	phase6UsernameRE     = regexp.MustCompile(`^[a-z][a-z0-9]{2,31}$`)
	phase6DBIdentifierRE = regexp.MustCompile(`^[a-z][a-z0-9_]{1,47}$`)
)

type DatabaseDumper interface {
	DumpDatabase(ctx context.Context, name string) ([]byte, error)
}

type DatabaseRestorer interface {
	RestoreDatabase(ctx context.Context, name string, dump []byte) error
}

type BackupProvisionerOptions struct {
	OutputDir      string
	DatabaseDumper DatabaseDumper
	Now            func() time.Time
}

type BackupProvisioner struct {
	outputDir string
	dumper    DatabaseDumper
	now       func() time.Time
}

func NewBackupProvisioner(opts BackupProvisionerOptions) *BackupProvisioner {
	outputDir := opts.OutputDir
	if outputDir == "" {
		outputDir = "/var/lib/nakpanel/backups"
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &BackupProvisioner{outputDir: outputDir, dumper: opts.DatabaseDumper, now: now}
}

func (p *BackupProvisioner) CreateBackup(ctx context.Context, req types.CreateBackupReq) (types.CreateBackupResult, error) {
	normalized, err := normalizeBackupRequest(req, p.outputDir)
	if err != nil {
		return types.CreateBackupResult{}, err
	}
	if err := os.MkdirAll(normalized.OutputDir, 0o750); err != nil {
		return types.CreateBackupResult{}, fmt.Errorf("create backup directory: %w", err)
	}

	timestamp := p.now().UTC().Format("20060102T150405Z")
	baseName := normalized.Domain + "-" + timestamp + ".tar.gz"
	archivePath := filepath.Join(normalized.OutputDir, baseName)
	tmp, err := os.CreateTemp(normalized.OutputDir, ".nakpanel-backup-*.tar.gz")
	if err != nil {
		return types.CreateBackupResult{}, fmt.Errorf("create backup temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	hash := sha256.New()
	writer := io.MultiWriter(tmp, hash)
	gzipWriter := gzip.NewWriter(writer)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := p.writeBackupArchive(ctx, tarWriter, normalized); err != nil {
		_ = tarWriter.Close()
		_ = gzipWriter.Close()
		_ = tmp.Close()
		return types.CreateBackupResult{}, err
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		_ = tmp.Close()
		return types.CreateBackupResult{}, fmt.Errorf("close backup tar: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		_ = tmp.Close()
		return types.CreateBackupResult{}, fmt.Errorf("close backup gzip: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return types.CreateBackupResult{}, fmt.Errorf("sync backup archive: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return types.CreateBackupResult{}, fmt.Errorf("close backup archive: %w", err)
	}
	if err := os.Rename(tmpName, archivePath); err != nil {
		return types.CreateBackupResult{}, fmt.Errorf("publish backup archive: %w", err)
	}
	cleanup = false
	if err := syncDir(normalized.OutputDir); err != nil {
		return types.CreateBackupResult{}, fmt.Errorf("sync backup directory: %w", err)
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		return types.CreateBackupResult{}, fmt.Errorf("stat backup archive: %w", err)
	}
	return types.CreateBackupResult{
		ArchivePath: archivePath,
		SizeBytes:   info.Size(),
		SHA256:      hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

func (p *BackupProvisioner) writeBackupArchive(ctx context.Context, writer *tar.Writer, req types.CreateBackupReq) error {
	manifest := map[string]any{
		"domain":    req.Domain,
		"username":  req.Username,
		"databases": req.Databases,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode backup manifest: %w", err)
	}
	if err := writeTarFile(writer, "manifest.json", manifestBytes, 0o644); err != nil {
		return err
	}

	if err := filepath.WalkDir(req.Docroot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(req.Docroot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(filepath.Clean(rel))
		if rel == "." || strings.HasPrefix(rel, "../") {
			return fmt.Errorf("invalid backup path %q", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return writeTarFile(writer, "files/"+rel, data, info.Mode().Perm())
	}); err != nil {
		return fmt.Errorf("archive docroot: %w", err)
	}

	for _, database := range req.Databases {
		if p.dumper == nil {
			return errors.New("database dumper is not configured")
		}
		dump, err := p.dumper.DumpDatabase(ctx, database)
		if err != nil {
			return fmt.Errorf("dump database %q: %w", database, err)
		}
		if err := writeTarFile(writer, "databases/"+database+".sql", dump, 0o600); err != nil {
			return err
		}
	}
	return nil
}

type CommandDatabaseDumper struct {
	Runner CommandRunner
}

func (d CommandDatabaseDumper) DumpDatabase(ctx context.Context, name string) ([]byte, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if !phase6DBIdentifierRE.MatchString(normalized) {
		return nil, errors.New("database name must start with a lowercase letter and contain only lowercase letters, digits, and underscores")
	}
	runner := d.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	out, err := runner.Run(ctx, "mariadb-dump", "--single-transaction", "--databases", normalized)
	if err != nil {
		return nil, fmt.Errorf("mariadb-dump: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

type CommandDatabaseRestorer struct{}

func (r CommandDatabaseRestorer) RestoreDatabase(ctx context.Context, name string, dump []byte) error {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if !phase6DBIdentifierRE.MatchString(normalized) {
		return errors.New("database name must start with a lowercase letter and contain only lowercase letters, digits, and underscores")
	}
	cmd := exec.CommandContext(ctx, "mariadb", normalized)
	cmd.Stdin = bytes.NewReader(dump)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mariadb restore: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

type RestoreProvisionerOptions struct {
	DatabaseRestorer DatabaseRestorer
	OwnershipManager OwnershipManager
	Now              func() time.Time
}

type RestoreProvisioner struct {
	restorer  DatabaseRestorer
	ownership OwnershipManager
	now       func() time.Time
}

func NewRestoreProvisioner(opts RestoreProvisionerOptions) *RestoreProvisioner {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &RestoreProvisioner{restorer: opts.DatabaseRestorer, ownership: opts.OwnershipManager, now: now}
}

func (p *RestoreProvisioner) RestoreBackup(ctx context.Context, req types.RestoreBackupReq) (types.RestoreBackupResult, error) {
	normalized, err := normalizeRestoreRequest(req)
	if err != nil {
		return types.RestoreBackupResult{}, err
	}

	parent := filepath.Dir(normalized.Docroot)
	stamp := p.now().UTC().Format("20060102T150405Z")
	tempDocroot := filepath.Join(parent, ".nakpanel-restore-"+stamp)
	previousDocroot := filepath.Join(parent, ".nakpanel-before-restore-"+stamp)
	if err := os.RemoveAll(tempDocroot); err != nil {
		return types.RestoreBackupResult{}, fmt.Errorf("remove stale restore temp: %w", err)
	}
	if err := os.MkdirAll(tempDocroot, 0o755); err != nil {
		return types.RestoreBackupResult{}, fmt.Errorf("create restore temp docroot: %w", err)
	}
	cleanupTemp := true
	defer func() {
		if cleanupTemp {
			_ = os.RemoveAll(tempDocroot)
		}
	}()

	fileCount, dumps, err := extractRestoreArchive(normalized.ArchivePath, tempDocroot, normalized.Databases)
	if err != nil {
		return types.RestoreBackupResult{}, err
	}

	if _, err := os.Stat(normalized.Docroot); err == nil {
		if err := os.Rename(normalized.Docroot, previousDocroot); err != nil {
			return types.RestoreBackupResult{}, fmt.Errorf("move existing docroot aside: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return types.RestoreBackupResult{}, fmt.Errorf("stat existing docroot: %w", err)
	}
	if err := os.Rename(tempDocroot, normalized.Docroot); err != nil {
		return types.RestoreBackupResult{}, fmt.Errorf("publish restored docroot: %w", err)
	}
	cleanupTemp = false

	if p.ownership != nil {
		if err := p.ownership.ChownRecursive(ctx, normalized.Docroot, normalized.Username); err != nil {
			return types.RestoreBackupResult{}, fmt.Errorf("chown restored docroot: %w", err)
		}
	}

	restoredDatabases := make([]string, 0, len(dumps))
	for _, database := range sortedMapKeys(dumps) {
		if p.restorer == nil {
			return types.RestoreBackupResult{}, errors.New("database restorer is not configured")
		}
		if err := p.restorer.RestoreDatabase(ctx, database, dumps[database]); err != nil {
			return types.RestoreBackupResult{}, fmt.Errorf("restore database %q: %w", database, err)
		}
		restoredDatabases = append(restoredDatabases, database)
	}

	return types.RestoreBackupResult{
		Domain:            normalized.Domain,
		RestoredFiles:     fileCount,
		RestoredDatabases: restoredDatabases,
		PreviousDocroot:   previousDocroot,
	}, nil
}

func normalizeRestoreRequest(req types.RestoreBackupReq) (types.RestoreBackupReq, error) {
	req.Domain = site.NormalizeDomain(req.Domain)
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if req.Docroot == "" && req.Username != "" {
		req.Docroot = filepath.Join("/home", req.Username, "public_html")
	}
	if err := site.ValidateDomain(req.Domain); err != nil {
		return types.RestoreBackupReq{}, err
	}
	if !phase6UsernameRE.MatchString(req.Username) {
		return types.RestoreBackupReq{}, fmt.Errorf("username must match %s", phase6UsernameRE.String())
	}
	if strings.TrimSpace(req.ArchivePath) == "" {
		return types.RestoreBackupReq{}, errors.New("archive path is required")
	}
	archivePath, err := filepath.Abs(req.ArchivePath)
	if err != nil {
		return types.RestoreBackupReq{}, fmt.Errorf("resolve archive path: %w", err)
	}
	docroot, err := filepath.Abs(req.Docroot)
	if err != nil {
		return types.RestoreBackupReq{}, fmt.Errorf("resolve docroot: %w", err)
	}
	req.ArchivePath = archivePath
	req.Docroot = docroot
	for i, database := range req.Databases {
		normalized := strings.ToLower(strings.TrimSpace(database))
		if !phase6DBIdentifierRE.MatchString(normalized) {
			return types.RestoreBackupReq{}, errors.New("database name must start with a lowercase letter and contain only lowercase letters, digits, and underscores")
		}
		req.Databases[i] = normalized
	}
	sort.Strings(req.Databases)
	return req, nil
}

func extractRestoreArchive(archivePath string, docroot string, requestedDatabases []string) (int, map[string][]byte, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return 0, nil, fmt.Errorf("open backup archive: %w", err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return 0, nil, fmt.Errorf("open backup gzip: %w", err)
	}
	defer gzipReader.Close()

	requested := make(map[string]struct{}, len(requestedDatabases))
	for _, name := range requestedDatabases {
		requested[name] = struct{}{}
	}
	restoreAllDatabases := len(requested) == 0
	dumps := make(map[string][]byte)
	fileCount := 0
	reader := tar.NewReader(gzipReader)
	for {
		header, err := reader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, nil, fmt.Errorf("read backup tar: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		cleanName := path.Clean(header.Name)
		switch {
		case strings.HasPrefix(cleanName, "files/"):
			rel := strings.TrimPrefix(cleanName, "files/")
			target, err := safeRestorePath(docroot, rel)
			if err != nil {
				return 0, nil, err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return 0, nil, fmt.Errorf("create restore file directory: %w", err)
			}
			mode := os.FileMode(header.Mode).Perm()
			if mode == 0 {
				mode = 0o644
			}
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
			if err != nil {
				return 0, nil, fmt.Errorf("create restore file %q: %w", target, err)
			}
			if _, err := io.Copy(out, reader); err != nil {
				_ = out.Close()
				return 0, nil, fmt.Errorf("write restore file %q: %w", target, err)
			}
			if err := out.Close(); err != nil {
				return 0, nil, fmt.Errorf("close restore file %q: %w", target, err)
			}
			fileCount++
		case strings.HasPrefix(cleanName, "databases/") && strings.HasSuffix(cleanName, ".sql"):
			name := strings.TrimSuffix(strings.TrimPrefix(cleanName, "databases/"), ".sql")
			if !phase6DBIdentifierRE.MatchString(name) {
				return 0, nil, fmt.Errorf("invalid database dump name %q", name)
			}
			if _, ok := requested[name]; !restoreAllDatabases && !ok {
				continue
			}
			dump, err := io.ReadAll(reader)
			if err != nil {
				return 0, nil, fmt.Errorf("read database dump %q: %w", name, err)
			}
			dumps[name] = dump
		}
	}
	return fileCount, dumps, nil
}

func safeRestorePath(root string, rel string) (string, error) {
	if rel == "" || rel == "." {
		return "", errors.New("invalid empty restore path")
	}
	cleanRel := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(cleanRel) || cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid restore path %q", rel)
	}
	return filepath.Join(root, cleanRel), nil
}

func sortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func writeTarFile(writer *tar.Writer, name string, data []byte, mode os.FileMode) error {
	header := &tar.Header{
		Name:    name,
		Mode:    int64(mode),
		Size:    int64(len(data)),
		ModTime: time.Unix(0, 0).UTC(),
	}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write tar header %q: %w", name, err)
	}
	if _, err := io.Copy(writer, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("write tar file %q: %w", name, err)
	}
	return nil
}

func normalizeBackupRequest(req types.CreateBackupReq, defaultOutputDir string) (types.CreateBackupReq, error) {
	req.Domain = site.NormalizeDomain(req.Domain)
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if req.OutputDir == "" {
		req.OutputDir = defaultOutputDir
	}
	if req.Docroot == "" && req.Username != "" {
		req.Docroot = filepath.Join("/home", req.Username, "public_html")
	}
	if err := site.ValidateDomain(req.Domain); err != nil {
		return types.CreateBackupReq{}, err
	}
	if !phase6UsernameRE.MatchString(req.Username) {
		return types.CreateBackupReq{}, fmt.Errorf("username must match %s", phase6UsernameRE.String())
	}
	cleanDocroot, err := filepath.Abs(req.Docroot)
	if err != nil {
		return types.CreateBackupReq{}, fmt.Errorf("resolve docroot: %w", err)
	}
	req.Docroot = cleanDocroot
	for i, database := range req.Databases {
		normalized := strings.ToLower(strings.TrimSpace(database))
		if !phase6DBIdentifierRE.MatchString(normalized) {
			return types.CreateBackupReq{}, errors.New("database name must start with a lowercase letter and contain only lowercase letters, digits, and underscores")
		}
		req.Databases[i] = normalized
	}
	sort.Strings(req.Databases)
	return req, nil
}

type WebmailProvisionerOptions struct {
	NginxAvailableDir string
	NginxEnabledDir   string
	RoundcubeRoot     string
	Reloader          SiteServiceReloader
}

type WebmailProvisioner struct {
	availableDir  string
	enabledDir    string
	roundcubeRoot string
	reloader      SiteServiceReloader
}

func NewWebmailProvisioner(opts WebmailProvisionerOptions) *WebmailProvisioner {
	availableDir := opts.NginxAvailableDir
	if availableDir == "" {
		availableDir = "/etc/nginx/sites-available"
	}
	enabledDir := opts.NginxEnabledDir
	if enabledDir == "" {
		enabledDir = "/etc/nginx/sites-enabled"
	}
	root := opts.RoundcubeRoot
	if root == "" {
		root = "/usr/share/roundcube"
	}
	return &WebmailProvisioner{availableDir: availableDir, enabledDir: enabledDir, roundcubeRoot: root, reloader: opts.Reloader}
}

func (p *WebmailProvisioner) ConfigureWebmail(ctx context.Context, req types.ConfigureWebmailReq) (types.ConfigureWebmailResult, error) {
	normalized, err := normalizeWebmailRequest(req, p.roundcubeRoot)
	if err != nil {
		return types.ConfigureWebmailResult{}, err
	}
	configPath := filepath.Join(p.availableDir, normalized.Hostname+".conf")
	enabledPath := filepath.Join(p.enabledDir, normalized.Hostname+".conf")
	if err := writeFileAtomic(configPath, []byte(RenderWebmailNginxConfig(normalized)), 0o644); err != nil {
		return types.ConfigureWebmailResult{}, fmt.Errorf("write webmail nginx config: %w", err)
	}
	if err := ensureSymlink(configPath, enabledPath); err != nil {
		return types.ConfigureWebmailResult{}, fmt.Errorf("enable webmail nginx config: %w", err)
	}
	if p.reloader != nil {
		if err := p.reloader.ReloadService(ctx, "nginx"); err != nil {
			return types.ConfigureWebmailResult{}, err
		}
	}
	return types.ConfigureWebmailResult{Hostname: normalized.Hostname, ConfigPath: configPath, EnabledPath: enabledPath}, nil
}

func RenderWebmailNginxConfig(req types.ConfigureWebmailReq) string {
	return fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %[1]s;
    root %[2]s;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
`, req.Hostname, req.RoundcubeRoot)
}

func normalizeWebmailRequest(req types.ConfigureWebmailReq, defaultRoot string) (types.ConfigureWebmailReq, error) {
	req.Domain = site.NormalizeDomain(req.Domain)
	if req.Hostname == "" && req.Domain != "" {
		req.Hostname = "webmail." + req.Domain
	}
	req.Hostname = site.NormalizeDomain(req.Hostname)
	if req.RoundcubeRoot == "" {
		req.RoundcubeRoot = defaultRoot
	}
	if err := site.ValidateDomain(req.Domain); err != nil {
		return types.ConfigureWebmailReq{}, err
	}
	if err := site.ValidateDomain(req.Hostname); err != nil {
		return types.ConfigureWebmailReq{}, err
	}
	if !strings.HasSuffix(req.Hostname, "."+req.Domain) && req.Hostname != "webmail."+req.Domain {
		return types.ConfigureWebmailReq{}, fmt.Errorf("webmail hostname %q is outside domain %q", req.Hostname, req.Domain)
	}
	return req, nil
}

type DNSProvisionerOptions struct {
	ZoneDir         string
	IncludeDir      string
	AggregatePath   string
	ValidatorRunner CommandRunner
	Reloader        SiteServiceReloader
}

type DNSProvisioner struct {
	zoneDir         string
	includeDir      string
	aggregatePath   string
	validatorRunner CommandRunner
	reloader        SiteServiceReloader
}

func NewDNSProvisioner(opts DNSProvisionerOptions) *DNSProvisioner {
	zoneDir := opts.ZoneDir
	if zoneDir == "" {
		zoneDir = "/etc/bind/nakpanel/zones"
	}
	includeDir := opts.IncludeDir
	if includeDir == "" {
		includeDir = "/etc/bind/nakpanel/zones.d"
	}
	aggregatePath := opts.AggregatePath
	if aggregatePath == "" {
		aggregatePath = "/etc/bind/nakpanel/named.conf"
	}
	validator := opts.ValidatorRunner
	if validator == nil {
		validator = ExecRunner{}
	}
	return &DNSProvisioner{
		zoneDir:         zoneDir,
		includeDir:      includeDir,
		aggregatePath:   aggregatePath,
		validatorRunner: validator,
		reloader:        opts.Reloader,
	}
}

func (p *DNSProvisioner) ConfigureDNSZone(ctx context.Context, req types.ConfigureDNSZoneReq) (_ types.ConfigureDNSZoneResult, err error) {
	normalized, err := normalizeDNSZoneRequest(req, p.zoneDir)
	if err != nil {
		return types.ConfigureDNSZoneResult{}, err
	}
	zonePath := filepath.Join(normalized.ZoneDir, "db."+normalized.Domain)
	includePath := filepath.Join(p.includeDir, normalized.Domain+".conf")
	snapshots, err := snapshotFiles([]string{zonePath, includePath, p.aggregatePath})
	if err != nil {
		return types.ConfigureDNSZoneResult{}, err
	}
	reloadAttempted := false
	defer func() {
		if err == nil {
			return
		}
		_ = restoreSnapshots(snapshots)
		if reloadAttempted && p.reloader != nil {
			_ = p.reloader.ReloadService(context.Background(), "named.service")
		}
	}()
	if err := writeFileAtomic(zonePath, []byte(RenderDNSZone(normalized)), 0o644); err != nil {
		return types.ConfigureDNSZoneResult{}, fmt.Errorf("write dns zone: %w", err)
	}
	if err := writeFileAtomic(includePath, []byte(RenderDNSZoneInclude(normalized.Domain, zonePath)), 0o644); err != nil {
		return types.ConfigureDNSZoneResult{}, fmt.Errorf("write dns include: %w", err)
	}
	if err := p.writeAggregateDNSIncludes(); err != nil {
		return types.ConfigureDNSZoneResult{}, err
	}
	if err := p.validateDNSZone(ctx, normalized.Domain, zonePath); err != nil {
		return types.ConfigureDNSZoneResult{}, err
	}
	if err := p.validateDNSConfig(ctx); err != nil {
		return types.ConfigureDNSZoneResult{}, err
	}
	if p.reloader != nil {
		reloadAttempted = true
		if err := p.reloader.ReloadService(ctx, "named.service"); err != nil {
			return types.ConfigureDNSZoneResult{}, err
		}
	}
	return types.ConfigureDNSZoneResult{Domain: normalized.Domain, ZonePath: zonePath, IncludePath: includePath, Serial: normalized.Serial}, nil
}

func RenderDNSZone(req types.ConfigureDNSZoneReq) string {
	header := fmt.Sprintf(`$ORIGIN %[1]s.
$TTL 300
@ IN SOA ns1.%[1]s. hostmaster.%[1]s. (
    %[3]d
    3600
    900
    604800
    300
)
@ IN NS ns1.%[1]s.
ns1 IN A %[2]s
webmail IN A %[2]s
`, req.Domain, req.Address, req.Serial)
	if len(req.Records) == 0 {
		return header + fmt.Sprintf("@ IN A %s\nwww IN A %s\n", req.Address, req.Address)
	}
	var builder strings.Builder
	builder.WriteString(header)
	for _, record := range req.Records {
		host := strings.TrimSpace(record.Host)
		if host == "" {
			host = "@"
		}
		value := strings.TrimSpace(record.Value)
		switch record.Type {
		case "CNAME", "MX":
			if !strings.HasSuffix(value, ".") {
				value += "."
			}
		case "TXT":
			value = `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
		}
		if record.Type == "MX" {
			fmt.Fprintf(&builder, "%s %d IN MX %d %s\n", host, record.TTL, record.Priority, value)
		} else {
			fmt.Fprintf(&builder, "%s %d IN %s %s\n", host, record.TTL, record.Type, value)
		}
	}
	return builder.String()
}

func RenderDNSZoneInclude(domain string, zonePath string) string {
	return fmt.Sprintf(`zone "%[1]s" {
    type master;
    file "%[2]s";
};
`, domain, zonePath)
}

func RenderDNSAggregateInclude(paths []string) string {
	var builder strings.Builder
	builder.WriteString("// Generated by nakpanel. Include this file from /etc/bind/named.conf.local.\n")
	for _, includePath := range paths {
		builder.WriteString(fmt.Sprintf("include \"%s\";\n", includePath))
	}
	return builder.String()
}

func (p *DNSProvisioner) writeAggregateDNSIncludes() error {
	entries, err := os.ReadDir(p.includeDir)
	if err != nil {
		return fmt.Errorf("read dns include directory: %w", err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		paths = append(paths, filepath.Join(p.includeDir, entry.Name()))
	}
	sort.Strings(paths)
	if err := writeFileAtomic(p.aggregatePath, []byte(RenderDNSAggregateInclude(paths)), 0o644); err != nil {
		return fmt.Errorf("write dns aggregate include: %w", err)
	}
	return nil
}

func (p *DNSProvisioner) validateDNSZone(ctx context.Context, domain string, zonePath string) error {
	out, err := p.validatorRunner.Run(ctx, "named-checkzone", domain, zonePath)
	if err != nil {
		return fmt.Errorf("named-checkzone %q: %w: %s", domain, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *DNSProvisioner) validateDNSConfig(ctx context.Context) error {
	out, err := p.validatorRunner.Run(ctx, "named-checkconf", p.aggregatePath)
	if err != nil {
		return fmt.Errorf("named-checkconf: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func normalizeDNSZoneRequest(req types.ConfigureDNSZoneReq, defaultZoneDir string) (types.ConfigureDNSZoneReq, error) {
	req.Domain = site.NormalizeDomain(req.Domain)
	req.Address = strings.TrimSpace(req.Address)
	if req.ZoneDir == "" {
		req.ZoneDir = defaultZoneDir
	}
	if req.Serial == 0 {
		req.Serial = time.Now().UTC().Unix()
	}
	if err := site.ValidateDomain(req.Domain); err != nil {
		return types.ConfigureDNSZoneReq{}, err
	}
	if net.ParseIP(req.Address) == nil {
		return types.ConfigureDNSZoneReq{}, fmt.Errorf("invalid dns address %q", req.Address)
	}
	for _, record := range req.Records {
		if record.TTL < 60 || record.TTL > 86400 {
			return types.ConfigureDNSZoneReq{}, errors.New("DNS record TTL is invalid")
		}
		switch record.Type {
		case "A":
			if ip := net.ParseIP(record.Value); ip == nil || ip.To4() == nil {
				return types.ConfigureDNSZoneReq{}, errors.New("invalid A record")
			}
		case "AAAA":
			if ip := net.ParseIP(record.Value); ip == nil || ip.To4() != nil {
				return types.ConfigureDNSZoneReq{}, errors.New("invalid AAAA record")
			}
		case "CNAME", "MX", "TXT":
		default:
			return types.ConfigureDNSZoneReq{}, fmt.Errorf("unsupported DNS record type %q", record.Type)
		}
	}
	return req, nil
}

type ReconciliationProvisioner struct {
	sites interface {
		CreateSite(context.Context, types.CreateSiteReq) error
	}
	webmail interface {
		ConfigureWebmail(context.Context, types.ConfigureWebmailReq) (types.ConfigureWebmailResult, error)
	}
	dns interface {
		ConfigureDNSZone(context.Context, types.ConfigureDNSZoneReq) (types.ConfigureDNSZoneResult, error)
	}
}

func NewReconciliationProvisioner(siteProvisioner interface {
	CreateSite(context.Context, types.CreateSiteReq) error
}, webmail interface {
	ConfigureWebmail(context.Context, types.ConfigureWebmailReq) (types.ConfigureWebmailResult, error)
}, dns interface {
	ConfigureDNSZone(context.Context, types.ConfigureDNSZoneReq) (types.ConfigureDNSZoneResult, error)
}) *ReconciliationProvisioner {
	return &ReconciliationProvisioner{sites: siteProvisioner, webmail: webmail, dns: dns}
}

func (p *ReconciliationProvisioner) ReconcileSystem(ctx context.Context, req types.ReconcileSystemReq) (types.ReconcileSystemResult, error) {
	result := types.ReconcileSystemResult{SitesTotal: len(req.Sites)}
	for _, siteReq := range req.Sites {
		createSite := types.CreateSiteReq{Username: siteReq.Username, Domain: siteReq.Domain, PHPVersion: siteReq.PHPVersion}
		if p.sites != nil {
			if err := p.sites.CreateSite(ctx, createSite); err != nil {
				return result, fmt.Errorf("reconcile site %q: %w", siteReq.Domain, err)
			}
		}
		if siteReq.EnableWebmail && p.webmail != nil {
			if _, err := p.webmail.ConfigureWebmail(ctx, types.ConfigureWebmailReq{Domain: siteReq.Domain, Hostname: "webmail." + site.NormalizeDomain(siteReq.Domain)}); err != nil {
				return result, fmt.Errorf("reconcile webmail %q: %w", siteReq.Domain, err)
			}
		}
		if siteReq.EnableDNS && p.dns != nil {
			if _, err := p.dns.ConfigureDNSZone(ctx, types.ConfigureDNSZoneReq{Domain: siteReq.Domain, Address: siteReq.Address}); err != nil {
				return result, fmt.Errorf("reconcile dns %q: %w", siteReq.Domain, err)
			}
		}
		result.SitesOK++
	}
	return result, nil
}
