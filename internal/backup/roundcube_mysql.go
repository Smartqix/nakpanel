package backup

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const RoundcubeMySQLDumpName = "roundcube/mysql.sql.gz"
const roundcubeMySQLSocket = "/run/mysqld/mysqld.sock"
const roundcubeConfigLimit = 65536
const roundcubeSQLLimit = int64(8) << 30

type RoundcubeMySQLMetadata struct {
	Database   string `json:"database"`
	Username   string `json:"username"`
	Host       string `json:"host"`
	ConfigPath string `json:"config_path"`
}
type RoundcubeDatabase struct {
	SQLitePath    string
	MySQL         *RoundcubeMySQLMetadata
	mysqlPassword string
}

func (m RoundcubeMySQLMetadata) Validate() error {
	if m.Database != "roundcube" || m.Username != "roundcube" || m.Host != "localhost" || (m.ConfigPath != "/etc/roundcube/debian-db.php" && m.ConfigPath != "/etc/roundcube/debian-db-roundcube.php") {
		return errors.New("unsupported Roundcube MySQL database/account/configuration; only the default local roundcube account and database are supported")
	}
	return nil
}

func checkRoundcubeMySQLSourceProvenance(source Manifest) error {
	if source.RoundcubeMySQL == nil {
		return nil
	}
	if source.Platform == nil {
		return errors.New("Roundcube MySQL format-3 archives require complete observed source platform provenance")
	}
	return completeRoundcubeSQLProvenance(*source.Platform)
}
func completeRoundcubeSQLProvenance(p PlatformProvenance) error {
	known := p.OSID == "ubuntu" && (p.VersionID == "26.04" && p.Codename == "resolute" && (p.Profile == "ubuntu-26.04-native" || p.Profile == "ubuntu-26.04-sury") && p.InternalPHPVersion == "8.5")
	if !known || !p.PHPInventoryComplete || len(p.HostingPHPVersions) == 0 {
		return errors.New("Roundcube MySQL format-3 recovery requires complete observed platform and PHP provenance")
	}
	for _, version := range []string{p.PostgresServerVersion, p.PostgresDumpVersion, p.PostgresRestoreVersion, p.MariaDBServerVersion, p.MariaDBDumpVersion, p.MariaDBClientVersion} {
		if len(versionNumbers(version)) < 2 {
			return errors.New("Roundcube MySQL format-3 recovery requires complete observed database server and tool provenance")
		}
	}
	return nil
}
func CheckRoundcubeMySQLBackupPlatform(platform PlatformProvenance, includeMail bool) error {
	if err := completeRoundcubeSQLProvenance(platform); err != nil {
		return err
	}
	if includeMail && platform.StalwartVersion == "" {
		return errors.New("Roundcube MySQL format-3 mail backup requires observed mail store provenance")
	}
	return nil
}

func checkRoundcubeMySQLCompatibility(source Manifest, target PlatformProvenance) error {
	if source.RoundcubeMySQL == nil {
		return nil
	}
	if err := checkRoundcubeMySQLSourceProvenance(source); err != nil {
		return err
	}
	if err := completeRoundcubeSQLProvenance(target); err != nil {
		return err
	}
	if source.IncludeMailData && (source.Platform.StalwartVersion == "" || target.StalwartVersion == "") {
		return errors.New("Roundcube MySQL format-3 mail recovery requires observed mail store provenance")
	}
	return nil
}

func validateRoundcubeManifest(m Manifest) error {
	if m.RoundcubeMySQL != nil {
		if m.FormatVersion != 3 {
			return errors.New("Roundcube MySQL backups require archive format version 3")
		}
		if m.RoundcubeSQLitePath != "" {
			return errors.New("Roundcube archive cannot declare both SQLite and MySQL")
		}
		if err := m.RoundcubeMySQL.Validate(); err != nil {
			return err
		}
		for _, database := range m.TenantDatabases {
			if database == "roundcube" {
				return errors.New("Roundcube service database cannot be declared as a tenant database")
			}
		}
		return checkRoundcubeMySQLSourceProvenance(m)
	}
	if m.FormatVersion == 3 {
		return errors.New("archive format version 3 requires its Roundcube MySQL declaration")
	}
	if m.RoundcubeSQLitePath != "" && m.FormatVersion != 2 {
		return errors.New("Roundcube SQLite snapshots require archive format version 2")
	}
	return nil
}

// ParseRoundcubeDatabaseFiles reads only literal database values. It never
// executes PHP or includes configuration, and errors never include credentials.
func ParseRoundcubeDatabaseFiles(files map[string][]byte) (RoundcubeDatabase, error) {
	var result RoundcubeDatabase
	if data, present := files["debian-db-roundcube.php"]; present {
		dsn, found, err := roundcubeDSNLiteral(data)
		if err != nil {
			return result, err
		}
		if found {
			if strings.HasPrefix(dsn, "sqlite:") {
				path := filepath.Clean("/" + strings.TrimLeft(strings.TrimPrefix(dsn, "sqlite:"), "/"))
				if !IsRoundcubeSQLitePath(path) {
					return result, errors.New("Roundcube SQLite configuration uses an unsupported backup path")
				}
				result.SQLitePath = path
				return result, nil
			}
			parsed, err := url.Parse(dsn)
			if err != nil || parsed.Scheme != "mysql" || parsed.User == nil || parsed.Hostname() != "localhost" || (parsed.Port() != "" && parsed.Port() != "3306") || parsed.Path != "/roundcube" || parsed.RawQuery != "" || parsed.Fragment != "" {
				return result, errors.New("unsupported configured non-SQLite Roundcube database")
			}
			password, ok := parsed.User.Password()
			if !ok || !validRoundcubePassword(password) {
				return result, errors.New("Roundcube local MySQL credentials are incomplete")
			}
			if err := checkRoundcubeConfigOverride(files); err != nil {
				return result, err
			}
			result.MySQL = &RoundcubeMySQLMetadata{Database: "roundcube", Username: parsed.User.Username(), Host: "localhost", ConfigPath: "/etc/roundcube/debian-db-roundcube.php"}
			result.mysqlPassword = password
			return result, result.MySQL.Validate()
		}
	}
	data, present := files["debian-db.php"]
	if !present {
		if _, wrapperPresent := files["debian-db-roundcube.php"]; wrapperPresent {
			return result, errors.New("Roundcube database wrapper requires its static backend configuration")
		}
		if err := checkRoundcubeConfigOverride(files); err != nil {
			return result, err
		}
		return result, nil
	}
	values, err := roundcubePHPVariables(data)
	if err != nil {
		return result, err
	}
	switch values["dbtype"] {
	case "":
		return result, errors.New("present Roundcube database configuration has no supported static backend")
	case "sqlite", "sqlite3":
		base := values["dbbasepath"]
		if base == "" {
			base = values["basepath"]
		}
		path := filepath.Join(base, values["dbname"])
		if !IsRoundcubeSQLitePath(path) {
			return result, errors.New("Roundcube SQLite configuration uses an unsupported backup path")
		}
		result.SQLitePath = path
		return result, nil
	case "mysql":
		if err := checkRoundcubeConfigOverride(files); err != nil {
			return result, err
		}
		if (values["dbserver"] != "" && values["dbserver"] != "localhost") || (values["dbport"] != "" && values["dbport"] != "3306") {
			return result, errors.New("unsupported configured non-SQLite Roundcube database: local default MySQL is required")
		}
		result.MySQL = &RoundcubeMySQLMetadata{Database: values["dbname"], Username: values["dbuser"], Host: "localhost", ConfigPath: "/etc/roundcube/debian-db.php"}
		if err := result.MySQL.Validate(); err != nil {
			return RoundcubeDatabase{}, err
		}
		if !validRoundcubePassword(values["dbpass"]) {
			return RoundcubeDatabase{}, errors.New("Roundcube local MySQL credentials are incomplete")
		}
		result.mysqlPassword = values["dbpass"]
		return result, nil
	default:
		return result, errors.New("unsupported configured non-SQLite Roundcube database")
	}
}

var roundcubeVariableRE = regexp.MustCompile(`(?m)^\s*\$(dbtype|dbserver|dbport|dbbasepath|basepath|dbname|dbuser|dbpass)\s*=\s*(.*?)\s*;\s*(?://[^\r\n]*)?$`)

func roundcubePHPVariables(data []byte) (map[string]string, error) {
	values := map[string]string{}
	for _, match := range roundcubeVariableRE.FindAllStringSubmatch(string(data), -1) {
		if _, ok := values[match[1]]; ok {
			return nil, errors.New("ambiguous Roundcube database configuration")
		}
		value, err := parseRoundcubePHPLiteral(match[2])
		if err != nil {
			return nil, err
		}
		values[match[1]] = value
	}
	return values, nil
}
func parseRoundcubePHPLiteral(raw string) (string, error) {
	if len(raw) < 2 || (raw[0] != '\'' && raw[0] != '"') || raw[len(raw)-1] != raw[0] {
		return "", errors.New("Roundcube database configuration must contain static literal values")
	}
	quote := raw[0]
	raw = raw[1 : len(raw)-1]
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if ch == '\r' || ch == '\n' || ch == 0 || ch == quote || (quote == '"' && ch == '$') {
			return "", errors.New("unsupported Roundcube database literal")
		}
		if ch == '\\' {
			if i+1 >= len(raw) {
				return "", errors.New("unsupported Roundcube database literal")
			}
			next := raw[i+1]
			if next == '\\' || next == quote {
				b.WriteByte(next)
				i++
				continue
			}
			if quote == '"' {
				return "", errors.New("unsupported Roundcube database literal")
			}
		}
		b.WriteByte(ch)
	}
	return b.String(), nil
}

const defaultDebianRoundcubeWrapper = `<?php
require("/etc/roundcube/debian-db.php");

switch ($dbtype) {
 case "sqlite":
 case "sqlite3":
   $config['db_dsnw'] = "sqlite:///$basepath/$dbname?mode=0640";
   break;
 default:
   if ($dbport != '') $dbport=":$dbport";
   if ($dbserver == '') $dbserver="localhost";
   $config['db_dsnw'] = "$dbtype://$dbuser:$dbpass@$dbserver$dbport/$dbname";
   break;
 }
?>`

func roundcubeDSNLiteral(data []byte) (string, bool, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte(defaultDebianRoundcubeWrapper)) {
		return "", false, nil
	}
	re := regexp.MustCompile(`(?m)^\s*\$config\[['"]db_dsnw['"]\]\s*=\s*(.*?)\s*;\s*$`)
	matches := re.FindAllStringSubmatch(string(data), -1)
	if len(matches) != 1 {
		return "", false, errors.New("unsupported or ambiguous Roundcube database wrapper")
	}
	value, err := parseRoundcubePHPLiteral(matches[0][1])
	return value, true, err
}
func checkRoundcubeConfigOverride(files map[string][]byte) error {
	data := files["config.inc.php"]
	assignment := regexp.MustCompile(`^\$config\s*\[\s*(?:'db_dsnw'|"db_dsnw")\s*\]\s*=`)
	for i := 0; i < len(data); {
		if data[i] == '#' || (data[i] == '/' && i+1 < len(data) && data[i+1] == '/') {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			continue
		}
		if data[i] == '/' && i+1 < len(data) && data[i+1] == '*' {
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			i += 2
			continue
		}
		if data[i] == '\'' || data[i] == '"' {
			quote := data[i]
			i++
			for i < len(data) {
				if data[i] == '\\' {
					i += 2
					continue
				}
				if data[i] == quote {
					i++
					break
				}
				i++
			}
			continue
		}
		if data[i] == '$' && assignment.Match(data[i:]) {
			return errors.New("custom Roundcube database DSN overrides are unsupported")
		}
		i++
	}
	return nil
}

func validRoundcubePassword(password string) bool {
	return password != "" && len(password) <= 4096 && !strings.ContainsAny(password, "\x00\r\n")
}

func ReadRoundcubeDatabase(configDir string, ownerUID uint32) (RoundcubeDatabase, error) {
	files := map[string][]byte{}
	for _, name := range []string{"debian-db-roundcube.php", "debian-db.php", "config.inc.php"} {
		file, err := os.OpenFile(filepath.Join(configDir, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return RoundcubeDatabase{}, errors.New("cannot read trusted Roundcube database configuration")
		}
		info, statErr := file.Stat()
		var data []byte
		if statErr == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != ownerUID || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
				statErr = errors.New("untrusted configuration ownership or mode")
			} else {
				data, statErr = io.ReadAll(io.LimitReader(file, roundcubeConfigLimit+1))
			}
		}
		_ = file.Close()
		if statErr != nil || len(data) > roundcubeConfigLimit {
			return RoundcubeDatabase{}, errors.New("Roundcube database configuration must be a bounded root-owned regular file without group/world write access")
		}
		files[name] = data
	}
	return ParseRoundcubeDatabaseFiles(files)
}

func roundcubeRootCommand(ctx context.Context, args ...string) *exec.Cmd {
	fixed := []string{"--no-defaults", "--protocol=socket", "--socket=" + roundcubeMySQLSocket, "--user=root", "--connect-timeout=10"}
	cmd := exec.CommandContext(ctx, "mariadb", append(fixed, args...)...)
	cmd.Env = make([]string, 0)
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if !strings.HasPrefix(name, "MYSQL_") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	return cmd
}

type RoundcubeMySQLRuntimeCheck func(context.Context, string) error

func CheckRoundcubeMySQLTarget(ctx context.Context, source Manifest, target PlatformProvenance, mode RestoreMode, runtimeChecks ...RoundcubeMySQLRuntimeCheck) error {
	if source.RoundcubeMySQL == nil {
		return nil
	}
	if err := validateRoundcubeManifest(source); err != nil {
		return err
	}
	if mode == RestoreForwardMigration {
		return errors.New("Roundcube MySQL forward migration is unsupported; use same-platform recovery preserving its local MySQL backend")
	}
	if !regexp.MustCompile(`^8\.[1-5]$`).MatchString(target.InternalPHPVersion) {
		return errors.New("Roundcube MySQL restore requires the trusted target internal PHP version")
	}
	if _, err := exec.LookPath("mariadb"); err != nil {
		return errors.New("Roundcube MySQL restore requires the local mariadb client")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := roundcubeRootCommand(bounded, "--batch", "--skip-column-names")
	cmd.Stdin = strings.NewReader("SELECT CURRENT_USER(), VERSION();\n")
	out, err := cmd.Output()
	if err != nil || !strings.HasPrefix(string(out), "root@localhost\t") || !strings.Contains(string(out), "MariaDB") {
		return errors.New("Roundcube MySQL restore requires a working root socket connection to local MariaDB")
	}
	if len(runtimeChecks) != 1 || runtimeChecks[0] == nil {
		return errors.New("Roundcube MySQL restore requires an authoritative target internal PHP runtime check")
	}
	if err := runtimeChecks[0](bounded, target.InternalPHPVersion); err != nil {
		return fmt.Errorf("Roundcube MySQL target internal PHP readiness: %w", err)
	}
	return nil
}

func DumpRoundcubeMySQL(ctx context.Context, metadata RoundcubeMySQLMetadata, target string) error {
	if err := metadata.Validate(); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	gz := gzip.NewWriter(file)
	args := []string{"--no-defaults", "--protocol=socket", "--socket=" + roundcubeMySQLSocket, "--user=root", "--single-transaction", "--routines", "--events", "--triggers", "--hex-blob", "--databases", metadata.Database}
	cmd := exec.CommandContext(bounded, "mariadb-dump", args...)
	cmd.Stdout = gz
	cmd.Stderr = io.Discard
	if err = cmd.Run(); err != nil {
		return errors.New("Roundcube local MySQL database dump failed")
	}
	if err = gz.Close(); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	return validateRoundcubeSQLDump(target)
}
func validateRoundcubeSQLDump(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return errors.New("Roundcube MySQL SQL payload is not a valid gzip dump")
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: roundcubeSQLLimit + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 65536), 64<<20)
	headerSeen, createSeen, useSeen := false, false, false
	usersSeen, contactsSeen := false, false
	createRE := regexp.MustCompile("^CREATE DATABASE(?: /\\*![0-9]+ IF NOT EXISTS\\*/| IF NOT EXISTS)? `([^`]+)`(?: |;)")
	useRE := regexp.MustCompile("^USE `([^`]+)`;$")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "CREATE TABLE ") {
			table := strings.TrimSpace(line[len("CREATE TABLE "):])
			table = strings.TrimLeft(table, "`")
			if strings.HasPrefix(table, "users`") || strings.HasPrefix(table, "users(") || strings.HasPrefix(table, "users ") {
				usersSeen = true
			}
			if strings.HasPrefix(table, "contacts`") || strings.HasPrefix(table, "contacts(") || strings.HasPrefix(table, "contacts ") {
				contactsSeen = true
			}
		}
		if strings.HasPrefix(line, "-- MariaDB dump") {
			headerSeen = true
		}
		if strings.HasPrefix(upper, "CREATE DATABASE") {
			match := createRE.FindStringSubmatch(line)
			if len(match) != 2 || match[1] != "roundcube" {
				return errors.New("Roundcube MySQL SQL payload declares an unexpected database")
			}
			createSeen = true
		}
		if strings.HasPrefix(upper, "USE ") {
			match := useRE.FindStringSubmatch(line)
			if len(match) != 2 || match[1] != "roundcube" {
				return errors.New("Roundcube MySQL SQL payload selects an unexpected database")
			}
			useSeen = true
		}
		if strings.HasPrefix(upper, "CREATE USER ") || strings.HasPrefix(upper, "ALTER USER ") || strings.HasPrefix(upper, "GRANT ") || strings.HasPrefix(upper, "DROP DATABASE") {
			return errors.New("Roundcube MySQL SQL payload contains unsupported account/database statements")
		}
	}
	if scanner.Err() != nil || limited.N <= 0 {
		return errors.New("Roundcube MySQL SQL payload is corrupt or exceeds the restore limit")
	}
	if !headerSeen || !createSeen || !useSeen || !usersSeen || !contactsSeen {
		return errors.New("Roundcube MySQL SQL payload lacks the expected MariaDB database dump structure")
	}
	return nil
}

func RestoreRoundcubeMySQL(ctx context.Context, metadata RoundcubeMySQLMetadata, dumpPath, configDir string) error {
	if err := metadata.Validate(); err != nil {
		return err
	}
	config, err := ReadRoundcubeDatabase(configDir, 0)
	if err != nil {
		return err
	}
	return restoreRoundcubeMySQL(ctx, metadata, dumpPath, config)
}

func runRoundcubeSQL(ctx context.Context, input io.Reader) error {
	cmd := roundcubeRootCommand(ctx)
	cmd.Stdin = input
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Roundcube local MySQL restore command failed: %w", err)
	}
	return nil
}

func checkRoundcubeFPMState(ctx context.Context, version string) (bool, error) {
	if !regexp.MustCompile(`^8\.[1-5]$`).MatchString(version) {
		return false, errors.New("Roundcube restore requires the trusted target internal PHP version")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(bounded, "systemctl", "is-active", "php"+version+"-fpm.service").Output()
	switch strings.TrimSpace(string(out)) {
	case "active":
		if err == nil {
			return true, nil
		}
	case "inactive", "failed":
		return false, nil
	}
	return false, errors.New("cannot inspect target internal PHP FPM service state before Roundcube restore")
}

func restoreRoundcubeMySQL(ctx context.Context, metadata RoundcubeMySQLMetadata, dumpPath string, config RoundcubeDatabase) error {
	// /run is root-controlled even after the restore dump directory is handed
	// to the unprivileged PostgreSQL role. Credentials must not follow dumps.
	return restoreRoundcubeMySQLWithOptionsParent(ctx, metadata, dumpPath, config, "/run", 0)
}
func restoreRoundcubeMySQLWithOptionsParent(ctx context.Context, metadata RoundcubeMySQLMetadata, dumpPath string, config RoundcubeDatabase, optionsParent string, optionsOwnerUID uint32) error {
	if err := metadata.Validate(); err != nil {
		return err
	}
	if config.MySQL == nil || *config.MySQL != metadata {
		return errors.New("restored Roundcube MySQL configuration differs from authenticated archive metadata")
	}
	if err := validateRoundcubeSQLDump(dumpPath); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	optionsPath, privateDir, err := createRoundcubeMySQLClientOptions(optionsParent, config.mysqlPassword, optionsOwnerUID)
	if err != nil {
		return err
	}
	defer os.RemoveAll(privateDir)
	// Identifiers/account names are restricted above. NO_BACKSLASH_ESCAPES makes
	// doubling apostrophes sufficient for every accepted literal password.
	password := strings.ReplaceAll(config.mysqlPassword, "'", "''")
	setup := "SET SESSION sql_mode='NO_BACKSLASH_ESCAPES';\nDROP DATABASE IF EXISTS `roundcube`;\nDROP USER IF EXISTS 'roundcube'@'localhost';\nCREATE USER 'roundcube'@'localhost' IDENTIFIED BY '" + password + "';\nGRANT ALL PRIVILEGES ON `roundcube`.* TO 'roundcube'@'localhost';\n"
	if err := runRoundcubeSQL(bounded, strings.NewReader(setup)); err != nil {
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
	// binary-mode disables client shell/source commands in batch input. Database
	// grants, not a SQL text parser, enforce the import's privilege boundary.
	cmd := exec.CommandContext(bounded, "mariadb", "--defaults-file="+optionsPath, "--protocol=socket", "--socket="+roundcubeMySQLSocket, "--user=roundcube", "--binary-mode", "--batch", "--local-infile=0", "--default-character-set=utf8mb4")
	cmd.Env = roundcubeRootCommand(bounded).Env
	cmd.Stdin = gz
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Roundcube database-scoped MySQL import failed: %w", err)
	}
	return nil
}

const RoundcubePackageConfigPath = "/etc/dbconfig-common/roundcube.conf"

func ValidateRoundcubePackageConfig(data []byte, metadata RoundcubeMySQLMetadata) error {
	if err := metadata.Validate(); err != nil {
		return err
	}
	values := map[string]string{}
	re := regexp.MustCompile(`(?m)^\s*(dbc_dbtype|dbc_dbserver|dbc_dbport|dbc_dbname|dbc_dbuser)\s*=\s*([^\r\n]*)$`)
	for _, match := range re.FindAllStringSubmatch(string(data), -1) {
		if _, duplicate := values[match[1]]; duplicate {
			return errors.New("ambiguous Roundcube package database configuration")
		}
		raw := strings.TrimSpace(match[2])
		value := raw
		if strings.HasPrefix(raw, "'") || strings.HasPrefix(raw, `"`) {
			var err error
			value, err = parseRoundcubePHPLiteral(raw)
			if err != nil {
				return errors.New("unsupported Roundcube package database configuration")
			}
		}
		values[match[1]] = value
	}
	if values["dbc_dbtype"] != "mysql" || values["dbc_dbname"] != metadata.Database || values["dbc_dbuser"] != metadata.Username || (values["dbc_dbserver"] != "" && values["dbc_dbserver"] != "localhost") || (values["dbc_dbport"] != "" && values["dbc_dbport"] != "3306") {
		return errors.New("Roundcube package database configuration does not match the declared default local MySQL backend")
	}
	return nil
}
func ReadRoundcubePackageConfig(path string, ownerUID uint32, metadata RoundcubeMySQLMetadata) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot read required Roundcube package database configuration")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Roundcube package database configuration must be a private root-owned regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, roundcubeConfigLimit+1))
	if err != nil || len(data) > roundcubeConfigLimit {
		return nil, errors.New("Roundcube package database configuration exceeds its read limit")
	}
	if err := ValidateRoundcubePackageConfig(data, metadata); err != nil {
		return nil, err
	}
	return data, nil
}

func createRoundcubeMySQLClientOptions(parent, password string, ownerUID uint32) (string, string, error) {
	info, err := os.Lstat(parent)
	if err != nil {
		return "", "", errors.New("cannot inspect root-controlled Roundcube credential directory parent")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return "", "", errors.New("Roundcube credential directory parent must be root-owned without symlinks or group/world write access")
	}
	privateDir, err := os.MkdirTemp(parent, ".roundcube-client-")
	if err != nil {
		return "", "", err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(privateDir)
		}
	}()
	optionsPath := filepath.Join(privateDir, "client.cnf")
	options, err := os.OpenFile(optionsPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return "", "", err
	}
	optionPassword := strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(password)
	_, writeErr := io.WriteString(options, "[client]\npassword=\""+optionPassword+"\"\n")
	closeErr := options.Close()
	if writeErr != nil {
		return "", "", writeErr
	}
	if closeErr != nil {
		return "", "", closeErr
	}
	keep = true
	return optionsPath, privateDir, nil
}
