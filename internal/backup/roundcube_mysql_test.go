package backup

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const mysqlRoundcubeConfig = "<?php\n$dbtype='mysql';\n$dbserver='localhost';\n$dbport='3306';\n$dbname='roundcube';\n$dbuser='roundcube';\n$dbpass='secret-canary';\n"

func defaultRoundcubeMySQLMetadata() *RoundcubeMySQLMetadata {
	return &RoundcubeMySQLMetadata{Database: "roundcube", Username: "roundcube", Host: "localhost", ConfigPath: "/etc/roundcube/debian-db.php"}
}

func TestDefaultLocalMySQLRoundcubeIsBackedUpWithoutCredentialDiagnostics(t *testing.T) {
	got, err := ParseRoundcubeDatabaseFiles(map[string][]byte{"debian-db.php": []byte(mysqlRoundcubeConfig)})
	if err != nil || got.MySQL == nil || got.MySQL.Database != "roundcube" || got.MySQL.Username != "roundcube" || got.MySQL.Host != "localhost" || got.mysqlPassword != "secret-canary" {
		t.Fatal("default local MySQL Roundcube backend was omitted or rejected")
	}
	for _, replacement := range []string{"$dbserver='remote.example.test';", "$dbname='tenantdb';", "$dbuser='root';", "$dbport='3307';"} {
		config := mysqlRoundcubeConfig + replacement + "\n"
		if _, err := ParseRoundcubeDatabaseFiles(map[string][]byte{"debian-db.php": []byte(config)}); err == nil || strings.Contains(err.Error(), "secret-canary") {
			t.Fatal("ambiguous/custom database was accepted or leaked a credential")
		}
	}
}

func makeMySQLRoundcubeArchive(t *testing.T, version int, metadata *RoundcubeMySQLMetadata, sqlCopies int, config string) []byte {
	t.Helper()
	key := bytes.Repeat([]byte{7}, KeySize)
	var encrypted bytes.Buffer
	w, err := NewArchiveWriter(&encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{FormatVersion: version, RoundcubeMySQL: metadata, Platform: ptrPlatform(platformFixture("24.04"))}
	data, _ := json.Marshal(manifest)
	if err = w.AddBytes(ManifestName, data, 0600); err != nil {
		t.Fatal(err)
	}
	if config != "" {
		if err = w.AddBytes(TreePrefix+"etc/roundcube/debian-db.php", []byte(config), 0640); err != nil {
			t.Fatal(err)
		}
	}
	if config != "" {
		_ = w.AddBytes(TreePrefix+strings.TrimPrefix(RoundcubePackageConfigPath, "/"), []byte("dbc_dbtype='mysql'\ndbc_dbname='roundcube'\ndbc_dbuser='roundcube'\ndbc_dbserver='localhost'\ndbc_dbport='3306'\n"), 0600)
	}
	var sql bytes.Buffer
	gz := gzip.NewWriter(&sql)
	_, _ = io.WriteString(gz, "-- MariaDB dump\nCREATE DATABASE IF NOT EXISTS `roundcube`;\nUSE `roundcube`;\nCREATE TABLE contacts(email TEXT); INSERT INTO contacts VALUES('contact-canary@example.test');\nCREATE TABLE users(preferences TEXT); INSERT INTO users VALUES('preference-canary');\n")
	_ = gz.Close()
	for i := 0; i < sqlCopies; i++ {
		if err = w.AddBytes(RoundcubeMySQLDumpName, sql.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return encrypted.Bytes()
}

func TestMySQLRoundcubeArchiveRequiresNewFormatAndAuthenticatedPayloadConfig(t *testing.T) {
	for _, tc := range []struct {
		name            string
		version, copies int
		config          string
		valid           bool
	}{{"valid", 3, 1, mysqlRoundcubeConfig, true}, {"old-reader-boundary", 2, 1, mysqlRoundcubeConfig, false}, {"missing-sql", 3, 0, mysqlRoundcubeConfig, false}, {"duplicate-sql", 3, 2, mysqlRoundcubeConfig, false}, {"missing-credentials", 3, 1, "", false}, {"wrong-account", 3, 1, strings.Replace(mysqlRoundcubeConfig, "$dbuser='roundcube'", "$dbuser='root'", 1), false}} {
		t.Run(tc.name, func(t *testing.T) {
			archive := makeMySQLRoundcubeArchive(t, tc.version, defaultRoundcubeMySQLMetadata(), tc.copies, tc.config)
			err := CheckArchiveIntegrity(bytes.NewReader(archive), bytes.Repeat([]byte{7}, KeySize))
			if tc.valid != (err == nil) {
				t.Fatalf("archive valid=%v err=%v", tc.valid, err)
			}
			if bytes.Contains(archive, []byte("secret-canary")) || bytes.Contains(archive, []byte("contact-canary")) || bytes.Contains(archive, []byte("preference-canary")) {
				t.Fatal("webmail data escaped archive encryption")
			}
		})
	}
}

// Noble's mariadb-dump rejects the mariadb client's --connect-timeout option.
// Keep the real dump/gzip/validation path while modeling that external CLI boundary.
func TestRoundcubeMySQLDumpUsesSupportedMariaDBDumpOptions(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nfor arg do\n case \"$arg\" in --connect-timeout=*) echo \"mariadb-dump: unknown variable '$arg'\" >&2; exit 7;; esac\ndone\n/bin/cat <<'SQL'\n-- MariaDB dump 10.19\nCREATE DATABASE IF NOT EXISTS `roundcube`;\nUSE `roundcube`;\nCREATE TABLE `contacts` (email TEXT);\nINSERT INTO `contacts` VALUES ('durable-contact@example.test');\nCREATE TABLE `users` (preferences TEXT);\nINSERT INTO `users` VALUES ('durable-preference');\nSQL\n"
	if err := os.WriteFile(filepath.Join(dir, "mariadb-dump"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	target := filepath.Join(dir, "roundcube.sql.gz")
	if err := DumpRoundcubeMySQL(context.Background(), *defaultRoundcubeMySQLMetadata(), target); err != nil {
		t.Fatalf("default local MySQL backup could not produce a valid dump: %v", err)
	}
	file, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	contents, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(contents, []byte("durable-contact@example.test")) || !bytes.Contains(contents, []byte("durable-preference")) {
		t.Fatal("dump archive omitted Roundcube contact or preferences")
	}
}

func TestMySQLRoundcubeForwardMigrationRejectedBeforeTargetCommands(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "commands")
	if err := os.WriteFile(filepath.Join(dir, "mariadb"), []byte("#!/bin/sh\necho called >> \"$SQL_COMMAND_LOG\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SQL_COMMAND_LOG", log)
	err := CheckRoundcubeMySQLTarget(context.Background(), Manifest{FormatVersion: 3, RoundcubeMySQL: defaultRoundcubeMySQLMetadata()}, PlatformProvenance{}, RestoreForwardMigration)
	if err == nil {
		t.Fatal("MySQL forward restore accepted")
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("unsupported forward restore ran target command")
	}
}

func TestRoundcubeMySQLRestoreUsesPrivateStdinAndDatabaseScopedAccount(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "sql.log")
	argsLog := filepath.Join(dir, "args.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SQL_ARGS_LOG\"\n/bin/cat >> \"$SQL_STDIN_LOG\"\n"
	if err := os.WriteFile(filepath.Join(dir, "mariadb"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SQL_ARGS_LOG", argsLog)
	t.Setenv("SQL_STDIN_LOG", log)
	config := mysqlRoundcubeConfig
	config = strings.Replace(config, "secret-canary", `p\'ass\\word`, 1)
	db, err := ParseRoundcubeDatabaseFiles(map[string][]byte{"debian-db.php": []byte(config)})
	if err != nil {
		t.Fatal(err)
	}
	dump := filepath.Join(dir, "dump.sql.gz")
	file, err := os.Create(dump)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	_, _ = io.WriteString(gz, "-- MariaDB dump\nCREATE DATABASE `roundcube`;\nUSE `roundcube`;\nCREATE TABLE contacts(email TEXT); INSERT INTO contacts VALUES('contact-canary@example.test');\nCREATE TABLE users(preferences TEXT); INSERT INTO users VALUES('preference-canary');\n")
	_ = gz.Close()
	_ = file.Close()
	if err := restoreRoundcubeMySQLWithOptionsParent(context.Background(), *db.MySQL, dump, db, dir, uint32(os.Geteuid())); err != nil {
		t.Fatal(err)
	}
	arguments, _ := os.ReadFile(argsLog)
	sql, _ := os.ReadFile(log)
	if bytes.Contains(arguments, []byte(`p'ass\word`)) || !bytes.Contains(arguments, []byte("--no-defaults --protocol=socket --socket=/run/mysqld/mysqld.sock --user=root")) {
		t.Fatalf("credential exposed in arguments or root socket not enforced: %s", arguments)
	}
	for _, literal := range []string{"contact-canary@example.test", "preference-canary", "SET SESSION sql_mode='NO_BACKSLASH_ESCAPES'", `IDENTIFIED BY 'p''ass\word'`, "GRANT ALL PRIVILEGES ON `roundcube`.* TO 'roundcube'@'localhost'", "DROP USER IF EXISTS 'roundcube'@'localhost'"} {
		if !bytes.Contains(sql, []byte(literal)) {
			t.Fatalf("SQL did not preserve canaries or restricted credential/grant contract: missing %q", literal)
		}
	}
	if !bytes.Contains(arguments, []byte("--user=roundcube --binary-mode --batch --local-infile=0")) {
		t.Fatal("SQL payload import lacks the scoped account/client-file isolation boundary")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".roundcube-client-*")); len(matches) != 0 {
		t.Fatal("private MySQL option directory survived restore")
	}
	if bytes.Contains(sql, []byte("GRANT ALL PRIVILEGES ON *.*")) {
		t.Fatal("restored global database privilege")
	}
}

func TestMySQLRoundcubeManifestRejectsDualBackendsAndSystemAccounts(t *testing.T) {
	for _, metadata := range []*RoundcubeMySQLMetadata{{Database: "mysql", Username: "root", Host: "localhost", ConfigPath: "/etc/roundcube/debian-db.php"}, {Database: "nakpanel", Username: "roundcube", Host: "localhost", ConfigPath: "/etc/roundcube/debian-db.php"}, {Database: "roundcube", Username: "root", Host: "localhost", ConfigPath: "/etc/roundcube/debian-db.php"}} {
		if err := validateRoundcubeManifest(Manifest{FormatVersion: 3, RoundcubeMySQL: metadata}); err == nil {
			t.Fatal("system DB/account accepted")
		}
	}
	if err := validateRoundcubeManifest(Manifest{FormatVersion: 3, RoundcubeMySQL: defaultRoundcubeMySQLMetadata(), RoundcubeSQLitePath: NativeRoundcubeSQLitePath}); err == nil {
		t.Fatal("dual backend declaration accepted")
	}
}

func TestRoundcubeFPMInspectionPreservesStoppedServiceIntent(t *testing.T) {
	for _, tc := range []struct {
		state         string
		code          int
		active, valid bool
	}{{"active", 0, true, true}, {"inactive", 3, false, true}, {"failed", 3, false, true}, {"unknown", 4, false, false}} {
		t.Run(tc.state, func(t *testing.T) {
			dir := t.TempDir()
			script := "#!/bin/sh\nprintf '" + tc.state + "\\n'\nexit " + string(rune('0'+tc.code)) + "\n"
			if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			active, err := checkRoundcubeFPMState(context.Background(), "8.3")
			if (err == nil) != tc.valid || active != tc.active {
				t.Fatalf("state=%s active=%v err=%v", tc.state, active, err)
			}
		})
	}
}

func TestMySQLRoundcubeRejectsUnknownWrapperAndActiveDSNOverride(t *testing.T) {
	for _, files := range []map[string][]byte{
		{"debian-db.php": []byte(mysqlRoundcubeConfig), "debian-db-roundcube.php": []byte(`<?php require('/etc/roundcube/debian-db.php');` + "\n" + `$config['db_dsnw'] = "mysql://remote.example.test/$dbtype";`)},
		{"debian-db.php": []byte(mysqlRoundcubeConfig), "config.inc.php": []byte(`<?php $config['db_dsnw']='mysql://roundcube:secret-canary@remote.example.test/roundcube';`)},
	} {
		if _, err := ParseRoundcubeDatabaseFiles(files); err == nil || strings.Contains(err.Error(), "secret-canary") {
			t.Fatal("custom active DSN was accepted or leaked credentials")
		}
	}
	files := map[string][]byte{"debian-db.php": []byte(mysqlRoundcubeConfig), "debian-db-roundcube.php": []byte(defaultDebianRoundcubeWrapper)}
	if got, err := ParseRoundcubeDatabaseFiles(files); err != nil || got.MySQL == nil {
		t.Fatal("observed stock Noble wrapper was rejected")
	}
}

func TestRunRestoreMySQLAuthenticatesArchiveBeforeAnyMutation(t *testing.T) {
	old := restoreEffectiveUID
	restoreEffectiveUID = func() int { return 0 }
	t.Cleanup(func() { restoreEffectiveUID = old })
	archive := makeMySQLRoundcubeArchive(t, 3, defaultRoundcubeMySQLMetadata(), 2, mysqlRoundcubeConfig)
	dir := t.TempDir()
	log := filepath.Join(dir, "commands")
	for name, script := range map[string]string{
		"mariadb":   "#!/bin/sh\necho mariadb-read >> \"$RESTORE_COMMAND_LOG\"\nprintf 'root@localhost\\t10.11.14-MariaDB\\n'\n",
		"systemctl": "#!/bin/sh\necho \"systemctl $*\" >> \"$RESTORE_COMMAND_LOG\"\nprintf 'inactive\\n'\nexit 3\n",
		"runuser":   "#!/bin/sh\necho read-schema >> \"$RESTORE_COMMAND_LOG\"\nprintf '0\\n'\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	t.Setenv("RESTORE_COMMAND_LOG", log)
	target := platformFixture("24.04")
	called := false
	_, err := RunRestore(context.Background(), RestoreOptions{TargetPlatform: &target, ReadyPHPVersions: func(context.Context) ([]string, error) { return target.HostingPHPVersions, nil }, Key: bytes.Repeat([]byte{7}, KeySize), OpenArchive: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(archive)), nil }, RoundcubeMySQLRuntimeCheck: func(_ context.Context, version string) error {
		called = true
		if version != "8.3" {
			t.Fatal("wrong target runtime")
		}
		return nil
	}})
	if err == nil || !strings.Contains(err.Error(), "duplicate") || !called {
		t.Fatalf("err=%v runtime checked=%v", err, called)
	}
	data, _ := os.ReadFile(log)
	if bytes.Contains(data, []byte("stop")) || bytes.Contains(data, []byte("start")) || bytes.Contains(data, []byte("DROP")) {
		t.Fatalf("malformed archive changed service/database state: %s", data)
	}
}

func TestRoundcubeSQLDumpRejectsWrongDatabaseAndBrokenGzip(t *testing.T) {
	for _, sql := range []string{"", "-- MariaDB dump\n", "-- MariaDB dump\nCREATE DATABASE `mysql`;\nUSE `mysql`;\n", "-- MariaDB dump\nCREATE DATABASE `roundcube`;\nUSE `other`;\n", "-- MariaDB dump\nCREATE DATABASE `roundcube`;\nUSE `roundcube`;\nGRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost';\n"} {
		path := filepath.Join(t.TempDir(), "dump.sql.gz")
		file, _ := os.Create(path)
		gz := gzip.NewWriter(file)
		_, _ = io.WriteString(gz, sql)
		_ = gz.Close()
		_ = file.Close()
		if err := validateRoundcubeSQLDump(path); err == nil {
			t.Fatal("invalid or wrong-scope SQL dump accepted")
		}
	}
}

func TestMySQLFormat3RequiresCompleteObservedProvenance(t *testing.T) {
	target := platformFixture("24.04")
	source := Manifest{FormatVersion: 3, RoundcubeMySQL: defaultRoundcubeMySQLMetadata(), Platform: ptrPlatform(platformFixture("24.04"))}
	for _, mutate := range []func(*Manifest, *PlatformProvenance){func(m *Manifest, _ *PlatformProvenance) { m.Platform = nil }, func(m *Manifest, _ *PlatformProvenance) { m.Platform.MariaDBDumpVersion = "" }, func(m *Manifest, _ *PlatformProvenance) { m.Platform.PostgresDumpVersion = "" }, func(m *Manifest, _ *PlatformProvenance) { m.Platform.Profile = "" }, func(m *Manifest, _ *PlatformProvenance) { m.Platform.PHPInventoryComplete = false }, func(_ *Manifest, p *PlatformProvenance) { p.MariaDBClientVersion = "" }} {
		copySource := source
		copyPlatform := *source.Platform
		copySource.Platform = &copyPlatform
		copyTarget := target
		mutate(&copySource, &copyTarget)
		if err := CheckRestoreCompatibility(copySource, copyTarget, RestoreSamePlatform); err == nil {
			t.Fatal("new format inherited incomplete legacy provenance exemption")
		}
	}
	if err := CheckRestoreCompatibility(Manifest{FormatVersion: 1}, target, RestoreSamePlatform); err != nil {
		t.Fatalf("legacy format 1 behavior changed: %v", err)
	}
}

func TestRoundcubeSQLRejectsWhitespaceForeignCommandAndMissingSchema(t *testing.T) {
	for _, sql := range []string{"-- MariaDB dump\nCREATE DATABASE `roundcube`;\nUSE `roundcube`;\n", "-- MariaDB dump\nCREATE DATABASE `roundcube`;\nUSE `roundcube`;\nCREATE TABLE users(preferences TEXT);\nCREATE TABLE contacts(email TEXT);\n DROP DATABASE `foreign_database`;\n"} {
		path := filepath.Join(t.TempDir(), "dump.sql.gz")
		file, _ := os.Create(path)
		gz := gzip.NewWriter(file)
		_, _ = io.WriteString(gz, sql)
		_ = gz.Close()
		_ = file.Close()
		if err := validateRoundcubeSQLDump(path); err == nil {
			t.Fatal("empty schema or whitespace foreign database command accepted")
		}
	}
}

func TestMySQLArchiveRejectsAliasedProtectedConfigurationBeforeRestore(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	raw := makeMySQLRoundcubeArchive(t, 3, defaultRoundcubeMySQLMetadata(), 1, mysqlRoundcubeConfig)
	reader, err := NewArchiveReader(bytes.NewReader(raw), key)
	if err != nil {
		t.Fatal(err)
	}
	var rewritten bytes.Buffer
	writer, _ := NewArchiveWriter(&rewritten, key)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(reader)
		if err = writer.AddBytes(header.Name, data, header.Mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.AddBytes("files/etc/roundcube/./debian-db.php", []byte("<?php\n$dbtype='mysql';\n$dbname='mysql';\n$dbuser='root';\n$dbpass='secret-canary';\n"), 0640); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	if err := CheckArchiveIntegrity(bytes.NewReader(rewritten.Bytes()), key); err == nil {
		t.Fatal("aliased protected configuration was authenticated for destructive extraction")
	}
}

func TestRoundcubeOverrideDetectionHandlesWhitespaceAndStatementPositions(t *testing.T) {
	for _, code := range []string{`<?php $config [ 'db_dsnw' ] = 'mysql://root:secret-canary@localhost/mysql';`, `<?php $config['other']=true; $config['db_dsnw']='mysql://root:secret-canary@localhost/mysql';`} {
		if _, err := ParseRoundcubeDatabaseFiles(map[string][]byte{"debian-db.php": []byte(mysqlRoundcubeConfig), "config.inc.php": []byte(code)}); err == nil || strings.Contains(err.Error(), "secret-canary") {
			t.Fatal("active override ignored or credential leaked")
		}
	}
	for _, code := range []string{"<?php\n// $config['db_dsnw']='example';\n", "<?php\n/* $config [ 'db_dsnw' ] = 'example'; */\n"} {
		if _, err := ParseRoundcubeDatabaseFiles(map[string][]byte{"debian-db.php": []byte(mysqlRoundcubeConfig), "config.inc.php": []byte(code)}); err != nil {
			t.Fatalf("commented example rejected: %v", err)
		}
	}
}

func TestObservedLegacyNobleProfileCanProduceRestorableMySQLBackup(t *testing.T) {
	for _, actual := range []struct {
		os, version, codename, php string
		profile                    string
	}{{"ubuntu", "24.04", "noble", "8.3", "ubuntu-24.04"}, {"ubuntu", "24.04", "noble", "8.5", ""}, {"ubuntu", "26.04", "resolute", "8.3", ""}} {
		observed, err := collectPlatform(context.Background(), "test", platformProbe{readFile: func(path string) ([]byte, error) {
			if path == "/etc/os-release" {
				return []byte("ID=" + actual.os + "\nVERSION_ID=" + actual.version + "\nVERSION_CODENAME=" + actual.codename + "\n"), nil
			}
			return nil, os.ErrNotExist
		}, command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "php8.3" {
				return []byte(actual.php), nil
			}
			return nil, os.ErrNotExist
		}})
		if err != nil || observed.Profile != actual.profile {
			t.Fatalf("observed profile=%q wanted=%q err=%v", observed.Profile, actual.profile, err)
		}
	}
}

func TestRoundcubePrivateClientOptionsCleanedAfterFailureAndCancellation(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancelled=%t", cancelled), func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "app-started")
			action := "exit 19"
			if cancelled {
				action = "exec /bin/sleep 10"
			}
			script := "#!/bin/sh\ncase \"$*\" in *--user=roundcube*) echo started > \"$APP_MARKER\"; " + action + ";; *) /bin/cat >/dev/null;; esac\n"
			if err := os.WriteFile(filepath.Join(dir, "mariadb"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			t.Setenv("APP_MARKER", marker)
			db, err := ParseRoundcubeDatabaseFiles(map[string][]byte{"debian-db.php": []byte(mysqlRoundcubeConfig)})
			if err != nil {
				t.Fatal(err)
			}
			dump := filepath.Join(dir, "dump.sql.gz")
			file, _ := os.Create(dump)
			gz := gzip.NewWriter(file)
			_, _ = io.WriteString(gz, "-- MariaDB dump\nCREATE DATABASE `roundcube`;\nUSE `roundcube`;\nCREATE TABLE users(preferences TEXT);\nCREATE TABLE contacts(email TEXT);\n")
			_ = gz.Close()
			_ = file.Close()
			ctx := context.Background()
			if cancelled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
				defer cancel()
			}
			err = restoreRoundcubeMySQLWithOptionsParent(ctx, *db.MySQL, dump, db, dir, uint32(os.Geteuid()))
			if err == nil || strings.Contains(err.Error(), "secret-canary") {
				t.Fatal("failed import was hidden or leaked password")
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("did not reach private credential import boundary: %v", err)
			}
			if files, _ := filepath.Glob(filepath.Join(dir, ".roundcube-client-*")); len(files) != 0 {
				t.Fatal("private option directory survived failed/cancelled import")
			}
		})
	}
}

func TestRoundcubePrivateClientOptionsRequireControlledParent(t *testing.T) {
	for _, kind := range []string{"writable", "symlink", "foreign-owner"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			owner := uint32(os.Geteuid())
			if kind == "writable" {
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "symlink" {
				link := filepath.Join(t.TempDir(), "parent")
				if err := os.Symlink(parent, link); err != nil {
					t.Fatal(err)
				}
				parent = link
			}
			if kind == "foreign-owner" {
				owner++
			}
			if path, dir, err := createRoundcubeMySQLClientOptions(parent, "secret-canary", owner); err == nil {
				defer os.RemoveAll(dir)
				t.Fatalf("untrusted credential parent accepted path=%q", path)
			}
		})
	}
}

func TestPresentRoundcubeDatabaseConfigurationCannotBeSilentlyOmitted(t *testing.T) {
	for _, data := range []string{"<?php $dbtype='mysql'; $dbserver='localhost'; $dbport='3306'; $dbname='roundcube'; $dbuser='roundcube'; $dbpass='secret-canary';", "<?php\n$dbuser='roundcube';\n$dbpass='secret-canary';\n", "", "<?php\n// no database backend configured\n"} {
		got, err := ParseRoundcubeDatabaseFiles(map[string][]byte{"debian-db.php": []byte(data)})
		if err == nil && got.MySQL == nil && got.SQLitePath == "" {
			t.Fatal("present database configuration was silently omitted")
		}
		if err != nil && strings.Contains(err.Error(), "secret-canary") {
			t.Fatal("unsupported config diagnostic leaked credentials")
		}
	}
	for _, files := range []map[string][]byte{{"debian-db-roundcube.php": {}}, {"debian-db-roundcube.php": []byte(defaultDebianRoundcubeWrapper)}, {"config.inc.php": []byte(`<?php $config['db_dsnw']='mysql://root:secret-canary@localhost/mysql';`)}} {
		if _, err := ParseRoundcubeDatabaseFiles(files); err == nil {
			t.Fatal("present wrapper or active database configuration was silently omitted")
		}
	}
	if got, err := ParseRoundcubeDatabaseFiles(map[string][]byte{}); err != nil || got.MySQL != nil || got.SQLitePath != "" {
		t.Fatalf("genuinely absent optional Roundcube rejected: %v", err)
	}
}
