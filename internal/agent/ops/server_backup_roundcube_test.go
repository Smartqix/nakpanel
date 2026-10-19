package ops

import (
	"bufio"
	"context"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/backup"
	"github.com/nakroteck/nakpanel/internal/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRoundcubeSQLiteDiscoveryNativeAndNoble(t *testing.T) {
	for _, tc := range []struct{ name, file, contents, want string }{
		{"native", "debian-db-roundcube.php", "<?php\n$config['db_dsnw'] = 'sqlite:////var/lib/roundcube/roundcube.sqlite';\n", "/var/lib/roundcube/roundcube.sqlite"},
		{"noble", "debian-db.php", "<?php\n$dbtype='sqlite3';\n$dbbasepath='/var/lib/roundcube/db';\n$dbname='roundcube';\n", "/var/lib/roundcube/db/roundcube"},
		{"legacy dbconfig", "debian-db.php", "<?php\n$dbtype='sqlite3';\n$basepath='/var/lib/dbconfig-common/sqlite3/roundcube';\n$dbname='roundcube';\n", "/var/lib/dbconfig-common/sqlite3/roundcube/roundcube"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.contents), 0600); err != nil {
				t.Fatal(err)
			}
			database, err := backup.ReadRoundcubeDatabase(dir, uint32(os.Geteuid()))
			got := database.SQLitePath
			if err != nil || got != tc.want {
				t.Fatalf("got=%q err=%v want=%q", got, err, tc.want)
			}
		})
	}
}
func TestRoundcubeSQLiteSnapshotKeepsLiveContactsAndPreferences(t *testing.T) {
	binary, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("sqlite3 not installed")
	}
	dir := t.TempDir()
	source, dest := filepath.Join(dir, "live.sqlite"), filepath.Join(dir, "snapshot.sqlite")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	live := exec.CommandContext(ctx, binary, source)
	stdin, err := live.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := live.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); _ = live.Wait() })
	sql := `PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE users(user_id INTEGER PRIMARY KEY, preferences TEXT); CREATE TABLE contacts(contact_id INTEGER PRIMARY KEY,user_id INT,email TEXT); INSERT INTO users VALUES(1,'a:1:{s:6:"canary";s:8:"retained";}'); INSERT INTO contacts VALUES(1,1,'friend@example.test');`
	if _, err := fmt.Fprintln(stdin, sql+"\n.print ready"); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	ready := false
	for scanner.Scan() {
		if scanner.Text() == "ready" {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("live SQLite fixture did not become ready")
	}
	if wal, err := os.Stat(source + "-wal"); err != nil || wal.Size() == 0 {
		t.Fatalf("fixture has no uncheckpointed WAL: %v", err)
	}
	mainOnly, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mainOnly), "friend@example.test") {
		t.Fatal("fixture checkpointed contact into main file; raw-copy regression would not be detected")
	}
	if err := snapshotRoundcubeSQLite(context.Background(), source, dest); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(binary, "-readonly", dest, "SELECT preferences||'|'||email FROM users JOIN contacts USING(user_id); PRAGMA quick_check;").CombinedOutput(); err != nil || !strings.Contains(string(out), "retained") || !strings.Contains(string(out), "friend@example.test") || !strings.Contains(string(out), "ok") {
		t.Fatalf("lost contacts/preferences: %s err=%v", out, err)
	}
}

func TestRoundcubeBackupRejectsConfiguredNonSQLiteWithoutLeakingCredentials(t *testing.T) {
	for _, tc := range []struct{ name, file, contents string }{
		{"dbconfig mysql", "debian-db.php", "<?php\n$dbtype='mysql';\n$dbpass='secret-canary';\n"},
		{"dsn mysql", "debian-db-roundcube.php", "<?php\n$config['db_dsnw']='mysql://user:secret-canary@localhost/roundcube';\n"},
		{"dsn postgres", "debian-db-roundcube.php", "<?php\n$config['db_dsnw']='pgsql://user:secret-canary@localhost/roundcube';\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.contents), 0600); err != nil {
				t.Fatal(err)
			}
			database, err := backup.ReadRoundcubeDatabase(dir, uint32(os.Geteuid()))
			got := database.SQLitePath
			if err == nil || !strings.Contains(err.Error(), "Roundcube") {
				t.Fatalf("got=%q err=%v; unsupported configured storage must never be omitted", got, err)
			}
			if strings.Contains(err.Error(), "secret-canary") {
				t.Fatal("diagnostic leaked database credentials")
			}
		})
	}
}

func TestUnsupportedRoundcubeBackupFailsBeforeSpoolOrExternalCommands(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "roundcube")
	if err := os.Mkdir(config, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config, "debian-db.php"), []byte("<?php\n$dbtype='pgsql';\n"), 0600); err != nil {
		t.Fatal(err)
	}
	commandLog := filepath.Join(dir, "commands")
	for _, name := range []string{"pg_dump", "mariadb-dump", "systemctl", "runuser", "php8.3", "php8.5"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\necho called >> \"$BACKUP_COMMAND_LOG\"\nexit 19\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	t.Setenv("BACKUP_COMMAND_LOG", commandLog)
	spool := filepath.Join(dir, "spool")
	p := NewServerBackupProvisioner(ServerBackupProvisionerOptions{SpoolDir: spool})
	p.roundcubeConfigDir = config
	p.roundcubeConfigOwnerUID = uint32(os.Geteuid())
	_, err := p.CreateServerBackup(context.Background(), types.CreateServerBackupReq{ArchiveKey: make([]byte, 32), Destination: types.BackupDestinationSpec{Kind: "local", Settings: []byte(fmt.Sprintf(`{"dir":%q}`, filepath.Join(dir, "destination")))}, IncludeMailData: true, TenantDatabases: []string{"tenant"}})
	if err == nil || !strings.Contains(err.Error(), "Roundcube") {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Stat(commandLog); !os.IsNotExist(err) {
		t.Fatal("ran a dump, platform probe or service command before rejecting webmail backend")
	}
	if _, err := os.Stat(spool); !os.IsNotExist(err) {
		t.Fatal("created spool state before rejecting webmail backend")
	}
}
