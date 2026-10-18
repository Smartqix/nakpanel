package ops

import (
	"bufio"
	"context"
	"fmt"
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
		{"maria", "debian-db.php", "<?php\n$dbtype='mysql';\n$dbname='roundcube';\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.contents), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := roundcubeSQLitePath(dir)
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
