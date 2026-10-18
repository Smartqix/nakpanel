package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundcubeDRCanaryUsesRealContactAndPreferenceSchema(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("PHP CLI required for Roundcube fixture test")
	}
	if err := exec.Command(php, "-r", `exit(class_exists('SQLite3')?0:1);`).Run(); err != nil {
		t.Skip("PHP SQLite3 required")
	}
	helper, err := filepath.Abs("roundcube-dr-canary.php")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	database := filepath.Join(dir, "roundcube.sqlite")
	source := `require $argv[1];
$db=new SQLite3($argv[2]);
$db->exec("CREATE TABLE users(user_id INTEGER PRIMARY KEY, username TEXT, mail_host TEXT, created TEXT, last_login TEXT, language TEXT, preferences TEXT); CREATE TABLE contacts(contact_id INTEGER PRIMARY KEY, user_id INTEGER, changed TEXT, del INTEGER, name TEXT, email TEXT, firstname TEXT, surname TEXT, vcard TEXT, words TEXT)");
$db->exec("INSERT INTO users(user_id,username,preferences) VALUES (1,'phase29@example.test',NULL)");
$db->close();
roundcube_canary($argv[2], 'phase29@example.test', true);
roundcube_canary($argv[2], 'phase29@example.test', false);
$db=new SQLite3($argv[2]);$db->exec('DELETE FROM contacts');$db->close();
try { roundcube_canary($argv[2], 'phase29@example.test', false); exit(77); } catch (RuntimeException $e) { if (!str_contains($e->getMessage(), 'contact did not survive')) throw $e; }
try { roundcube_canary($argv[2].'.absent', 'phase29@example.test', false); exit(78); } catch (RuntimeException $e) { if (!str_contains($e->getMessage(), 'fixture is missing')) throw $e; }
`
	if out, err := exec.Command(php, "-r", source, helper, database).CombinedOutput(); err != nil {
		t.Fatalf("Roundcube canary: %s %v", out, err)
	}
	for _, kind := range []string{"debian", "native", "legacy"} {
		native := kind == "native"
		config := filepath.Join(dir, kind)
		if native {
			config = filepath.Join(dir, "native")
		}
		if err := os.Mkdir(config, 0700); err != nil {
			t.Fatal(err)
		}
		file, content := "debian-db.php", `<?php $dbtype='sqlite3'; $dbbasepath='/var/lib/roundcube/db'; $dbname='roundcube';`
		want := "/var/lib/roundcube/db/roundcube"
		if kind == "legacy" {
			content = `<?php $dbtype='sqlite3'; $basepath='/var/lib/dbconfig-common/sqlite3/roundcube'; $dbname='roundcube';`
			want = "/var/lib/dbconfig-common/sqlite3/roundcube/roundcube"
		}
		if native {
			file = "debian-db-roundcube.php"
			content = `<?php $config['db_dsnw']='sqlite:////var/lib/roundcube/roundcube.sqlite';`
			want = "/var/lib/roundcube/roundcube.sqlite"
		}
		if err := os.WriteFile(filepath.Join(config, file), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(php, "-r", `require $argv[1];echo roundcube_database_path($argv[2]);`, helper, config).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != want {
			t.Fatalf("configured Roundcube path: %s %v", out, err)
		}
	}
}
