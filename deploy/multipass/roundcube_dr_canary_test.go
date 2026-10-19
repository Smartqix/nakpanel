package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundcubeDRCanaryNewUserIdentityTransaction(t *testing.T) {
	// Register the subprocess input with Go's test cache as well as executing it.
	if _, err := os.ReadFile("roundcube-dr-canary.php"); err != nil {
		t.Fatal(err)
	}
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("PHP CLI required for Roundcube fixture test")
	}
	if err := exec.Command(php, "-r", `exit(in_array('sqlite',PDO::getAvailableDrivers(),true)?0:1);`).Run(); err != nil {
		t.Skip("real PDO SQLite required for Roundcube identity behavior")
	}
	helper, err := filepath.Abs("roundcube-dr-canary.php")
	if err != nil {
		t.Fatal(err)
	}
	// The identity columns follow Roundcube's SQLite/MySQL schemas. In
	// particular, name/email have no default, as required by MySQL; SQLite
	// execution here is not a claim of running a MySQL server or its NOW().
	setup := `require $argv[1];
function check_fixture($condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
}
function identities(PDO $db): array {
    return $db->query('SELECT * FROM identities ORDER BY identity_id')->fetchAll(PDO::FETCH_ASSOC);
}
function forbid_identity_writes(PDO $db): void {
    foreach (['INSERT','UPDATE','DELETE'] as $operation) {
        $db->exec("CREATE TRIGGER identity_no_$operation BEFORE $operation ON identities BEGIN SELECT RAISE(ABORT, 'existing identities changed'); END");
    }
}
function fixture_state(PDO $db): array {
    $state=[];
    foreach (['users','contacts','identities'] as $table) $state[$table]=$db->query("SELECT * FROM $table ORDER BY 1")->fetchAll(PDO::FETCH_ASSOC);
    return $state;
}
$db=new PDO('sqlite:'.$argv[2],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
$db->exec("CREATE TABLE users(user_id INTEGER PRIMARY KEY, username VARCHAR(128) NOT NULL, mail_host VARCHAR(128) NOT NULL, created TEXT NOT NULL, last_login TEXT, language VARCHAR(16), preferences TEXT, UNIQUE(username,mail_host));
CREATE TABLE contacts(contact_id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(user_id), changed TEXT NOT NULL, del INTEGER NOT NULL DEFAULT 0, name VARCHAR(128) NOT NULL, email TEXT NOT NULL, firstname VARCHAR(128) NOT NULL, surname VARCHAR(128) NOT NULL, vcard TEXT, words TEXT);
CREATE TABLE identities(identity_id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(user_id), changed TEXT NOT NULL, del INTEGER NOT NULL DEFAULT 0, standard INTEGER NOT NULL DEFAULT 0, name VARCHAR(128) NOT NULL, organization VARCHAR(128) NOT NULL DEFAULT '', email VARCHAR(128) NOT NULL, \"reply-to\" VARCHAR(128) NOT NULL DEFAULT '', bcc VARCHAR(128) NOT NULL DEFAULT '', signature TEXT, html_signature INTEGER NOT NULL DEFAULT 0);");
`
	for _, tc := range []struct{ name, body string }{
		{"new-user-and-repeat", `
roundcube_canary($argv[2], 'phase29@example.test', true);
$user=$db->query('SELECT * FROM users')->fetch(PDO::FETCH_ASSOC);
$rows=identities($db);
check_fixture(count($rows)===1, 'new fixture user has no single default identity');
check_fixture($rows[0]['user_id']===$user['user_id'] && $rows[0]['email']==='phase29@example.test' && $rows[0]['name']==='' && $rows[0]['del']===0 && $rows[0]['standard']===1 && $rows[0]['changed']!=='', 'new identity does not match active default self sender');
check_fixture($user['mail_host']==='127.0.0.1', 'seeded user host differs from application login');
forbid_identity_writes($db);
roundcube_canary($argv[2], 'phase29@example.test', true);
check_fixture(identities($db)===$rows, 'repeated seed changed identity bytes');
check_fixture((int)$db->query('SELECT count(*) FROM users')->fetchColumn()===1, 'repeated seed duplicated user');
check_fixture((int)$db->query('SELECT count(*) FROM contacts')->fetchColumn()===1, 'repeated seed duplicated contact');
roundcube_canary($argv[2], 'phase29@example.test', false);
`},
		{"preserve-preexisting-identities", `
$db->exec("INSERT INTO users VALUES(17,'phase29@example.test','127.0.0.1','2020-01-01',NULL,'en_US','a:0:{}');
INSERT INTO identities VALUES(23,17,'2020-01-01',0,0,'Custom Sender','Private Organization','alias@example.test','reply@example.test','copy@example.test','keep signature',1);
INSERT INTO identities VALUES(24,17,'2020-01-02',0,1,'Own Name','','phase29@example.test','','','keep plain signature',0);
INSERT INTO identities VALUES(25,17,'2020-01-03',1,0,'Deleted Name','','retired@example.test','','','keep deleted signature',0);");
$before=identities($db);
forbid_identity_writes($db);
roundcube_canary($argv[2], 'phase29@example.test', true);
roundcube_canary($argv[2], 'phase29@example.test', false);
check_fixture(identities($db)===$before, 'existing active/deleted identities were rewritten');
`},
		{"preserve-preexisting-identity-free-user", `
$db->exec("INSERT INTO users VALUES(17,'phase29@example.test','127.0.0.1','2020-01-01',NULL,'en_US','a:0:{}')");
forbid_identity_writes($db);
roundcube_canary($argv[2], 'phase29@example.test', true);
roundcube_canary($argv[2], 'phase29@example.test', false);
check_fixture(identities($db)===[], 'preexisting user was silently repaired');
`},
		{"assert-mode-never-writes", `
roundcube_canary($argv[2], 'phase29@example.test', true);
$before=fixture_state($db);
foreach (['users','contacts','identities'] as $table) foreach (['INSERT','UPDATE','DELETE'] as $operation) {
    $db->exec("CREATE TRIGGER no_{$table}_$operation BEFORE $operation ON $table BEGIN SELECT RAISE(ABORT, 'assert mode wrote database'); END");
}
roundcube_canary($argv[2], 'phase29@example.test', false);
check_fixture(fixture_state($db)===$before, 'assert mode changed database contents');
`},
		{"assert-missing-user-never-creates-one", `
$rejected=false;
try { roundcube_canary($argv[2], 'phase29@example.test', false); }
catch (RuntimeException $error) { $rejected=str_contains($error->getMessage(), 'user is missing'); }
check_fixture($rejected, 'assert mode accepted missing user');
check_fixture(fixture_state($db)===['users'=>[],'contacts'=>[],'identities'=>[]], 'assert mode created fixture data');
`},
		{"identity-failure-rolls-back-new-user", `
$db->exec("CREATE TRIGGER fail_identity BEFORE INSERT ON identities BEGIN SELECT RAISE(ABORT, 'fixture identity insert failure'); END");
$rejected=false;
try { roundcube_canary($argv[2], 'phase29@example.test', true); }
catch (PDOException $error) { $rejected=str_contains($error->getMessage(), 'fixture identity insert failure'); }
check_fixture($rejected, 'identity insertion failure did not fail fixture seed');
check_fixture(fixture_state($db)===['users'=>[],'contacts'=>[],'identities'=>[]], 'failed identity left a partial user/contact');
`},
		{"later-contact-failure-rolls-back-user-and-identity", `
$db->exec("CREATE TRIGGER fail_contact BEFORE INSERT ON contacts BEGIN SELECT RAISE(ABORT, 'fixture contact insert failure'); END");
$rejected=false;
try { roundcube_canary($argv[2], 'phase29@example.test', true); }
catch (PDOException $error) { $rejected=str_contains($error->getMessage(), 'fixture contact insert failure'); }
check_fixture($rejected, 'contact insertion failure did not fail fixture seed');
check_fixture(fixture_state($db)===['users'=>[],'contacts'=>[],'identities'=>[]], 'later failure left partial identity data');
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := filepath.Join(t.TempDir(), "roundcube.sqlite")
			if output, err := exec.Command(php, "-r", setup+tc.body, helper, database).CombinedOutput(); err != nil {
				t.Fatalf("real PDO SQLite identity behavior: %v\n%s", err, output)
			}
		})
	}
}

func TestRoundcubeDRCanaryUsesRealContactAndPreferenceSchema(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("PHP CLI required for Roundcube fixture test")
	}
	if err := exec.Command(php, "-r", `exit((class_exists('SQLite3') && in_array('sqlite',PDO::getAvailableDrivers(),true))?0:1);`).Run(); err != nil {
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
		out, err := exec.Command(php, "-r", `require $argv[1];echo roundcube_database_path($argv[2], posix_geteuid());`, helper, config).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != want {
			t.Fatalf("configured Roundcube path: %s %v", out, err)
		}
	}
}

func TestRoundcubeDRCanaryDetectsDefaultLocalMySQLWithoutExecutingPHP(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("PHP CLI required")
	}
	helper, err := filepath.Abs("roundcube-dr-canary.php")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	wrapper := `<?php
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
?>
`
	config := "<?php\n$dbtype='mysql';\n$dbserver='localhost';\n$dbport='3306';\n$dbname='roundcube';\n$dbuser='roundcube';\n$dbpass='secret-canary';\nfile_put_contents('" + marker + "','executed');\n"
	for name, data := range map[string]string{"debian-db.php": config, "debian-db-roundcube.php": wrapper} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	code := `require $argv[1];$db=roundcube_database_config($argv[2],posix_geteuid());if($db['backend']!=='mysql'||$db['username']!=='roundcube'||$db['database']!=='roundcube'||$db['password']!=='secret-canary')exit(17);echo $db['backend'];`
	out, err := exec.Command(php, "-r", code, helper, dir).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "mysql" {
		t.Fatalf("default MySQL discovery failed: %s %v", out, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("database configuration executed PHP")
	}
	if strings.Contains(string(out), "secret-canary") {
		t.Fatal("database credential printed")
	}
	if err := os.WriteFile(filepath.Join(dir, "debian-db-roundcube.php"), []byte("<?php require('/etc/roundcube/debian-db.php');\n$config['db_dsnw'] = \"mysql://remote.example.test/$dbtype\";"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err = exec.Command(php, "-r", `require $argv[1];try{roundcube_database_config($argv[2],posix_geteuid());exit(18);}catch(RuntimeException $e){echo 'rejected';}`, helper, dir).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "rejected" {
		t.Fatalf("custom active database wrapper was accepted: %s %v", out, err)
	}
}
