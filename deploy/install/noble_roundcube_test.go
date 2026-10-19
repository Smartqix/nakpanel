package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests execute both package-install stages. Selecting SQLite only in
// phase 18 is too late: roundcube-core already creates its database in phase 7.
func TestNobleRoundcubeFreshSelectionPrecedesFirstPackageInstall(t *testing.T) {
	result := runNobleRoundcubePackageStages(t, "fresh", "")
	if result.database != "sqlite3" {
		t.Fatalf("first install initialized %q, want sqlite3; events:\n%s", result.database, result.events)
	}
	lines := strings.Split(result.events, "\n")
	selected, provider := false, false
	for _, line := range lines {
		if strings.Contains(line, "database-type select sqlite3") {
			selected = true
		}
		if strings.HasPrefix(line, "install ") && strings.Contains(line, " roundcube ") {
			provider = strings.Contains(line, " roundcube-sqlite3 ")
			if !selected || !provider {
				t.Fatalf("first Roundcube install lacked SQLite selection/provider: %s", result.events)
			}
			break
		}
	}
	if !selected || !provider {
		t.Fatalf("Roundcube install not exercised: %s", result.events)
	}
	if strings.Contains(result.events, "reconfigure") {
		t.Fatalf("fresh install forced reconfiguration: %s", result.events)
	}
}

func TestNobleRoundcubeExistingConfigurationIsPreserved(t *testing.T) {
	for _, kind := range []string{"mysql", "sqlite3", "custom", "dbconfig", "data", "installed", "residual", "debconf", "declined"} {
		t.Run(kind, func(t *testing.T) {
			result := runNobleRoundcubePackageStages(t, kind, "")
			if strings.Contains(result.events, "selection ") || strings.Contains(result.events, "reconfigure") {
				t.Fatalf("existing %s configuration was changed: %s", kind, result.events)
			}
			if result.database != "preserved" {
				t.Fatalf("existing database was replaced: %q", result.database)
			}
		})
	}
}

func TestNobleRoundcubePreseedFailureStopsBeforePackageInstallation(t *testing.T) {
	result := runNobleRoundcubePackageStages(t, "fresh", "preseed-failure")
	if result.err == nil {
		t.Fatalf("failed preseed accepted: %s", result.events)
	}
	if strings.HasPrefix(result.events, "install ") || strings.Contains(result.events, "\ninstall ") {
		t.Fatalf("packages installed after failed preseed: %s", result.events)
	}
}

func TestNobleRoundcubeMetadataFailureStopsBeforePackageInstallation(t *testing.T) {
	result := runNobleRoundcubePackageStages(t, "fresh", "metadata-failure")
	if result.err == nil {
		t.Fatalf("unreadable configuration treated as a fresh host: %s", result.events)
	}
	if strings.HasPrefix(result.events, "install ") || strings.Contains(result.events, "\ninstall ") {
		t.Fatalf("packages installed after failed configuration read: %s", result.events)
	}
}

func TestNobleRoundcubeSourceHasNoExternalEffects(t *testing.T) {
	output, err := exec.Command("bash", "-c", `debconf-communicate(){ echo unexpected;return 99; }; dpkg-query(){ echo unexpected;return 99; }; source ./noble-roundcube.sh`).CombinedOutput()
	if err != nil || len(output) != 0 {
		t.Fatalf("helper source caused external effects: %v: %s", err, output)
	}
}

type nobleRoundcubeResult struct {
	events, database string
	err              error
}

func runNobleRoundcubePackageStages(t *testing.T, kind, failure string) nobleRoundcubeResult {
	t.Helper()
	root := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	switch kind {
	case "mysql", "sqlite3":
		write("etc/roundcube/debian-db.php", "<?php $dbtype='"+kind+"'; /* preserve credentials */\n")
	case "custom":
		write("etc/roundcube/config.inc.php", "<?php $config['db_dsnw']='pgsql://custom:secret@db.example/webmail';\n")
	case "dbconfig":
		write("etc/dbconfig-common/roundcube.conf", "dbc_dbtype='mysql'\ndbc_dbpass='keep-me'\n")
	case "data":
		write("var/lib/roundcube/custom.db", "existing database bytes\n")
	}
	if kind != "fresh" {
		write("database", "preserved")
	}
	if kind == "installed" {
		write("package-status", "installed")
	}
	if kind == "residual" {
		write("package-status", "config-files")
	}
	if kind == "debconf" {
		write("selections/roundcube/database-type", "pgsql")
	}
	if kind == "declined" {
		write("selections/roundcube/dbconfig-install", "false")
	}
	// The real Noble maintainer script supplies the namespace to dbc_go. Run it
	// with its external debconf/dbconfig libraries replaced at their boundaries;
	// a fake that accepts any question suffix would miss roundcube-core/* typos.
	config, err := os.ReadFile("testdata/roundcube-core-1.6.6.config")
	if err != nil {
		t.Fatal(err)
	}
	config = []byte(strings.NewReplacer("/usr/share/debconf/confmodule", root+"/confmodule", "/usr/share/dbconfig-common/dpkg/config", root+"/dbconfig").Replace(string(config)))
	write("roundcube-core.config", string(config))
	write("confmodule", `db_input(){ :; }; db_go(){ :; };`)
	write("dbconfig", `dbc_go(){
 local namespace="$1" value=mysql
 if [[ "$FIXTURE_HAS_SQLITE_PROVIDER" == 1 && -e "$FIXTURE/selections/$namespace/database-type" ]]; then value="$(cat "$FIXTURE/selections/$namespace/database-type")";fi
 printf '%s' "$value" > "$FIXTURE/database"
}`)
	original := map[string][]byte{}
	for _, name := range []string{"etc/roundcube/debian-db.php", "etc/roundcube/config.inc.php", "etc/dbconfig-common/roundcube.conf", "var/lib/roundcube/custom.db"} {
		if data, err := os.ReadFile(filepath.Join(root, name)); err == nil {
			original[name] = data
		}
	}
	// Relocate only filesystem paths in a private copy; execute the production
	// shell logic unchanged, with apt/debconf/dpkg as the external boundaries.
	if helper, err := os.ReadFile("noble-roundcube.sh"); err == nil {
		helper = []byte(strings.NewReplacer("/etc/roundcube", root+"/etc/roundcube", "/etc/dbconfig-common/roundcube.conf", root+"/etc/dbconfig-common/roundcube.conf", "/var/lib/roundcube", root+"/var/lib/roundcube").Replace(string(helper)))
		write("noble-roundcube.sh", string(helper))
	}
	stage7, err := os.ReadFile("phase7-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	phase7 := string(stage7)
	start := strings.Index(phase7, "apt-get update")
	end := strings.Index(phase7, "bash \"${SCRIPT_DIR}/nginx-server-names-install.sh\"")
	if start < 0 || end < start {
		t.Fatal("phase7 package boundary missing")
	}
	stage18, err := os.ReadFile("phase18-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	phase18 := string(stage18)
	start18 := strings.Index(phase18, "export DEBIAN_FRONTEND=noninteractive")
	end18 := strings.Index(phase18, "# Roundcube may pull")
	if start18 < 0 || end18 < start18 {
		t.Fatal("phase18 package boundary missing")
	}
	script := `set -euo pipefail
SCRIPT_DIR="$FIXTURE"
NAKPANEL_PLATFORM_ID=ubuntu-24.04
NAKPANEL_INTERNAL_PHP_VERSION=8.3
NAKPANEL_POSTGRES_PACKAGES=(postgresql postgresql-contrib)
apt-get(){
 printf '%s \n' "$*" >> "$FIXTURE/events"
 if [[ "$*" == *'install '* && " $* " == *' roundcube '* && ! -e "$FIXTURE/database" ]]; then
  FIXTURE_HAS_SQLITE_PROVIDER=0
  if [[ " $* " == *' roundcube-sqlite3 '* ]]; then FIXTURE_HAS_SQLITE_PROVIDER=1;fi
  export FIXTURE_HAS_SQLITE_PROVIDER
  DPKG_MAINTSCRIPT_NAME=config bash "$FIXTURE/roundcube-core.config" configure
  mkdir -p "$FIXTURE/etc/roundcube"
  printf '%s' 'configured by package' > "$FIXTURE/etc/roundcube/debian-db.php"
 fi
 if [[ "$*" == *'install '* && " $* " == *' roundcube '* ]]; then echo installed > "$FIXTURE/package-status"; fi
}
debconf-set-selections(){
 local input owner question type value;input="$(cat)";printf 'selection %s\n' "$input" >> "$FIXTURE/events"
 [[ "$FAILURE" != preseed-failure ]] || return 73
 while read -r owner question type value;do
  mkdir -p "$FIXTURE/selections/$(dirname "$question")"
  printf '%s' "$value" > "$FIXTURE/selections/$question"
 done <<<"$input"
}
debconf-communicate(){
 local operation question;read -r operation question
 if [[ "$FAILURE" == metadata-failure ]]; then echo '20 database unavailable';return 20;fi
 if [[ -e "$FIXTURE/selections/$question" ]]; then printf '0 %s\n' "$(cat "$FIXTURE/selections/$question")"; else echo '10 question does not exist';return 10;fi
}
dpkg-query(){ if [[ -f "$FIXTURE/package-status" ]]; then cat "$FIXTURE/package-status";else return 1;fi; }
dpkg-reconfigure(){ echo reconfigure >> "$FIXTURE/events";return 2; }
` + phase7[start:end] + "\n" + phase18[start18:end18]
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "FIXTURE="+root, "FAILURE="+failure)
	output, runErr := cmd.CombinedOutput()
	if runErr != nil && failure == "" {
		t.Fatalf("package stages failed: %v: %s", runErr, output)
	}
	for name, before := range original {
		after, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(after) != string(before) {
			t.Fatalf("existing %s changed: %q -> %q (%v)", name, before, after, err)
		}
	}
	events, _ := os.ReadFile(filepath.Join(root, "events"))
	database, _ := os.ReadFile(filepath.Join(root, "database"))
	return nobleRoundcubeResult{events: string(events), database: string(database), err: runErr}
}
