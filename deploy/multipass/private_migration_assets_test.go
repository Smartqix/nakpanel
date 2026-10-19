package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ef8's packaged installer uses these same migration-copy functions. Keep the
// verified original private; only the small owned migration copy is readable
// to the panel UID. The real historical native install exercises its frozen
// copy again; this test catches either migrator being sent the private root.
func TestPrivateInstallerAssetsStageBothMigratorsWithoutRelaxingOriginal(t *testing.T) {
	data, err := os.ReadFile("../install/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	functions := shellFixtureFunction(t, string(data), "prepare_migration_root", true) + shellFixtureFunction(t, string(data), "run_goose_up", true) + shellFixtureFunction(t, string(data), "run_river_up", true)
	dir := t.TempDir()
	root := filepath.Join(dir, "private-release")
	migrations := filepath.Join(root, "migrations")
	if err := os.MkdirAll(migrations, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"go.mod": "module frozen", "go.sum": "checksums", "Makefile": "frozen makefile", "VERSION": "29.0.0", "migrations/00001.sql": "-- immutable migration"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0400); err != nil {
			t.Fatal(err)
		}
	}
	makefile := `#!/bin/bash
set -euo pipefail
test "$1" = -C
[[ "$2" == "$EXPECTED_COPY_PARENT"/migrate-stage.* ]]
test "$(cat "$2/go.mod")" = 'module frozen'
test -f "$2/migrations/00001.sql"
printf '%s\n' "$2|$3" >>"$CALL_LOG"
`
	if err := os.WriteFile(filepath.Join(dir, "make"), []byte(makefile), 0700); err != nil {
		t.Fatal(err)
	}
	body := `set -euo pipefail
ROOT_DIR="$PRIVATE_RELEASE";DB_DSN=fixture
sudo(){ shift 2; if [[ "$1 $2" == 'test -r' ]]; then return 1; fi; "$@"; }
chown(){ [[ "$*" == *migrate-stage.* && "$*" != *private-release* ]]; printf 'ownership-copy\n' >>"$CALL_LOG"; }
mktemp(){ command mktemp -d "$EXPECTED_COPY_PARENT/migrate-stage.XXXXXX"; }
` + functions + `prepare_migration_root;run_goose_up;run_river_up`
	cmd := exec.Command("bash", "-c", body)
	log := filepath.Join(dir, "calls")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "EXPECTED_COPY_PARENT="+dir, "PRIVATE_RELEASE="+root, "CALL_LOG="+log)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("private migration copy: %s %v", out, err)
	}
	calls, _ := os.ReadFile(log)
	for _, want := range []string{"ownership-copy", "|goose-up", "|river-up"} {
		if !strings.Contains(string(calls), want) {
			t.Fatalf("missing owned-copy operation %s: %s", want, calls)
		}
	}
	info, err := os.Stat(root)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("private original relaxed: %v %v", info, err)
	}
	if content, _ := os.ReadFile(filepath.Join(root, "go.mod")); string(content) != "module frozen" {
		t.Fatal("verified source modified")
	}
}
