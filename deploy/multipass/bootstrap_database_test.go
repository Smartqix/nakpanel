package multipass

import (
	"os"
	"os/exec"
	"testing"
)

func TestBootstrapDatabaseRequiresActualMariaDBCanary(t *testing.T) {
	data, err := os.ReadFile("current-install-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, string(data), "assert_bootstrap_mariadb", false)
	for _, mode := range []string{"ready", "wrong engine", "wrong name", "missing schema", "wrong canary"} {
		t.Run(mode, func(t *testing.T) {
			body := `set -euo pipefail
VM_NAME=nakpanel-fixture;database_id=17
db(){ case "$1" in
 *'SELECT engine '*) if [[ "$MODE" == 'wrong engine' ]];then echo postgresql;else echo mariadb;fi;;
 *'SELECT db_name '*) if [[ "$MODE" == 'wrong name' ]];then echo different_schema;else echo np_current_bootstrap;fi;;
 *) echo 'unexpected fixture query' >&2;return 1;;
esac; }
multipass_exec_short(){
 [[ "$*" == *'mariadb'* && "$*" == *'np_current_bootstrap'* && "$*" == *'INSERT INTO nakpanel_qualification_canary'* && "$*" == *'SELECT value FROM nakpanel_qualification_canary'* ]] || return 98
 if [[ "$MODE" == 'missing schema' ]];then echo 'unknown database' >&2;return 1;fi
 if [[ "$MODE" == 'wrong canary' ]];then echo corrupted;else echo current-bootstrap-mariadb-canary;fi
}
` + function + `assert_bootstrap_mariadb`
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(), "MODE="+mode)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "ready") {
				t.Fatalf("%s: %s %v", mode, out, err)
			}
		})
	}
}
