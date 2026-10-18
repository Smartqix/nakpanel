package multipass

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func shellFixtureFunction(t *testing.T, script, name string, required bool) string {
	t.Helper()
	start := strings.Index(script, name+"() {")
	if start < 0 {
		if required {
			t.Fatalf("fixture function missing: %s", name)
		}
		return ""
	}
	body := script[start:]
	end := strings.Index(body, "\n}")
	if end < 0 {
		t.Fatal("unclosed fixture function")
	}
	return body[:end+2] + "\n"
}

func TestSecurityResourceFixturesRejectFailedProductOperations(t *testing.T) {
	data, err := os.ReadFile("security-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	functions := shellFixtureFunction(t, script, "require_fixture_id", false) + shellFixtureFunction(t, script, "require_fixture_http", false) + shellFixtureFunction(t, script, "provision_resources", true)
	for _, mode := range []string{"mail enable", "mail add", "backup create", "database HTTP", "missing ID", "success"} {
		t.Run(mode, func(t *testing.T) {
			body := `set -euo pipefail
STAMP=123;VM_IP=127.0.0.1;A_SUB=1;A_DOMAIN=one.test;A_SITE=2
fail(){ echo "failed: $*" >&2; return 1; }
admin_post(){ if [[ "$FAIL_MODE" == 'database HTTP' && "$1" == databases ]]; then echo 400; else echo 202; fi; }
cli(){ if [[ "$1 $2" == "$FAIL_MODE" ]]; then return 78; fi; if [[ "$1 $2" == 'backup create' ]]; then echo 'Backup queued (backup 17).'; fi; }
db(){ if [[ "$FAIL_MODE" != 'missing ID' ]]; then echo 17; fi; }
wait_for(){ return 0; }
` + functions + `provision_resources A`
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(), "FAIL_MODE="+mode)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "success") {
				t.Fatalf("fixture mode %s accepted/skipped incorrectly: %v %s", mode, err, out)
			}
		})
	}
}

func TestSecurityConstrainedPlanRequiresRealActiveProductFixture(t *testing.T) {
	data, err := os.ReadFile("security-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	functions := shellFixtureFunction(t, script, "require_fixture_id", true) + shellFixtureFunction(t, script, "require_fixture_http", true) + shellFixtureFunction(t, script, "provision_downgrade_plan", true)
	for _, mode := range []string{"rejected plan", "missing plan", "missing slug", "success"} {
		t.Run(mode, func(t *testing.T) {
			body := `set -euo pipefail
STAMP=123;NAKPANEL_BASELINE_PHP=8.5
fail(){ echo "failed: $*" >&2; return 1; }
admin_post(){ if [[ "$FAIL_MODE" == 'rejected plan' ]]; then echo 400; else echo 202; fi; }
db(){
 if [[ "$*" == *api_slug* ]]; then
  if [[ "$FAIL_MODE" != 'missing slug' ]]; then echo security-tiny-123-17; fi
 elif [[ "$FAIL_MODE" != 'missing plan' ]]; then echo 17; fi
}
` + functions + `provision_downgrade_plan; test "$TINY_SLUG" = security-tiny-123-17`
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(), "FAIL_MODE="+mode)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "success") {
				t.Fatalf("plan fixture mode %s accepted/skipped incorrectly: %v %s", mode, err, out)
			}
		})
	}
	for _, skip := range []string{"skip: B has no mailbox", "skip: B has no backup", "skip downgrade:", `db "INSERT INTO plans(name,is_active`} {
		if strings.Contains(script, skip) {
			t.Errorf("security fixture bypass remains: %s", skip)
		}
	}
}
