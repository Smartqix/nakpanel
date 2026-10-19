package multipass

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPhase31PHPResponseGuards(t *testing.T) {
	if _, err := os.ReadFile("phase31-plan-php-verify.sh"); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, kind, payload string
		want                bool
	}{
		{"preview", "preview", `{"ok":true,"plan_id":7,"revision":3,"no_change":false,"preview":{"allowed":true,"changes":[{"path":"php.allowed_versions"}]},"blockers":[]}`, true},
		{"unwritten diff", "preview", `{"ok":true,"plan_id":7,"revision":3,"no_change":false,"preview":{"allowed":true,"changes":[{"path":"web.rate_limit_burst"}]},"blockers":[]}`, false},
		{"null blockers", "preview", `{"ok":true,"plan_id":7,"revision":3,"no_change":false,"preview":{"allowed":true,"changes":[{"path":"php.allowed_versions"}]},"blockers":null}`, false},
		{"apply", "apply", `{"ok":true,"plan_id":7,"revision":3,"changed":true,"sync_state":"pending"}`, true},
		{"wrong revision", "apply", `{"ok":true,"plan_id":7,"revision":2,"changed":true,"sync_state":"pending"}`, false},
		{"bool id", "apply", `{"ok":true,"plan_id":true,"revision":3,"changed":true,"sync_state":"pending"}`, false},
		{"no-op", "noop", `{"ok":true,"plan_id":7,"revision":3,"changed":false,"sync_state":"in_sync"}`, true},
		{"changed no-op", "noop", `{"ok":true,"plan_id":7,"revision":3,"changed":true,"sync_state":"in_sync"}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			payload := filepath.Join(dir, "response.json")
			if err := os.WriteFile(payload, []byte(tt.payload), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", "-c", `set -eu; source ./phase31-plan-php-verify.sh; phase31_php_json "$1" "$2" 7 3`, "test", payload, tt.kind)
			output, err := command.CombinedOutput()
			if (err == nil) != tt.want {
				t.Fatalf("accepted=%t want=%t: %s", err == nil, tt.want, output)
			}
		})
	}
}

func TestPhase31NativeSingleRuntimeStillChecksActiveNoop(t *testing.T) {
	if _, err := os.ReadFile("phase31-plan-php-verify.sh"); err != nil {
		t.Fatal(err)
	}
	for _, badAck := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "bad active acknowledgement"}[badAck], func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "draft-revision"), []byte("3"), 0600); err != nil {
				t.Fatal(err)
			}
			script := `set -euo pipefail
source ./phase31-plan-php-verify.sh
tmpdir="$1"; draft_id=7; plan_id=9; subscription_id=11; NAKPANEL_FIXTURE_PHP=8.5
fail(){ echo "$*" >&2; exit 1; }
phase31_php_ready(){ echo 8.5; }
wait_for(){ return 0; }
db(){
 case "$1" in
  *"SELECT revision FROM plans WHERE id=7"*) cat "${tmpdir}/draft-revision";;
  *"SELECT revision FROM plans WHERE id=9"*) echo 3;;
  *"SELECT php_allowlist"*) echo '8.5|8.5';;
  *"SELECT lifecycle_status"*) echo 'draft:false';;
  *"SELECT (count(*)=1"*) echo true;;
  *"SELECT count(*) FROM audit_events"*) echo "$(( $(cat "${tmpdir}/draft-revision")-2 ))";;
  *"a.desired_revision"*) echo '5:3:1:1:2';;
  *"encode(sha256"*) echo unchanged-raw-oracle;;
  *) fail "unhandled read oracle";;
 esac
}
post_expect(){
 local expected="$1" label="$2" endpoint="$3"; shift 3
 printf '%s\n' "${label}" >> "${tmpdir}/calls"
 local payload status
 case "${label}" in
  phase31-php-draft-preview) status=200;payload='{"ok":true,"plan_id":7,"revision":3,"no_change":false,"preview":{"allowed":true,"changes":[{"path":"php.allowed_versions"}]},"blockers":[]}' ;;
  phase31-php-draft-update) status=200;echo 4 > "${tmpdir}/draft-revision";payload='{"ok":true,"plan_id":7,"revision":4,"changed":true,"sync_state":"in_sync"}' ;;
  phase31-php-stale) status=409;payload='{"ok":false,"code":"stale_revision"}' ;;
  phase31-php-noop) status=200;payload='{"ok":true,"plan_id":7,"revision":4,"changed":false,"sync_state":"in_sync"}' ;;
  phase31-php-unready|phase31-php-active-unready) status=400;payload='{"ok":false,"code":"php_version_unready"}' ;;
  phase31-php-active-noop) status=200;payload='{"ok":true,"plan_id":9,"revision":3,"changed":false,"sync_state":"in_sync"}'; if [[ "${NP_BAD_ACTIVE:-0}" == 1 ]];then payload='{"ok":true,"plan_id":9,"revision":3,"changed":true,"sync_state":"in_sync"}';fi ;;
  *) fail "unexpected operation";;
 esac
 [[ "${expected}" == "${status}" ]] || fail "incorrect requested status"
 printf '%s\n' "${payload}" > "${tmpdir}/${label}.out"
}
verify_phase31_php_versions
`
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", script, "test", dir)
			cmd.Env = os.Environ()
			if badAck {
				cmd.Env = append(cmd.Env, "NP_BAD_ACTIVE=1")
			}
			out, err := cmd.CombinedOutput()
			if (err == nil) == badAck {
				t.Fatalf("bad=%t error=%v output=%s", badAck, err, out)
			}
			calls, readErr := os.ReadFile(filepath.Join(dir, "calls"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !strings.Contains(string(calls), "phase31-php-active-noop") {
				t.Fatal("single85 returned before active zero-write check")
			}
			if strings.Contains(string(calls), "phase31-php-active-unready") == badAck {
				t.Fatal("active refusal missing or bad acknowledgement did not stop flow")
			}
			if strings.Contains(string(calls), "phase31-php-active-update") {
				t.Fatal("single85 attempted an alternate-runtime mutation")
			}
		})
	}
}
