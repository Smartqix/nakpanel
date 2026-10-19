package multipass

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A simple systemd unit can be active before its peer-restricted socket is
// usable. Bootstrap must wait for a successful RPC as the actual panel UID.
func TestNativeBootstrapRequiresBoundedSamePeerAgentReadiness(t *testing.T) {
	data, err := os.ReadFile("../install/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	extract := func(name string) string {
		return string(regexp.MustCompile(`(?ms)^` + name + `\(\) \{\n.*?^\}`).Find(data))
	}
	if extract("bootstrap_native_plans") == "" {
		t.Fatal("native bootstrap is missing")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"ready", "delayed-permission", "delayed-no-socket", "permanent-permission", "unauthorized", "hung", "failed-unit"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			write := func(name, contents string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(bin, name), []byte(contents), 0700); err != nil {
					t.Fatal(err)
				}
			}
			write("sudo", `#!/bin/bash
set -eu
[[ "$1" == -u && "$2" == nakpanel ]] || { echo wrong-peer >> "$STATE/trace"; exit 91; }
if [[ " $* " == *' agent ping '* ]]; then
  n=$(<"$STATE/pings"); n=$((n+1)); echo "$n" > "$STATE/pings"
  echo ping >> "$STATE/trace"
  case "$MODE" in
    ready) ;;
    delayed-permission) [[ "$n" -ge 3 ]] || { echo 'connect: permission denied' >&2; exit 13; };;
    delayed-no-socket) [[ "$n" -ge 3 ]] || { echo 'connect: no such file or directory' >&2; exit 2; };;
    permanent-permission) echo 'connect: permission denied' >&2; exit 13;;
    unauthorized) echo 'unauthorized peer uid' >&2; exit 77;;
    hung) trap '' TERM; while :; do /bin/sleep 20; done;;
    *) exit 92;;
  esac
  touch "$STATE/ready"
  echo authenticated >> "$STATE/trace"
  exit 0
fi
if [[ " $* " == *' platform bootstrap-plans '* ]]; then
  echo bootstrap-attempt >> "$STATE/trace"
  test -f "$STATE/ready" || { echo 'agent socket not ready' >&2; exit 13; }
  echo bootstrap-committed >> "$STATE/trace"
  exit 0
fi
echo unexpected-peer-command >> "$STATE/trace"
exit 93
`)
			// Model the GNU timeout boundary with a fast clock on hosts without
			// coreutils. The client really hangs and ignores TERM; the adapter
			// must kill its process group, so a missing bounded call fails the
			// enclosing wall-clock deadline rather than passing the failure case.
			write("timeout", `#!/bin/bash
set -eu
[[ "$1" == --kill-after=1s && "$2" == 5s ]] || { echo invalid-timeout >> "$STATE/trace"; exit 94; }
shift 2
echo bounded-call >> "$STATE/trace"
exec "$PYTHON" - "$@" <<'PY'
import os,signal,subprocess,sys
p=subprocess.Popen(sys.argv[1:],start_new_session=True)
try: result=p.wait(timeout=0.05)
except subprocess.TimeoutExpired:
    os.killpg(p.pid,signal.SIGTERM)
    try: result=p.wait(timeout=0.05)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid,signal.SIGKILL); result=p.wait()
sys.exit(result if result>=0 else 128-result)
PY
`)
			write("sleep", "#!/bin/sh\nexit 0\n")
			for name, value := range map[string]string{"pings": "0\n", "pending": "true\n", "admin": "locked\n", "intent": "retained\n", "trace": ""} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			program := `set -euo pipefail
NAKPANEL_PLATFORM_ID=ubuntu-26.04-native
PLATFORM_BOOTSTRAP_PENDING=true
RESTORE_ARCHIVE=''
DB_DSN=unused
systemctl(){
  [[ "$*" == 'is-failed --quiet nakpanel-agent.service' ]] || { echo unexpected-unit-command >> "$STATE/trace"; return 95; }
  [[ "$MODE" == failed-unit ]]
}
resolve_native_admin_intent(){ printf 'admin@example.test\n'; }
ensure_admin(){ echo secured > "$STATE/admin"; echo admin-secured >> "$STATE/trace"; }
nakpanel_write_platform_state(){ echo "$1" > "$STATE/pending"; echo marker-cleared >> "$STATE/trace"; }
clear_native_admin_intent(){ rm "$STATE/intent"; }
` + extract("wait_for_agent_ready") + "\n" + extract("bootstrap_native_plans") + "\nbootstrap_native_plans\n"
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", "-c", program)
			command.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "STATE="+dir, "MODE="+mode, "PYTHON="+python)
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
			command.WaitDelay = 100 * time.Millisecond
			output, runErr := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("agent readiness did not bound its client: %s", output)
			}
			read := func(name string) string {
				contents, _ := os.ReadFile(filepath.Join(dir, name))
				return string(contents)
			}
			trace := read("trace")
			if strings.Contains(trace, "wrong-peer") || strings.Contains(trace, "invalid-timeout") || strings.Contains(trace, "unexpected-") {
				t.Fatalf("readiness changed the peer or bounded command contract: %s %s", trace, output)
			}
			positive := mode == "ready" || strings.HasPrefix(mode, "delayed-")
			if positive {
				if runErr != nil || read("pending") != "false\n" || read("admin") != "secured\n" {
					t.Fatalf("transient agent startup prevented safe bootstrap: %v %s %s", runErr, trace, output)
				}
				if strings.Index(trace, "authenticated") < 0 || strings.Index(trace, "authenticated") > strings.Index(trace, "bootstrap-attempt") || strings.Count(trace, "bootstrap-committed") != 1 {
					t.Fatalf("bootstrap mutated before same-peer RPC readiness: %s", trace)
				}
			} else if runErr == nil || read("pending") != "true\n" || read("admin") != "locked\n" || read("intent") != "retained\n" || strings.Contains(trace, "bootstrap-attempt") {
				t.Fatalf("unready agent changed pending/admin/bootstrap state: %v %s %s", runErr, trace, output)
			}
			pings, err := strconv.Atoi(strings.TrimSpace(read("pings")))
			if err != nil || pings > 30 || (mode == "failed-unit" && pings != 0) || (mode != "failed-unit" && pings == 0) || (strings.HasPrefix(mode, "delayed-") && pings < 3) {
				t.Fatalf("readiness skipped authentication or did not bound retries: mode=%s pings=%d %s", mode, pings, trace)
			}
		})
	}
}
