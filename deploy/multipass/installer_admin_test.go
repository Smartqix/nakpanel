package multipass

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInstallerStagesPrivateAdminPasswordAndCleansIt(t *testing.T) {
	data, err := os.ReadFile("../install/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "ensure_admin() ")
	if start < 0 {
		t.Fatal("administrator bootstrap function missing")
	}
	end := strings.Index(script[start:], "\nhealth_gate()")
	if end < 0 {
		t.Fatal("administrator bootstrap boundary missing")
	}
	function := script[start : start+end]
	modes := []string{"success", "failure", "TERM", "HUP"}
	if runtime.GOOS == "linux" {
		modes = append(modes, "self-TERM", "self-HUP")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			original := filepath.Join(dir, "root-password")
			if err := os.WriteFile(original, []byte("private-test-password\n"), 0600); err != nil {
				t.Fatal(err)
			}
			harness := `set -eu
ADMIN_EMAIL=admin@example.test
ADMIN_PASSWORD_FILE="$ROOT_PASSWORD"
DB_DSN=unused
chown() { :; }
sudo() {
  if [[ " $* " == *' psql '* ]]; then
    cat > "$SEED_QUERY"
    printf '%s\n' lock-seeds >> "$ORDER"
    return 0
  fi
  local last="${@: -1}"
  [[ "$last" != "$ROOT_PASSWORD" ]] || { echo 'root-only file passed directly to service user'; return 66; }
  if [[ $(uname) == Darwin ]]; then mode=$(stat -f '%Lp' "$last"); else mode=$(stat -c '%a' "$last"); fi
  [[ "$mode" == 600 ]] || return 67
  cmp -s "$ROOT_PASSWORD" "$last" || return 68
  printf '%s' "$last" > "$OBSERVED"
  printf '%s\n' ensure-admin >> "$ORDER"
  if [[ "$BOOTSTRAP_MODE" == self-* ]]; then kill -s "${BOOTSTRAP_MODE#self-}" "$BASHPID"; fi
  if [[ "$BOOTSTRAP_MODE" == TERM || "$BOOTSTRAP_MODE" == HUP ]]; then
    sh -c 'echo "$PPID" > "$BOOTSTRAP_PID.tmp"; mv "$BOOTSTRAP_PID.tmp" "$BOOTSTRAP_PID"'
    while true; do sleep 1; done
  fi
  [[ "$BOOTSTRAP_MODE" != failure ]] || return 69
}
` + function + `
ensure_admin
`
			cmd := exec.Command("bash", "-c", harness)
			cmd.Env = append(os.Environ(), "TMPDIR="+dir, "ROOT_PASSWORD="+original, "OBSERVED="+filepath.Join(dir, "observed"), "BOOTSTRAP_PID="+filepath.Join(dir, "pid"), "SEED_QUERY="+filepath.Join(dir, "seed-query"), "ORDER="+filepath.Join(dir, "order"), "BOOTSTRAP_MODE="+mode)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			var buffer bytes.Buffer
			cmd.Stdout, cmd.Stderr = &buffer, &buffer
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if mode == "TERM" || mode == "HUP" {
				deadline := time.Now().Add(5 * time.Second)
				for {
					if _, err := os.Stat(filepath.Join(dir, "pid")); err == nil {
						break
					}
					if time.Now().After(deadline) {
						syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
						cmd.Wait()
						t.Fatalf("bootstrap did not reach signal boundary: %s", buffer.String())
					}
					time.Sleep(10 * time.Millisecond)
				}
				signal := syscall.SIGTERM
				if mode == "HUP" {
					signal = syscall.SIGHUP
				}
				pidText, err := os.ReadFile(filepath.Join(dir, "pid"))
				if err != nil {
					t.Fatal(err)
				}
				pid, err := strconv.Atoi(strings.TrimSpace(string(pidText)))
				if err != nil {
					t.Fatal(err)
				}
				if err := syscall.Kill(pid, signal); err != nil {
					t.Fatal(err)
				}
			}
			runErr := cmd.Wait()
			output := buffer.Bytes()
			fail := mode != "success"
			if fail && runErr == nil {
				t.Fatal("bootstrap failure swallowed")
			}
			if !fail && runErr != nil {
				t.Fatalf("bootstrap failed: %v: %s", runErr, output)
			}
			observed, err := os.ReadFile(filepath.Join(dir, "observed"))
			if err != nil {
				t.Fatalf("password was not privately staged: %v: %s", err, output)
			}
			if _, err := os.Stat(string(observed)); !os.IsNotExist(err) {
				t.Fatalf("staged password remains after bootstrap: %v", err)
			}
			if data, err := os.ReadFile(original); err != nil || string(data) != "private-test-password\n" {
				t.Fatal("original credential changed")
			}
			if strings.Contains(string(output), "private-test-password") {
				t.Fatal("password leaked in bootstrap output")
			}
			seedQuery, seedErr := os.ReadFile(filepath.Join(dir, "seed-query"))
			if seedErr != nil || !strings.Contains(string(seedQuery), "login_disabled") {
				t.Fatal("production bootstrap did not disable seeded logins")
			}
			if !fail {
				order, _ := os.ReadFile(filepath.Join(dir, "order"))
				if string(order) != "lock-seeds\nensure-admin\n" {
					t.Fatal("seed lockdown must run first so EnsureAdmin re-enables any chosen seed admin after normalizing its email")
				}
			}
		})
	}
}

func TestFreshInstallerBootstrapsAdminBeforeStartingPanel(t *testing.T) {
	data, err := os.ReadFile("../install/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "fresh_install() {")
	end := strings.Index(script[start:], "# Upgrade with pre-upgrade backup")
	if start < 0 || end < 0 {
		t.Fatal("fresh install function missing")
	}
	body := script[start : start+end]
	admin := strings.Index(body, "\n  ensure_admin\n")
	services := strings.Index(body, "\n  run_component_installers\n")
	if admin < 0 || services < 0 || admin > services {
		t.Fatal("fresh installer exposes the panel before securing administrator access")
	}
}
