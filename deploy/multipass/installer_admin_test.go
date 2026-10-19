package multipass

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	extract := func(name string) string {
		block := regexp.MustCompile(`(?ms)^` + name + `\(\) \{\n.*?^\}`).Find(data)
		if len(block) == 0 {
			t.Fatalf("%s function missing", name)
		}
		return string(block)
	}
	for _, profile := range []string{"ubuntu-24.04", "ubuntu-26.04-native", "ubuntu-26.04-sury"} {
		for _, failure := range []string{"0", "1"} {
			t.Run(profile+"/admin_failure_"+failure, func(t *testing.T) {
				trace := filepath.Join(t.TempDir(), "trace")
				program := `set -euo pipefail
BIN_DIR=/unused
SCRIPT_DIR=/unused
DB_DSN=unused
RESTORE_ARCHIVE=''
ADMIN_EMAIL=admin@example.com
PLATFORM_BOOTSTRAP_PENDING=false
TARGET_VERSION=test
NEW_PANEL_DATABASE=0
RESUMING_NATIVE_BOOTSTRAP=0
gate=false
secured=false
for name in cleanup_stages prepare_platform_install pause_apt_background ensure_build_prereqs ensure_go_toolchain stage_binaries install_agent_and_ctl install_panel_binary prepare_panel_prerequisites harden_etc_nakpanel bootstrap_secret_key prepare_migration_root run_goose_up run_river_up ensure_dns_include_target setup_fail2ban health_gate write_version_file run_restore record_native_admin_intent clear_native_admin_intent wait_for_agent_ready; do eval "$name(){ :; }"; done
bootstrap_postgres(){ NEW_PANEL_DATABASE=1; }
install_agent_and_ctl(){
 if [[ "$NAKPANEL_PLATFORM_ID" == ubuntu-26.04-native && "$gate" != true ]]; then
  printf 'unsafe-binary-write\n' >> "$TRACE"; return 1
 fi
}

nakpanel_write_platform_state(){ gate="$1"; }
ensure_admin(){ printf 'admin\n' >> "$TRACE"; test "$FAIL_ADMIN" = 0; secured=true; }
resolve_native_admin_intent(){ printf 'admin@example.com\n'; }
sudo(){ :; }
bash(){ :; }
run_component_installers(){
 if [[ "$gate" == true ]]; then printf 'panel-blocked\n' >> "$TRACE";
 elif [[ "$secured" != true ]]; then printf 'unsafe-panel-start\n' >> "$TRACE"; return 1;
 fi
}
systemctl(){
 if [[ "$*" == 'restart nakpanel.service' ]]; then
  [[ "$secured" == true && "$gate" == false ]] || { printf 'unsafe-panel-start\n' >> "$TRACE"; return 1; }
  printf 'panel-start\n' >> "$TRACE"
 fi
}
` + extract("bootstrap_native_plans") + "\n" + extract("fresh_install") + "\nfresh_install\n"
				command := exec.Command("bash", "-c", program)
				command.Env = append(os.Environ(), "TRACE="+trace, "FAIL_ADMIN="+failure, "NAKPANEL_PLATFORM_ID="+profile)
				output, runErr := command.CombinedOutput()
				events, _ := os.ReadFile(trace)
				if strings.Contains(string(events), "unsafe-panel-start") || strings.Contains(string(events), "unsafe-binary-write") {
					t.Fatalf("panel exposed before administrator: %s %s", events, output)
				}
				if failure == "1" {
					if runErr == nil || strings.Contains(string(events), "panel-start") {
						t.Fatalf("failed admin started panel: %v %s %s", runErr, events, output)
					}
				} else if runErr != nil || !strings.Contains(string(events), "panel-start") {
					t.Fatalf("secured installation did not start: %v %s %s", runErr, events, output)
				}
			})
		}
	}
}

func TestNativeFreshRetryCompletesPrerequisitesAfterEveryInterruptedStage(t *testing.T) {
	data, err := os.ReadFile("../install/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	functions := ""
	for _, name := range []string{"resolve_install_mode", "fresh_install", "bootstrap_native_plans"} {
		block := regexp.MustCompile(`(?ms)^` + name + `\(\) \{\n.*?^\}`).Find(data)
		if len(block) == 0 {
			t.Fatalf("%s missing", name)
		}
		functions += string(block) + "\n"
	}
	for _, interrupted := range []string{"stage_binaries", "install_agent_and_ctl", "prepare_panel_prerequisites", "bootstrap_postgres", "run_goose_up", "run_component_installers", "ensure_admin"} {
		t.Run(interrupted, func(t *testing.T) {
			root := t.TempDir()
			program := `set -euo pipefail
MODE=''; FORCE=0; RESTORE_ARCHIVE=''; BIN_DIR=/unused; SCRIPT_DIR=/unused
DB_DSN=unused; TARGET_VERSION=29.0.0; NEW_PANEL_DATABASE=0
NAKPANEL_PLATFORM_ID=ubuntu-26.04-native
ADMIN_EMAIL=admin@example.com
have_binaries=0; installed_version=''; gate=false
[[ ! -f "$FIXTURE/binary" ]] || { have_binaries=1; installed_version=29.0.0; }
[[ ! -f "$FIXTURE/gate" ]] || gate=true
PLATFORM_BOOTSTRAP_PENDING="$gate"
stage(){ printf '%s\n' "$1" >> "$FIXTURE/trace"; [[ "$INTERRUPTED_STAGE" != "$1" ]] || return 77; }
for name in cleanup_stages prepare_platform_install pause_apt_background ensure_build_prereqs ensure_go_toolchain install_panel_binary harden_etc_nakpanel bootstrap_secret_key prepare_migration_root run_river_up ensure_dns_include_target setup_fail2ban health_gate write_version_file run_restore wait_for_agent_ready; do eval "$name(){ :; }"; done
stage_binaries(){ stage stage_binaries; }
install_agent_and_ctl(){ test -f "$FIXTURE/gate"; touch "$FIXTURE/binary"; stage install_agent_and_ctl; }
prepare_panel_prerequisites(){ touch "$FIXTURE/os-user"; stage prepare_panel_prerequisites; }
bootstrap_postgres(){
 test -f "$FIXTURE/os-user"
 if [[ ! -f "$FIXTURE/database" ]]; then touch "$FIXTURE/database"; NEW_PANEL_DATABASE=1; fi
 stage bootstrap_postgres
}
run_goose_up(){ test -f "$FIXTURE/database"; stage run_goose_up; }
run_component_installers(){ test -f "$FIXTURE/gate"; stage run_component_installers; }
record_native_admin_intent(){ printf '%s' "$ADMIN_EMAIL" > "$FIXTURE/intent"; }
resolve_native_admin_intent(){ if [[ -f "$FIXTURE/intent" ]]; then cat "$FIXTURE/intent"; else printf '%s' "$ADMIN_EMAIL"; fi; }
clear_native_admin_intent(){ rm -f "$FIXTURE/intent"; }
nakpanel_write_platform_state(){
 gate="$1"
 if [[ "$gate" == true ]]; then touch "$FIXTURE/gate"; else test -f "$FIXTURE/admin"; rm "$FIXTURE/gate"; fi
}
ensure_admin(){ test "$ADMIN_EMAIL" = admin@example.com; stage ensure_admin; touch "$FIXTURE/admin"; }
sudo(){ test -f "$FIXTURE/database"; test -f "$FIXTURE/os-user"; test -f "$FIXTURE/gate"; }
bash(){ :; }
systemctl(){
 if [[ "$*" == 'restart nakpanel.service' ]]; then
  test -f "$FIXTURE/admin"; test ! -f "$FIXTURE/gate"; echo panel-start >> "$FIXTURE/trace"
 fi
}
` + functions + `
resolve_install_mode
[[ "$MODE" == fresh ]]
fresh_install
`
			run := func(inject string) ([]byte, error) {
				command := exec.Command("bash", "-c", program)
				command.Env = append(os.Environ(), "FIXTURE="+root, "INTERRUPTED_STAGE="+inject)
				return command.CombinedOutput()
			}
			if out, err := run(interrupted); err == nil {
				t.Fatalf("interruption did not fail: %s", out)
			}
			if out, err := run(""); err != nil {
				t.Fatalf("ordinary retry could not complete: %v: %s", err, out)
			}
			trace, _ := os.ReadFile(filepath.Join(root, "trace"))
			if strings.Count(string(trace), "panel-start") != 1 {
				t.Fatalf("panel did not start exactly once after secured retry: %s", trace)
			}
			if _, err := os.Stat(filepath.Join(root, "gate")); !os.IsNotExist(err) {
				t.Fatalf("successful retry left the startup gate: %v", err)
			}
		})
	}
}
