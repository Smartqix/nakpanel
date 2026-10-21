package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase29FailedUnitsRetainActualDRDiagnosticsAndStillFail(t *testing.T) {
	data, err := os.ReadFile("phase29-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, string(data), "assert_no_failed_units", true)
	for _, state := range []string{"healthy", "failed", "journal-unavailable", "query-unavailable", "query-partial"} {
		t.Run(state, func(t *testing.T) {
			log := filepath.Join(t.TempDir(), "calls")
			cmd := exec.Command("bash", "-c", `set -euo pipefail
IMAGE=26.04; NAKPANEL_MULTIPASS_ARCH=amd64; NAKPANEL_RUN_TOKEN=test-owner
assert_vm_identity(){ [[ "$*" == 'nakpanel-target-dr 26.04 amd64 test-owner' ]]; }
multipass_exec_short(){
 [[ "$1" == nakpanel-target-dr ]] || return 97
 echo "$*" >>"$CALLS"
 case "$*" in
  *'systemctl --failed'*)
    [[ "$STATE" != query-unavailable ]] || return 97
    [[ "$STATE" == healthy ]] || echo 'fwupd-refresh.service loaded failed failed Refresh fwupd metadata'
    [[ "$STATE" != query-partial ]] || return 97;;
  *'systemctl show'*) echo 'Result=exit-code'; echo 'ExecMainStatus=1';;
  *'journalctl'*) [[ "$STATE" != journal-unavailable ]] || return 98; echo 'Failed to obtain auth';;
 esac
}
fail(){ echo "$*" >&2; exit 90; }
`+function+`if assert_no_failed_units nakpanel-target-dr 'disaster-recovery deployment'; then exit 0; else exit "$?"; fi`)
			cmd.Env = append(os.Environ(), "STATE="+state, "CALLS="+log)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (state == "healthy") {
				t.Fatalf("%s health result: %s %v", state, out, err)
			}
			calls, _ := os.ReadFile(log)
			if strings.HasPrefix(state, "query-") {
				if !strings.Contains(string(out), "unable to query failed systemd units") || strings.Contains(string(calls), "journalctl") {
					t.Fatalf("%s did not reject incomplete health query: %s %s", state, calls, out)
				}
				return
			}
			if state != "healthy" && (!strings.Contains(string(calls), "systemctl show") || !strings.Contains(string(calls), "journalctl") || !strings.Contains(string(out), "disaster-recovery deployment has failed")) {
				t.Fatalf("%s did not retain DR details and fail: %s %s", state, calls, out)
			}
			if state == "failed" && !strings.Contains(string(out), "Failed to obtain auth") {
				t.Fatalf("actual service error missing: %s", out)
			}
		})
	}
}

func TestSignedFaultDrillsAreIsolatedAndFailurePreventsReclaim(t *testing.T) {
	data, err := os.ReadFile("phase29-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, string(data), "run_phase29_signed_fault_companion", false)
	for _, mode := range []string{"success", "failure", "bootstrap failure", "existing companion", "reclaim failure"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			for name, body := range map[string]string{
				"current-install-verify.sh": `#!/bin/bash
set -eu
test "$NAKPANEL_MULTIPASS_VM" = nakpanel-primary-fault
test "$NAKPANEL_MULTIPASS_SOURCE_VM" = nakpanel-primary-fault
test "$NAKPANEL_MULTIPASS_DR_VM" = nakpanel-primary-fault-dr
test "$NAKPANEL_RELEASE_BUNDLE" = /selected
test "${NAKPANEL_INSTALL_ONLY:-0}" = 0
printf 'fresh-selected\n' >>"$CALL_LOG"
[[ "$FAIL_MODE" != 'bootstrap failure' ]]
`,
				"phase29-verify.sh": `#!/bin/bash
set -eu
test "$NAKPANEL_PHASE29_FAULT_DRILLS_ONLY" = 1
test "$NAKPANEL_PHASE29_FAULT_COMPANION_VM" = nakpanel-primary-fault
test "$NAKPANEL_REMOTE_SRC" = /tmp/nakpanel-phase29-fault-src
test -z "${NAKPANEL_RELEASE_BUNDLE:-}${NAKPANEL_RELEASE_PUBLIC_KEY:-}${NAKPANEL_RELEASE_VERSION:-}"
printf 'fault-only\n' >>"$CALL_LOG"
[[ "$FAIL_MODE" != failure ]]
`,
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			body := `set -euo pipefail
VM_NAME=nakpanel-primary;NAKPANEL_MULTIPASS_VM=nakpanel-primary
NAKPANEL_MULTIPASS_SOURCE_VM=nakpanel-primary;NAKPANEL_MULTIPASS_DR_VM=nakpanel-primary-dr
NAKPANEL_RUN_TOKEN=run123;NAKPANEL_RELEASE_BUNDLE=/selected
SCRIPT_DIR="$FIXTURE_DIR";tmpdir="$FIXTURE_DIR";NAKPANEL_CELL_REPORT_DIR="$FIXTURE_DIR"
multipass(){ [[ "$FAIL_MODE" == 'existing companion' ]]; };fail(){ echo "$*" >&2;return 1; }
destroy_owned_vm(){ printf 'destroy|%s|%s\n' "$1" "$2" >>"$CALL_LOG"; [[ "$FAIL_MODE" != 'reclaim failure' ]]; }
` + function + `
result=0
run_phase29_signed_fault_companion || result=$?
test "$NAKPANEL_MULTIPASS_VM|$NAKPANEL_MULTIPASS_SOURCE_VM|$NAKPANEL_MULTIPASS_DR_VM" = 'nakpanel-primary|nakpanel-primary|nakpanel-primary-dr'
exit "$result"
`
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(), "FIXTURE_DIR="+dir, "CALL_LOG="+log, "FAIL_MODE="+mode)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "success") {
				t.Fatalf("companion result: %s %v", out, err)
			}
			calls, _ := os.ReadFile(log)
			if mode == "existing companion" {
				if len(calls) != 0 {
					t.Fatalf("existing companion mutated: %s", calls)
				}
				return
			}
			if !strings.HasPrefix(string(calls), "fresh-selected\n") {
				t.Fatalf("signed bootstrap absent: %s %s", calls, out)
			}
			if strings.Contains(string(calls), "fault-only") != (mode != "bootstrap failure") {
				t.Fatalf("wrong synthetic fault execution: %s", calls)
			}
			if strings.Contains(string(calls), "destroy|") != (mode == "success" || mode == "reclaim failure") {
				t.Fatalf("wrong companion reclaim: %s", calls)
			}
		})
	}
}

func TestSignedPhase29FreshDRUsesSelectedInstallerWithoutFixtureOrRawFallback(t *testing.T) {
	data, err := os.ReadFile("phase29-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, string(data), "install_phase29_fresh_dr", false)
	for _, mode := range []string{"success", "failure"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			installer := `#!/bin/bash
set -euo pipefail
test "$NAKPANEL_MULTIPASS_VM" = nakpanel-primary-dr
test "$NAKPANEL_MULTIPASS_SOURCE_VM" = nakpanel-primary
test "$NAKPANEL_MULTIPASS_DR_VM" = nakpanel-primary-dr
test "$NAKPANEL_INSTALL_ONLY" = 1
test "$NAKPANEL_RELEASE_BUNDLE" = /selected
echo signed-fresh-no-fixtures >> "$CALL_LOG"
[[ "$FAIL_MODE" != failure ]]
`
			if err := os.WriteFile(filepath.Join(dir, "current-install-verify.sh"), []byte(installer), 0o700); err != nil {
				t.Fatal(err)
			}
			body := `set -euo pipefail
VM_NAME=nakpanel-primary;DR_VM_NAME=nakpanel-primary-dr
export NAKPANEL_MULTIPASS_VM=nakpanel-primary NAKPANEL_MULTIPASS_SOURCE_VM=nakpanel-primary NAKPANEL_MULTIPASS_DR_VM=nakpanel-primary-dr NAKPANEL_RELEASE_BUNDLE=/selected
SCRIPT_DIR="$FIXTURE_DIR";ROOT_DIR="$FIXTURE_DIR";tmpdir="$FIXTURE_DIR";REMOTE_SRC=/private/selected/source
NAKPANEL_QUALIFICATION_PHP_PROVIDER=native
destroy_vm(){ echo "destroy|$1" >> "$CALL_LOG"; }
ensure_vm(){ echo forbidden-raw >> "$CALL_LOG";return 96; }
sync_repo(){ echo forbidden-raw >> "$CALL_LOG";return 96; }
multipass(){ echo forbidden-raw >> "$CALL_LOG";return 96; }
` + function + `
result=0
install_phase29_fresh_dr || result=$?
test "$NAKPANEL_MULTIPASS_VM|$NAKPANEL_MULTIPASS_SOURCE_VM|$NAKPANEL_MULTIPASS_DR_VM" = 'nakpanel-primary|nakpanel-primary|nakpanel-primary-dr'
exit "$result"
`
			log := filepath.Join(dir, "calls")
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(), "FIXTURE_DIR="+dir, "CALL_LOG="+log, "FAIL_MODE="+mode)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "success") {
				t.Fatalf("DR preparation: %s %v", out, err)
			}
			calls, _ := os.ReadFile(log)
			if string(calls) != "destroy|nakpanel-primary-dr\nsigned-fresh-no-fixtures\n" {
				t.Fatalf("signed DR fell back or populated fixtures: %s %s", calls, out)
			}
		})
	}
}

func TestSignedPhase29CompanionFailureStopsPrimaryBeforeFixtureMutation(t *testing.T) {
	dir := t.TempDir()
	script, err := os.ReadFile("phase29-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "phase29-verify.sh"), script, 0o700); err != nil {
		t.Fatal(err)
	}
	common := `NAKPANEL_MULTIPASS_VM=nakpanel-primary
NAKPANEL_MULTIPASS_IMAGE=26.04
NAKPANEL_MULTIPASS_DR_VM=nakpanel-primary-dr
NAKPANEL_REMOTE_SRC=/private/source
assert_distinct_vm_names(){ :; }
assert_current_vm_identity(){ :; }
assert_qualification_bundle_staged(){ :; }
assert_qualification_installed_release(){ echo selected-hashes >> "$CALL_LOG"; }
require_nakpanel_vm_name(){ :; }
sync_repo(){ :; }
vm_ip(){ echo 127.0.0.1; }
multipass(){ [[ "$1" == info ]] && return 1;echo forbidden-primary-mutation >> "$CALL_LOG";return 97; }
multipass_exec_short(){ echo forbidden-primary-mutation >> "$CALL_LOG";return 97; }
`
	if err = os.WriteFile(filepath.Join(dir, "common.sh"), []byte(common), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "current-install-verify.sh"), []byte("#!/bin/bash\necho failed-companion-bootstrap >> \"$CALL_LOG\"\nexit 78\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err = os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"dig", "curl"} {
		if err = os.WriteFile(filepath.Join(bin, tool), []byte("#!/bin/bash\nexit 97\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(dir, "calls")
	cmd := exec.Command("bash", filepath.Join(dir, "phase29-verify.sh"))
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "CALL_LOG="+log, "NAKPANEL_RUN_TOKEN=run123", "NAKPANEL_RELEASE_BUNDLE=/selected", "NAKPANEL_RELEASE_VERSION=29.0.0", "NAKPANEL_SKIP_PRIOR_PHASES=1", "NAKPANEL_CELL_REPORT_DIR="+filepath.Join(dir, "report"))
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "mandatory additional signed-bootstrap fault companion failed") {
		t.Fatalf("companion failure did not fail primary: %s %v", out, err)
	}
	calls, _ := os.ReadFile(log)
	if string(calls) != "selected-hashes\nfailed-companion-bootstrap\n" {
		t.Fatalf("primary mutation after companion failure: %s", calls)
	}
	results, _ := filepath.Glob(filepath.Join(dir, "report", "phase29-additional-fault-drills", "attempt.*", "result.tsv"))
	if len(results) != 1 {
		t.Fatalf("failed companion evidence missing: %v", results)
	}
	result, err := os.ReadFile(results[0])
	if err != nil || !strings.HasPrefix(string(result), "FAIL\tadditional-synthetic-fault-drills\tnakpanel-primary-fault\t78") {
		t.Fatalf("incorrect failed companion evidence: %s %v", result, err)
	}
}

func TestPhase29QuotaAssertionUsesActualUserStateDespiteAggregateExit(t *testing.T) {
	data, err := os.ReadFile("phase29-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, string(data), "assert_phase29_user_quota", false)
	for _, state := range []string{"on", "off"} {
		cmd := exec.Command("bash", "-c", `set -euo pipefail
findmnt(){ echo /; }
quotaon(){ echo "user quota on / (/dev/sda1) is $STATE";echo 'group quota off';return 1; }
`+function+`assert_phase29_user_quota`)
		cmd.Env = append(os.Environ(), "STATE="+state)
		out, err := cmd.CombinedOutput()
		if (err == nil) != (state == "on") {
			t.Fatalf("%s quota state: %s %v", state, out, err)
		}
	}
}

func TestPhase29ReconciliationWaitsForItsCommittedRun(t *testing.T) {
	data, err := os.ReadFile("phase29-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	functions := shellFixtureFunction(t, string(data), "wait_for", false) + shellFixtureFunction(t, string(data), "reconcile_phase29_after_reboot", false)
	for _, mode := range []string{"active", "pending", "queue failure", "malformed ID"} {
		dir := t.TempDir()
		body := `set -euo pipefail
cli(){
 [[ "$MODE" != 'queue failure' ]] || return 78
 if [[ "$MODE" == 'malformed ID' ]];then echo 'System reconciliation queued (run unknown).';else echo 'System reconciliation queued (run 41).';fi
}
db(){
 echo "$1" >> "$QUERIES"
 if [[ "$1" == *'MAX(id)'* ]];then echo 42
 elif [[ "$1" == *'id=41' ]];then echo "$MODE"
 elif [[ "$1" == *'id=42' ]];then echo active
 else return 97;fi
}
sleep(){ :; };fail(){ echo "$*" >&2;return 1; }
` + functions + `reconcile_phase29_after_reboot`
		queries := filepath.Join(dir, "queries")
		cmd := exec.Command("bash", "-c", body)
		cmd.Env = append(os.Environ(), "MODE="+mode, "QUERIES="+queries)
		out, err := cmd.CombinedOutput()
		if (err == nil) != (mode == "active") {
			t.Fatalf("%s reconciliation: %s %v", mode, out, err)
		}
		observed, _ := os.ReadFile(queries)
		if strings.Contains(string(observed), "MAX(id)") || strings.Contains(string(observed), "id=42") {
			t.Fatalf("concurrent run substituted: %s", observed)
		}
		if (mode == "active" || mode == "pending") && !strings.Contains(string(observed), "id=41") {
			t.Fatalf("returned run not observed: %s", observed)
		}
		if (mode == "queue failure" || mode == "malformed ID") && len(observed) > 0 {
			t.Fatalf("query without valid returned ID: %s", observed)
		}
	}
}

// Execute the actual post-mail DR convergence block. An archived source row
// (or another concurrent active row) cannot stand in for a new DR request.
func TestPhase29DRRequiresFreshReturnedReconciliationWithoutRetargetingPrimary(t *testing.T) {
	data, err := os.ReadFile("phase29-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	marker := `imap_canary "${DR_VM_NAME}" assert >/dev/null || fail "restored mailbox IMAP login failed"`
	start := strings.Index(script, marker)
	if start < 0 {
		t.Fatal("DR mailbox/convergence boundary missing")
	}
	block := script[start+len(marker):]
	end := strings.Index(block, `assert_no_failed_units "${DR_VM_NAME}" "disaster-recovery deployment"`)
	if end < 0 {
		t.Fatal("DR convergence/health boundary missing")
	}
	block = block[:end]
	functions := shellFixtureFunction(t, script, "wait_for", true) + shellFixtureFunction(t, script, "reconcile_phase29_after_reboot", true) + shellFixtureFunction(t, script, "reconcile_phase29_dr", false)
	for _, mode := range []string{"active", "pending", "queue failure", "malformed ID"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			body := `set -euo pipefail
VM_NAME=nakpanel-primary;DR_VM_NAME=nakpanel-primary-dr
export NAKPANEL_MULTIPASS_VM=nakpanel-primary NAKPANEL_MULTIPASS_SOURCE_VM=nakpanel-primary NAKPANEL_MULTIPASS_DR_VM=nakpanel-primary-dr
assert_current_vm_identity(){
 [[ "$VM_NAME|$NAKPANEL_MULTIPASS_VM|$NAKPANEL_MULTIPASS_SOURCE_VM|$NAKPANEL_MULTIPASS_DR_VM" == 'nakpanel-primary-dr|nakpanel-primary-dr|nakpanel-primary|nakpanel-primary-dr' ]] || return 96
}
cli(){
 [[ "$VM_NAME|$NAKPANEL_MULTIPASS_VM" == 'nakpanel-primary-dr|nakpanel-primary-dr' ]] || return 97
 echo fresh-dr-request >> "$OBSERVED"
 [[ "$MODE" != 'queue failure' ]] || return 78
 if [[ "$MODE" == 'malformed ID' ]];then echo 'System reconciliation queued (run unknown).';else echo 'System reconciliation queued (run 41).';fi
}
db(){
 [[ "$VM_NAME|$NAKPANEL_MULTIPASS_VM" == 'nakpanel-primary-dr|nakpanel-primary-dr' ]] || return 97
 echo "$1" >> "$OBSERVED"
 if [[ "$1" == *'id=41' ]];then echo "$MODE";else echo active;fi
}
# Old code can observe an archived or concurrent active row despite a failed
# or still-pending new request. Keep that realistic trap available to the gate.
dr_db(){ echo archived-or-concurrent-row >> "$OBSERVED";echo active; }
sleep(){ :; };fail(){ echo "$*" >&2;return 1; }
` + functions + `
result=0
( ` + block + ` ) || result=$?
test "$VM_NAME|$NAKPANEL_MULTIPASS_VM|$NAKPANEL_MULTIPASS_SOURCE_VM|$NAKPANEL_MULTIPASS_DR_VM" = 'nakpanel-primary|nakpanel-primary|nakpanel-primary|nakpanel-primary-dr'
exit "$result"
`
			log := filepath.Join(dir, "observed")
			cmd := exec.Command("bash", "-c", body)
			cmd.Env = append(os.Environ(), "MODE="+mode, "OBSERVED="+log)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "active") {
				t.Fatalf("%s DR convergence: %s %v", mode, out, err)
			}
			observed, _ := os.ReadFile(log)
			if !strings.HasPrefix(string(observed), "fresh-dr-request\n") || strings.Contains(string(observed), "archived-or-concurrent-row") {
				t.Fatalf("fresh DR reconciliation was substituted: %s", observed)
			}
			if mode == "active" || mode == "pending" {
				if !strings.Contains(string(observed), "WHERE id=41") {
					t.Fatalf("new DR run not observed: %s", observed)
				}
			} else if strings.Contains(string(observed), "SELECT") {
				t.Fatalf("status queried without committed DR ID: %s", observed)
			}
		})
	}
}
