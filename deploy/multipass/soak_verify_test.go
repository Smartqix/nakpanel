package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/backup"
)

func TestSoakInitRejectsMissingOrInvalidSignedReleaseBeforeVMWork(t *testing.T) {
	for _, mode := range []string{"missing bundle", "missing key", "missing version", "invalid bundle", "legacy installer"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			calls := filepath.Join(dir, "calls")
			if err := os.WriteFile(filepath.Join(dir, "multipass"), []byte("#!/bin/bash\necho VM_WORK >> \"$CALLS\"\nexit 99\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "./soak-verify.sh", "--init")
			env := append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "CALLS="+calls, "NAKPANEL_SOAK_LOG_DIR="+filepath.Join(dir, "logs"), "NAKPANEL_RELEASE_BUNDLE="+dir, "NAKPANEL_RELEASE_PUBLIC_KEY="+filepath.Join(dir, "missing.pem"), "NAKPANEL_RELEASE_VERSION=29.0.0", "NAKPANEL_RUN_TOKEN=soak-test-token", "NAKPANEL_MULTIPASS_VM=nakpanel-test-unique", "NAKPANEL_OWNERSHIP_DIR="+filepath.Join(dir, "ownership"))
			switch mode {
			case "missing bundle":
				env = append(env, "NAKPANEL_RELEASE_BUNDLE=")
			case "missing key":
				env = append(env, "NAKPANEL_RELEASE_PUBLIC_KEY=")
			case "missing version":
				env = append(env, "NAKPANEL_RELEASE_VERSION=")
			case "legacy installer":
				env = append(env, "NAKPANEL_RELEASE_LEGACY_INSTALLER=1")
			}
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("%s accepted: %s", mode, out)
			}
			if data, _ := os.ReadFile(calls); len(data) > 0 {
				t.Fatalf("VM touched before trusted current release: %s\n%s", data, out)
			}
		})
	}
}

// Keep the soak control flow and scheduler decisions real, replacing only the
// VM boundary and the canonical current installer/verifier subprocess.
func TestSoakInitUsesCanonicalSignedInstallerBeforeVerifiedScheduledBackup(t *testing.T) {
	for _, mode := range []string{"ready", "installer failure", "unverified scheduled backup", "existing run metadata"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "repo")
			scripts := filepath.Join(root, "deploy", "multipass")
			if err := os.MkdirAll(scripts, 0o700); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile("soak-verify.sh")
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(scripts, "soak-verify.sh"), data, 0o700); err != nil {
				t.Fatal(err)
			}
			common := `NAKPANEL_MULTIPASS_IMAGE=26.04
NAKPANEL_MULTIPASS_ARCH=arm64
NAKPANEL_MULTIPASS_VM=nakpanel-lab
NAKPANEL_OWNERSHIP_DIR="$LOG_DIR/ownership"
NAKPANEL_QUALIFICATION_PHP_PROVIDER=sury
require_nakpanel_vm_name(){ :; }
init_qualification_run(){ export NAKPANEL_MULTIPASS_VM=nakpanel-26-04-arm64-owned NAKPANEL_MULTIPASS_SOURCE_VM=nakpanel-26-04-arm64-owned NAKPANEL_MULTIPASS_DR_VM=nakpanel-26-04-arm64-owned-dr NAKPANEL_RUN_TOKEN=soak-test-token; }
assert_current_vm_identity(){ printf '%s\n' identity >> "$CALLS"; }
assert_vm_identity(){ printf '%s\n' identity >> "$CALLS"; }
ensure_vm(){ echo FORBIDDEN_RAW_LAUNCH >&2;return 96; }
sync_repo(){ echo FORBIDDEN_RAW_SYNC >&2;return 96; }
multipass(){ [[ "$1" == info ]] || return 95;return 1; }
multipass_exec_short(){
 case "$*" in
  *' psql '*)
   if [[ "$*" == *'backup.scheduled'* && "$*" == *'backup.verified_at IS NOT NULL'* && "$MODE" == ready ]]; then echo 1;else echo 0;fi;;
  *'backup-server key init'*) printf '%s\n' 'Backup archive key created (fingerprint test).' 'Store this key OFFLINE now:' 'nkbk1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; echo key >> "$CALLS";;
  *'destination add'*) echo schedule-minute >> "$CALLS";;
  *'destination update'*) echo schedule-daily >> "$CALLS";;
  *) echo 'unexpected VM command' >&2;return 94;;
 esac
}
sleep(){ :; }
`
			if err = os.WriteFile(filepath.Join(scripts, "common.sh"), []byte(common), 0o600); err != nil {
				t.Fatal(err)
			}
			canonical := `#!/bin/bash
set -euo pipefail
[[ "$NAKPANEL_RELEASE_BUNDLE" == "$BUNDLE" && "$NAKPANEL_RELEASE_PUBLIC_KEY" == "$KEY" && "$NAKPANEL_RELEASE_VERSION" == 29.0.0 && "$NAKPANEL_RELEASE_ALLOW_DEVELOPMENT" == 1 ]]
[[ "$NAKPANEL_QUALIFICATION_VM_CPUS" == 2 && "$NAKPANEL_QUALIFICATION_VM_MEMORY" == 3G && "$NAKPANEL_QUALIFICATION_VM_DISK" == 32G ]]
echo canonical-installer >> "$CALLS"
[[ "$MODE" != 'installer failure' ]]
`
			if err = os.WriteFile(filepath.Join(scripts, "current-install-verify.sh"), []byte(canonical), 0o700); err != nil {
				t.Fatal(err)
			}
			fakeBin := filepath.Join(dir, "bin")
			if err = os.MkdirAll(fakeBin, 0o700); err != nil {
				t.Fatal(err)
			}
			verify := `#!/bin/bash
set -euo pipefail
[[ "$*" == *'--bundle '* && "$*" == *'--public-key '* && "$*" == *'--version 29.0.0 --architecture arm64 --allow-development'* ]]
echo verify-host >> "$CALLS"
`
			if err = os.WriteFile(filepath.Join(fakeBin, "python3"), []byte(verify), 0o700); err != nil {
				t.Fatal(err)
			}
			bundle := filepath.Join(dir, "bundle")
			if err = os.MkdirAll(bundle, 0o700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(bundle, "manifest.json"), []byte("{\"development\":true}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(dir, "public.pem")
			if err = os.WriteFile(key, []byte("public-fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			calls := filepath.Join(dir, "calls")
			logs := filepath.Join(dir, "logs")
			if mode == "existing run metadata" {
				if err = os.MkdirAll(logs, 0o700); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(logs, "run.env"), []byte("existing-owned-run\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(logs, "backup-key.txt"), []byte("existing-offline-key\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", filepath.Join(scripts, "soak-verify.sh"), "--init")
			cmd.Env = append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH"), "MODE="+mode, "CALLS="+calls, "LOG_DIR="+logs, "BUNDLE="+bundle, "KEY="+key, "NAKPANEL_SOAK_VM=", "NAKPANEL_SOAK_LOG_DIR="+logs, "NAKPANEL_RELEASE_BUNDLE="+bundle, "NAKPANEL_RELEASE_PUBLIC_KEY="+key, "NAKPANEL_RELEASE_VERSION=29.0.0", "NAKPANEL_RELEASE_ALLOW_DEVELOPMENT=1", "NAKPANEL_RELEASE_LEGACY_INSTALLER=0")
			out, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "ready") {
				t.Fatalf("%s: %s %v", mode, out, err)
			}
			observed, _ := os.ReadFile(calls)
			if mode == "existing run metadata" {
				if string(observed) != "verify-host\n" {
					t.Fatalf("old run touched by initialization: %s", observed)
				}
				for name, want := range map[string]string{"run.env": "existing-owned-run\n", "backup-key.txt": "existing-offline-key\n"} {
					got, err := os.ReadFile(filepath.Join(logs, name))
					if err != nil || string(got) != want {
						t.Fatalf("old run metadata overwritten: %s %v", got, err)
					}
				}
				return
			}
			want := "verify-host\ncanonical-installer\n"
			if !strings.HasPrefix(string(observed), want) {
				t.Fatalf("canonical install order = %q\n%s", observed, out)
			}
			if mode == "installer failure" {
				if strings.Contains(string(observed), "key") {
					t.Fatalf("backup started after install failure: %s", observed)
				}
				return
			}
			if strings.Contains(string(out), "nkbk1-AAAA") {
				t.Fatal("archive key leaked")
			}
			if mode == "unverified scheduled backup" {
				if strings.Contains(string(observed), "schedule-daily") || strings.Contains(string(out), "initialized") {
					t.Fatalf("unverified scheduled archive accepted: %s %s", observed, out)
				}
				return
			}
			if !strings.Contains(string(observed), "identity\nkey\nschedule-minute\nschedule-daily\n") {
				t.Fatalf("verified scheduling order = %q", observed)
			}
			run, err := os.ReadFile(filepath.Join(logs, "run.env"))
			if err != nil || !strings.Contains(string(run), "NAKPANEL_QUALIFICATION_PHP_PROVIDER=sury") || !strings.Contains(string(run), "NAKPANEL_RUN_TOKEN=soak-test-token") {
				t.Fatalf("incomplete run identity: %s %v", run, err)
			}
			keyData, err := os.ReadFile(filepath.Join(logs, "backup-key.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = backup.DecodeKey(string(keyData)); err != nil {
				t.Fatalf("saved key is not directly restorable: %v", err)
			}
			info, err := os.Stat(filepath.Join(logs, "backup-key.txt"))
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("archive key file unsafe: %v %v", info, err)
			}
		})
	}
}

func TestSoakSweepDoesNotAcceptFreshUnverifiedOrManualArchive(t *testing.T) {
	dir := t.TempDir()
	script, err := os.ReadFile("soak-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "soak-verify.sh"), script, 0o700); err != nil {
		t.Fatal(err)
	}
	common := `NAKPANEL_MULTIPASS_IMAGE=26.04
NAKPANEL_MULTIPASS_ARCH=arm64
require_nakpanel_vm_name(){ :; }
assert_vm_identity(){ :; }
multipass(){ echo 'IPv4: 127.0.0.1'; }
multipass_exec_short(){
 case "$*" in
  *'max(completed_at)'*)
   # Fixture: a 30-second-old manual/unverified row, but no verified scheduled row.
   if [[ "$*" == *'AND scheduled'* && "$*" == *'AND verified_at IS NOT NULL'* ]];then echo 999999;else echo 30;fi;;
  *'river_job'*) echo 0;;
  *'MAX(id)'*) echo 1;;
  *'SELECT status FROM reconciliation_runs'*) echo active;;
  *'df --output=pcent'*) printf 'Use%%\n50%%\n';;
  *'reconcile --system'*) echo 'System reconciliation queued (run 1).';;
  *'systemctl --failed'*|*'openssl x509'*|*'systemctl is-active'*) :;;
  *) echo 'unexpected sweep command' >&2;return 94;;
 esac
}
`
	if err = os.WriteFile(filepath.Join(dir, "common.sh"), []byte(common), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err = os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(bin, "curl"), []byte("#!/bin/bash\nprintf 'ok\\nversion=29.0.0\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join(dir, "soak-verify.sh"))
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "NAKPANEL_SOAK_VM=nakpanel-owned-endurance", "NAKPANEL_SOAK_LOG_DIR="+filepath.Join(dir, "logs"), "NAKPANEL_RUN_TOKEN=owned-endurance")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "newest verified server backup is 999999s old") {
		t.Fatalf("unverified/manual backup masked missing scheduled backup: %s %v", out, err)
	}
}

// A concurrent active run 42 must never satisfy the freshly requested run 41.
func TestSoakSweepWaitsForTheReturnedReconciliationRun(t *testing.T) {
	for _, mode := range []string{"active", "pending", "queue failure", "malformed ID"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			script, err := os.ReadFile("soak-verify.sh")
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, "soak-verify.sh"), script, 0o700); err != nil {
				t.Fatal(err)
			}
			common := `NAKPANEL_MULTIPASS_IMAGE=26.04
NAKPANEL_MULTIPASS_ARCH=arm64
require_nakpanel_vm_name(){ :; }
assert_vm_identity(){ :; }
multipass(){ echo 'IPv4: 127.0.0.1'; }
multipass_exec_short(){
 case "$*" in
  *'reconcile --system'*)
   case "$MODE" in
    'queue failure') return 78;;
    'malformed ID') echo 'System reconciliation queued (run unknown).';;
    *) echo 'System reconciliation queued (run 41).';;
   esac;;
  *'max(completed_at)'*) echo 30;;
  *'river_job'*) echo 0;;
  *'MAX(id)'*) echo max-query >> "$QUERIES";echo 42;;
  *'SELECT status FROM reconciliation_runs WHERE id=41')
   echo id-41 >> "$QUERIES"
   if [[ "$MODE" == pending ]];then echo pending;else echo active;fi;;
  *'SELECT status FROM reconciliation_runs WHERE id=42') echo id-42 >> "$QUERIES";echo active;;
  *'df --output=pcent'*) printf 'Use%%\n50%%\n';;
  *'systemctl --failed'*|*'openssl x509'*|*'systemctl is-active'*) :;;
  *) echo 'unexpected sweep command' >&2;return 94;;
 esac
}
sleep(){ :; }
`
			if err = os.WriteFile(filepath.Join(dir, "common.sh"), []byte(common), 0o600); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(dir, "bin")
			if err = os.MkdirAll(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(bin, "curl"), []byte("#!/bin/bash\nprintf 'ok\\nversion=29.0.0\\n'\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			queries := filepath.Join(dir, "queries")
			cmd := exec.Command("bash", filepath.Join(dir, "soak-verify.sh"))
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "MODE="+mode, "QUERIES="+queries, "NAKPANEL_SOAK_VM=nakpanel-owned-endurance", "NAKPANEL_SOAK_LOG_DIR="+filepath.Join(dir, "logs"), "NAKPANEL_RUN_TOKEN=owned-endurance")
			out, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "active") {
				t.Fatalf("%s reconciliation result: %s %v", mode, out, err)
			}
			observed, _ := os.ReadFile(queries)
			if strings.Contains(string(observed), "max-query") || strings.Contains(string(observed), "id-42") {
				t.Fatalf("concurrent reconciliation substituted: %s", observed)
			}
			if mode == "active" || mode == "pending" {
				if !strings.Contains(string(observed), "id-41") {
					t.Fatalf("returned run was not observed: %s", observed)
				}
			} else if len(observed) > 0 {
				t.Fatalf("status queried without valid returned ID: %s", observed)
			}
			if mode == "pending" && !strings.Contains(string(out), "reconciliation run 41 is pending") {
				t.Fatalf("requested pending run was not reported: %s", out)
			}
		})
	}
}
