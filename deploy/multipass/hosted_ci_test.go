package multipass

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// GitHub artifact extraction discards executable bits. The producer must wrap
// the bundle in an archive so the installer receives executable assets intact.
func TestCISecurityArtifactPreservesExecutableModesAndExcludesPrivateKey(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow qualificationWorkflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	program := ""
	for _, step := range workflow.Jobs["release-build"].Steps {
		if step.Name == "Build and inspect application bundles" {
			program = step.Run
		}
	}
	if program == "" {
		t.Fatal("release producer missing")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "deploy/release"), 0755); err != nil {
		t.Fatal(err)
	}
	build := `#!/bin/sh
set -eu
bundle="$1/nakpanel-29.0.0-linux-amd64"
mkdir -p "$bundle/bin"
for binary in panel agent panelctl; do printf 'executable fixture\n' > "$bundle/bin/$binary";chmod 755 "$bundle/bin/$binary";done
printf '29.0.0\n' > "$bundle/VERSION"
`
	for name, content := range map[string]string{"deploy/release/build.sh": build, "VERSION": "29.0.0\n", "README.md": "fixture\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "-c", program)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "RUNNER_TEMP="+root, "GITHUB_RUN_ID=test")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("CI bundle producer: %s %v", out, err)
	}
	file, err := os.Open(filepath.Join(root, "security-release/bundle.tar.gz"))
	if err != nil {
		t.Fatalf("artifact transport did not preserve executable modes in a tar archive: %v", err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	found := false
	for {
		header, err := archive.Next()
		if err != nil {
			break
		}
		if strings.HasSuffix(header.Name, "/bin/panel") {
			found = true
			if header.Mode&0111 == 0 {
				t.Fatal("archive stripped executable mode")
			}
		}
	}
	if !found {
		t.Fatal("archive omitted the application executable")
	}
	entries, err := os.ReadDir(filepath.Join(root, "security-release"))
	if err != nil || len(entries) != 2 || entries[0].Name() != "bundle.tar.gz" || entries[1].Name() != "public.pem" {
		t.Fatalf("uploaded artifact must contain only bundle archive and public key: %v %v", entries, err)
	}
}

// Execute the actual CI step and Phase29 companion routing. Only external
// guest/bootstrap operations are replaced; failed private attempt logs must
// land in the paths the workflow actually uploads, not just the parent tee.
func TestCISecurityPhase29RetainsFailedCompanionEvidence(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow qualificationWorkflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	program, uploadPaths := "", ""
	var stepEnv map[string]string
	for _, step := range workflow.Jobs["security-suite"].Steps {
		if step.Name == "Run the Phase 29 reliability gate (upgrade, reboot, DR)" {
			program, stepEnv = step.Run, step.Env
		}
		if strings.HasPrefix(fmt.Sprint(step.With["name"]), "security-evidence-") {
			if step.If != "always()" {
				t.Fatal("failed companion evidence must upload even when the gate fails")
			}
			uploadPaths, _ = step.With["path"].(string)
		}
	}
	if program == "" || uploadPaths == "" {
		t.Fatal("Phase29 gate or its evidence upload is missing")
	}
	gate, err := os.ReadFile("phase29-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"bootstrap", "synthetic-drill"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			runner := filepath.Join(root, "runner-temp")
			for _, path := range []string{"deploy/multipass", "commands", "runner-temp/security-evidence"} {
				if err := os.MkdirAll(filepath.Join(root, path), 0700); err != nil {
					t.Fatal(err)
				}
			}
			common := `NAKPANEL_MULTIPASS_VM="${NAKPANEL_MULTIPASS_VM:-nakpanel-primary}"
NAKPANEL_MULTIPASS_IMAGE=24.04
NAKPANEL_MULTIPASS_DR_VM="${NAKPANEL_MULTIPASS_DR_VM:-nakpanel-primary-dr}"
NAKPANEL_REMOTE_SRC=/private/source
if [[ "${NAKPANEL_PHASE29_FAULT_DRILLS_ONLY:-0}" == 1 ]]; then
  echo 'synthetic-drill error canary: ConnectionRefusedError' >&2
  exit 79
fi
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
			bootstrap := `#!/bin/bash
set -eu
echo signed-bootstrap >> "$CALL_LOG"
echo 'signed-bootstrap output canary'
if [[ "$FAIL_MODE" == bootstrap ]]; then echo 'bootstrap failure canary' >&2;exit 78;fi
`
			for name, body := range map[string]string{
				"deploy/multipass/phase29-verify.sh":         string(gate),
				"deploy/multipass/common.sh":                 common,
				"deploy/multipass/current-install-verify.sh": bootstrap,
				"commands/dig":  "#!/bin/bash\nexit 97\n",
				"commands/curl": "#!/bin/bash\nexit 97\n",
			} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "-c", program)
			cmd.Dir = root
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "NAKPANEL_") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "PATH="+filepath.Join(root, "commands")+":"+os.Getenv("PATH"), "RUNNER_TEMP="+runner,
				"CALL_LOG="+filepath.Join(root, "calls"), "FAIL_MODE="+mode, "NAKPANEL_RUN_TOKEN=run123",
				"NAKPANEL_OWNERSHIP_DIR="+filepath.Join(root, "private-ownership"), "NAKPANEL_RELEASE_BUNDLE=/selected", "NAKPANEL_RELEASE_VERSION=29.0.0")
			for name, value := range stepEnv {
				value = strings.ReplaceAll(value, "${{ runner.temp }}", runner)
				cmd.Env = append(cmd.Env, name+"="+value)
			}
			out, runErr := cmd.CombinedOutput()
			if runErr == nil || !strings.Contains(string(out), "mandatory additional signed-bootstrap fault companion failed") {
				t.Fatalf("failed companion did not fail the real CI step: %v: %s", runErr, out)
			}
			calls, err := os.ReadFile(filepath.Join(root, "calls"))
			if err != nil || string(calls) != "selected-hashes\nsigned-bootstrap\n" {
				t.Fatalf("companion failure mutated the primary or bypassed signed bootstrap: %s %v", calls, err)
			}
			retained := map[string]string{}
			for _, upload := range strings.Split(strings.TrimSpace(uploadPaths), "\n") {
				path := strings.ReplaceAll(strings.TrimSpace(upload), "${{ runner.temp }}", runner)
				err := filepath.Walk(path, func(path string, info os.FileInfo, walkErr error) error {
					if os.IsNotExist(walkErr) {
						return nil
					}
					if walkErr != nil {
						return walkErr
					}
					if !info.IsDir() {
						content, err := os.ReadFile(path)
						if err != nil {
							return err
						}
						retained[info.Name()] = string(content)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if !strings.Contains(retained["bootstrap.log"], "signed-bootstrap output canary") || !strings.Contains(retained["identity.tsv"], "nakpanel-primary-fault") {
				t.Fatalf("actual upload omitted the private failed companion's bootstrap/identity logs; retained=%v: %s", retained, out)
			}
			code := "78"
			if mode == "synthetic-drill" {
				code = "79"
				if !strings.Contains(retained["fault-drills.log"], "synthetic-drill error canary: ConnectionRefusedError") {
					t.Fatalf("actual upload omitted the failed synthetic drill: %v", retained)
				}
			} else if _, ok := retained["fault-drills.log"]; ok {
				t.Fatal("bootstrap failure must not execute synthetic drills")
			}
			if !strings.Contains(retained["result.tsv"], "FAIL\tadditional-synthetic-fault-drills\tnakpanel-primary-fault\t"+code) {
				t.Fatalf("actual upload omitted the exact companion failure status: %v", retained)
			}
		})
	}
}

// Removing the real daemon probe, its deadline, or its failure diagnostics must
// fail these tests. Only the external Multipass client and journal are replaced.
func TestHostedMultipassReadinessRequiresActualDaemonAndBoundsFailure(t *testing.T) {
	helper, err := filepath.Abs("hosted-multipass-ready.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"transient", "hang", "permanent", "invalid-json"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			client := `#!/usr/bin/env python3
import os,pathlib,sys,time
root=pathlib.Path(os.environ['FIXTURE']); count=root/'attempts'
attempt=int(count.read_text())+1 if count.exists() else 1; count.write_text(str(attempt))
assert sys.argv[1:]==['list','--format','json'],sys.argv
mode=os.environ['CLIENT_MODE']
if mode=='hang':time.sleep(60)
if mode=='invalid-json':print('');sys.exit(0)
if mode=='permanent' or attempt==1:
 print('failed to open multipass_root_cert.pem: No such file or directory',file=sys.stderr);sys.exit(1)
print('{"errors":[],"list":[]}')
`
			if err := os.WriteFile(filepath.Join(root, "multipass"), []byte(client), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "sudo"), []byte("#!/bin/sh\nprintf 'multipassd journal canary\\n'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			evidence := filepath.Join(root, "evidence")
			cmd := exec.Command("python3", helper, "--output-dir", evidence, "--timeout", "0.45", "--attempt-timeout", "0.15", "--retry-interval", "0.02")
			cmd.Env = append(os.Environ(), "PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"), "FIXTURE="+root, "CLIENT_MODE="+mode)
			started := time.Now()
			output, runErr := cmd.CombinedOutput()
			if time.Since(started) > 3*time.Second {
				t.Fatalf("daemon wait exceeded its bounded deadline: %s", output)
			}
			if (runErr == nil) != (mode == "transient") {
				t.Fatalf("mode=%s err=%v: %s", mode, runErr, output)
			}
			data, err := os.ReadFile(filepath.Join(evidence, "multipass-readiness.json"))
			if err != nil {
				t.Fatalf("missing daemon readiness evidence: %v: %s", err, output)
			}
			var report struct {
				Ready    bool `json:"ready"`
				Attempts int  `json:"attempts"`
			}
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			if report.Ready != (mode == "transient") || report.Attempts < 2 {
				t.Fatalf("incorrect readiness result: %s", data)
			}
			if mode == "transient" {
				data, err = os.ReadFile(filepath.Join(evidence, "multipass-list.json"))
				if err != nil || !strings.Contains(string(data), `"list":[]`) {
					t.Fatalf("daemon success did not retain its actual list response: %s %v", data, err)
				}
			} else {
				data, err = os.ReadFile(filepath.Join(evidence, "multipass-journal.log"))
				if err != nil || !strings.Contains(string(data), "multipassd journal canary") {
					t.Fatalf("failed daemon did not retain journal: %s %v", data, err)
				}
			}
		})
	}
}

func TestHostedPreparationRejectsOtherHostsBeforeMutation(t *testing.T) {
	helper, err := filepath.Abs("prepare-hosted-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"self-hosted", "missing-actions"} {
		t.Run(host, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"sudo", "snap", "docker", "multipass"} {
				if err := os.WriteFile(filepath.Join(root, name), []byte("#!/bin/sh\necho mutation >> \"$FIXTURE/mutations\"\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", helper)
			actions, environment := "true", "self-hosted"
			if host == "missing-actions" {
				actions, environment = "false", "github-hosted"
			}
			cmd.Env = append(os.Environ(), "PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"), "FIXTURE="+root, "RUNNER_TEMP="+root, "GITHUB_ACTIONS="+actions, "RUNNER_ENVIRONMENT="+environment)
			output, runErr := cmd.CombinedOutput()
			if runErr == nil || !strings.Contains(string(output), "disposable GitHub-hosted") {
				t.Fatalf("unsupported host was not explicitly refused: %v: %s", runErr, output)
			}
			if _, err := os.Stat(filepath.Join(root, "mutations")); !os.IsNotExist(err) {
				t.Fatal("host preparation mutated a non-hosted machine")
			}
		})
	}
}

// Run the complete preparer with only host commands replaced. The actual
// readiness helper must see the same unprivileged client become usable after
// a narrowly scoped socket ACL; mere daemon startup cannot make it pass.
func TestHostedPreparationAuthorizesOnlyItsRunnerOnTheActualSocket(t *testing.T) {
	helper, err := filepath.Abs("prepare-hosted-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	// These literal outcomes describe snap's external boundary; the complete
	// preparer still controls retry classification, timeouts, evidence and all
	// downstream daemon/KVM admission. No real sudo/snap/timeout is executed.
	snapCases := map[string]struct {
		codes    []int
		backoffs []string
		wantExit int
	}{
		"snap-retry-once":          {[]int{1, 0}, []string{"10"}, 0},
		"snap-retry-twice":         {[]int{1, 1, 0}, []string{"10", "20"}, 0},
		"snap-three-fail":          {[]int{1, 1, 1}, []string{"10", "20"}, 1},
		"snap-timeout":             {[]int{124}, nil, 124},
		"snap-timeout-after-retry": {[]int{1, 124}, []string{"10"}, 124},
		"snap-killed":              {[]int{137}, nil, 137},
		"snap-tool125":             {[]int{125}, nil, 125},
		"snap-tool126":             {[]int{126}, nil, 126},
		"snap-tool127":             {[]int{127}, nil, 127},
		"snap-other2":              {[]int{2}, nil, 2},
		"snap-interrupted":         {[]int{130}, nil, 130},
	}
	for _, mode := range []string{"ready", "delayed-kvm", "reset-kvm", "missing", "symlink", "not-root", "acl-failure", "settle-failure", "missing-kvm", "symlink-kvm", "not-root-kvm", "kvm-acl-failure", "linked-temp-root", "file-temp-root", "foreign-temp-root", "snap-retry-once", "snap-retry-twice", "snap-three-fail", "snap-timeout", "snap-timeout-after-retry", "snap-killed", "snap-tool125", "snap-tool126", "snap-tool127", "snap-other2", "snap-interrupted"} {
		t.Run(mode, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			runnerTemp := root
			switch mode {
			case "linked-temp-root":
				runnerTemp = filepath.Join(root, "linked-temp")
				if err := os.Symlink(root, runnerTemp); err != nil {
					t.Fatal(err)
				}
			case "file-temp-root":
				runnerTemp = filepath.Join(root, "temp-file")
				if err := os.WriteFile(runnerTemp, []byte("regular file"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-temp-root":
				if os.Getuid() == 0 {
					t.Skip("foreign-owned root requires an unprivileged test actor")
				}
				runnerTemp = "/"
			}
			commands := map[string]string{
				"uname": `#!/bin/sh
case "$1" in -s) echo Linux;; -m) echo x86_64;; *) exit 90;; esac
`,
				"id": `#!/bin/sh
test "$1" = -u || exit 90
echo 1001
`,
				"df": "#!/bin/sh\necho 'disposable hosted disk fixture'\n",
				"sleep": `#!/bin/sh
printf '%s\n' "$*" >> "$FIXTURE/sleeps"
printf 'sleep %s\n' "$*" >> "$FIXTURE/host-commands"
exit 0
`,
				"mktemp": `#!/bin/sh
# Model GNU mktemp's TMPDIR behavior even on a BSD/macOS test host.
case "$*" in
 -d) exec "$FIXTURE_PYTHON" -c 'import tempfile;print(tempfile.mkdtemp(prefix="tmp."))';;
 -d\ *) exec "$FIXTURE_PYTHON" -c 'import pathlib,sys,tempfile;p=pathlib.Path(sys.argv[1]);assert p.name=="snap-install-multipass.XXXXXX";print(tempfile.mkdtemp(prefix="snap-install-multipass.",dir=p.parent))' "$2";;
 *) exit 99;;
esac
`,
				"sudo": `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FIXTURE/host-commands"
socket=/var/snap/multipass/common/multipass_socket
case "$1" in
 test)
  case "$3" in
   "$socket")
    case "$2" in
     -S)
      test "$CLIENT_MODE" != missing || exit 1
      count=0;test ! -f "$FIXTURE/socket-attempts" || count=$(cat "$FIXTURE/socket-attempts")
      count=$((count+1));echo "$count" > "$FIXTURE/socket-attempts"
      test "$count" -gt 2
      ;;
     -L) test "$CLIENT_MODE" = symlink;;
     *) exit 92;;
    esac
    ;;
   /dev/kvm)
    case "$2" in
     -c) test "$CLIENT_MODE" != missing-kvm && test -f "$FIXTURE/udev-settled";;
     -L) test "$CLIENT_MODE" = symlink-kvm;;
     *) exit 92;;
    esac
    ;;
   *) exit 91;;
  esac
  ;;
 stat)
  case "$*" in
   "stat -c %u $socket")
    if test "$CLIENT_MODE" = not-root;then echo 1001;else echo 0;fi
    ;;
   'stat -c %u /dev/kvm')
    if test "$CLIENT_MODE" = not-root-kvm;then echo 1001;else echo 0;fi
    ;;
   'stat -c uid=%u gid=%g mode=%a type=%F /dev/kvm') echo 'uid=0 gid=108 mode=660 type=character special file';;
   *) exit 93;;
  esac
  ;;
 setfacl)
  case "$*" in
   'setfacl -m u:1001:rw /dev/kvm')
    test "$CLIENT_MODE" != kvm-acl-failure || exit 69
    # Delayed creation cannot be authorized before pending udev completes.
    if test "$CLIENT_MODE" = delayed-kvm;then test -f "$FIXTURE/udev-settled" || exit 70;fi
    touch "$FIXTURE/kvm-authorized"
    ;;
   "setfacl -m u:1001:rw $socket")
    test "$CLIENT_MODE" != acl-failure || exit 67
    touch "$FIXTURE/runner-authorized"
    ;;
   *) exit 94;;
  esac
  ;;
 getfacl)
  case "$*" in
   "getfacl -n -p $socket"|'getfacl -n -p /dev/kvm') :;;
   *) exit 95;;
  esac
  printf '# owner: 0\nuser::rw-\nuser:1001:rw-\ngroup::rw-\nmask::rw-\nother::---\n'
  ;;
 udevadm)
  case "$*" in
   'udevadm settle --timeout=30')
    test "$CLIENT_MODE" != settle-failure || exit 68
    # Complete the pending event, including any reset of a previous ACL.
    if test "$CLIENT_MODE" = reset-kvm;then rm -f "$FIXTURE/kvm-authorized";fi
    touch "$FIXTURE/udev-settled"
    ;;
   'udevadm control --reload-rules'|'udevadm trigger --name-match=kvm') :;;
   *) exit 98;;
  esac
  ;;
 journalctl) echo 'multipassd journal fixture';;
 snap|timeout)
  # Accept the legacy unbounded boundary only for the meaningful RED control.
  # Tests independently require every successful new invocation to be bounded.
  case "$*" in
   'snap install multipass'|'timeout --kill-after=5s 360s snap install multipass') :;;
   *) exit 90;;
  esac
  n=0;test ! -f "$FIXTURE/snap-attempts" || n=$(cat "$FIXTURE/snap-attempts")
  n=$((n+1));printf '%s\n' "$n" > "$FIXTURE/snap-attempts"
  printf 'snap stdout attempt %s\n' "$n"
  printf 'snap stderr attempt %s\n' "$n" >&2
  case "$CLIENT_MODE" in
   snap-retry-once) test "$n" -gt 1 || exit 1;;
   snap-retry-twice) test "$n" -gt 2 || exit 1;;
   snap-three-fail) exit 1;;
   snap-timeout) exit 124;;
   snap-timeout-after-retry) if test "$n" = 1;then exit 1;else exit 124;fi;;
   snap-killed) exit 137;;
   snap-tool125) exit 125;;
   snap-tool126) exit 126;;
   snap-tool127) exit 127;;
   snap-other2) exit 2;;
   snap-interrupted) exit 130;;
  esac
  ;;
 rm|docker|apt-get) :;;
 *) exit 96;;
esac
`,
				"multipass": `#!/bin/sh
set -eu
case "${TMPDIR:-}" in "$FIXTURE"/nakpanel-hosted-*) :;; *) echo 'current helper process did not export workspace TMPDIR' >&2;exit 97;;esac
case "$*" in
 'list --format json')
  echo attempt >> "$FIXTURE/client-attempts"
  if test ! -f "$FIXTURE/runner-authorized";then echo 'list failed: multipass socket access denied';exit 2;fi
  touch "$FIXTURE/daemon-ready"
  printf '{"errors":[],"list":[]}\n'
  ;;
 version)
  if test "$CLIENT_MODE" = reset-kvm;then rm -f "$FIXTURE/kvm-authorized";fi
  echo 'multipass fixture'
  ;;
 transfer\ *)
  "$FIXTURE_PYTHON" - "$2" <<'PYTRANSFER'
import os,pathlib,shutil,stat,sys
source=pathlib.Path(sys.argv[1]);root=pathlib.Path(os.environ['FIXTURE'])
# Snap's private /tmp namespace cannot see host temporary paths. This fake
# exposes only the runner workspace, while the real common helpers create
# and hash their actual archives on the ordinary host filesystem.
if not source.is_relative_to(root):
 print('[sftp] cannot access '+str(source)+': No such file or directory',file=sys.stderr);sys.exit(2)
assert source.is_file(),source
if source.name in ('source.tar','release.tar'):
 assert stat.S_IMODE(source.parent.stat().st_mode)==0o700
 assert source.parent.stat().st_uid==os.getuid()
 shutil.copyfile(source,root/('captured-'+source.name))
PYTRANSFER
  ;;
 *) exit 97;;
esac
`,
				"python3": `#!/bin/sh
case "$1" in
 */hosted-multipass-ready.py) exec "$FIXTURE_PYTHON" "$@" --timeout 0.2 --attempt-timeout 0.05 --retry-interval 0.01;;
 *) exec "$FIXTURE_PYTHON" "$@";;
esac
`,
				"timeout": `#!/bin/sh
shift 2
exec "$@"
`,
			}
			for name, content := range commands {
				if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", helper)
			cmd.Env = append(os.Environ(), "PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"), "FIXTURE="+root, "FIXTURE_PYTHON="+python, "RUNNER_TEMP="+runnerTemp, "GITHUB_ENV="+filepath.Join(root, "environment"), "GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted", "CLIENT_MODE="+mode)
			output, runErr := cmd.CombinedOutput()
			snapCase, isSnapCase := snapCases[mode]
			wantReady := mode == "ready" || mode == "delayed-kvm" || mode == "reset-kvm" || isSnapCase && snapCase.wantExit == 0
			if (runErr == nil) != wantReady {
				t.Fatalf("mode=%s preparation err=%v: %s", mode, runErr, output)
			}
			commandsLog, _ := os.ReadFile(filepath.Join(root, "host-commands"))
			if isSnapCase {
				if snapCase.wantExit != 0 {
					exit, ok := runErr.(*exec.ExitError)
					if !ok || exit.ExitCode() != snapCase.wantExit {
						t.Fatalf("Snap failure class changed: %v, want %d: %s", runErr, snapCase.wantExit, output)
					}
				}
				count, err := os.ReadFile(filepath.Join(root, "snap-attempts"))
				if err != nil || strings.TrimSpace(string(count)) != fmt.Sprint(len(snapCase.codes)) {
					t.Fatalf("wrong bounded install count: %q %v: %s", count, err, commandsLog)
				}
				if strings.Count(string(commandsLog), "timeout --kill-after=5s 360s snap install multipass\n") != len(snapCase.codes) {
					t.Fatalf("install bypassed exact bounded default-store invocation: %s", commandsLog)
				}
				var trace []string
				for _, line := range strings.Split(string(commandsLog), "\n") {
					if strings.HasPrefix(line, "udevadm ") {
						break
					}
					if line == "timeout --kill-after=5s 360s snap install multipass" {
						trace = append(trace, "install")
					}
					if strings.HasPrefix(line, "sleep ") {
						trace = append(trace, line)
					}
				}
				wantTrace := []string{"install"}
				for _, pause := range snapCase.backoffs {
					wantTrace = append(wantTrace, "sleep "+pause, "install")
				}
				if strings.Join(trace, ",") != strings.Join(wantTrace, ",") {
					t.Fatalf("wrong install/backoff order: %v want %v", trace, wantTrace)
				}
				dirs, err := filepath.Glob(filepath.Join(root, "hosted-evidence", "snap-install-multipass.*"))
				if err != nil || len(dirs) != 1 {
					t.Fatalf("one retained private attempt directory required: %v %v", dirs, err)
				}
				if info, err := os.Lstat(dirs[0]); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
					t.Fatalf("Snap evidence directory is not private: %v %v", info, err)
				}
				for i, code := range snapCase.codes {
					for suffix, want := range map[string]string{"stdout.log": fmt.Sprintf("snap stdout attempt %d\n", i+1), "stderr.log": fmt.Sprintf("snap stderr attempt %d\n", i+1), "exit-code": fmt.Sprintln(code)} {
						path := filepath.Join(dirs[0], fmt.Sprintf("attempt-%d.%s", i+1, suffix))
						data, err := os.ReadFile(path)
						if err != nil || string(data) != want {
							t.Fatalf("original Snap %s evidence lost: %q %v", suffix, data, err)
						}
						info, err := os.Lstat(path)
						if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
							t.Fatalf("Snap attempt evidence is not private: %v %v", info, err)
						}
						if suffix != "exit-code" && !strings.Contains(string(output), strings.TrimSpace(want)) {
							t.Fatalf("original Snap output not surfaced: %s", output)
						}
					}
				}
				if snapCase.wantExit != 0 {
					if strings.Contains(string(commandsLog), "udevadm ") || strings.Contains(string(commandsLog), "setfacl ") {
						t.Fatalf("failed Snap reached daemon/KVM setup: %s", commandsLog)
					}
					for _, name := range []string{"client-attempts", "daemon-ready", "kvm-authorized"} {
						if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
							t.Fatalf("failed Snap reached downstream admission: %s", name)
						}
					}
				}
			}
			if strings.HasSuffix(mode, "temp-root") {
				if len(commandsLog) != 0 || !strings.Contains(string(output), "absolute current-owner directory without symlinks") {
					t.Fatalf("unsafe runner temp root reached hosted mutations: %s %s", commandsLog, output)
				}
				return
			}
			if strings.Contains(string(commandsLog), "chmod ") || strings.Contains(string(commandsLog), "chown ") || strings.Contains(string(commandsLog), "usermod ") {
				t.Fatalf("preparation broadened socket permissions: %s", commandsLog)
			}
			_, clientErr := os.Stat(filepath.Join(root, "client-attempts"))
			badSocket := mode == "missing" || mode == "symlink" || mode == "not-root" || mode == "acl-failure"
			if badSocket && !os.IsNotExist(clientErr) {
				t.Fatalf("untrusted/unconfigured socket reached daemon query: %s", commandsLog)
			}
			if wantReady {
				if _, err := os.Stat(filepath.Join(root, "kvm-authorized")); err != nil {
					t.Fatalf("preparation left KVM inaccessible after pending udev setup: %v", err)
				}
				if _, err := os.Stat(filepath.Join(root, "udev-settled")); err != nil {
					t.Fatalf("preparation left udev events pending: %v", err)
				}
				acl, err := os.ReadFile(filepath.Join(root, "hosted-evidence/multipass-socket-acl.log"))
				if err != nil || !strings.Contains(string(acl), "user:1001:rw-") || !strings.Contains(string(acl), "other::---") {
					t.Fatalf("runner-only socket access evidence missing: %s %v", acl, err)
				}
				if clientErr != nil {
					t.Fatal("successful preparation did not require the actual client query")
				}
				acl, err = os.ReadFile(filepath.Join(root, "hosted-evidence/kvm-device-acl.log"))
				if err != nil || !strings.Contains(string(acl), "uid=0 gid=108 mode=660") || !strings.Contains(string(acl), "user:1001:rw-") || !strings.Contains(string(acl), "other::---") {
					t.Fatalf("numeric KVM ownership and runner-only ACL evidence missing: %s %v", acl, err)
				}
				if mode == "ready" {
					assertHostedTemporaryArchiveTransfers(t, root, cmd.Env, python)
					before, _ := os.ReadFile(filepath.Join(root, "environment"))
					again := exec.Command("bash", helper)
					again.Env = cmd.Env
					if out, err := again.CombinedOutput(); err != nil {
						t.Fatalf("second private temp preparation: %s %v", out, err)
					}
					after, _ := os.ReadFile(filepath.Join(root, "environment"))
					lines := strings.Fields(string(after))
					if len(lines) != 2 || !strings.HasPrefix(string(after), string(before)) || lines[0] == lines[1] {
						t.Fatalf("hosted temporary directory was reused or prior exports replaced: %s", after)
					}
					for _, line := range lines {
						path := strings.TrimPrefix(line, "TMPDIR=")
						info, err := os.Lstat(path)
						if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || filepath.Dir(path) != root {
							t.Fatalf("hosted temp export is not a unique private workspace directory: %s %v", line, err)
						}
					}
				}
			}
		})
	}
}

func assertHostedTemporaryArchiveTransfers(t *testing.T, root string, env []string, python string) {
	t.Helper()
	common, err := filepath.Abs("common.sh")
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := filepath.Abs("qualification_artifacts_test.py")
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the existing real RSA-signed static-ELF fixture. Verification,
	// source export, tar creation and archive hashing remain actual helpers.
	setup := `import importlib.util,pathlib,shutil,sys
spec=importlib.util.spec_from_file_location('artifacts_fixture',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.QualificationArtifacts.setUpClass();case=m.QualificationArtifacts();case.setUp()
try:
 root=pathlib.Path(sys.argv[2]);shutil.copytree(case.bundle,root/'selected-bundle');shutil.copyfile(case.key,root/'selected-public.pem')
finally:case.doCleanups();m.QualificationArtifacts.tearDownClass()
`
	if out, err := exec.Command(python, "-c", setup, fixtures, root).CombinedOutput(); err != nil {
		t.Fatalf("signed transfer fixture: %s %v", out, err)
	}
	source := filepath.Join(root, "source-fixture")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "go.mod"), []byte("module fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "go.mod"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = source
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("source fixture git: %s %v", out, err)
		}
	}
	// An invisible host temp namespace makes this independent of whether the
	// test itself runs on macOS or Linux. Only the preparer's persisted export
	// can move both real helper-created archives into the visible workspace.
	invisible := t.TempDir()
	temporary := invisible
	data, _ := os.ReadFile(filepath.Join(root, "environment"))
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TMPDIR=") {
			temporary = strings.TrimPrefix(line, "TMPDIR=")
		}
	}
	base := `set -euo pipefail
source "$1"
assert_current_vm_identity(){ :; }
# Guest execution is the replaced external boundary; no VM is contacted.
multipass_exec_short(){ if [[ "$*" == *'wc -l'* ]];then echo 7;else cat >/dev/null;fi; }
`
	for _, operation := range []struct{ name, program string }{{"source", `sync_repo "$2"`}, {"release", "stage_qualification_release"}} {
		caller := filepath.Join(root, operation.name+"-transfer.sh")
		if err := os.WriteFile(caller, []byte(base+operation.program+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", caller, common, source)
		cmd.Env = append(env, "TMPDIR="+temporary, "NAKPANEL_RUN_TOKEN=hosted-test123", "NAKPANEL_MULTIPASS_VM=nakpanel-hosted-test123", "NAKPANEL_MULTIPASS_ARCH=amd64", "NAKPANEL_RELEASE_BUNDLE="+filepath.Join(root, "selected-bundle"), "NAKPANEL_RELEASE_PUBLIC_KEY="+filepath.Join(root, "selected-public.pem"), "NAKPANEL_RELEASE_VERSION=1.2.3", "NAKPANEL_REMOTE_SRC=")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("actual %s archive helper used snap-invisible host temp: %s %v", operation.name, out, err)
		}
		if _, err := os.Stat(filepath.Join(root, "captured-"+operation.name+".tar")); err != nil {
			t.Errorf("actual %s archive was not transferred: %v", operation.name, err)
		} else {
			t.Logf("actual %s archive helper transferred through the Snap-visible workspace", operation.name)
		}
	}
	if temporary == invisible || filepath.Dir(temporary) != root {
		t.Errorf("hosted prep did not persist a private runner workspace TMPDIR: %s", data)
	}
}

func TestRequiredSecurityGateUsesDisposableHostedRunnerWithoutSkippingBuildFailures(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	// Decode explicit YAML names; these are the externally observable check contract.
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	jobs := document["jobs"].(map[string]any)
	security := jobs["security-suite"].(map[string]any)
	if security["name"] != "adversarial security + reliability gate (Multipass)" || security["runs-on"] != "ubuntu-24.04" {
		t.Fatalf("required security check changed identity or still needs unavailable infrastructure: %v", security["runs-on"])
	}
	if security["if"] != "always()" || security["needs"] != "release-build" {
		t.Fatal("failed artifact builds must produce a failed security check, never a skipped check")
	}
	steps := security["steps"].([]any)
	guard, prep, sequence := "", false, ""
	for _, raw := range steps {
		step := raw.(map[string]any)
		run, _ := step["run"].(string)
		if step["name"] == "Require the signed application build" {
			guard = run
		}
		prep = prep || strings.Contains(run, "prepare-hosted-runner.sh")
		sequence += run + "\n"
	}
	if guard == "" || !prep {
		t.Fatal("strict build dependency or reusable hosted preparation missing")
	}
	last := -1
	for _, script := range []string{"current-install-verify.sh", "phase28-verify.sh", "security-verify.sh", "phase29-verify.sh"} {
		next := strings.Index(sequence, script)
		if next <= last {
			t.Fatalf("required security/reliability sequence omitted or reordered %s", script)
		}
		last = next
	}
	for _, result := range []string{"success", "failure", "cancelled", "skipped"} {
		cmd := exec.Command("bash", "-c", guard+"\necho gates-may-run\n")
		cmd.Env = append(os.Environ(), "RELEASE_BUILD_RESULT="+result)
		out, err := cmd.CombinedOutput()
		if (err == nil) != (result == "success") || (strings.Contains(string(out), "gates-may-run")) != (result == "success") {
			t.Fatalf("upstream %s silently skipped/accepted security: %v: %s", result, err, out)
		}
	}
}

func TestRequiredSecurityGateStagesAuthenticatedPinnedNobleBeforeLaunch(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow qualificationWorkflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	program := ""
	pins := map[string]string{}
	stageIndex, capacityIndex, ownershipIndex := -1, -1, -1
	for index, step := range workflow.Jobs["security-suite"].Steps {
		if step.Name == "Stage the pinned signed Noble cloud image" {
			program, pins, stageIndex = step.Run, step.Env, index
		}
		if strings.Contains(step.Run, "hosted-runner-preflight.py") {
			capacityIndex = index
		}
		if strings.Contains(step.Run, "init_qualification_run") {
			ownershipIndex = index
		}
	}
	common, err := filepath.Abs("common.sh")
	if err != nil {
		t.Fatal(err)
	}
	image := "pinned official cloud image fixture\n"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(image)))
	for _, mode := range []string{"ready", "bad-signature", "manifest-mismatch", "image-mismatch", "invalid-serial"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			commands := map[string]string{
				"curl": `#!/usr/bin/env python3
import os,pathlib,sys
assert sys.argv[1:8]==['--fail','--location','--retry','3','--proto','=https','--proto-redir'],sys.argv
assert sys.argv[8]=='=https' and sys.argv[-2]=='--output',sys.argv
url=sys.argv[9];name=url.rsplit('/',1)[-1]
assert url.startswith('https://cloud-images.ubuntu.com/releases/noble/release-20261017/'),url
root=pathlib.Path(os.environ['FIXTURE'])
with (root/'calls').open('a') as out:out.write('download:'+name+'\n')
target=pathlib.Path(sys.argv[-1])
if name=='SHA256SUMS':
 digest='0'*64 if os.environ['CLIENT_MODE']=='manifest-mismatch' else os.environ['IMAGE_SHA']
 target.write_text(digest+' *ubuntu-24.04-server-cloudimg-amd64.img\n')
elif name=='SHA256SUMS.gpg':target.write_text('signature fixture\n')
else:
 assert name=='ubuntu-24.04-server-cloudimg-amd64.img',name
 assert 'signature-verified' in (root/'calls').read_text(),'image download preceded signature validation'
 target.write_text('corrupt image' if os.environ['CLIENT_MODE']=='image-mismatch' else os.environ['IMAGE_BYTES'])
`,
				"gpgv": `#!/bin/sh
set -eu
test "$1" = --keyring && test "$2" = /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
test -f "$3" && test -f "$4"
test "$CLIENT_MODE" != bad-signature || exit 7
echo signature-verified >> "$FIXTURE/calls"
`,
				"multipass": `#!/bin/sh
set -eu
test "$1" = launch
case "$2" in
 file://*) echo "local-image-launched:$2" >> "$FIXTURE/calls";;
 *) echo 'launch failed: Remote "release" is unknown or unreachable.' >&2;exit 8;;
esac
`,
			}
			for name, body := range commands {
				if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			serial := "20261017"
			if mode == "invalid-serial" {
				serial = "latest/../unreviewed"
			}
			env := append(os.Environ(), "PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"), "FIXTURE="+root, "RUNNER_TEMP="+root, "GITHUB_ENV="+filepath.Join(root, "environment"), "NOBLE_SERIAL="+serial, "NOBLE_SHA256="+digest, "IMAGE_BYTES="+image, "IMAGE_SHA="+digest, "CLIENT_MODE="+mode)
			stage := exec.Command("bash", "-c", program)
			stage.Env = env
			output, stageErr := stage.CombinedOutput()
			if mode != "ready" {
				if stageErr == nil {
					t.Fatalf("%s image was staged without rejection: %s", mode, output)
				}
				if _, err := os.Stat(filepath.Join(root, "environment")); !os.IsNotExist(err) {
					t.Fatal("unverified image was exported for guest launch")
				}
				return
			}
			if stageErr != nil {
				t.Fatalf("pinned image staging: %s %v", output, stageErr)
			}
			exports := map[string]string{}
			data, _ := os.ReadFile(filepath.Join(root, "environment"))
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			for len(lines) >= 3 {
				name, delimiter, ok := strings.Cut(lines[0], "<<")
				if !ok || lines[2] != delimiter {
					t.Fatalf("invalid GitHub environment export: %s", data)
				}
				exports[name] = lines[1]
				env = append(env, name+"="+lines[1])
				lines = lines[3:]
			}
			launch := exec.Command("bash", "-c", `set -euo pipefail; source "$1"; multipass launch "$(resolve_multipass_launch_image)"`, "_", common)
			launch.Env = append(env, "NAKPANEL_MULTIPASS_IMAGE=24.04", "NAKPANEL_MULTIPASS_ARCH=amd64", "NAKPANEL_MULTIPASS_IMAGE_SOURCE="+exports["NAKPANEL_MULTIPASS_IMAGE_SOURCE"], "NAKPANEL_MULTIPASS_IMAGE_SHA256="+exports["NAKPANEL_MULTIPASS_IMAGE_SHA256"])
			if out, err := launch.CombinedOutput(); err != nil {
				t.Fatalf("required security still depends on the unavailable release alias: %s %v", out, err)
			}
			if exports["NAKPANEL_MULTIPASS_IMAGE_SHA256"] != digest {
				t.Fatalf("independently pinned image hash missing: %v", exports)
			}
		})
	}
	if stageIndex < 0 || stageIndex >= capacityIndex || capacityIndex >= ownershipIndex {
		t.Fatal("authenticated image staging must precede measured capacity and owned launch")
	}
	metadata, err := os.ReadFile("../../.github/workflows/ubuntu-hosted-qualification.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(metadata, &workflow); err != nil {
		t.Fatal(err)
	}
	inputs := workflow.On["workflow_dispatch"].(map[string]any)["inputs"].(map[string]any)
	if pins["NOBLE_SERIAL"] != inputs["noble_image_serial"].(map[string]any)["default"] || pins["NOBLE_SHA256"] != inputs["noble_image_sha256"].(map[string]any)["default"] {
		t.Fatal("required security and full hosted matrix must use the identical pinned Noble image")
	}
}
