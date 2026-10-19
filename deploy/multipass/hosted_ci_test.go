package multipass

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
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
	for _, mode := range []string{"ready", "delayed-kvm", "reset-kvm", "missing", "symlink", "not-root", "acl-failure", "settle-failure", "missing-kvm", "symlink-kvm", "not-root-kvm", "kvm-acl-failure"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			commands := map[string]string{
				"uname": `#!/bin/sh
case "$1" in -s) echo Linux;; -m) echo x86_64;; *) exit 90;; esac
`,
				"id": `#!/bin/sh
test "$1" = -u || exit 90
echo 1001
`,
				"df":    "#!/bin/sh\necho 'disposable hosted disk fixture'\n",
				"sleep": "#!/bin/sh\nexit 0\n",
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
 rm|docker|apt-get|snap) :;;
 *) exit 96;;
esac
`,
				"multipass": `#!/bin/sh
set -eu
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
 *) exit 97;;
esac
`,
				"python3": `#!/bin/sh
exec "$FIXTURE_PYTHON" "$@" --timeout 0.2 --attempt-timeout 0.05 --retry-interval 0.01
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
			cmd.Env = append(os.Environ(), "PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"), "FIXTURE="+root, "FIXTURE_PYTHON="+python, "RUNNER_TEMP="+root, "GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted", "CLIENT_MODE="+mode)
			output, runErr := cmd.CombinedOutput()
			wantReady := mode == "ready" || mode == "delayed-kvm" || mode == "reset-kvm"
			if (runErr == nil) != wantReady {
				t.Fatalf("mode=%s preparation err=%v: %s", mode, runErr, output)
			}
			commandsLog, _ := os.ReadFile(filepath.Join(root, "host-commands"))
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
			}
		})
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
