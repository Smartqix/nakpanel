package multipass

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The real quota4.09 print-state contract returns1 for one enabled class.
// A conventional zero-exit check rejects healthy quotas; ignoring errors can
// instead accept an unrelated/ambiguous ON line. Exercise the shipped checker
// at its external command boundary, without invoking quota mutation commands.
func TestQualificationQuotaPrintState(t *testing.T) {
	const on = "user quota on / (/dev/sda1) is on\n"
	const warning = "quotaon: Cannot stat() mounted device tmpfs: No such file or directory\n"
	for _, tc := range []struct {
		name, stdout, stderr string
		status               int
		want                 bool
	}{
		{"noble-user-enabled", on, "", 1, true},
		{"native26-observed-tmpfs-scans", on, warning + warning, 1, true},
		{"sury26-user-enabled", on, "", 1, true},
		{"user-disabled", "user quota on / (/dev/sda1) is off\n", "", 0, false},
		{"enabled-output-with-zero-exit", on, "", 0, false},
		{"default-all-classes-exit", on, "", 2, false},
		{"execution-error", on, "", 127, false},
		{"empty-state", "", "", 1, false},
		{"wrong-device", "user quota on / (/dev/vdb1) is on\n", "", 1, false},
		{"wrong-target", "user quota on /home (/dev/sda1) is on\n", "", 1, false},
		{"group-only", "group quota on / (/dev/sda1) is on\n", "", 1, false},
		{"multiple-state", on + "group quota on / (/dev/sda1) is on\n", "", 1, false},
		{"repeated-state", on + on, "", 1, false},
		{"trailing-unknown", on + "unknown\n", "", 1, false},
		{"trailing-blank", on + "\n", "", 1, false},
		{"missing-newline", strings.TrimSuffix(on, "\n"), "", 1, false},
		{"accounting-only", "user quota on / (/dev/sda1) is on (accounting)\n", "", 1, false},
		{"unknown-diagnostic", on, "quotaon: permission denied\n", 1, false},
		{"known-then-unknown-diagnostic", on, warning + "quotaon: permission denied\n", 1, false},
		{"different-device-diagnostic", on, strings.ReplaceAll(warning, "tmpfs", "/dev/sda1"), 1, false},
		{"trailing-diagnostic-blank", on, warning + "\n", 1, false},
		{"unterminated-diagnostic", on, strings.TrimSuffix(warning, "\n"), 1, false},
		{"excessive-diagnostics", on, strings.Repeat(warning, 1000), 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newQuotaFixture(t, tc.stdout, tc.stderr, tc.status)
			out, err := f.run(t, "python3", filepath.Join(f.repo, "qualification_quota.py"), "/home")
			if (err == nil) != tc.want {
				t.Fatalf("success=%v want%v: %v %s", err == nil, tc.want, err, out)
			}
			if tc.want {
				f.assertReadOnlyCommands(t)
			}
		})
	}
}

func TestQualificationQuotaRejectsUnresolvedMount(t *testing.T) {
	for _, tc := range []struct {
		name, mount string
		exit        int
	}{
		{"findmnt-failure", `{"filesystems":[{"target":"/","source":"/dev/sda1"}]}`, 1},
		{"empty-mount", `{"filesystems":[]}`, 0},
		{"multiple-mounts", `{"filesystems":[{"target":"/","source":"/dev/sda1"},{"target":"/home","source":"/dev/sdb1"}]}`, 0},
		{"missing-device", `{"filesystems":[{"target":"/"}]}`, 0},
		{"relative-device", `{"filesystems":[{"target":"/","source":"tmpfs"}]}`, 0},
		{"newline-target", `{"filesystems":[{"target":"/\nforeign","source":"/dev/sda1"}]}`, 0},
		{"malformed-json", `not-json`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newQuotaFixture(t, "user quota on / (/dev/sda1) is on\n", "", 1)
			f.env = append(f.env, "QUOTA_MOUNT="+tc.mount, "QUOTA_MOUNT_EXIT="+strconv.Itoa(tc.exit))
			out, err := f.run(t, "python3", filepath.Join(f.repo, "qualification_quota.py"), "/home")
			if err == nil {
				t.Fatalf("invalid mount accepted: %s", out)
			}
			for _, c := range f.calls(t) {
				if c.Name == "quotaon" {
					t.Fatal("quota queried after invalid mount")
				}
			}
		})
	}
}

func TestPhase30QuotaAssertionsUseStrictPrintState(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	start := strings.Index(script, "set -euo pipefail\nusername=\"$1\"; second_username=")
	if start < 0 {
		t.Fatal("initial isolation assertion missing")
	}
	end := strings.Index(script[start:], "\nquota -u ")
	if end < 0 {
		t.Fatal("initial quota boundary missing")
	}
	initial := script[start : start+end]
	start = strings.Index(script, "# Persistence is observed before application or system reconciliation.")
	if start < 0 {
		t.Fatal("reboot persistence assertion missing")
	}
	end = strings.Index(script[start:], "\nVM_IP=")
	if end < 0 {
		t.Fatal("reboot persistence assertion missing")
	}
	reboot := script[start : start+end]
	for _, boundary := range []struct{ name, program string }{{"initial", initial}, {"after-reboot", reboot}} {
		for _, tc := range []struct {
			name, output string
			status       int
			want         bool
		}{
			{"healthy-enabled", "user quota on / (/dev/sda1) is on\n", 1, true},
			{"ambiguous-error-with-on-line", "user quota on / (/dev/sda1) is on\n", 2, false},
			{"wrong-mount-on", "user quota on /other (/dev/sda1) is on\n", 1, false},
		} {
			t.Run(boundary.name+"/"+tc.name, func(t *testing.T) {
				f := newQuotaFixture(t, tc.output, "", tc.status)
				program := `set -euo pipefail
NAKPANEL_REMOTE_SRC=$1
VM_NAME=fixture
multipass_exec_short() { shift; test "$1" = --; shift; test "$1" = sudo; shift; "$@"; }
` + boundary.program
				// The early guest block's fifth argument is the protected staged source.
				out, err := f.run(t, "bash", "-c", program, "quota-boundary", filepath.Dir(filepath.Dir(f.repo)), "other", "1", "/home/site", filepath.Dir(filepath.Dir(f.repo)))
				if (err == nil) != tc.want {
					t.Fatalf("success=%v want%v: %v %s", err == nil, tc.want, err, out)
				}
			})
		}
	}
}

type quotaCall struct {
	Name   string   `json:"name"`
	Args   []string `json:"args"`
	Locale string   `json:"locale"`
}
type quotaFixture struct {
	dir, repo string
	env       []string
}

func newQuotaFixture(t *testing.T, stdout, stderr string, status int) *quotaFixture {
	t.Helper()
	dir := t.TempDir()
	repo, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	stub := "#!" + python + `\nimport os,sys,json,pathlib
name=pathlib.Path(sys.argv[0]).name
with open(os.environ['QUOTA_CALLS'],'a') as f:f.write(json.dumps({'name':name,'args':sys.argv[1:],'locale':os.environ.get('LC_ALL')})+'\n')
if name=='findmnt':
 if '--json' in sys.argv: print(os.environ.get('QUOTA_MOUNT','{"filesystems":[{"target":"/","source":"/dev/sda1"}]}'))
 elif '-n' in sys.argv: print('/')
 else: print('TARGET SOURCE FSTYPE OPTIONS\n/ /dev/sda1 ext4 rw,usrquota,grpquota')
 sys.exit(int(os.environ.get('QUOTA_MOUNT_EXIT','0')))
sys.stdout.write(pathlib.Path(os.environ['QUOTA_STDOUT']).read_text());sys.stderr.write(pathlib.Path(os.environ['QUOTA_STDERR']).read_text());sys.exit(int(os.environ['QUOTA_EXIT']))
`
	stub = strings.Replace(stub, `\n`, "\n", 1)
	for _, name := range []string{"quotaon", "findmnt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(stub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range map[string]string{"stdout": stdout, "stderr": stderr, "calls": ""} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return &quotaFixture{dir: dir, repo: repo, env: []string{"PATH=" + dir + ":" + os.Getenv("PATH"), "LC_ALL=spoofed_locale", "QUOTA_CALLS=" + filepath.Join(dir, "calls"), "QUOTA_STDOUT=" + filepath.Join(dir, "stdout"), "QUOTA_STDERR=" + filepath.Join(dir, "stderr"), "QUOTA_EXIT=" + strconv.Itoa(status)}}
}
func (f *quotaFixture) run(t *testing.T, name string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), f.env...)
	return cmd.CombinedOutput()
}
func (f *quotaFixture) calls(t *testing.T) []quotaCall {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	var calls []quotaCall
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "" {
			continue
		}
		var c quotaCall
		if err := json.Unmarshal([]byte(l), &c); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, c)
	}
	return calls
}
func (f *quotaFixture) assertReadOnlyCommands(t *testing.T) {
	t.Helper()
	calls := f.calls(t)
	if len(calls) != 2 {
		t.Fatalf("calls=%v", calls)
	}
	m := calls[0]
	if m.Name != "findmnt" || strings.Join(m.Args, " ") != "--json --output TARGET,SOURCE --target /home" || m.Locale != "C" {
		t.Fatalf("mount lookup must select the hosting filesystem in C locale: %+v", m)
	}
	q := calls[1]
	if q.Name != "quotaon" || strings.Join(q.Args, " ") != "-p -u /" || q.Locale != "C" {
		t.Fatalf("quota call must select only read-only user state in C locale: %+v", q)
	}
}
