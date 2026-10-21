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

// Execute the actual phase18 maintenance boundary with filesystem/systemctl
// effects redirected to a private root. A tenant PHP8.3 may exist on Sury but
// must not be selected for its internal PHP8.5 webmail database.
func TestRoundcubeMaintenanceProfiles(t *testing.T) {
	for _, tc := range []struct{ profile, release, codename, php string }{
		{"ubuntu-26.04-native", "26.04", "resolute", "8.5"},
		{"ubuntu-26.04-sury", "26.04", "resolute", "8.5"},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			f := newMaintenanceFixture(t, tc.profile, tc.release, tc.codename, true, 0)
			first, err := f.run(t, false)
			if err != nil {
				t.Fatalf("maintenance failed: %v %s", err, first)
			}
			files := f.managedFiles(t)
			second, err := f.run(t, false)
			if err != nil {
				t.Fatalf("idempotent retry failed: %v %s", err, second)
			}
			for _, name := range []string{"/etc/systemd/system/roundcube-gc.service.d/nakpanel.conf", "/etc/systemd/system/roundcube-gc.service", "/etc/systemd/system/roundcube-gc.timer"} {
				if f.exists(name) {
					info, err := os.Stat(f.root + name)
					if err != nil || info.Mode().Perm() != 0644 {
						t.Fatalf("unsafe managed unit mode for %s", name)
					}
				}
			}
			if files != f.managedFiles(t) {
				t.Fatal("idempotent install changed rendered unit bytes")
			}
			dropin := f.read(t, "/etc/systemd/system/roundcube-gc.service.d/nakpanel.conf")
			if !strings.Contains(dropin, "ExecStart=\nExecStart=/usr/bin/php"+tc.php+" /usr/share/roundcube/bin/gc.sh\n") {
				t.Fatalf("incorrect maintenance runtime: %s", dropin)
			}
			if tc.release == "24.04" {
				if f.exists("/etc/systemd/system/roundcube-gc.service") || f.exists("/etc/systemd/system/roundcube-gc.timer") {
					t.Fatal("Noble package unit/timer replaced")
				}
				if f.read(t, "/usr/lib/systemd/system/roundcube-gc.service") != nobleMaintenanceUnit || f.read(t, "/usr/lib/systemd/system/roundcube-gc.timer") != nobleMaintenanceTimer {
					t.Fatal("Noble package maintenance assets changed")
				}
			} else {
				unit := f.read(t, "/etc/systemd/system/roundcube-gc.service")
				for _, line := range []string{"Type=oneshot\n", "User=www-data\n", "Group=www-data\n", "ConditionPathExists=/etc/roundcube/config.inc.php\n", "ProtectSystem=strict\n", "ReadWritePaths=/var/lib/roundcube /var/log/roundcube\n"} {
					if !strings.Contains(unit, line) {
						t.Fatalf("missing maintenance boundary %q", line)
					}
				}
				timer := f.read(t, "/etc/systemd/system/roundcube-gc.timer")
				for _, line := range []string{"OnCalendar=daily\n", "Persistent=true\n", "WantedBy=timers.target\n"} {
					if !strings.Contains(timer, line) {
						t.Fatalf("missing daily timer boundary %q", line)
					}
				}
			}
			events := f.events(t)
			phpCalls := 0
			for _, event := range events {
				if event.Name == "php" {
					phpCalls++
					if event.Runtime != tc.php {
						t.Fatalf("maintenance used tenant/PATH PHP: %+v", event)
					}
				}
				if event.Name == "install" && !event.RootOwned {
					t.Fatalf("managed maintenance assets must request root:root ownership: %+v", event)
				}
				if tc.release == "24.04" && event.Name == "timer-enable" {
					t.Fatal("Noble package timer enablement changed")
				}
			}
			if phpCalls != 2 {
				t.Fatalf("maintenance invocations=%d want2", phpCalls)
			}
		})
	}
}

func TestRoundcubeMaintenanceConfigurationAndFailureBoundaries(t *testing.T) {
	for _, profile := range []string{"ubuntu-26.04-native", "ubuntu-26.04-sury"} {
		for _, tc := range []struct {
			name       string
			configured bool
			phpExit    int
			want       bool
		}{
			{"fresh-unconfigured", false, 0, true}, {"configured-start-failure", true, 17, false}, {"configured-success", true, 0, true},
		} {
			t.Run(profile+"/"+tc.name, func(t *testing.T) {
				release, codename := "26.04", "resolute"
				f := newMaintenanceFixture(t, profile, release, codename, tc.configured, tc.phpExit)
				out, err := f.run(t, false)
				if (err == nil) != tc.want {
					t.Fatalf("success=%v want%v: %v %s", err == nil, tc.want, err, out)
				}
				phpCalls := 0
				for _, event := range f.events(t) {
					if event.Name == "php" {
						phpCalls++
					}
				}
				if tc.configured && phpCalls != 1 {
					t.Fatalf("configured maintenance calls=%d want1", phpCalls)
				}
				if tc.configured && f.read(t, "/etc/roundcube/config.inc.php") != "existing-private-config-preserved\n" {
					t.Fatal("existing webmail config changed")
				}
				if !tc.configured && (phpCalls != 0 || f.exists("/etc/roundcube/config.inc.php")) {
					t.Fatal("unconfigured installation executed PHP or invented webmail config")
				}
			})
		}
	}
}

func TestRoundcubeMaintenanceValidatesPlatformBeforeWrites(t *testing.T) {
	f := newMaintenanceFixture(t, "ubuntu-26.04-native", "26.04", "resolute", true, 0)
	out, err := f.run(t, true)
	if err == nil {
		t.Fatalf("invalid platform accepted: %s", out)
	}
	if len(f.events(t)) != 0 {
		t.Fatal("platform failure must precede file installation or systemctl actions")
	}
}

type maintenanceEvent struct {
	Name      string `json:"name"`
	Runtime   string `json:"runtime"`
	RootOwned bool   `json:"root_owned"`
}
type maintenanceFixture struct {
	dir, root, scriptDir, profile string
	phpExit                       int
}

// Exact package assets from Ubuntu roundcube-core1.6.6+dfsg-2ubuntu0.1;
// SHA256/provenance is retained with the integration evidence.
const nobleMaintenanceUnit = "[Unit]\nDescription=Purge expired Roundcube sessions, caches and tempfiles\nDocumentation=https://github.com/roundcube/roundcubemail/wiki/Installation\n\n[Service]\nType=oneshot\nUser=www-data\nGroup=www-data\nExecStart=/usr/share/roundcube/bin/gc.sh\n\n# Hardening -- further hardening can be achieved via unit overrides:\n# - if sqlite is used, set RestrictAddressFamilies=none;\n# - otherwise, set ProtectSystem=strict and set RestrictAddressFamilies\n#   to the address family used for DB connection\n#\nNoNewPrivileges=yes\nPrivateDevices=yes\nProtectHome=yes\nProtectSystem=full\nProtectControlGroups=yes\nProtectKernelModules=yes\nProtectKernelTunables=yes\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n# these ReadWritePaths= directives are useless for ProtectSystem=full\n# but handy when overridden with ProtectSystem=strict\nReadWritePaths=/var/lib/roundcube/temp\nReadWritePaths=/var/log/roundcube\n"
const nobleMaintenanceTimer = "[Unit]\nDescription=Purge expired Roundcube sessions, caches and tempfiles\n\n[Timer]\nOnCalendar=*-*-* *:05,35:00\nPersistent=false\n\n[Install]\nWantedBy=timers.target\n"

func newMaintenanceFixture(t *testing.T, profile, release, codename string, configured bool, phpExit int) *maintenanceFixture {
	t.Helper()
	// Bash reads these dependencies outside Go's test log. Register them here
	// so a normal cached test cannot conceal a changed helper or unit template.
	for _, name := range []string{
		"../install/platform.sh", "../install/roundcube-maintenance.sh",
		"../systemd/roundcube-gc.service.d/nakpanel.conf",
		"../systemd/roundcube-gc.service", "../systemd/roundcube-gc.timer",
		"../systemd/stalwart-mail.service",
	} {
		if _, err := os.ReadFile(name); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	f := &maintenanceFixture{dir: dir, root: filepath.Join(dir, "root"), scriptDir: filepath.Join(filepath.Dir(cwd), "install"), profile: profile, phpExit: phpExit}
	f.write(t, "/events", "")
	f.write(t, "/os-release", "ID=ubuntu\nVERSION_ID="+release+"\nVERSION_CODENAME="+codename+"\n")
	if configured {
		f.write(t, "/etc/roundcube/config.inc.php", "existing-private-config-preserved\n")
	}
	if release == "24.04" {
		f.write(t, "/usr/lib/systemd/system/roundcube-gc.service", nobleMaintenanceUnit)
		f.write(t, "/usr/lib/systemd/system/roundcube-gc.timer", nobleMaintenanceTimer)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	stub := "#!" + python + "\n" + maintenanceBoundaryStub
	for _, name := range []string{"install", "systemctl"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(stub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	return f
}
func (f *maintenanceFixture) run(t *testing.T, invalid bool) ([]byte, error) {
	t.Helper()
	script := readExecutableScript(t, "../install/phase18-install.sh")
	start := strings.Index(script, "# The package's env-php shebang")
	if start < 0 {
		t.Fatal("maintenance phase18 boundary missing")
	}
	end := strings.Index(script[start:], "# The service starts on the first configure_mail run")
	if end < 0 {
		t.Fatal("maintenance phase18 end missing")
	}
	program := `set -euo pipefail
SCRIPT_DIR=$1
source "$SCRIPT_DIR/platform.sh"
nakpanel_require_platform() { test "$INVALID_PLATFORM" != 1 || return 59; nakpanel_load_platform "$FIXTURE_ROOT/os-release" arm64; if [[ "$PROFILE" == ubuntu-26.04-sury ]]; then nakpanel_select_php_provider sury; fi; }
# Deliberately inherited spoof: the maintenance helper must revalidate it.
NAKPANEL_PLATFORM_ID=$PROFILE
NAKPANEL_INTERNAL_PHP_VERSION=8.3
` + script[start:start+end]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", program, "maintenance-fixture", f.scriptDir)
	invalidValue := "0"
	if invalid {
		invalidValue = "1"
	}
	cmd.Env = append(os.Environ(), "PATH="+f.dir+":"+os.Getenv("PATH"), "FIXTURE_ROOT="+f.root, "PROFILE="+f.profile, "PHP_EXIT="+strconv.Itoa(f.phpExit), "INVALID_PLATFORM="+invalidValue)
	return cmd.CombinedOutput()
}
func (f *maintenanceFixture) write(t *testing.T, name, value string) {
	t.Helper()
	p := f.root + name
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}
func (f *maintenanceFixture) read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(f.root + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func (f *maintenanceFixture) exists(name string) bool {
	_, err := os.Stat(f.root + name)
	return err == nil
}
func (f *maintenanceFixture) events(t *testing.T) []maintenanceEvent {
	t.Helper()
	var events []maintenanceEvent
	for _, line := range strings.Split(strings.TrimSpace(f.read(t, "/events")), "\n") {
		if line == "" {
			continue
		}
		var e maintenanceEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	return events
}
func (f *maintenanceFixture) managedFiles(t *testing.T) string {
	t.Helper()
	var result strings.Builder
	for _, name := range []string{"/etc/systemd/system/roundcube-gc.service.d/nakpanel.conf", "/etc/systemd/system/roundcube-gc.service", "/etc/systemd/system/roundcube-gc.timer"} {
		if f.exists(name) {
			result.WriteString(name + f.read(t, name))
		}
	}
	return result.String()
}

const maintenanceBoundaryStub = `import os,sys,pathlib,json,shutil
root=pathlib.Path(os.environ['FIXTURE_ROOT']);args=sys.argv[1:];name=pathlib.Path(sys.argv[0]).name
def event(name,**extra):
 with (root/'events').open('a') as f:f.write(json.dumps(dict(name=name,**extra))+'\n')
def mapped(path):return root/str(path).lstrip('/')
if name=='install':
 owner='-o' in args and args[args.index('-o')+1]=='root' and '-g' in args and args[args.index('-g')+1]=='root'
 event('install' if any('roundcube-gc' in a for a in args) else 'install-other',root_owned=owner)
 mode=int(args[args.index('-m')+1],8) if '-m' in args else 0o755
 positional=[];i=0
 while i<len(args):
  if args[i] in ('-m','-o','-g'):i+=2
  elif args[i]=='-d':i+=1
  else:positional.append(args[i]);i+=1
 if '-d' in args:
  for path in positional:mapped(path).mkdir(parents=True,exist_ok=True)
 else:
  target=mapped(positional[-1]);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(positional[-2],target);target.chmod(mode)
 sys.exit(0)
if args==['daemon-reload']:event('reload');sys.exit(0)
if args==['enable','--now','roundcube-gc.timer']:
 if not mapped('/etc/systemd/system/roundcube-gc.timer').is_file():sys.exit(19)
 event('timer-enable');sys.exit(0)
if args==['start','roundcube-gc.service']:
 unit=mapped('/etc/systemd/system/roundcube-gc.service')
 if not unit.exists():unit=mapped('/usr/lib/systemd/system/roundcube-gc.service')
 if not unit.is_file():print('unit not found',file=sys.stderr);sys.exit(5)
 text=unit.read_text();drop=mapped('/etc/systemd/system/roundcube-gc.service.d/nakpanel.conf')
 if drop.exists():text+='\n'+drop.read_text()
 conditions=[l.split('=',1)[1] for l in text.splitlines() if l.startswith('ConditionPathExists=')]
 if any(not mapped(c).exists() for c in conditions):event('condition-skip');sys.exit(0)
 starts=[l.split('=',1)[1] for l in text.splitlines() if l.startswith('ExecStart=') and l!='ExecStart=']
 command=starts[-1].split();runtime=pathlib.Path(command[0]).name.removeprefix('php')
 event('php',runtime=runtime)
 if os.environ['PROFILE']=='ubuntu-26.04-native' and runtime!='8.5':sys.exit(127)
 sys.exit(int(os.environ['PHP_EXIT']))
print('unexpected systemctl operation',file=sys.stderr);sys.exit(99)
`
