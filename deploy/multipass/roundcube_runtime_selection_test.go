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

// Selecting the tenant baseline breaks Surý's SQLite webmail; trusting an
// inherited version or skipping authoritative validation must also fail here.
func TestRoundcubeCanaryUsesValidatedInternalRuntime(t *testing.T) {
	helper, err := filepath.Abs("qualification-artifacts.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, profile, baseline, internal                    string
		rejectPlatform, missingPlatform, rejectProbe, legacy bool
	}{
		{name: "noble", profile: "ubuntu-24.04", baseline: "8.3", internal: "8.3"},
		{name: "resolute-native", profile: "ubuntu-26.04-native", baseline: "8.5", internal: "8.5"},
		{name: "resolute-sury-baseline83-internal85", profile: "ubuntu-26.04-sury", baseline: "8.3", internal: "8.5"},
		{name: "inherited-runtime-spoof", profile: "ubuntu-26.04-sury", baseline: "8.3", internal: "8.5"},
		{name: "platform-rejected", profile: "ubuntu-26.04-sury", baseline: "8.3", internal: "8.5", rejectPlatform: true},
		{name: "platform-source-missing", profile: "ubuntu-26.04-sury", baseline: "8.3", internal: "8.5", missingPlatform: true},
		{name: "public-probe-rejected", profile: "ubuntu-26.04-sury", baseline: "8.3", internal: "8.5", rejectProbe: true},
		{name: "legacy-noble-source", profile: "ubuntu-24.04", baseline: "8.3", internal: "8.3", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "private-source")
			bin := filepath.Join(dir, "bin")
			for _, path := range []string{filepath.Join(source, "deploy/install"), bin} {
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path, contents string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(contents), mode); err != nil {
					t.Fatal(err)
				}
			}
			// OS/root-record validation is the external guest boundary. Its fixture
			// returns the authoritative internal version, never the host's spoof.
			platform := "nakpanel_require_platform(){\n printf 'validate-platform\\n' >>\"$TRACE\"\n"
			if tc.rejectPlatform {
				platform += " return 69\n"
			} else {
				platform += " NAKPANEL_PLATFORM_ID=" + tc.profile + "\n NAKPANEL_INTERNAL_PHP_VERSION=" + tc.internal + "\n export NAKPANEL_INTERNAL_PHP_VERSION\n"
			}
			platform += "}\n"
			if !tc.missingPlatform {
				write(filepath.Join(source, "deploy/install/platform.sh"), platform, 0600)
			}
			// Only the external privilege/transport boundary is replaced. The real
			// root Bash payload and the real helper choose which PHP argv to execute.
			write(filepath.Join(bin, "sudo"), `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == bash ]]; then
 printf 'root-shell\n' >>"$TRACE"
 exec "$@"
fi
if [[ "$1" == -u && "$2" == www-data ]]; then
 shift 2
 printf '%s\0' "$@" >"$PHP_ARGV"
 printf 'php-canary\n' >>"$TRACE"
 exit 0
fi
exit 88
`, 0700)
			for _, command := range []string{"apt-get", "apt", "php"} {
				write(filepath.Join(bin, command), "#!/usr/bin/env bash\nprintf 'unexpected-package-or-path-command\\n' >>\"$TRACE\"\nexit 91\n", 0700)
			}
			trace := filepath.Join(dir, "trace")
			argv := filepath.Join(dir, "php-argv")
			probe := filepath.Join(dir, "public-probe.php")
			write(probe, "<?php // inert public probe fixture\n", 0600)
			program := `set -euo pipefail
source "$1"
multipass_exec_short(){
 [[ "$1" == owned-test-vm && "$2" == -- ]]
 shift 2
 "$@"
}
stage_qualification_public_probe(){
 printf 'stage-public-probe\n' >>"$TRACE"
 [[ "$REJECT_PROBE" == 0 ]] || return 73
 printf '%s\n' "$PUBLIC_PROBE"
}
run_qualification_roundcube_canary owned-test-vm assert canary@example.test
`
			bundle, rejectProbe := "selected-signed-bundle", "0"
			if tc.legacy {
				bundle = ""
				probe = filepath.Join(source, "deploy/multipass/roundcube-dr-canary.php")
			}
			if tc.rejectProbe {
				rejectProbe = "1"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", "-c", program, "roundcube-runtime-test", helper)
			command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TRACE="+trace, "PHP_ARGV="+argv, "PUBLIC_PROBE="+probe, "REJECT_PROBE="+rejectProbe, "NAKPANEL_RELEASE_BUNDLE="+bundle, "NAKPANEL_REMOTE_SRC="+source, "NAKPANEL_BASELINE_PHP="+tc.baseline, "NAKPANEL_INTERNAL_PHP_VERSION=9.9")
			output, runErr := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("runtime selection exceeded bounded execution: %v", ctx.Err())
			}
			invocation, readErr := os.ReadFile(argv)
			if tc.rejectPlatform || tc.missingPlatform || tc.rejectProbe {
				if runErr == nil || !os.IsNotExist(readErr) {
					t.Fatalf("unvalidated canary executed: error=%v argv=%q output=%s", runErr, invocation, output)
				}
				return
			}
			if runErr != nil {
				t.Fatalf("validated runtime rejected: %v\n%s", runErr, output)
			}
			want := "/usr/bin/php" + tc.internal + "\x00" + probe + "\x00assert\x00canary@example.test\x00"
			if readErr != nil || string(invocation) != want {
				t.Fatalf("canary argv=%q, want%q: %v", invocation, want, readErr)
			}
			observed, err := os.ReadFile(trace)
			if err != nil {
				t.Fatal(err)
			}
			wantTrace := "root-shell\nvalidate-platform\nphp-canary\n"
			if !tc.legacy {
				wantTrace = "stage-public-probe\n" + wantTrace
			}
			if strings.TrimSpace(string(observed)) != strings.TrimSpace(wantTrace) {
				t.Fatalf("canary ran outside root validation order: %q", observed)
			}
		})
	}
}
