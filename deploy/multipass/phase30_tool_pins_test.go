package multipass

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A universal Noble pin rejects supported Resolute tools; substring matching
// accepts a different release such as 2.10.30. Exercise the actual assertions.
func TestPhase30ToolVersionBoundaries(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	start := strings.Index(script, `python3 - "${tmpdir}/runtime.json"`)
	if start < 0 {
		t.Fatal("runtime inventory assertion is missing")
	}
	end := strings.Index(script[start:], "\nPY\n")
	if end < 0 {
		t.Fatal("runtime inventory assertion terminator is missing")
	}
	runtimeCheck := script[start : start+end+4]
	var commandChecks []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "grep -") && (strings.Contains(line, `<<<"${composer_version_before}"`) || strings.Contains(line, `<<<"${wp_info}"`) || strings.Contains(line, `<<<"${wp_version}"`)) {
			commandChecks = append(commandChecks, line)
		}
	}
	if len(commandChecks) != 3 {
		t.Fatalf("got %d direct tool assertions, want3", len(commandChecks))
	}
	uiStart := strings.Index(script, "# Runtime inventory is provider-only")
	uiEnd := strings.Index(script, "for marker in 'Managed PHP deployments'")
	if uiStart < 0 || uiEnd <= uiStart {
		t.Fatal("runtime UI assertion boundary is missing")
	}
	uiCheck := script[uiStart:uiEnd]
	for _, tc := range []struct {
		name, expectedComposer, composer, wp string
		wantPass                             bool
	}{
		{"noble-current", "2.8.11", "2.8.11", "2.12.0", true},
		{"resolute-native-current", "2.10.3", "2.10.3", "2.12.0", true},
		{"resolute-sury-current", "2.10.3", "2.10.3", "2.12.0", true},
		{"noble-foreign-composer", "2.8.11", "2.10.3", "2.12.0", false},
		{"resolute-stale-composer", "2.10.3", "2.8.11", "2.12.0", false},
		{"resolute-neighbor-composer", "2.10.3", "2.10.30", "2.12.0", false},
		{"noble-neighbor-composer", "2.8.11", "2.8.110", "2.12.0", false},
		{"wrong-wp-cli", "2.10.3", "2.10.3", "2.12.1", false},
		{"neighbor-wp-cli", "2.8.11", "2.8.11", "2.12.00", false},
	} {
		for _, boundary := range []string{"runtime-json", "direct-cli", "rendered-ui"} {
			t.Run(tc.name+"/"+boundary, func(t *testing.T) {
				dir := t.TempDir()
				runtime := map[string]any{"version": "8.5", "ready": true, "cli_available": true, "fpm_available": true, "fpm_config_valid": true, "opcache_available": true, "missing_extensions": []string{}, "validation_errors": []string{}, "extensions": []string{"bcmath", "curl", "dom", "exif", "fileinfo", "gd", "imagick", "intl", "mbstring", "mysqli", "openssl", "redis", "simplexml", "soap", "xml", "zip", "Zend OPcache"}}
				payload := map[string]any{"ok": true, "data": map[string]any{"php_versions": []string{"8.5"}, "php_runtimes": []any{runtime}, "composer_available": true, "composer_version": tc.composer, "wp_cli_available": true, "wp_cli_version": tc.wp}}
				encoded, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "runtime.json"), encoded, 0600); err != nil {
					t.Fatal(err)
				}
				html := "<main>PHP Runtime Inventory FPM validation OPcache PHP 8.5 <span>Composer " + tc.composer + "</span><span>WP-CLI " + tc.wp + "</span></main>\n"
				if err := os.WriteFile(filepath.Join(dir, "php-runtime.html"), []byte(html), 0600); err != nil {
					t.Fatal(err)
				}
				program := `set -euo pipefail
tmpdir=$1
EXPECTED_COMPOSER_VERSION=$2
expected_composer_version=$2
EXPECTED_WPCLI_VERSION=2.12.0
expected_wp_cli_version=2.12.0
NAKPANEL_PHP_VERSIONS=8.5
composer_version_before="Composer version $3 2026-10-01 00:00:00"
wp_info="$(printf 'WP-CLI version:\t%s\n' "$4")"
wp_version="WP-CLI $4"
fail(){ exit 1; }
`
				switch boundary {
				case "runtime-json":
					program += runtimeCheck
				case "direct-cli":
					program += strings.Join(commandChecks, "\n")
				case "rendered-ui":
					program += uiCheck
				}
				output, runErr := runPhase30ToolAssertion(t, program, dir, tc.expectedComposer, tc.composer, tc.wp)
				if (runErr == nil) != tc.wantPass {
					t.Fatalf("pass=%t, want%t: %v\n%s", runErr == nil, tc.wantPass, runErr, output)
				}
			})
		}
	}
}

func TestPhase30SelectedDependencyPins(t *testing.T) {
	script := readExecutableScript(t, "phase30-verify.sh")
	definition := regexp.MustCompile(`(?s)phase30_expected_tool_versions\(\)\s*\{.*?\n\}\n`).FindString(script)
	if definition == "" {
		t.Fatal("selected profile has no fail-closed dependency pin resolver")
	}
	manifest, err := os.ReadFile("../install/dependencies.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, profile, mutation, want string
	}{
		{"noble", "ubuntu-24.04", "", "2.8.11\t2.12.0\n"},
		{"resolute-native", "ubuntu-26.04-native", "", "2.10.3\t2.12.0\n"},
		{"resolute-sury", "ubuntu-26.04-sury", "", "2.10.3\t2.12.0\n"},
		{"unknown-profile", "unsupported", "", ""},
		{"missing-schema", "ubuntu-24.04", "missing-schema", ""},
		{"wrong-schema", "ubuntu-24.04", "wrong-schema", ""},
		{"missing-profile", "ubuntu-26.04-native", "missing-profile", ""},
		{"missing-composer", "ubuntu-24.04", "missing-composer", ""},
		{"missing-wp-cli", "ubuntu-24.04", "missing-wp-cli", ""},
		{"invalid-version", "ubuntu-24.04", "invalid-version", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var data map[string]any
			if err := json.Unmarshal(manifest, &data); err != nil {
				t.Fatal(err)
			}
			switch tc.mutation {
			case "missing-schema":
				delete(data, "schema_version")
			case "wrong-schema":
				data["schema_version"] = 2
			case "missing-profile":
				delete(data, tc.profile)
			case "missing-composer":
				delete(data[tc.profile].(map[string]any), "composer")
			case "missing-wp-cli":
				delete(data[tc.profile].(map[string]any), "wp_cli")
			case "invalid-version":
				data[tc.profile].(map[string]any)["composer"] = "2.8.*"
			}
			encoded, err := json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "dependencies.json")
			if err := os.WriteFile(path, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			program := "set -euo pipefail\n" + definition + "phase30_expected_tool_versions \"$1\" \"$2\"\n"
			output, runErr := runPhase30ToolAssertion(t, program, path, tc.profile)
			if tc.want == "" {
				if runErr == nil {
					t.Fatalf("invalid manifest/profile accepted: %s", output)
				}
			} else if runErr != nil || string(output) != tc.want {
				t.Fatalf("resolved %q, want%q: %v", output, tc.want, runErr)
			}
		})
	}
}

func runPhase30ToolAssertion(t *testing.T, program string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", append([]string{"-c", program, "phase30-tool-test"}, args...)...)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("tool assertion exceeded bounded execution: %v", ctx.Err())
	}
	return output, err
}
