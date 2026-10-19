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

// The privacy assertion must reject a rendered credential even when it begins
// with a dash, and a failed file read must never count as proof of absence.
func TestValkeyCredentialPrivacyGuard(t *testing.T) {
	script, err := os.ReadFile("valkey-platform-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	// Execute the production assertion alone, without provisioning a guest.
	// Its preceding socket check and following runtime checks are separate gates.
	startMarker := `|| fail "domain cache page does not show the subscription socket"` + "\n"
	start := strings.Index(string(script), startMarker)
	if start < 0 {
		t.Fatal("cache page socket boundary is missing")
	}
	guard := string(script)[start+len(startMarker):]
	end := strings.Index(guard, "\nassert_valkey_boundary()")
	if end < 0 {
		t.Fatal("cache page privacy boundary is missing")
	}
	guard = guard[:end]
	for _, tc := range []struct {
		name       string
		credential string
		file       string
		wantPass   bool
	}{
		{"leading-hyphen-present", "-Pprivate-canary", "present", false},
		{"leading-hyphen-absent", "-Pprivate-canary", "absent", true},
		{"ordinary-present", "private-canary", "present", false},
		{"ordinary-absent", "private-canary", "absent", true},
		{"missing-html", "private-canary", "missing", false},
		{"unreadable-html", "private-canary", "unreadable", false},
		{"directory-read-error", "private-canary", "directory", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.file == "unreadable" && os.Geteuid() == 0 {
				t.Skip("root bypasses ordinary file read permissions; missing/directory cases still cover grep errors")
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "cache.html")
			const privateHTML = "private-html-canary"
			switch tc.file {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "missing":
			default:
				contents := "<html>" + privateHTML + "</html>\n"
				if tc.file == "present" {
					contents = "<html>" + privateHTML + tc.credential + "</html>\n"
				}
				if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
				if tc.file == "unreadable" {
					if err := os.Chmod(path, 0000); err != nil {
						t.Fatal(err)
					}
				}
			}
			program := `set -euo pipefail
credential=$1
tmpdir=$2
fail(){ echo "valkey-platform: $*" >&2; exit 1; }
` + guard + "\nprintf 'privacy-guard-passed\\n'\n"
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", "-c", program, "valkey-privacy-test", tc.credential, dir)
			output, runErr := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal("privacy guard did not terminate")
			}
			if strings.Contains(string(output), tc.credential) || strings.Contains(string(output), privateHTML) {
				t.Fatal("privacy guard printed credential or private HTML")
			}
			if tc.wantPass {
				if runErr != nil || string(output) != "privacy-guard-passed\n" {
					t.Fatalf("credential absence was not established cleanly: error=%v, output=%q", runErr, output)
				}
			} else if runErr == nil || strings.Contains(string(output), "privacy-guard-passed") {
				t.Fatalf("privacy assertion accepted rendered credential or unreadable HTML: error=%v", runErr)
			}
		})
	}
}
