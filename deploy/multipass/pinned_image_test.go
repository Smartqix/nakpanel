package multipass

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlatformPinnedImageRejectsInvalidInputBeforeLaunch(t *testing.T) {
	for _, test := range []string{"wrong digest", "missing digest", "missing source", "missing file", "symlink", "relative path"} {
		t.Run(test, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "ubuntu.img")
			content := []byte("trusted local cloud image fixture")
			if err := os.WriteFile(source, content, 0600); err != nil {
				t.Fatal(err)
			}
			digest := fmt.Sprintf("%x", sha256.Sum256(content))
			switch test {
			case "wrong digest":
				digest = strings.Repeat("0", 64)
			case "missing digest":
				digest = ""
			case "missing source":
				source = ""
			case "missing file":
				source += ".absent"
			case "symlink":
				target := source
				source += ".link"
				if err := os.Symlink(target, source); err != nil {
					t.Fatal(err)
				}
			case "relative path":
				source = "ubuntu.img"
			}
			calls := filepath.Join(dir, "calls")
			fake := `#!/bin/bash
printf '%s\n' "$*" >> "$FAKE_LOG"
if [[ "$1" == info ]]; then exit 1; fi
exit 88
`
			if err := os.WriteFile(filepath.Join(dir, "multipass"), []byte(fake), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", `set -euo pipefail; source ./common.sh; ensure_vm`)
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "FAKE_LOG="+calls, "NAKPANEL_RUN_TOKEN=pin123", "NAKPANEL_MULTIPASS_VM=nakpanel-24-04-arm64-pin123", "NAKPANEL_MULTIPASS_IMAGE=24.04", "NAKPANEL_MULTIPASS_ARCH=arm64", "NAKPANEL_OWNERSHIP_DIR="+dir, "NAKPANEL_MULTIPASS_IMAGE_SOURCE="+source, "NAKPANEL_MULTIPASS_IMAGE_SHA256="+digest)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("invalid image accepted: %s", out)
			}
			data, _ := os.ReadFile(calls)
			if strings.Contains(string(data), "launch") {
				t.Fatalf("unverified image launched: %s", data)
			}
		})
	}
}

func TestPlatformPinnedImageResolvesVerifiedFileAndDefaultAlias(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "ubuntu cloud.img")
	content := []byte("trusted local image")
	if err := os.WriteFile(source, content, 0600); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	sourceURI := (&url.URL{Scheme: "file", Path: resolved}).String()
	for _, tc := range []struct{ source, digest, want string }{{source, digest, sourceURI}, {"", "", "24.04"}} {
		cmd := exec.Command("bash", "-c", `set -euo pipefail; source ./common.sh; resolve_multipass_launch_image`)
		cmd.Env = append(os.Environ(), "NAKPANEL_MULTIPASS_IMAGE=24.04", "NAKPANEL_MULTIPASS_IMAGE_SOURCE="+tc.source, "NAKPANEL_MULTIPASS_IMAGE_SHA256="+tc.digest)
		out, err := cmd.CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != tc.want {
			t.Fatalf("image source: %s %v; want %s", out, err, tc.want)
		}
	}
}

func TestPlatformPinnedImageLaunchStillRequiresActualGuestRelease(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "noble.img")
	content := []byte("verified image")
	if err := os.WriteFile(source, content, 0600); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	sourceURI := (&url.URL{Scheme: "file", Path: resolved}).String()
	calls := filepath.Join(dir, "calls")
	fake := `#!/bin/bash
printf '%s\n' "$*" >> "$FAKE_LOG"
case "$1" in
 info) exit 1;;
 launch) test "$2" = "$FAKE_SOURCE_URI" || exit 77;;
 exec) case "$*" in
  *nakpanel-identity-probe*) printf '24.04\narm64\n';;
  *'cloud-init status'*) printf 'status: done\n';;
  *) echo UNSAFE >> "$FAKE_LOG";exit 99;;
 esac;;
 *) echo UNSAFE >> "$FAKE_LOG";exit 99;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "multipass"), []byte(fake), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `set -euo pipefail; source ./common.sh; ensure_vm`)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "FAKE_SOURCE_URI="+sourceURI, "FAKE_LOG="+calls, "NAKPANEL_RUN_TOKEN=pin123", "NAKPANEL_MULTIPASS_VM=nakpanel-26-04-arm64-pin123", "NAKPANEL_MULTIPASS_IMAGE=26.04", "NAKPANEL_MULTIPASS_ARCH=arm64", "NAKPANEL_OWNERSHIP_DIR="+dir, "NAKPANEL_MULTIPASS_IMAGE_SOURCE="+source, "NAKPANEL_MULTIPASS_IMAGE_SHA256="+digest, "NAKPANEL_QUALIFICATION_VM_CPUS=2", "NAKPANEL_QUALIFICATION_VM_MEMORY=5G", "NAKPANEL_QUALIFICATION_VM_DISK=32G")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("wrong guest release accepted: %s", out)
	}
	data, _ := os.ReadFile(calls)
	if !strings.Contains(string(data), "launch "+sourceURI+" --name") || !strings.Contains(string(data), "--cpus 2 --memory 5G --disk 32G") || strings.Contains(string(data), "UNSAFE") {
		t.Fatalf("launch/identity guard: %s %s", data, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "pin123", "nakpanel-26-04-arm64-pin123")); !os.IsNotExist(err) {
		t.Fatal("wrong guest claimed")
	}
}

func TestPlatformStaleImageEvidenceRejectsBeforeAnyLaunch(t *testing.T) {
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	record := filepath.Join(dir, "ownership", "testtoken", "nakpanel-test-native.image.json")
	if err := os.MkdirAll(filepath.Dir(record), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte(`{"source":"preserved earlier launch"}`), 0600); err != nil {
		t.Fatal(err)
	}
	fake := "#!/bin/bash\nprintf '%s\\n' \"$*\" >> \"$FAKE_LOG\"\nif [[ \"$1\" == info ]]; then exit 1; fi\nexit 79\n"
	if err := os.WriteFile(filepath.Join(dir, "multipass"), []byte(fake), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `set -euo pipefail; source ./common.sh; ensure_vm 2 5G 32G`)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "FAKE_LOG="+calls, "NAKPANEL_OWNERSHIP_DIR="+filepath.Join(dir, "ownership"), "NAKPANEL_RUN_TOKEN=testtoken", "NAKPANEL_MULTIPASS_VM=nakpanel-test-native", "NAKPANEL_MULTIPASS_IMAGE=26.04", "NAKPANEL_MULTIPASS_ARCH=arm64")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("stale image evidence accepted: %s", out)
	}
	data, _ := os.ReadFile(calls)
	if strings.Contains(string(data), "launch") {
		t.Fatalf("launched before stale evidence check: %s %s", data, out)
	}
	evidence, err := os.ReadFile(record)
	if err != nil || !strings.Contains(string(evidence), "preserved earlier launch") {
		t.Fatal("earlier image evidence mutated")
	}
}
