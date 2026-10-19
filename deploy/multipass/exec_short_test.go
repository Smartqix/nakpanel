package multipass

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The external fake models only Multipass transport. The real shell wrapper
// must preserve binary input, propagate command results and remove its private
// buffers, including when it has to restart a hung client.
func TestMultipassExecShortPreservesInputAndResult(t *testing.T) {
	for _, tc := range []struct {
		name            string
		hangs, exitCode int
	}{
		{"success", 0, 0}, {"command failure", 0, 37},
		{"watchdog retry", 1, 0}, {"watchdog exhausted", 3, 124},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			buffers := filepath.Join(dir, "buffers")
			if err := os.Mkdir(buffers, 0700); err != nil {
				t.Fatal(err)
			}
			fake := `#!/bin/bash
set -eu
test "$1" = exec
n=0
test ! -f "$FAKE_DIR/count" || n=$(cat "$FAKE_DIR/count")
n=$((n+1)); printf '%s' "$n" >"$FAKE_DIR/count"
cat >"$FAKE_DIR/input.$n"
if [[ "$n" -le "$FAKE_HANGS" ]]; then exec sleep 30; fi
printf 'remote stdout\n'
printf 'remote stderr\n' >&2
exit "$FAKE_EXIT"
`
			if err := os.WriteFile(filepath.Join(dir, "multipass"), []byte(fake), 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", `source ./common.sh; multipass_exec_short nakpanel-test -- bash -se`)
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "FAKE_DIR="+dir,
				fmt.Sprintf("FAKE_HANGS=%d", tc.hangs), fmt.Sprintf("FAKE_EXIT=%d", tc.exitCode),
				"NAKPANEL_MULTIPASS_SHORT_TIMEOUT=1", "TMPDIR="+buffers)
			payload := []byte("private here-doc\nquotes ' \" $ ` \\ \x00\xff\nwithout-final-newline")
			cmd.Stdin = bytes.NewReader(payload)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			gotExit := 0
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					gotExit = exitErr.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if gotExit != tc.exitCode {
				t.Fatalf("exit=%d, want %d: %s", gotExit, tc.exitCode, stderr.String())
			}
			attempts := tc.hangs + 1
			if attempts > 3 {
				attempts = 3
			}
			for attempt := 1; attempt <= attempts; attempt++ {
				input, readErr := os.ReadFile(filepath.Join(dir, fmt.Sprintf("input.%d", attempt)))
				if readErr != nil || !bytes.Equal(input, payload) {
					t.Errorf("attempt %d lost input: %q, %v", attempt, input, readErr)
				}
			}
			if tc.hangs < 3 && (stdout.String() != "remote stdout\n" || !strings.Contains(stderr.String(), "remote stderr\n")) {
				t.Errorf("lost command output: %q / %q", stdout.String(), stderr.String())
			}
			if bytes.Contains(stdout.Bytes(), payload) || bytes.Contains(stderr.Bytes(), payload) {
				t.Error("private stdin leaked into diagnostic output")
			}
			remaining, readErr := os.ReadDir(buffers)
			if readErr != nil || len(remaining) != 0 {
				t.Errorf("private buffers retained: %v, %v", remaining, readErr)
			}
		})
	}
}

func TestMultipassExecShortDoesNotWaitForTerminalInput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "multipass"), []byte("#!/bin/bash\ncat >\"$FAKE_INPUT\"\nprintf done\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-c", `import os,pty,subprocess
master,slave=pty.openpty()
try:
    result=subprocess.run(['bash','-c','source ./common.sh; multipass_exec_short nakpanel-test -- true'],stdin=slave,capture_output=True,timeout=4)
    assert result.returncode==0,(result.returncode,result.stderr)
    assert result.stdout==b'done',result.stdout
finally:
    os.close(master);os.close(slave)
`)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "FAKE_INPUT="+filepath.Join(dir, "stdin"), "NAKPANEL_MULTIPASS_SHORT_TIMEOUT=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("terminal command blocked: %s %v", out, err)
	}
	input, err := os.ReadFile(filepath.Join(dir, "stdin"))
	if err != nil || len(input) != 0 {
		t.Fatalf("terminal input consumed: %q %v", input, err)
	}
}
