package multipass

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Exercise the installer's actual curl command against a local TLS/HTTP2
// endpoint. Only the network destination and test CA are substituted; no
// installer function that writes /usr/local or starts services is executed.
func installerGoDownloadCommand(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("../install/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "ensure_go_toolchain() {")
	if start < 0 {
		t.Fatal("Go toolchain installer missing")
	}
	block := strings.SplitN(string(source)[start:], "checksum=", 2)[0]
	lines := strings.Split(block, "\n")
	var command string
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "curl ") {
			continue
		}
		command = strings.TrimSpace(line)
		for strings.HasSuffix(command, "\\") {
			i++
			if i >= len(lines) {
				t.Fatal("unfinished Go download command")
			}
			command += "\n" + lines[i]
		}
		break
	}
	const destination = `"https://go.dev/dl/go${go_version}.linux-${goarch}.tar.gz"`
	if strings.Count(command, destination) != 1 {
		t.Fatal("expected one pinned official Go archive URL")
	}
	command = strings.Replace(command, destination, `"${NAKPANEL_TEST_DOWNLOAD_URL}"`, 1)
	return command + ` --noproxy '*' --cacert "${NAKPANEL_TEST_CA}"`
}

func TestInstallerGoArchiveDownload(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Fatal("installer regression requires actual curl")
	}
	version, err := exec.Command(curl, "--version").Output()
	if err != nil || !strings.Contains(string(version), "HTTP2") {
		t.Fatal("installer regression requires curl with HTTP2 support")
	}
	command := installerGoDownloadCommand(t)
	for _, tc := range []struct {
		name         string
		resetCount   int32
		untrustedCA  bool
		downgrade    bool
		wantExit     int
		wantRequests int32
	}{
		{name: "stream_reset_then_complete", resetCount: 1, wantRequests: 2},
		{name: "persistent_stream_reset_fails_closed", resetCount: 100, wantExit: 92, wantRequests: 4},
		{name: "certificate_failure_stays_rejected", untrustedCA: true, wantExit: 60},
		{name: "redirect_cannot_downgrade_to_http", downgrade: true, wantExit: 1, wantRequests: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const complete = "complete-go-archive-fixture\n"
			var requests, plainRequests, nonHTTP2 atomic.Int32
			plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				plainRequests.Add(1)
				_, _ = io.WriteString(w, complete)
			}))
			defer plain.Close()
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempt := requests.Add(1)
				if r.ProtoMajor != 2 {
					nonHTTP2.Add(1)
				}
				if tc.downgrade {
					http.Redirect(w, r, plain.URL, http.StatusFound)
					return
				}
				w.Header().Set("Content-Length", fmt.Sprint(len(complete)))
				if attempt <= tc.resetCount {
					_, _ = io.WriteString(w, "partial-")
					w.(http.Flusher).Flush()
					panic(http.ErrAbortHandler) // sends a real HTTP2 INTERNAL_ERROR reset
				}
				_, _ = io.WriteString(w, complete)
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			directory := t.TempDir()
			ca := filepath.Join(directory, "ca.pem")
			certificate := server.Certificate()
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			archive, marker := filepath.Join(directory, "go.tar.gz"), filepath.Join(directory, "later-install-stage")
			script := "set -euo pipefail\n" + command + "\nprintf complete >\"${NAKPANEL_TEST_MARKER}\"\n"
			if tc.untrustedCA {
				// Use the normal system trust store, which cannot trust this fixture.
				script = strings.Replace(script, ` --cacert "${NAKPANEL_TEST_CA}"`, "", 1)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, "bash", "-c", script)
			child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			child.Cancel = func() error { return syscall.Kill(-child.Process.Pid, syscall.SIGKILL) }
			child.WaitDelay = time.Second
			child.Env = append(os.Environ(), "archive="+archive, "NAKPANEL_TEST_DOWNLOAD_URL="+server.URL,
				"NAKPANEL_TEST_CA="+ca, "NAKPANEL_TEST_MARKER="+marker)
			output, runErr := child.CombinedOutput()
			exit := 0
			if runErr != nil {
				if ee, ok := runErr.(*exec.ExitError); ok {
					exit = ee.ExitCode()
				} else {
					t.Fatal(runErr)
				}
			}
			if ctx.Err() != nil {
				t.Fatalf("download did not terminate: %v\n%s", ctx.Err(), output)
			}
			if exit != tc.wantExit || requests.Load() != tc.wantRequests || nonHTTP2.Load() != 0 {
				t.Fatalf("exit=%d requests=%d nonHTTP2=%d; want exit=%d requests=%d\n%s", exit, requests.Load(), nonHTTP2.Load(), tc.wantExit, tc.wantRequests, output)
			}
			if plainRequests.Load() != 0 {
				t.Fatal("Go download followed an HTTP downgrade")
			}
			if tc.wantExit == 0 {
				body, err := os.ReadFile(archive)
				if err != nil || string(body) != complete {
					t.Fatalf("retry did not replace partial archive: %q %v", body, err)
				}
				if _, err := os.Stat(marker); err != nil {
					t.Fatal("successful download did not reach the next stage")
				}
			} else if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("failed download reached a later install stage")
			}
			t.Logf("actual curl exit=%d HTTP2 requests=%d plain HTTP requests=%d; stage and archive assertions passed", exit, requests.Load(), plainRequests.Load())
		})
	}
}
