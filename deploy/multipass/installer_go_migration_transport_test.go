package multipass

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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

// This child uses the same pinned standard-library HTTP transport and GODEBUG
// mechanism as cmd/go. It is not cmd/go, a checksum database, or a migration.
func TestInstallerMigrationTransportChild(t *testing.T) {
	if os.Getenv("NAKPANEL_MIGRATION_TRANSPORT_CHILD") != "1" {
		return
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if os.Getenv("NAKPANEL_MIGRATION_TRUST_CA") == "1" {
		certificate, err := os.ReadFile(os.Getenv("NAKPANEL_MIGRATION_CA"))
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certificate) {
			t.Fatal("invalid fixture CA")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(os.Getenv("NAKPANEL_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "complete fixture metadata\n" {
		t.Fatalf("metadata response status=%d body=%q error=%v", response.StatusCode, body, err)
	}
}

func installerMigrationFunction(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("../install/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(data), name+"() {\n")
	if start < 0 {
		t.Fatal("missing installer migration function")
	}
	end := strings.Index(string(data)[start:], "\n}")
	if end < 0 {
		t.Fatal("unfinished installer migration function")
	}
	return string(data)[start : start+end+2]
}

func TestInstallerMigrationGoTransport(t *testing.T) {
	childBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, function := range []string{"run_goose_up", "run_river_up"} {
		for _, mode := range []string{"http2_reset_http1_complete", "unset_parent_debug", "persistent_http503", "untrusted_CA"} {
			t.Run(function+"/"+mode, func(t *testing.T) {
				var h1, h2 atomic.Int32
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.ProtoMajor == 2 {
						h2.Add(1)
						_, _ = io.WriteString(w, "partial-")
						w.(http.Flusher).Flush()
						panic(http.ErrAbortHandler) // actual HTTP2 INTERNAL_ERROR reset
					}
					h1.Add(1)
					if mode == "persistent_http503" {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					_, _ = io.WriteString(w, "complete fixture metadata\n")
				}))
				server.EnableHTTP2 = true
				server.Config.ErrorLog = log.New(io.Discard, "", 0)
				server.StartTLS()
				defer server.Close()
				directory := t.TempDir()
				ca := filepath.Join(directory, "ca.pem")
				if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
					t.Fatal(err)
				}
				makefile := `.PHONY: goose-up river-up
goose-up river-up:
	@printf '%s\n' "$${GODEBUG}" "$${GOSUMDB}" "$${GOINSECURE}" "$${GONOSUMDB}" >>"$${NAKPANEL_MIGRATION_CALLS}"
	@"$${NAKPANEL_MIGRATION_CHILD_BINARY}" -test.run '^TestInstallerMigrationTransportChild$$' -test.count=1
	@printf complete >"$${NAKPANEL_MIGRATION_LATER}"
`
				if err := os.WriteFile(filepath.Join(directory, "Makefile"), []byte(makefile), 0600); err != nil {
					t.Fatal(err)
				}
				calls, later, parent := filepath.Join(directory, "calls"), filepath.Join(directory, "later"), filepath.Join(directory, "parent")
				script := `set -euo pipefail
# Only the privileged UID switch is replaced; env, make and HTTPS are real.
sudo() { [[ "$1" == -u && "$2" == nakpanel ]] || return 99; shift 2; "$@"; }
` + installerMigrationFunction(t, function) + "\n" + function + "\nprintf '%s' \"${GODEBUG-UNSET}\" >\"${NAKPANEL_MIGRATION_PARENT}\"\n"
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, "bash", "-c", script)
				command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
				command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
				command.WaitDelay = time.Second
				// Avoid ambient authentication bypasses even though this child only
				// uses a synthetic stdlib transport, not the Go module command.
				for _, entry := range os.Environ() {
					name := strings.SplitN(entry, "=", 2)[0]
					if name != "GODEBUG" && name != "GOSUMDB" && name != "GOINSECURE" && name != "GONOSUMDB" && name != "BASH_ENV" && name != "ENV" && name != "MAKEFLAGS" && name != "MAKEFILES" && name != "MFLAGS" {
						command.Env = append(command.Env, entry)
					}
				}
				trust := "1"
				if mode == "untrusted_CA" {
					trust = "0"
				}
				wantDebug, wantParent := "panicnil=1,http2client=1,http2client=0", "panicnil=1,http2client=1"
				if mode == "unset_parent_debug" {
					wantDebug, wantParent = "http2client=0", "UNSET"
				} else {
					command.Env = append(command.Env, "GODEBUG=panicnil=1,http2client=1")
				}
				command.Env = append(command.Env, "GOSUMDB=sum.golang.org", "GOINSECURE=", "GONOSUMDB=",
					"migration_root="+directory, "DB_DSN=test-fixture-no-database", "NAKPANEL_MIGRATION_TRANSPORT_CHILD=1", "NAKPANEL_MIGRATION_TRUST_CA="+trust,
					"NAKPANEL_MIGRATION_URL="+server.URL, "NAKPANEL_MIGRATION_CA="+ca, "NAKPANEL_MIGRATION_CHILD_BINARY="+childBinary,
					"NAKPANEL_MIGRATION_CALLS="+calls, "NAKPANEL_MIGRATION_LATER="+later, "NAKPANEL_MIGRATION_PARENT="+parent)
				output, runErr := command.CombinedOutput()
				if ctx.Err() != nil {
					t.Fatalf("owned child timed out: %v\n%s", ctx.Err(), output)
				}
				observed, err := os.ReadFile(calls)
				if err != nil {
					t.Fatalf("missing actual make invocation: %v\n%s", err, output)
				}
				if string(observed) != wantDebug+"\nsum.golang.org\n\n\n" {
					t.Fatalf("migration env or invocation count differs: %q; HTTP1=%d HTTP2=%d\n%s", observed, h1.Load(), h2.Load(), output)
				}
				if h2.Load() != 0 {
					t.Fatalf("bootstrap used HTTP2: %d\n%s", h2.Load(), output)
				}
				if mode == "http2_reset_http1_complete" || mode == "unset_parent_debug" {
					if runErr != nil || h1.Load() != 1 {
						t.Fatalf("HTTP1 bootstrap failed: %v HTTP1=%d\n%s", runErr, h1.Load(), output)
					}
					if data, err := os.ReadFile(later); err != nil || string(data) != "complete" {
						t.Fatalf("next fixture stage not reached: %q %v", data, err)
					}
					if data, err := os.ReadFile(parent); err != nil || string(data) != wantParent {
						t.Fatalf("per-command option leaked to parent: %q %v", data, err)
					}
				} else {
					if runErr == nil {
						t.Fatal("failed bootstrap continued")
					}
					if _, err := os.Stat(later); !os.IsNotExist(err) {
						t.Fatal("failed bootstrap reached next stage")
					}
					want := int32(1)
					if mode == "untrusted_CA" {
						want = 0
						if !strings.Contains(string(output), "x509:") {
							t.Fatalf("failure did not observe certificate rejection: %s", output)
						}
					} else if !strings.Contains(string(output), "metadata response status=503") {
						t.Fatalf("failure did not observe actual HTTP503: %s", output)
					}
					if h1.Load() != want {
						t.Fatalf("HTTP1 requests=%d; want%d", h1.Load(), want)
					}
				}
				t.Logf("one make invocation; HTTP1=%d HTTP2=%d; unchanged checksum-related env, real TLS and stage/parent-env assertions passed", h1.Load(), h2.Load())
			})
		}
	}
}
