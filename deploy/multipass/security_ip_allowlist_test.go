package multipass

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/provisioningapi"
)

// Exercise the shipped shell probe and real curl, with only the guest CLI and
// remote HTTP transport replaced. The endpoint applies the product's real CIDR
// matcher to a trusted peer fixture; forwarded headers never select that peer.
// Restoring the old 10.99/16 fixture, weakening either status assertion, or
// omitting the successful-key control must make this test fail.
func TestSecurityIPAllowlistProbeExcludesPrivatePeers(t *testing.T) {
	for _, peer := range []string{
		"10.99.187.194", "10.99.187.1", "10.0.0.1", "10.255.255.254",
		"192.168.64.1", "192.168.64.2", "192.168.255.254",
		"172.16.0.1", "172.31.255.254", "127.0.0.1", "169.254.1.1",
		"::ffff:10.99.187.1", "::ffff:192.168.64.1", "::ffff:172.16.0.1",
		"::1", "fd00::1", "fe80::1",
	} {
		t.Run(peer, func(t *testing.T) {
			runSecurityIPAllowlistProbe(t, peer, 0, 0, true)
		})
	}
}

func TestSecurityIPAllowlistProbeRequiresExactDenialAndWorkingControl(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		allowedCode, denyCode int
	}{
		{"denied-key-accepted", 0, 200},
		{"denied-key-unauthorized", 0, 401},
		{"denied-key-server-error", 0, 500},
		{"normal-key-unauthorized", 401, 0},
		{"normal-key-forbidden", 403, 0},
		{"normal-key-server-error", 500, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runSecurityIPAllowlistProbe(t, "10.99.187.1", tc.allowedCode, tc.denyCode, false)
		})
	}
}

func runSecurityIPAllowlistProbe(t *testing.T, peer string, allowedCode, denyCode int, wantSuccess bool) {
	t.Helper()
	data, err := os.ReadFile("security-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "# IP allowlist:")
	end := strings.Index(script, "# Cross-surface scope:")
	if start < 0 || end <= start {
		t.Fatal("missing executable IP allowlist probe")
	}
	argsFile := filepath.Join(t.TempDir(), "cli-arguments")
	var allowedRequests, deniedRequests atomic.Int32
	var forwardedHeader atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ping" || r.Method != http.MethodGet {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" {
			forwardedHeader.Store(true)
		}
		var key provisioningapi.APIKey
		switch r.Header.Get("Authorization") {
		case "Bearer npk_allowed_fixture":
			allowedRequests.Add(1)
			key.IPAllowlist = []string{"0.0.0.0/0", "::/0"}
			if allowedCode != 0 {
				w.WriteHeader(allowedCode)
				return
			}
		case "Bearer npk_denied_fixture":
			deniedRequests.Add(1)
			args, readErr := os.ReadFile(argsFile)
			if readErr != nil {
				http.Error(w, "missing CLI key", http.StatusInternalServerError)
				return
			}
			fields := strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")
			if len(fields) < 2 || fields[0] != "api-key" || fields[1] != "create" {
				http.Error(w, "invalid CLI operation", http.StatusInternalServerError)
				return
			}
			for i := 2; i+1 < len(fields); i++ {
				if fields[i] == "--cidrs" {
					key.IPAllowlist = strings.Split(fields[i+1], ",")
				}
			}
			if len(key.IPAllowlist) == 0 {
				http.Error(w, "missing CLI allowlist", http.StatusInternalServerError)
				return
			}
			if denyCode != 0 {
				w.WriteHeader(denyCode)
				return
			}
		default:
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !key.AllowsIP(net.ParseIP(peer)) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	// Keep the real Multipass destination and curl argument sequence. Route only
	// its TCP connection to a local TLS endpoint; no actual VM or key is changed.
	body := `set -euo pipefail
STAMP=123;VM_IP=10.99.187.194;API_KEY=npk_allowed_fixture;FAILS=0
fail(){ echo "SECURITY-FAIL: $*" >&2; FAILS=$((FAILS + 1)); }
ok(){ echo "ok: $*"; }
cli(){ printf '%s\0' "$@" >"$TEST_CLI_ARGS"; printf '%s\n' npk_denied_fixture; }
curl(){ command curl --noproxy '*' --connect-to "${VM_IP}:7443:${TEST_CONNECT_TO}" "$@"; }
` + script[start:end] + `
test "$FAILS" = 0
`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", body)
	cmd.Env = append(os.Environ(), "TEST_CLI_ARGS="+argsFile, "TEST_CONNECT_TO="+server.Listener.Addr().String())
	out, runErr := cmd.CombinedOutput()
	if (runErr == nil) != wantSuccess {
		t.Errorf("peer %s: success=%t, want %t: %v\n%s", peer, runErr == nil, wantSuccess, runErr, out)
	}
	if allowedRequests.Load() != 1 || deniedRequests.Load() != 1 {
		t.Errorf("probe must execute both real curl controls: allowed=%d denied=%d", allowedRequests.Load(), deniedRequests.Load())
	}
	if forwardedHeader.Load() {
		t.Error("probe must use the actual peer without forwarding-header impersonation")
	}
	// CIDRs used only to simulate exclusion must not overlap any private peer.
	// A documentation-only IPv4 host prefix establishes that independently of
	// the sampled peers, including every mapped form of an RFC1918 address.
	if wantSuccess {
		args, err := os.ReadFile(argsFile)
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Split(string(args), "\x00")
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] != "--cidrs" {
				continue
			}
			ip, network, err := net.ParseCIDR(fields[i+1])
			ones, bits := 0, 0
			if err == nil {
				ones, bits = network.Mask.Size()
			}
			_, documentation, _ := net.ParseCIDR("192.0.2.0/24")
			if err != nil || bits != 32 || ones != 32 || !documentation.Contains(ip) {
				t.Errorf("exclusion fixture must be a TEST-NET-1 host, got %q", fields[i+1])
			}
		}
	}
}
