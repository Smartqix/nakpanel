package ops

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/types"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestACMEWaitsForChallengeReachabilityBeforeContactingCA(t *testing.T) {
	root := t.TempDir()
	client := &fakeACMEProtocolClient{certDER: testCertificateDER(t, "example.test", time.Now().Add(time.Hour))}
	issuer := NewACMEHTTP01Issuer(ACMEHTTP01IssuerOptions{Client: client, ChallengeChecker: func(context.Context, string, string, string) error { return errors.New("DNS not ready") }})
	_, err := issuer.Issue(context.Background(), ACMEIssueRequest{Domain: "example.test", Docroot: root, CertPath: filepath.Join(root, "cert.pem"), KeyPath: filepath.Join(root, "key.pem")})
	if !errors.Is(err, types.ErrACMEChallengePending) || client.registered || client.accepted {
		t.Fatalf("err=%v registered=%v accepted=%v", err, client.registered, client.accepted)
	}
}
func TestHTTP01PreflightPinsDNSAndRejectsRedirectsOrWrongContents(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		ok     bool
	}{{"correct token", 200, "proof", true}, {"redirect", 302, "proof", false}, {"forbidden", 403, "proof", false}, {"wrong host", 200, "wrong", false}} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "example.test" || r.URL.Path != "/.well-known/acme-challenge/np-token" {
					t.Errorf("wrong target %s %s", r.Host, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			resolutions := 0
			probe := http01ChallengeProbe{resolve: func(context.Context, string) ([]net.IPAddr, error) {
				resolutions++
				return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
			}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "8.8.8.8:80" {
					t.Errorf("DNS pin lost: %s", address)
				}
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}}
			err := probe.Check(context.Background(), "example.test", "/.well-known/acme-challenge/np-token", "proof")
			if (err == nil) != tc.ok || resolutions != 1 {
				t.Fatalf("err=%v resolutions=%d", err, resolutions)
			}
		})
	}
}
func TestHTTP01PreflightRejectsNonPublicAddressesWithoutDialing(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.1.1", "198.18.0.1", "192.0.2.1", "0.0.0.0"} {
		probe := http01ChallengeProbe{resolve: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP(address)}}, nil
		}, dial: func(context.Context, string, string) (net.Conn, error) {
			t.Fatalf("dialed forbidden %s", address)
			return nil, nil
		}}
		if err := probe.Check(context.Background(), "example.test", "/.well-known/acme-challenge/np-token", "proof"); err == nil {
			t.Fatalf("accepted private address %s", address)
		}
	}
}
