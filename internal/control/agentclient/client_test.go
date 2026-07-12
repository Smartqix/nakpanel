package agentclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentrpc "github.com/nakroteck/nakpanel/internal/agent/rpc"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestClientPingOverUnixSocket(t *testing.T) {
	socketPath, stop := startTestAgent(t)
	defer stop()

	client := New(socketPath)
	resp, err := client.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping returned error: %v", err)
	}
	if !resp.OK {
		t.Fatalf("Ping response OK = false: %#v", resp)
	}
}

func TestClientReloadServiceOverUnixSocket(t *testing.T) {
	socketPath, stop := startTestAgent(t)
	defer stop()

	client := New(socketPath)
	resp, err := client.ReloadService(context.Background(), "nginx")
	if err != nil {
		t.Fatalf("ReloadService returned error: %v", err)
	}
	if !resp.OK {
		t.Fatalf("ReloadService response OK = false: %#v", resp)
	}
}

func TestClientCreateSiteOverUnixSocket(t *testing.T) {
	socketPath, stop := startTestAgent(t)
	defer stop()

	client := New(socketPath)
	resp, err := client.CreateSite(context.Background(), types.CreateSiteReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
	})
	if err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}
	if !resp.OK {
		t.Fatalf("CreateSite response OK = false: %#v", resp)
	}
}

func TestClientCreateDatabaseOverUnixSocket(t *testing.T) {
	socketPath, stop := startTestAgent(t)
	defer stop()

	client := New(socketPath)
	resp, err := client.CreateDatabase(context.Background(), types.CreateDatabaseReq{
		Engine:   types.EngineMariaDB,
		DBName:   "np_demo",
		DBUser:   "np_demo_user",
		Password: "secret-password",
	})
	if err != nil {
		t.Fatalf("CreateDatabase returned error: %v", err)
	}
	if !resp.OK {
		t.Fatalf("CreateDatabase response OK = false: %#v", resp)
	}
}

func TestClientIssueCertOverUnixSocket(t *testing.T) {
	socketPath, stop := startTestAgent(t)
	defer stop()

	client := New(socketPath)
	resp, err := client.IssueCert(context.Background(), types.IssueCertReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
		Issuer:     types.CertIssuerLocalSelfSigned,
	})
	if err != nil {
		t.Fatalf("IssueCert returned error: %v", err)
	}
	if !resp.OK {
		t.Fatalf("IssueCert response OK = false: %#v", resp)
	}
}

func TestClientDoReturnsValidationResponse(t *testing.T) {
	socketPath, stop := startTestAgent(t)
	defer stop()

	client := New(socketPath)
	resp, err := client.Do(context.Background(), types.Request{
		Op:   "run_shell",
		ID:   "01JPHASE2CLIENT0000000001",
		Data: json.RawMessage(`{"command":"id"}`),
	})
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}
	if resp.OK {
		t.Fatalf("unknown op response OK = true: %#v", resp)
	}
}

func TestClientCancellationInterruptsAgentRead(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "nakagent-cancel-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "agent.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var req types.Request
		_ = json.NewDecoder(conn).Decode(&req)
		_, _ = io.Copy(io.Discard, conn)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = New(socketPath).Ping(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Ping error = %v, want context deadline exceeded", err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("agent connection remained open after cancellation")
	}
}

func TestLiveAgent(t *testing.T) {
	socketPath := os.Getenv("NAKPANEL_LIVE_AGENT_SOCKET")
	if socketPath == "" {
		t.Skip("set NAKPANEL_LIVE_AGENT_SOCKET to run live agent integration")
	}

	client := New(socketPath)
	if _, err := client.Ping(context.Background()); err != nil {
		t.Fatalf("live Ping returned error: %v", err)
	}

	resp, err := client.Do(context.Background(), types.Request{
		Op:   "run_shell",
		ID:   "01JPHASE2LIVE000000000001",
		Data: json.RawMessage(`{"command":"id"}`),
	})
	if err != nil {
		t.Fatalf("live unknown op returned transport error: %v", err)
	}
	if resp.OK {
		t.Fatalf("live unknown op returned OK: %#v", resp)
	}

	service := os.Getenv("NAKPANEL_LIVE_AGENT_RELOAD_SERVICE")
	if service == "" {
		service = "nginx"
	}
	if _, err := client.ReloadService(context.Background(), service); err != nil {
		t.Fatalf("live ReloadService returned error: %v", err)
	}
}

func startTestAgent(t *testing.T) (string, func()) {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "nakagent-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})

	socketPath := filepath.Join(dir, "agent.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	dispatcher := agentrpc.NewDispatcher(&testReloader{}, agentrpc.Options{
		AllowedServices:        []string{"nginx"},
		SiteProvisioner:        testSiteProvisioner{},
		DatabaseProvisioner:    testDatabaseProvisioner{},
		CertificateProvisioner: testCertificateProvisioner{},
	})
	server := agentrpc.NewServer(dispatcher)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx, listener)
	}()

	stop := func() {
		cancel()
		_ = listener.Close()
		<-done
	}
	return socketPath, stop
}

type testReloader struct{}

func (testReloader) ReloadService(ctx context.Context, name string) error {
	return nil
}

type testSiteProvisioner struct{}

func (testSiteProvisioner) CreateSite(ctx context.Context, req types.CreateSiteReq) error {
	return nil
}

type testDatabaseProvisioner struct{}

func (testDatabaseProvisioner) CreateDatabase(ctx context.Context, req types.CreateDatabaseReq) error {
	return nil
}

type testCertificateProvisioner struct{}

func (testCertificateProvisioner) IssueCert(ctx context.Context, req types.IssueCertReq) (types.IssueCertResult, error) {
	return types.IssueCertResult{
		Domain:   req.Domain,
		Issuer:   req.Issuer,
		CertPath: "/tmp/fullchain.pem",
		KeyPath:  "/tmp/privkey.pem",
	}, nil
}
