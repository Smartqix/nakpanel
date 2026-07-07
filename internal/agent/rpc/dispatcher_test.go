package rpc

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeReloader struct {
	calls []string
	err   error
}

func (r *fakeReloader) ReloadService(ctx context.Context, name string) error {
	r.calls = append(r.calls, name)
	return r.err
}

type fakeSiteProvisioner struct {
	requests []types.CreateSiteReq
	err      error
}

func (p *fakeSiteProvisioner) CreateSite(ctx context.Context, req types.CreateSiteReq) error {
	p.requests = append(p.requests, req)
	return p.err
}

type fakeDatabaseProvisioner struct {
	requests []types.CreateDatabaseReq
	err      error
}

func (p *fakeDatabaseProvisioner) CreateDatabase(ctx context.Context, req types.CreateDatabaseReq) error {
	p.requests = append(p.requests, req)
	return p.err
}

type fakeCertificateProvisioner struct {
	requests []types.IssueCertReq
	result   types.IssueCertResult
	err      error
}

func (p *fakeCertificateProvisioner) IssueCert(ctx context.Context, req types.IssueCertReq) (types.IssueCertResult, error) {
	p.requests = append(p.requests, req)
	return p.result, p.err
}

func TestDispatchPing(t *testing.T) {
	dispatcher := NewDispatcher(&fakeReloader{}, Options{})

	resp := dispatcher.Dispatch(context.Background(), types.Request{
		Op:   types.OpPing,
		ID:   "01JPHASE200000000000000001",
		Data: json.RawMessage(`{}`),
	})

	if !resp.OK {
		t.Fatalf("Ping response OK = false, error = %q", resp.Error)
	}
	if resp.ID != "01JPHASE200000000000000001" {
		t.Fatalf("response ID = %q", resp.ID)
	}
	if !strings.Contains(string(resp.Data), `"pong":true`) {
		t.Fatalf("Ping data = %s, want pong true", resp.Data)
	}
}

func TestDispatchRejectsUnknownOp(t *testing.T) {
	reloader := &fakeReloader{}
	dispatcher := NewDispatcher(reloader, Options{})

	resp := dispatcher.Dispatch(context.Background(), types.Request{
		Op:   "run_shell",
		ID:   "01JPHASE200000000000000002",
		Data: json.RawMessage(`{"command":"id"}`),
	})

	if resp.OK {
		t.Fatal("unknown op returned OK")
	}
	if !strings.Contains(resp.Error, "unknown op") {
		t.Fatalf("error = %q, want unknown op", resp.Error)
	}
	if len(reloader.calls) != 0 {
		t.Fatalf("unknown op invoked reloader: %#v", reloader.calls)
	}
}

func TestDispatchRejectsMalformedPingData(t *testing.T) {
	dispatcher := NewDispatcher(&fakeReloader{}, Options{})

	resp := dispatcher.Dispatch(context.Background(), types.Request{
		Op:   types.OpPing,
		ID:   "01JPHASE200000000000000003",
		Data: json.RawMessage(`{"extra":true}`),
	})

	if resp.OK {
		t.Fatal("malformed ping returned OK")
	}
	if !strings.Contains(resp.Error, "unexpected field") {
		t.Fatalf("error = %q, want unexpected field", resp.Error)
	}
}

func TestDispatchReloadServiceValidatesAllowlist(t *testing.T) {
	reloader := &fakeReloader{}
	dispatcher := NewDispatcher(reloader, Options{
		AllowedServices: []string{"nginx"},
	})

	resp := dispatcher.Dispatch(context.Background(), types.Request{
		Op:   types.OpReloadService,
		ID:   "01JPHASE200000000000000004",
		Data: json.RawMessage(`{"name":"postgresql"}`),
	})

	if resp.OK {
		t.Fatal("disallowed service returned OK")
	}
	if !strings.Contains(resp.Error, "service is not allowed") {
		t.Fatalf("error = %q, want service is not allowed", resp.Error)
	}
	if len(reloader.calls) != 0 {
		t.Fatalf("disallowed service invoked reloader: %#v", reloader.calls)
	}
}

func TestDispatchReloadServiceCallsReloader(t *testing.T) {
	reloader := &fakeReloader{}
	dispatcher := NewDispatcher(reloader, Options{
		AllowedServices: []string{"nginx"},
	})

	resp := dispatcher.Dispatch(context.Background(), types.Request{
		Op:   types.OpReloadService,
		ID:   "01JPHASE200000000000000005",
		Data: json.RawMessage(`{"name":"nginx"}`),
	})

	if !resp.OK {
		t.Fatalf("reload response OK = false, error = %q", resp.Error)
	}
	if len(reloader.calls) != 1 || reloader.calls[0] != "nginx" {
		t.Fatalf("reloader calls = %#v, want nginx once", reloader.calls)
	}
	if !strings.Contains(string(resp.Data), `"reloaded":true`) {
		t.Fatalf("reload data = %s, want reloaded true", resp.Data)
	}
}

func TestDispatchReloadServiceRejectsTrailingJSON(t *testing.T) {
	reloader := &fakeReloader{}
	dispatcher := NewDispatcher(reloader, Options{
		AllowedServices: []string{"nginx"},
	})

	resp := dispatcher.Dispatch(context.Background(), types.Request{
		Op:   types.OpReloadService,
		ID:   "01JPHASE200000000000000008",
		Data: json.RawMessage(`{"name":"nginx"} {"name":"nginx"}`),
	})

	if resp.OK {
		t.Fatal("trailing JSON returned OK")
	}
	if !strings.Contains(resp.Error, "multiple json values") {
		t.Fatalf("error = %q, want multiple json values", resp.Error)
	}
	if len(reloader.calls) != 0 {
		t.Fatalf("trailing JSON invoked reloader: %#v", reloader.calls)
	}
}

func TestDispatchCreateSiteCallsProvisioner(t *testing.T) {
	provisioner := &fakeSiteProvisioner{}
	dispatcher := NewDispatcher(&fakeReloader{}, Options{
		SiteProvisioner: provisioner,
	})

	resp := dispatcher.Dispatch(context.Background(), types.Request{
		Op: types.OpCreateSite,
		ID: "01JPHASE300000000000000001",
		Data: json.RawMessage(`{
			"username":"npdemo",
			"domain":"example.test",
			"php_version":"8.3"
		}`),
	})

	if !resp.OK {
		t.Fatalf("create_site response OK = false, error = %q", resp.Error)
	}
	if len(provisioner.requests) != 1 {
		t.Fatalf("provisioner call count = %d, want 1", len(provisioner.requests))
	}
	want := types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3"}
	if provisioner.requests[0] != want {
		t.Fatalf("provisioner request = %#v, want %#v", provisioner.requests[0], want)
	}
	if !strings.Contains(string(resp.Data), `"provisioned":true`) {
		t.Fatalf("create_site data = %s, want provisioned true", resp.Data)
	}
}

func TestDispatchCreateSiteRejectsUnknownFields(t *testing.T) {
	provisioner := &fakeSiteProvisioner{}
	dispatcher := NewDispatcher(&fakeReloader{}, Options{
		SiteProvisioner: provisioner,
	})

	resp := dispatcher.Dispatch(context.Background(), types.Request{
		Op:   types.OpCreateSite,
		ID:   "01JPHASE300000000000000002",
		Data: json.RawMessage(`{"username":"npdemo","domain":"example.test","php_version":"8.3","command":"id"}`),
	})

	if resp.OK {
		t.Fatal("create_site with unknown field returned OK")
	}
	if !strings.Contains(resp.Error, "unknown field") {
		t.Fatalf("error = %q, want unknown field", resp.Error)
	}
	if len(provisioner.requests) != 0 {
		t.Fatalf("unknown field invoked provisioner: %#v", provisioner.requests)
	}
}

func TestDispatchCreateDatabaseCallsProvisioner(t *testing.T) {
	provisioner := &fakeDatabaseProvisioner{}
	dispatcher := NewDispatcher(&fakeReloader{}, Options{
		DatabaseProvisioner: provisioner,
	})

	resp := dispatcher.Dispatch(context.Background(), types.Request{
		Op: types.OpCreateDatabase,
		ID: "01JPHASE400000000000000001",
		Data: json.RawMessage(`{
			"engine":"mariadb",
			"db_name":"np_demo",
			"db_user":"np_demo_user",
			"password":"secret-password"
		}`),
	})

	if !resp.OK {
		t.Fatalf("create_database response OK = false, error = %q", resp.Error)
	}
	if len(provisioner.requests) != 1 {
		t.Fatalf("provisioner call count = %d, want 1", len(provisioner.requests))
	}
	want := types.CreateDatabaseReq{
		Engine:   types.EngineMariaDB,
		DBName:   "np_demo",
		DBUser:   "np_demo_user",
		Password: "secret-password",
	}
	if provisioner.requests[0] != want {
		t.Fatalf("provisioner request = %#v, want %#v", provisioner.requests[0], want)
	}
	data := string(resp.Data)
	if !strings.Contains(data, `"created":true`) || !strings.Contains(data, `"db_name":"np_demo"`) {
		t.Fatalf("create_database data = %s, want created true and db_name", resp.Data)
	}
}

func TestDispatchCreateDatabaseRejectsUnknownFields(t *testing.T) {
	provisioner := &fakeDatabaseProvisioner{}
	dispatcher := NewDispatcher(&fakeReloader{}, Options{
		DatabaseProvisioner: provisioner,
	})

	resp := dispatcher.Dispatch(context.Background(), types.Request{
		Op:   types.OpCreateDatabase,
		ID:   "01JPHASE400000000000000002",
		Data: json.RawMessage(`{"engine":"mariadb","db_name":"np_demo","db_user":"np_demo_user","password":"secret","command":"id"}`),
	})

	if resp.OK {
		t.Fatal("create_database with unknown field returned OK")
	}
	if !strings.Contains(resp.Error, "unknown field") {
		t.Fatalf("error = %q, want unknown field", resp.Error)
	}
	if len(provisioner.requests) != 0 {
		t.Fatalf("unknown field invoked provisioner: %#v", provisioner.requests)
	}
}

func TestDispatchIssueCertCallsProvisioner(t *testing.T) {
	provisioner := &fakeCertificateProvisioner{
		result: types.IssueCertResult{
			Domain:   "example.test",
			Issuer:   types.CertIssuerLocalSelfSigned,
			CertPath: "/var/lib/nakpanel/certs/example.test/fullchain.pem",
			KeyPath:  "/var/lib/nakpanel/certs/example.test/privkey.pem",
		},
	}
	dispatcher := NewDispatcher(&fakeReloader{}, Options{
		CertificateProvisioner: provisioner,
	})

	resp := dispatcher.Dispatch(context.Background(), types.Request{
		Op: types.OpIssueCert,
		ID: "01JPHASE4CERT00000000001",
		Data: json.RawMessage(`{
			"username":"npdemo",
			"domain":"example.test",
			"php_version":"8.3",
			"issuer":"local-self-signed"
		}`),
	})

	if !resp.OK {
		t.Fatalf("issue_cert response OK = false, error = %q", resp.Error)
	}
	if len(provisioner.requests) != 1 {
		t.Fatalf("provisioner call count = %d, want 1", len(provisioner.requests))
	}
	want := types.IssueCertReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
		Issuer:     types.CertIssuerLocalSelfSigned,
	}
	if provisioner.requests[0] != want {
		t.Fatalf("provisioner request = %#v, want %#v", provisioner.requests[0], want)
	}
	if !strings.Contains(string(resp.Data), `"cert_path":"/var/lib/nakpanel/certs/example.test/fullchain.pem"`) {
		t.Fatalf("issue_cert data = %s, want cert path", resp.Data)
	}
}

func TestDispatchIssueCertRejectsUnknownFields(t *testing.T) {
	provisioner := &fakeCertificateProvisioner{}
	dispatcher := NewDispatcher(&fakeReloader{}, Options{
		CertificateProvisioner: provisioner,
	})

	resp := dispatcher.Dispatch(context.Background(), types.Request{
		Op:   types.OpIssueCert,
		ID:   "01JPHASE4CERT00000000002",
		Data: json.RawMessage(`{"username":"npdemo","domain":"example.test","php_version":"8.3","issuer":"local-self-signed","command":"id"}`),
	})

	if resp.OK {
		t.Fatal("issue_cert with unknown field returned OK")
	}
	if !strings.Contains(resp.Error, "unknown field") {
		t.Fatalf("error = %q, want unknown field", resp.Error)
	}
	if len(provisioner.requests) != 0 {
		t.Fatalf("unknown field invoked provisioner: %#v", provisioner.requests)
	}
}

func TestDispatchIdempotencyReturnsCachedResponseWithoutRepeatingWork(t *testing.T) {
	reloader := &fakeReloader{}
	dispatcher := NewDispatcher(reloader, Options{
		AllowedServices: []string{"nginx"},
	})
	req := types.Request{
		Op:   types.OpReloadService,
		ID:   "01JPHASE200000000000000006",
		Data: json.RawMessage(`{"name":"nginx"}`),
	}

	first := dispatcher.Dispatch(context.Background(), req)
	second := dispatcher.Dispatch(context.Background(), req)

	if !first.OK || !second.OK {
		t.Fatalf("responses = %#v %#v", first, second)
	}
	if string(first.Data) != string(second.Data) || first.Error != second.Error {
		t.Fatalf("second response was not cached: first=%#v second=%#v", first, second)
	}
	if len(reloader.calls) != 1 {
		t.Fatalf("reloader call count = %d, want 1", len(reloader.calls))
	}
}

func TestDispatchIdempotencySerializesConcurrentDuplicateRequests(t *testing.T) {
	reloader := &blockingReloader{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	dispatcher := NewDispatcher(reloader, Options{
		AllowedServices: []string{"nginx"},
	})
	req := types.Request{
		Op:   types.OpReloadService,
		ID:   "01JPHASE200000000000000009",
		Data: json.RawMessage(`{"name":"nginx"}`),
	}

	var wg sync.WaitGroup
	responses := make(chan types.Response, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			responses <- dispatcher.Dispatch(context.Background(), req)
		}()
	}

	select {
	case <-reloader.started:
	case <-time.After(time.Second):
		t.Fatal("reloader was not called")
	}
	close(reloader.release)
	wg.Wait()
	close(responses)

	for resp := range responses {
		if !resp.OK {
			t.Fatalf("response OK = false: %#v", resp)
		}
	}
	if reloader.CallCount() != 1 {
		t.Fatalf("reloader call count = %d, want 1", reloader.CallCount())
	}
}

type blockingReloader struct {
	started chan struct{}
	release chan struct{}

	mu    sync.Mutex
	calls int
}

func (r *blockingReloader) ReloadService(ctx context.Context, name string) error {
	r.mu.Lock()
	r.calls++
	if r.calls == 1 {
		close(r.started)
	}
	r.mu.Unlock()
	<-r.release
	return nil
}

func (r *blockingReloader) CallCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}
