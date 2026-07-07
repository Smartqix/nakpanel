package provision

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type fakeAgentSiteClient struct {
	req  types.CreateSiteReq
	resp types.Response
	err  error
}

func (c *fakeAgentSiteClient) CreateSite(ctx context.Context, req types.CreateSiteReq) (types.Response, error) {
	c.req = req
	return c.resp, c.err
}

type fakeAgentDatabaseClient struct {
	req  types.CreateDatabaseReq
	resp types.Response
	err  error
}

func (c *fakeAgentDatabaseClient) CreateDatabase(ctx context.Context, req types.CreateDatabaseReq) (types.Response, error) {
	c.req = req
	return c.resp, c.err
}

type fakeAgentCertificateClient struct {
	req  types.IssueCertReq
	resp types.Response
	err  error
}

func (c *fakeAgentCertificateClient) IssueCert(ctx context.Context, req types.IssueCertReq) (types.Response, error) {
	c.req = req
	return c.resp, c.err
}

type recordingDatabaseStatusStore struct {
	activeID    int64
	failedID    int64
	failedError string
	scrubJobID  int64
}

func (s *recordingDatabaseStatusStore) MarkDatabaseActive(ctx context.Context, id int64) error {
	s.activeID = id
	return nil
}

func (s *recordingDatabaseStatusStore) MarkDatabaseFailed(ctx context.Context, id int64, message string) error {
	s.failedID = id
	s.failedError = message
	return nil
}

func (s *recordingDatabaseStatusStore) ScrubDatabaseJobPassword(ctx context.Context, jobID int64) error {
	s.scrubJobID = jobID
	return nil
}

type recordingTLSStatusStore struct {
	activeID  int64
	certPath  string
	keyPath   string
	expiresAt time.Time
	failedID  int64
	lastError string
}

func (s *recordingTLSStatusStore) MarkSiteTLSActive(ctx context.Context, id int64, result types.IssueCertResult) error {
	s.activeID = id
	s.certPath = result.CertPath
	s.keyPath = result.KeyPath
	s.expiresAt = result.ExpiresAt
	return nil
}

func (s *recordingTLSStatusStore) MarkSiteTLSFailed(ctx context.Context, id int64, message string) error {
	s.failedID = id
	s.lastError = message
	return nil
}

func TestCreateSiteArgsKind(t *testing.T) {
	if got, want := (CreateSiteArgs{}).Kind(), "create_site"; got != want {
		t.Fatalf("Kind = %q, want %q", got, want)
	}
}

func TestCreateSiteArgsUniqueWhileWorkIsActive(t *testing.T) {
	opts := (CreateSiteArgs{}).InsertOpts()
	if !opts.UniqueOpts.ByArgs {
		t.Fatal("CreateSiteArgs uniqueness is not based on args")
	}
	if slices.Contains(opts.UniqueOpts.ByState, rivertype.JobStateCompleted) {
		t.Fatalf("ByState = %#v, want completed excluded so later reapplies enqueue work", opts.UniqueOpts.ByState)
	}
	for _, state := range []rivertype.JobState{
		rivertype.JobStateAvailable,
		rivertype.JobStatePending,
		rivertype.JobStateRetryable,
		rivertype.JobStateRunning,
		rivertype.JobStateScheduled,
	} {
		if !slices.Contains(opts.UniqueOpts.ByState, state) {
			t.Fatalf("ByState = %#v, missing %s", opts.UniqueOpts.ByState, state)
		}
	}
}

func TestCreateSiteWorkerCallsAgent(t *testing.T) {
	client := &fakeAgentSiteClient{
		resp: types.Response{ID: "job-1", OK: true, Data: json.RawMessage(`{"provisioned":true}`)},
	}
	worker := NewCreateSiteWorker(client, nil)
	job := &river.Job[CreateSiteArgs]{
		Args: CreateSiteArgs{
			SiteID:     7,
			Username:   "npdemo",
			Domain:     "example.test",
			PHPVersion: "8.3",
			Limits:     types.SiteResourceLimits{DiskQuotaMB: 512, PHPFPMMaxChildren: 3, PHPMemoryMB: 128},
		},
	}

	if err := worker.Work(context.Background(), job); err != nil {
		t.Fatalf("Work returned error: %v", err)
	}
	want := types.CreateSiteReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
		Limits:     types.SiteResourceLimits{DiskQuotaMB: 512, PHPFPMMaxChildren: 3, PHPMemoryMB: 128},
	}
	if client.req != want {
		t.Fatalf("CreateSite request = %#v, want %#v", client.req, want)
	}
}

func TestCreateSiteWorkerReturnsAgentErrors(t *testing.T) {
	worker := NewCreateSiteWorker(&fakeAgentSiteClient{
		err: errors.New("dial failed"),
	}, nil)

	err := worker.Work(context.Background(), &river.Job[CreateSiteArgs]{Args: CreateSiteArgs{SiteID: 7}})
	if err == nil {
		t.Fatal("Work returned nil error")
	}
	if !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("error = %q, want dial failed", err.Error())
	}
}

func TestCreateSiteWorkerReturnsNonOKResponses(t *testing.T) {
	worker := NewCreateSiteWorker(&fakeAgentSiteClient{
		resp: types.Response{ID: "job-1", OK: false, Error: "validation error: bad domain"},
	}, nil)

	err := worker.Work(context.Background(), &river.Job[CreateSiteArgs]{Args: CreateSiteArgs{SiteID: 7}})
	if err == nil {
		t.Fatal("Work returned nil error")
	}
	if !strings.Contains(err.Error(), "bad domain") {
		t.Fatalf("error = %q, want agent error", err.Error())
	}
}

func TestCreateDatabaseArgsKind(t *testing.T) {
	if got, want := (CreateDatabaseArgs{}).Kind(), "create_database"; got != want {
		t.Fatalf("Kind = %q, want %q", got, want)
	}
}

func TestCreateDatabaseArgsUniqueWhileWorkIsActive(t *testing.T) {
	opts := (CreateDatabaseArgs{}).InsertOpts()
	if !opts.UniqueOpts.ByArgs {
		t.Fatal("CreateDatabaseArgs uniqueness is not based on args")
	}
	if slices.Contains(opts.UniqueOpts.ByState, rivertype.JobStateCompleted) {
		t.Fatalf("ByState = %#v, want completed excluded so later reapplies enqueue work", opts.UniqueOpts.ByState)
	}
}

func TestCreateDatabaseWorkerCallsAgent(t *testing.T) {
	client := &fakeAgentDatabaseClient{
		resp: types.Response{ID: "job-1", OK: true, Data: json.RawMessage(`{"created":true}`)},
	}
	status := &recordingDatabaseStatusStore{}
	worker := NewCreateDatabaseWorker(client, status)
	job := &river.Job[CreateDatabaseArgs]{
		JobRow: &rivertype.JobRow{ID: 42},
		Args: CreateDatabaseArgs{
			DatabaseID: 11,
			Engine:     types.EngineMariaDB,
			DBName:     "np_demo",
			DBUser:     "np_demo_user",
			Password:   "generated-password",
		},
	}

	if err := worker.Work(context.Background(), job); err != nil {
		t.Fatalf("Work returned error: %v", err)
	}
	want := types.CreateDatabaseReq{
		Engine:   types.EngineMariaDB,
		DBName:   "np_demo",
		DBUser:   "np_demo_user",
		Password: "generated-password",
	}
	if client.req != want {
		t.Fatalf("CreateDatabase request = %#v, want %#v", client.req, want)
	}
	if status.activeID != 11 {
		t.Fatalf("activeID = %d, want 11", status.activeID)
	}
	if status.scrubJobID != 42 {
		t.Fatalf("scrubJobID = %d, want 42", status.scrubJobID)
	}
}

func TestCreateDatabaseWorkerReturnsNonOKResponses(t *testing.T) {
	worker := NewCreateDatabaseWorker(&fakeAgentDatabaseClient{
		resp: types.Response{ID: "job-1", OK: false, Error: "validation error: bad database"},
	}, nil)

	err := worker.Work(context.Background(), &river.Job[CreateDatabaseArgs]{Args: CreateDatabaseArgs{DatabaseID: 11}})
	if err == nil {
		t.Fatal("Work returned nil error")
	}
	if !strings.Contains(err.Error(), "bad database") {
		t.Fatalf("error = %q, want agent error", err.Error())
	}
}

func TestIssueCertArgsKind(t *testing.T) {
	if got, want := (IssueCertArgs{}).Kind(), "issue_cert"; got != want {
		t.Fatalf("Kind = %q, want %q", got, want)
	}
}

func TestIssueCertWorkerCallsAgentAndMarksTLSActive(t *testing.T) {
	expiresAt := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	result := types.IssueCertResult{
		Domain:    "example.test",
		Issuer:    types.CertIssuerLocalSelfSigned,
		CertPath:  "/var/lib/nakpanel/certs/example.test/fullchain.pem",
		KeyPath:   "/var/lib/nakpanel/certs/example.test/privkey.pem",
		ExpiresAt: expiresAt,
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	client := &fakeAgentCertificateClient{
		resp: types.Response{ID: "job-1", OK: true, Data: data},
	}
	status := &recordingTLSStatusStore{}
	worker := NewIssueCertWorker(client, status)
	job := &river.Job[IssueCertArgs]{
		Args: IssueCertArgs{
			SiteID:     7,
			Username:   "npdemo",
			Domain:     "example.test",
			PHPVersion: "8.3",
			Issuer:     types.CertIssuerLocalSelfSigned,
		},
	}

	if err := worker.Work(context.Background(), job); err != nil {
		t.Fatalf("Work returned error: %v", err)
	}
	wantReq := types.IssueCertReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
		Issuer:     types.CertIssuerLocalSelfSigned,
	}
	if client.req != wantReq {
		t.Fatalf("IssueCert request = %#v, want %#v", client.req, wantReq)
	}
	if status.activeID != 7 || status.certPath != result.CertPath || status.keyPath != result.KeyPath || !status.expiresAt.Equal(expiresAt) {
		t.Fatalf("TLS status = %#v, want active with result %#v", status, result)
	}
}

func TestIssueCertWorkerReturnsNonOKResponses(t *testing.T) {
	status := &recordingTLSStatusStore{}
	worker := NewIssueCertWorker(&fakeAgentCertificateClient{
		resp: types.Response{ID: "job-1", OK: false, Error: "validation error: bad cert"},
	}, status)

	err := worker.Work(context.Background(), &river.Job[IssueCertArgs]{Args: IssueCertArgs{SiteID: 7}})
	if err == nil {
		t.Fatal("Work returned nil error")
	}
	if !strings.Contains(err.Error(), "bad cert") {
		t.Fatalf("error = %q, want agent error", err.Error())
	}
	if status.failedID != 7 || !strings.Contains(status.lastError, "bad cert") {
		t.Fatalf("TLS failure status = %#v, want failed site 7 with agent error", status)
	}
}

func TestIssueCertWorkerRejectsInvalidSuccessfulResponses(t *testing.T) {
	expiresAt := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		data    json.RawMessage
		wantErr string
	}{
		{
			name:    "missing certificate path",
			data:    json.RawMessage(`{}`),
			wantErr: "missing certificate path",
		},
		{
			name: "mismatched domain",
			data: mustMarshalIssueCertResult(t, types.IssueCertResult{
				Domain:    "wrong.test",
				Issuer:    types.CertIssuerLocalSelfSigned,
				CertPath:  "/var/lib/nakpanel/certs/wrong.test/fullchain.pem",
				KeyPath:   "/var/lib/nakpanel/certs/wrong.test/privkey.pem",
				ExpiresAt: expiresAt,
			}),
			wantErr: "does not match job domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &recordingTLSStatusStore{}
			worker := NewIssueCertWorker(&fakeAgentCertificateClient{
				resp: types.Response{ID: "job-1", OK: true, Data: tt.data},
			}, status)

			err := worker.Work(context.Background(), &river.Job[IssueCertArgs]{
				Args: IssueCertArgs{
					SiteID: 7,
					Domain: "example.test",
					Issuer: types.CertIssuerLocalSelfSigned,
				},
			})
			if err == nil {
				t.Fatal("Work returned nil error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want %q", err.Error(), tt.wantErr)
			}
			if status.activeID != 0 {
				t.Fatalf("activeID = %d, want no active TLS mark", status.activeID)
			}
			if status.failedID != 7 || !strings.Contains(status.lastError, tt.wantErr) {
				t.Fatalf("TLS failure status = %#v, want failed site 7 with validation error %q", status, tt.wantErr)
			}
		})
	}
}

func mustMarshalIssueCertResult(t *testing.T, result types.IssueCertResult) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	return data
}
