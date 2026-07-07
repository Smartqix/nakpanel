package provision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type CreateSiteArgs struct {
	SiteID     int64                    `json:"site_id" river:"unique"`
	Username   string                   `json:"username"`
	Domain     string                   `json:"domain"`
	PHPVersion string                   `json:"php_version"`
	Limits     types.SiteResourceLimits `json:"limits"`
}

func (CreateSiteArgs) Kind() string { return "create_site" }

func (CreateSiteArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{
				rivertype.JobStateAvailable,
				rivertype.JobStatePending,
				rivertype.JobStateRetryable,
				rivertype.JobStateRunning,
				rivertype.JobStateScheduled,
			},
		},
	}
}

type AgentSiteClient interface {
	CreateSite(ctx context.Context, req types.CreateSiteReq) (types.Response, error)
}

type CreateDatabaseArgs struct {
	DatabaseID int64          `json:"database_id" river:"unique"`
	Engine     types.DBEngine `json:"engine"`
	DBName     string         `json:"db_name"`
	DBUser     string         `json:"db_user"`
	Password   string         `json:"password"`
}

func (CreateDatabaseArgs) Kind() string { return "create_database" }

func (CreateDatabaseArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{
				rivertype.JobStateAvailable,
				rivertype.JobStatePending,
				rivertype.JobStateRetryable,
				rivertype.JobStateRunning,
				rivertype.JobStateScheduled,
			},
		},
	}
}

type AgentDatabaseClient interface {
	CreateDatabase(ctx context.Context, req types.CreateDatabaseReq) (types.Response, error)
}

type IssueCertArgs struct {
	SiteID     int64            `json:"site_id" river:"unique"`
	Username   string           `json:"username"`
	Domain     string           `json:"domain"`
	PHPVersion string           `json:"php_version"`
	Issuer     types.CertIssuer `json:"issuer"`
}

func (IssueCertArgs) Kind() string { return "issue_cert" }

func (IssueCertArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{
				rivertype.JobStateAvailable,
				rivertype.JobStatePending,
				rivertype.JobStateRetryable,
				rivertype.JobStateRunning,
				rivertype.JobStateScheduled,
			},
		},
	}
}

type AgentCertificateClient interface {
	IssueCert(ctx context.Context, req types.IssueCertReq) (types.Response, error)
}

type SiteStatusStore interface {
	MarkSiteActive(ctx context.Context, id int64) error
	MarkSiteFailed(ctx context.Context, id int64, message string) error
}

type DatabaseStatusStore interface {
	MarkDatabaseActive(ctx context.Context, id int64) error
	MarkDatabaseFailed(ctx context.Context, id int64, message string) error
	ScrubDatabaseJobPassword(ctx context.Context, jobID int64) error
}

type SiteTLSStatusStore interface {
	MarkSiteTLSActive(ctx context.Context, id int64, result types.IssueCertResult) error
	MarkSiteTLSFailed(ctx context.Context, id int64, message string) error
}

type CreateSiteWorker struct {
	river.WorkerDefaults[CreateSiteArgs]

	agent AgentSiteClient
	sites SiteStatusStore
}

func NewCreateSiteWorker(agent AgentSiteClient, sites SiteStatusStore) *CreateSiteWorker {
	return &CreateSiteWorker{
		agent: agent,
		sites: sites,
	}
}

func (w *CreateSiteWorker) Work(ctx context.Context, job *river.Job[CreateSiteArgs]) error {
	if w.agent == nil {
		return errors.New("agent site client is not configured")
	}

	resp, err := w.agent.CreateSite(ctx, types.CreateSiteReq{
		Username:   job.Args.Username,
		Domain:     job.Args.Domain,
		PHPVersion: job.Args.PHPVersion,
		Limits:     job.Args.Limits,
	})
	if err != nil {
		w.markFailed(ctx, job.Args.SiteID, err.Error())
		return err
	}
	if !resp.OK {
		err := fmt.Errorf("agent create_site failed: %s", resp.Error)
		w.markFailed(ctx, job.Args.SiteID, err.Error())
		return err
	}
	if w.sites != nil {
		if err := w.sites.MarkSiteActive(ctx, job.Args.SiteID); err != nil {
			return fmt.Errorf("mark site active: %w", err)
		}
	}
	return nil
}

func (w *CreateSiteWorker) markFailed(ctx context.Context, id int64, message string) {
	if w.sites != nil {
		_ = w.sites.MarkSiteFailed(ctx, id, message)
	}
}

type CreateDatabaseWorker struct {
	river.WorkerDefaults[CreateDatabaseArgs]

	agent    AgentDatabaseClient
	database DatabaseStatusStore
}

func NewCreateDatabaseWorker(agent AgentDatabaseClient, database DatabaseStatusStore) *CreateDatabaseWorker {
	return &CreateDatabaseWorker{
		agent:    agent,
		database: database,
	}
}

func (w *CreateDatabaseWorker) Work(ctx context.Context, job *river.Job[CreateDatabaseArgs]) error {
	if w.agent == nil {
		return errors.New("agent database client is not configured")
	}

	resp, err := w.agent.CreateDatabase(ctx, types.CreateDatabaseReq{
		Engine:   job.Args.Engine,
		DBName:   job.Args.DBName,
		DBUser:   job.Args.DBUser,
		Password: job.Args.Password,
	})
	if err != nil {
		w.markFailed(ctx, job.Args.DatabaseID, err.Error())
		return err
	}
	if !resp.OK {
		err := fmt.Errorf("agent create_database failed: %s", resp.Error)
		w.markFailed(ctx, job.Args.DatabaseID, err.Error())
		return err
	}
	if w.database != nil {
		if err := w.database.MarkDatabaseActive(ctx, job.Args.DatabaseID); err != nil {
			return fmt.Errorf("mark database active: %w", err)
		}
		if job.JobRow != nil {
			if err := w.database.ScrubDatabaseJobPassword(ctx, job.ID); err != nil {
				return fmt.Errorf("scrub database job password: %w", err)
			}
		}
	}
	return nil
}

func (w *CreateDatabaseWorker) markFailed(ctx context.Context, id int64, message string) {
	if w.database != nil {
		_ = w.database.MarkDatabaseFailed(ctx, id, message)
	}
}

type IssueCertWorker struct {
	river.WorkerDefaults[IssueCertArgs]

	agent AgentCertificateClient
	sites SiteTLSStatusStore
}

func NewIssueCertWorker(agent AgentCertificateClient, sites SiteTLSStatusStore) *IssueCertWorker {
	return &IssueCertWorker{
		agent: agent,
		sites: sites,
	}
}

func (w *IssueCertWorker) Work(ctx context.Context, job *river.Job[IssueCertArgs]) error {
	if w.agent == nil {
		return errors.New("agent certificate client is not configured")
	}

	resp, err := w.agent.IssueCert(ctx, types.IssueCertReq{
		Username:   job.Args.Username,
		Domain:     job.Args.Domain,
		PHPVersion: job.Args.PHPVersion,
		Issuer:     job.Args.Issuer,
	})
	if err != nil {
		w.markFailed(ctx, job.Args.SiteID, err.Error())
		return err
	}
	if !resp.OK {
		err := fmt.Errorf("agent issue_cert failed: %s", resp.Error)
		w.markFailed(ctx, job.Args.SiteID, err.Error())
		return err
	}
	var result types.IssueCertResult
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		w.markFailed(ctx, job.Args.SiteID, err.Error())
		return fmt.Errorf("decode issue_cert response: %w", err)
	}
	if err := validateIssueCertResult(job.Args, result); err != nil {
		w.markFailed(ctx, job.Args.SiteID, err.Error())
		return fmt.Errorf("invalid issue_cert response: %w", err)
	}
	if w.sites != nil {
		if err := w.sites.MarkSiteTLSActive(ctx, job.Args.SiteID, result); err != nil {
			return fmt.Errorf("mark site tls active: %w", err)
		}
	}
	return nil
}

func (w *IssueCertWorker) markFailed(ctx context.Context, id int64, message string) {
	if w.sites != nil {
		_ = w.sites.MarkSiteTLSFailed(ctx, id, message)
	}
}

func validateIssueCertResult(args IssueCertArgs, result types.IssueCertResult) error {
	if result.CertPath == "" {
		return errors.New("missing certificate path")
	}
	if result.KeyPath == "" {
		return errors.New("missing certificate key path")
	}
	if result.ExpiresAt.IsZero() {
		return errors.New("missing certificate expiration")
	}
	if result.Domain != args.Domain {
		return fmt.Errorf("certificate domain %q does not match job domain %q", result.Domain, args.Domain)
	}
	expectedIssuer := args.Issuer
	if expectedIssuer == "" {
		expectedIssuer = types.CertIssuerLocalSelfSigned
	}
	if result.Issuer != expectedIssuer {
		return fmt.Errorf("certificate issuer %q does not match job issuer %q", result.Issuer, expectedIssuer)
	}
	return nil
}
