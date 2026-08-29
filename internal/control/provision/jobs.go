package provision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type CreateSiteArgs struct {
	SiteID        int64                    `json:"site_id" river:"unique"`
	Username      string                   `json:"username"`
	Domain        string                   `json:"domain"`
	PHPVersion    string                   `json:"php_version"`
	SharedAccount bool                     `json:"shared_account,omitempty"`
	Limits        types.SiteResourceLimits `json:"limits"`
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

const databaseCredentialScope = "database"

func databaseCredentialName(databaseID int64) (string, error) {
	if databaseID <= 0 {
		return "", errors.New("database ID must be positive")
	}
	return fmt.Sprintf("provision-%d", databaseID), nil
}

type CreateDatabaseArgs struct {
	DatabaseID    int64          `json:"database_id" river:"unique"`
	Engine        types.DBEngine `json:"engine"`
	DBName        string         `json:"db_name"`
	DBUser        string         `json:"db_user"`
	CredentialRef string         `json:"credential_ref,omitempty"`
	// Password is accepted only for jobs created before encrypted credential
	// references were introduced. New jobs must leave it empty.
	Password string `json:"password,omitempty"`
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
	SiteID         int64                    `json:"site_id" river:"unique"`
	Username       string                   `json:"username"`
	Domain         string                   `json:"domain"`
	PHPVersion     string                   `json:"php_version"`
	Issuer         types.CertIssuer         `json:"issuer"`
	SharedAccount  bool                     `json:"shared_account,omitempty"`
	Limits         types.SiteResourceLimits `json:"limits"`
	SubscriptionID int64                    `json:"subscription_id,omitempty"`
	CustomerID     int64                    `json:"customer_id,omitempty"`
	ActorUserID    int64                    `json:"actor_user_id,omitempty"`
	Automated      bool                     `json:"automated,omitempty"`
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
	MigrateDatabaseJobCredential(ctx context.Context, jobID, databaseID int64, plaintext []byte) (string, error)
	ScrubDatabaseJobPassword(ctx context.Context, jobID int64) error
}

type DatabaseCredentialStore interface {
	GetSecret(ctx context.Context, scope, name string) ([]byte, serveradmin.SecretReference, error)
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
		SiteID:        job.Args.SiteID,
		Username:      job.Args.Username,
		Domain:        job.Args.Domain,
		PHPVersion:    job.Args.PHPVersion,
		SharedAccount: job.Args.SharedAccount,
		Limits:        job.Args.Limits,
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
	secrets  DatabaseCredentialStore
}

func NewCreateDatabaseWorker(agent AgentDatabaseClient, database DatabaseStatusStore, secretStores ...DatabaseCredentialStore) *CreateDatabaseWorker {
	worker := &CreateDatabaseWorker{
		agent:    agent,
		database: database,
	}
	if len(secretStores) > 0 {
		worker.secrets = secretStores[0]
	}
	return worker
}

func (w *CreateDatabaseWorker) Work(ctx context.Context, job *river.Job[CreateDatabaseArgs]) error {
	if w.agent == nil {
		return errors.New("agent database client is not configured")
	}

	password, err := w.databasePassword(ctx, job)
	if err != nil {
		w.markFailed(ctx, job.Args.DatabaseID, err.Error())
		return err
	}
	defer clear(password)

	resp, err := w.agent.CreateDatabase(ctx, types.CreateDatabaseReq{
		Engine:   job.Args.Engine,
		DBName:   job.Args.DBName,
		DBUser:   job.Args.DBUser,
		Password: string(password),
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

func (w *CreateDatabaseWorker) databasePassword(ctx context.Context, job *river.Job[CreateDatabaseArgs]) ([]byte, error) {
	expectedRef, err := databaseCredentialName(job.Args.DatabaseID)
	if err != nil {
		return nil, err
	}
	if job.Args.CredentialRef != "" {
		if job.Args.CredentialRef != expectedRef {
			return nil, errors.New("database credential reference does not match the database")
		}
		if job.Args.Password != "" && w.database != nil && job.JobRow != nil {
			if err := w.database.ScrubDatabaseJobPassword(ctx, job.ID); err != nil {
				return nil, fmt.Errorf("scrub redundant database job password: %w", err)
			}
			job.Args.Password = ""
		}
		if w.secrets == nil {
			return nil, errors.New("database credential store is not configured")
		}
		plaintext, _, err := w.secrets.GetSecret(ctx, databaseCredentialScope, expectedRef)
		if err != nil {
			return nil, fmt.Errorf("resolve database credential: %w", err)
		}
		return plaintext, nil
	}

	if job.Args.Password == "" {
		return nil, errors.New("database credential is unavailable")
	}
	plaintext := []byte(job.Args.Password)
	if w.secrets == nil || w.database == nil || job.JobRow == nil {
		return plaintext, nil
	}
	credentialRef, err := w.database.MigrateDatabaseJobCredential(ctx, job.ID, job.Args.DatabaseID, plaintext)
	if err != nil {
		clear(plaintext)
		return nil, fmt.Errorf("migrate legacy database credential job: %w", err)
	}
	if credentialRef != expectedRef {
		clear(plaintext)
		return nil, errors.New("legacy database credential migration returned an invalid reference")
	}
	job.Args.Password = ""
	job.Args.CredentialRef = credentialRef
	return plaintext, nil
}

func (w *CreateDatabaseWorker) markFailed(ctx context.Context, id int64, message string) {
	if w.database != nil {
		_ = w.database.MarkDatabaseFailed(ctx, id, message)
	}
}

type IssueCertWorker struct {
	river.WorkerDefaults[IssueCertArgs]

	agent    AgentCertificateClient
	sites    SiteTLSStatusStore
	reporter AutomatedReporter
}

func NewIssueCertWorker(agent AgentCertificateClient, sites SiteTLSStatusStore, reporters ...AutomatedReporter) *IssueCertWorker {
	worker := &IssueCertWorker{
		agent: agent,
		sites: sites,
	}
	if len(reporters) > 0 {
		worker.reporter = reporters[0]
	}
	return worker
}

func (w *IssueCertWorker) Work(ctx context.Context, job *river.Job[IssueCertArgs]) error {
	if w.agent == nil {
		return errors.New("agent certificate client is not configured")
	}

	resp, err := w.agent.IssueCert(ctx, types.IssueCertReq{
		Username:      job.Args.Username,
		Domain:        job.Args.Domain,
		PHPVersion:    job.Args.PHPVersion,
		Issuer:        job.Args.Issuer,
		SharedAccount: job.Args.SharedAccount,
		Limits:        job.Args.Limits,
	})
	if err != nil {
		return errors.Join(err, w.markFailed(ctx, job.Args.SiteID, err.Error()), w.report(ctx, job.Args, err))
	}
	if !resp.OK {
		err := fmt.Errorf("agent issue_cert failed: %s", resp.Error)
		return errors.Join(err, w.markFailed(ctx, job.Args.SiteID, err.Error()), w.report(ctx, job.Args, err))
	}
	var result types.IssueCertResult
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		wrapped := fmt.Errorf("decode issue_cert response: %w", err)
		return errors.Join(wrapped, w.markFailed(ctx, job.Args.SiteID, err.Error()), w.report(ctx, job.Args, wrapped))
	}
	if err := validateIssueCertResult(job.Args, result); err != nil {
		wrapped := fmt.Errorf("invalid issue_cert response: %w", err)
		return errors.Join(wrapped, w.markFailed(ctx, job.Args.SiteID, err.Error()), w.report(ctx, job.Args, wrapped))
	}
	if w.sites != nil {
		if err := w.sites.MarkSiteTLSActive(ctx, job.Args.SiteID, result); err != nil {
			return fmt.Errorf("mark site tls active: %w", err)
		}
	}
	if w.reporter != nil {
		if err := w.reporter.ReportCertificate(ctx, job.Args, nil); err != nil {
			return err
		}
	}
	return nil
}

func (w *IssueCertWorker) report(ctx context.Context, args IssueCertArgs, err error) error {
	if w.reporter != nil {
		return w.reporter.ReportCertificate(ctx, args, err)
	}
	return nil
}

func (w *IssueCertWorker) markFailed(ctx context.Context, id int64, message string) error {
	if w.sites != nil {
		return w.sites.MarkSiteTLSFailed(ctx, id, message)
	}
	return nil
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
