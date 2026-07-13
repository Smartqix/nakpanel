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

type CreateBackupArgs struct {
	BackupID       int64    `json:"backup_id" river:"unique"`
	SiteID         int64    `json:"site_id,omitempty"`
	SubscriptionID int64    `json:"subscription_id,omitempty"`
	CustomerID     int64    `json:"customer_id,omitempty"`
	ActorUserID    int64    `json:"actor_user_id,omitempty"`
	Automated      bool     `json:"automated,omitempty"`
	Domain         string   `json:"domain"`
	Username       string   `json:"username"`
	Docroot        string   `json:"docroot"`
	Databases      []string `json:"databases"`
}

func (CreateBackupArgs) Kind() string { return "create_backup" }

func (CreateBackupArgs) InsertOpts() river.InsertOpts { return activeUniqueOpts() }

type ConfigureWebmailArgs struct {
	WebmailID int64  `json:"webmail_id" river:"unique"`
	Domain    string `json:"domain"`
	Hostname  string `json:"hostname"`
}

func (ConfigureWebmailArgs) Kind() string { return "configure_webmail" }

func (ConfigureWebmailArgs) InsertOpts() river.InsertOpts { return activeUniqueOpts() }

type RestoreBackupArgs struct {
	RestoreID   int64    `json:"restore_id" river:"unique"`
	BackupID    int64    `json:"backup_id"`
	Domain      string   `json:"domain"`
	Username    string   `json:"username"`
	Docroot     string   `json:"docroot"`
	ArchivePath string   `json:"archive_path"`
	Databases   []string `json:"databases"`
}

func (RestoreBackupArgs) Kind() string { return "restore_backup" }

func (RestoreBackupArgs) InsertOpts() river.InsertOpts { return activeUniqueOpts() }

type ConfigureDNSZoneArgs struct {
	ZoneID  int64             `json:"zone_id" river:"unique"`
	Domain  string            `json:"domain"`
	Address string            `json:"address"`
	Serial  int64             `json:"serial"`
	Records []types.DNSRecord `json:"records,omitempty"`
}

func (ConfigureDNSZoneArgs) Kind() string { return "configure_dns_zone" }

func (ConfigureDNSZoneArgs) InsertOpts() river.InsertOpts { return activeUniqueOpts() }

type ReconcileSystemArgs struct {
	RunID       int64                        `json:"run_id"`
	ScopeKey    string                       `json:"scope_key" river:"unique"`
	ActorUserID int64                        `json:"actor_user_id,omitempty"`
	Automated   bool                         `json:"automated,omitempty"`
	Sites       []types.ReconcileSiteReq     `json:"sites"`
	Databases   []types.ReconcileDatabaseReq `json:"databases,omitempty"`
}

func (ReconcileSystemArgs) Kind() string { return "reconcile_system" }

func (ReconcileSystemArgs) InsertOpts() river.InsertOpts { return activeUniqueOpts() }

func activeUniqueOpts() river.InsertOpts {
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

type AgentBackupClient interface {
	CreateBackup(ctx context.Context, req types.CreateBackupReq) (types.Response, error)
}

type AgentRestoreClient interface {
	RestoreBackup(ctx context.Context, req types.RestoreBackupReq) (types.Response, error)
}

type AgentWebmailClient interface {
	ConfigureWebmail(ctx context.Context, req types.ConfigureWebmailReq) (types.Response, error)
}

type AgentDNSClient interface {
	ConfigureDNSZone(ctx context.Context, req types.ConfigureDNSZoneReq) (types.Response, error)
}

type AgentReconciliationClient interface {
	ReconcileSystem(ctx context.Context, req types.ReconcileSystemReq) (types.Response, error)
}

type Phase6StatusStore interface {
	MarkBackupActive(ctx context.Context, id int64, result types.CreateBackupResult) error
	MarkBackupFailed(ctx context.Context, id int64, message string) error
	MarkRestoreActive(ctx context.Context, id int64, result types.RestoreBackupResult) error
	MarkRestoreFailed(ctx context.Context, id int64, message string) error
	MarkWebmailActive(ctx context.Context, id int64, result types.ConfigureWebmailResult) error
	MarkWebmailFailed(ctx context.Context, id int64, message string) error
	MarkDNSActive(ctx context.Context, id int64, result types.ConfigureDNSZoneResult) error
	MarkDNSFailed(ctx context.Context, id int64, message string) error
	MarkReconcileActive(ctx context.Context, id int64, result types.ReconcileSystemResult) error
	MarkReconcileFailed(ctx context.Context, id int64, message string) error
}

type AutomatedReporter interface {
	ReportCertificate(context.Context, IssueCertArgs, error) error
	ReportBackup(context.Context, CreateBackupArgs, error) error
	ReportReconcile(context.Context, ReconcileSystemArgs, *types.ReconcileSystemResult, error) error
}

type CreateBackupWorker struct {
	river.WorkerDefaults[CreateBackupArgs]
	agent    AgentBackupClient
	store    Phase6StatusStore
	reporter AutomatedReporter
}

func NewCreateBackupWorker(agent AgentBackupClient, store Phase6StatusStore, reporters ...AutomatedReporter) *CreateBackupWorker {
	w := &CreateBackupWorker{agent: agent, store: store}
	if len(reporters) > 0 {
		w.reporter = reporters[0]
	}
	return w
}

func (w *CreateBackupWorker) Work(ctx context.Context, job *river.Job[CreateBackupArgs]) error {
	if w.agent == nil {
		return errors.New("agent backup client is not configured")
	}
	resp, err := w.agent.CreateBackup(ctx, types.CreateBackupReq{
		Domain:    job.Args.Domain,
		Username:  job.Args.Username,
		Docroot:   job.Args.Docroot,
		Databases: job.Args.Databases,
	})
	if err != nil {
		return errors.Join(err, w.markBackupFailed(ctx, job.Args.BackupID, err.Error()), w.reportBackup(ctx, job.Args, err))
	}
	var result types.CreateBackupResult
	if err := decodeAgentResult(resp, &result); err != nil {
		return errors.Join(err, w.markBackupFailed(ctx, job.Args.BackupID, err.Error()), w.reportBackup(ctx, job.Args, err))
	}
	if w.store != nil {
		if err := w.store.MarkBackupActive(ctx, job.Args.BackupID, result); err != nil {
			return err
		}
	}
	if w.reporter != nil {
		if err := w.reporter.ReportBackup(ctx, job.Args, nil); err != nil {
			return err
		}
	}
	return nil
}

func (w *CreateBackupWorker) reportBackup(ctx context.Context, args CreateBackupArgs, err error) error {
	if w.reporter != nil {
		return w.reporter.ReportBackup(ctx, args, err)
	}
	return nil
}

func (w *CreateBackupWorker) markBackupFailed(ctx context.Context, id int64, message string) error {
	if w.store != nil {
		return w.store.MarkBackupFailed(ctx, id, message)
	}
	return nil
}

type RestoreBackupWorker struct {
	river.WorkerDefaults[RestoreBackupArgs]
	agent AgentRestoreClient
	store Phase6StatusStore
}

func NewRestoreBackupWorker(agent AgentRestoreClient, store Phase6StatusStore) *RestoreBackupWorker {
	return &RestoreBackupWorker{agent: agent, store: store}
}

func (w *RestoreBackupWorker) Work(ctx context.Context, job *river.Job[RestoreBackupArgs]) error {
	if w.agent == nil {
		return errors.New("agent restore client is not configured")
	}
	resp, err := w.agent.RestoreBackup(ctx, types.RestoreBackupReq{
		Domain:      job.Args.Domain,
		Username:    job.Args.Username,
		Docroot:     job.Args.Docroot,
		ArchivePath: job.Args.ArchivePath,
		Databases:   job.Args.Databases,
	})
	if err != nil {
		w.markRestoreFailed(ctx, job.Args.RestoreID, err.Error())
		return err
	}
	var result types.RestoreBackupResult
	if err := decodeAgentResult(resp, &result); err != nil {
		w.markRestoreFailed(ctx, job.Args.RestoreID, err.Error())
		return err
	}
	if w.store != nil {
		return w.store.MarkRestoreActive(ctx, job.Args.RestoreID, result)
	}
	return nil
}

func (w *RestoreBackupWorker) markRestoreFailed(ctx context.Context, id int64, message string) {
	if w.store != nil {
		_ = w.store.MarkRestoreFailed(ctx, id, message)
	}
}

type ConfigureWebmailWorker struct {
	river.WorkerDefaults[ConfigureWebmailArgs]
	agent AgentWebmailClient
	store Phase6StatusStore
}

func NewConfigureWebmailWorker(agent AgentWebmailClient, store Phase6StatusStore) *ConfigureWebmailWorker {
	return &ConfigureWebmailWorker{agent: agent, store: store}
}

func (w *ConfigureWebmailWorker) Work(ctx context.Context, job *river.Job[ConfigureWebmailArgs]) error {
	if w.agent == nil {
		return errors.New("agent webmail client is not configured")
	}
	resp, err := w.agent.ConfigureWebmail(ctx, types.ConfigureWebmailReq{Domain: job.Args.Domain, Hostname: job.Args.Hostname})
	if err != nil {
		w.markWebmailFailed(ctx, job.Args.WebmailID, err.Error())
		return err
	}
	var result types.ConfigureWebmailResult
	if err := decodeAgentResult(resp, &result); err != nil {
		w.markWebmailFailed(ctx, job.Args.WebmailID, err.Error())
		return err
	}
	if w.store != nil {
		return w.store.MarkWebmailActive(ctx, job.Args.WebmailID, result)
	}
	return nil
}

func (w *ConfigureWebmailWorker) markWebmailFailed(ctx context.Context, id int64, message string) {
	if w.store != nil {
		_ = w.store.MarkWebmailFailed(ctx, id, message)
	}
}

type ConfigureDNSZoneWorker struct {
	river.WorkerDefaults[ConfigureDNSZoneArgs]
	agent AgentDNSClient
	store Phase6StatusStore
}

func NewConfigureDNSZoneWorker(agent AgentDNSClient, store Phase6StatusStore) *ConfigureDNSZoneWorker {
	return &ConfigureDNSZoneWorker{agent: agent, store: store}
}

func (w *ConfigureDNSZoneWorker) Work(ctx context.Context, job *river.Job[ConfigureDNSZoneArgs]) error {
	if w.agent == nil {
		return errors.New("agent dns client is not configured")
	}
	resp, err := w.agent.ConfigureDNSZone(ctx, types.ConfigureDNSZoneReq{Domain: job.Args.Domain, Address: job.Args.Address, Serial: job.Args.Serial, Records: job.Args.Records})
	if err != nil {
		w.markDNSFailed(ctx, job.Args.ZoneID, err.Error())
		return err
	}
	var result types.ConfigureDNSZoneResult
	if err := decodeAgentResult(resp, &result); err != nil {
		w.markDNSFailed(ctx, job.Args.ZoneID, err.Error())
		return err
	}
	if w.store != nil {
		return w.store.MarkDNSActive(ctx, job.Args.ZoneID, result)
	}
	return nil
}

func (w *ConfigureDNSZoneWorker) markDNSFailed(ctx context.Context, id int64, message string) {
	if w.store != nil {
		_ = w.store.MarkDNSFailed(ctx, id, message)
	}
}

type ReconcileSystemWorker struct {
	river.WorkerDefaults[ReconcileSystemArgs]
	agent    AgentReconciliationClient
	store    Phase6StatusStore
	reporter AutomatedReporter
}

func NewReconcileSystemWorker(agent AgentReconciliationClient, store Phase6StatusStore, reporters ...AutomatedReporter) *ReconcileSystemWorker {
	w := &ReconcileSystemWorker{agent: agent, store: store}
	if len(reporters) > 0 {
		w.reporter = reporters[0]
	}
	return w
}

func (w *ReconcileSystemWorker) Work(ctx context.Context, job *river.Job[ReconcileSystemArgs]) error {
	if w.agent == nil {
		return errors.New("agent reconciliation client is not configured")
	}
	resp, err := w.agent.ReconcileSystem(ctx, types.ReconcileSystemReq{Sites: job.Args.Sites, Databases: job.Args.Databases})
	if err != nil {
		return errors.Join(err, w.markReconcileFailed(ctx, job.Args.RunID, err.Error()), w.reportReconcile(ctx, job.Args, nil, err))
	}
	var result types.ReconcileSystemResult
	if err := decodeAgentResult(resp, &result); err != nil {
		return errors.Join(err, w.markReconcileFailed(ctx, job.Args.RunID, err.Error()), w.reportReconcile(ctx, job.Args, nil, err))
	}
	if result.Failed > 0 {
		err := fmt.Errorf("reconciliation reported %d failed resources", result.Failed)
		return errors.Join(err, w.markReconcileFailed(ctx, job.Args.RunID, err.Error()), w.reportReconcile(ctx, job.Args, &result, err))
	}
	if w.store != nil {
		if err := w.store.MarkReconcileActive(ctx, job.Args.RunID, result); err != nil {
			return err
		}
	}
	if w.reporter != nil {
		if err := w.reporter.ReportReconcile(ctx, job.Args, &result, nil); err != nil {
			return err
		}
	}
	return nil
}

func (w *ReconcileSystemWorker) reportReconcile(ctx context.Context, args ReconcileSystemArgs, result *types.ReconcileSystemResult, err error) error {
	if w.reporter != nil {
		return w.reporter.ReportReconcile(ctx, args, result, err)
	}
	return nil
}

func (w *ReconcileSystemWorker) markReconcileFailed(ctx context.Context, id int64, message string) error {
	if w.store != nil {
		return w.store.MarkReconcileFailed(ctx, id, message)
	}
	return nil
}

func decodeAgentResult(resp types.Response, dst any) error {
	if !resp.OK {
		return fmt.Errorf("agent operation failed: %s", resp.Error)
	}
	if err := json.Unmarshal(resp.Data, dst); err != nil {
		return fmt.Errorf("decode agent result: %w", err)
	}
	return nil
}
