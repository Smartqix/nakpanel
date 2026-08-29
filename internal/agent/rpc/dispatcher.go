package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/nakroteck/nakpanel/internal/types"
)

const maxCachedResponses = 4096

type ServiceReloader interface {
	ReloadService(ctx context.Context, name string) error
}

type SiteProvisioner interface {
	CreateSite(ctx context.Context, req types.CreateSiteReq) error
}

type DatabaseProvisioner interface {
	CreateDatabase(ctx context.Context, req types.CreateDatabaseReq) error
}

type CertificateProvisioner interface {
	IssueCert(ctx context.Context, req types.IssueCertReq) (types.IssueCertResult, error)
}

type CustomCertificateProvisioner interface {
	InstallCustomCert(ctx context.Context, req types.InstallCustomCertReq) (types.InstallCustomCertResult, error)
}

type BackupProvisioner interface {
	CreateBackup(ctx context.Context, req types.CreateBackupReq) (types.CreateBackupResult, error)
}

type DeleteBackupProvisioner interface {
	DeleteBackup(ctx context.Context, req types.DeleteBackupReq) (types.DeleteBackupResult, error)
}

type WebmailProvisioner interface {
	ConfigureWebmail(ctx context.Context, req types.ConfigureWebmailReq) (types.ConfigureWebmailResult, error)
}

type DNSProvisioner interface {
	ConfigureDNSZone(ctx context.Context, req types.ConfigureDNSZoneReq) (types.ConfigureDNSZoneResult, error)
}

type ReconciliationProvisioner interface {
	ReconcileSystem(ctx context.Context, req types.ReconcileSystemReq) (types.ReconcileSystemResult, error)
}

type RestoreProvisioner interface {
	RestoreBackup(ctx context.Context, req types.RestoreBackupReq) (types.RestoreBackupResult, error)
}

type HostingStateProvisioner interface {
	SetHostingState(ctx context.Context, req types.SetHostingStateReq) error
}

type SiteRuntimeProvisioner interface {
	ApplySiteRuntime(ctx context.Context, req types.ApplySiteRuntimeReq) error
}

type SubscriptionAccountProvisioner interface {
	EnsureSubscriptionAccount(context.Context, types.EnsureSubscriptionAccountReq) (types.EnsureSubscriptionAccountResult, error)
	ApplyScheduledTasks(context.Context, types.ApplyScheduledTasksReq) error
	MigrateSubscriptionAccount(context.Context, types.MigrateSubscriptionAccountReq) (types.MigrateSubscriptionAccountResult, error)
	CleanupLegacyHomes(context.Context, types.CleanupLegacyHomesReq) (types.CleanupLegacyHomesResult, error)
}

type MailProvisioner interface {
	ConfigureMail(context.Context, types.ConfigureMailReq) (types.ConfigureMailResult, error)
	CollectMailQueue(context.Context) (types.CollectMailQueueResult, error)
	MailStatus(context.Context) (types.MailServerStatus, error)
}

type MailQueueReader interface {
	QueryMailQueue(context.Context, types.MailQueueQueryReq) (types.MailQueueQueryResult, error)
	InspectQueuedMail(context.Context, types.InspectQueuedMailReq) (types.MailQueueMessage, error)
}

type ApplicationProvisioner interface {
	EnsureApplication(context.Context, types.EnsureApplicationReq) error
}

type ApplicationRuntimeProvisioner interface {
	DeployApplicationGeneration(context.Context, types.EnsureApplicationReq) (types.DeployApplicationGenerationResult, error)
	ApplicationStatus(context.Context, types.ApplicationControlReq) (types.ApplicationObservedState, error)
	ControlApplication(context.Context, types.ApplicationControlReq) (types.ApplicationObservedState, error)
	ReadApplicationLog(context.Context, types.ApplicationLogReq) (types.ApplicationLogResult, error)
}

type SubscriptionTeardownProvisioner interface {
	TeardownSubscription(context.Context, types.TeardownSubscriptionReq) (types.TeardownSubscriptionResult, error)
}

type HostingToolkitProvisioner interface {
	EnsureFTPS(context.Context, types.EnsureFTPSReq) (types.EnsureFTPSResult, error)
	FTPSStatus(context.Context) (types.FTPSStatus, error)
	ReadSiteLog(context.Context, types.SiteLogRequest) (types.SiteLogResult, error)
	RunScheduledTask(context.Context, types.RunScheduledTaskReq) (types.RunScheduledTaskResult, error)
	EnsureValkey(context.Context, types.EnsureValkeyReq) (types.EnsureValkeyResult, error)
	ValkeyStatus(context.Context, int64) (types.ValkeyStatus, error)
	EnsureGitRepository(context.Context, types.EnsureGitRepositoryReq) (types.EnsureGitRepositoryResult, error)
	EnsureProtectedDirectories(context.Context, types.EnsureProtectedDirectoriesReq) (types.EnsureProtectedDirectoriesResult, error)
	RunStagingOperation(context.Context, types.RunStagingOperationReq) (types.RunStagingOperationResult, error)
}

type UsageCollector interface {
	CollectUsage(ctx context.Context, req types.CollectUsageReq) (types.CollectUsageResult, error)
	RuntimeCapabilities(ctx context.Context) (types.RuntimeCapabilities, error)
}

type ServerAdminInspector interface {
	InspectServer(context.Context) (types.ServerInventory, error)
	InspectManagedServices(context.Context, types.InspectManagedServicesReq) ([]types.ManagedService, error)
	InspectTime(context.Context) (types.TimeState, error)
	InspectPHP(context.Context) ([]types.PHPHandlerState, error)
}

type ManagedServiceController interface {
	ControlManagedService(context.Context, types.ControlManagedServiceReq) (types.ControlManagedServiceResult, error)
}

type ServerJournalReader interface {
	ReadJournal(context.Context, types.ReadJournalReq) (types.ReadJournalResult, error)
}

type ServerUpdateManager interface {
	InspectUpdates(context.Context) (types.UpdateState, error)
	ApplyUpdates(context.Context, types.ApplyUpdatesReq) (types.UpdateState, error)
}

type ServerSecurityManager interface {
	InspectServerSecurity(context.Context) (types.ServerSecurityPolicy, error)
	StageServerSecurity(context.Context, types.StageServerSecurityReq) (types.StagedSecurityResult, error)
	ConfirmServerSecurity(context.Context, string) (types.StagedSecurityResult, error)
	RevertServerSecurity(context.Context, string) (types.StagedSecurityResult, error)
}

type HostPowerController interface {
	ControlHostPower(context.Context, types.HostPowerReq) (types.HostPowerResult, error)
}

type Fail2BanManager interface {
	ApplyFail2BanPolicy(context.Context, types.ApplyFail2BanPolicyReq) (types.ApplyFail2BanPolicyResult, error)
	ListSecurityBans(context.Context) (types.SecurityBansResult, error)
	UnbanSecurityAddress(context.Context, types.UnbanSecurityAddressReq) (types.UnbanSecurityAddressResult, error)
}

type ServerBackupManager interface {
	CreateServerBackup(context.Context, types.CreateServerBackupReq) (types.CreateServerBackupResult, error)
	VerifyServerBackup(context.Context, types.VerifyServerBackupReq) (types.VerifyServerBackupResult, error)
	PruneServerBackups(context.Context, types.PruneServerBackupsReq) (types.PruneServerBackupsResult, error)
	TestBackupDestination(context.Context, types.TestBackupDestinationReq) (types.TestBackupDestinationResult, error)
}

type DatabaseAdministrator interface {
	InspectDatabaseAdmin(context.Context, types.InspectDatabaseAdminReq) (types.DatabaseAdminSnapshot, error)
	ManageDatabaseAdmin(context.Context, types.ManageDatabaseAdminReq) (types.ManageDatabaseAdminResult, error)
}

type FileManager interface {
	ListFiles(context.Context, types.FileListReq) (types.FileListResult, error)
	SearchFiles(context.Context, types.FileSearchReq) (types.FileSearchResult, error)
	ReadFile(context.Context, types.FileReadReq) (types.FileReadResult, error)
	WriteFile(context.Context, types.FileWriteReq) (types.FileMutationResult, error)
	CreateEntry(context.Context, types.FileCreateReq) (types.FileMutationResult, error)
	CopyFiles(context.Context, types.FileBatchReq) (types.FileMutationResult, error)
	MoveFiles(context.Context, types.FileBatchReq) (types.FileMutationResult, error)
	DeleteFiles(context.Context, types.FileBatchReq) (types.FileMutationResult, error)
	ArchiveFiles(context.Context, types.FileArchiveReq) (types.FileMutationResult, error)
	ExtractArchive(context.Context, types.FileExtractReq) (types.FileMutationResult, error)
	SetFileMode(context.Context, types.FileModeReq) (types.FileMutationResult, error)
	ImportTransfer(context.Context, types.FileTransferImportReq) (types.FileMutationResult, error)
	ExportTransfer(context.Context, types.FileTransferExportReq) (types.FileTransferResult, error)
}

type Options struct {
	AllowedServices           []string
	SiteProvisioner           SiteProvisioner
	DatabaseProvisioner       DatabaseProvisioner
	CertificateProvisioner    CertificateProvisioner
	BackupProvisioner         BackupProvisioner
	DeleteBackupProvisioner   DeleteBackupProvisioner
	WebmailProvisioner        WebmailProvisioner
	DNSProvisioner            DNSProvisioner
	ReconciliationProvisioner ReconciliationProvisioner
	RestoreProvisioner        RestoreProvisioner
	HostingStateProvisioner   HostingStateProvisioner
	SiteRuntimeProvisioner    SiteRuntimeProvisioner
	UsageCollector            UsageCollector
	FileManager               FileManager
	SubscriptionAccounts      SubscriptionAccountProvisioner
	Mail                      MailProvisioner
	Applications              ApplicationProvisioner
	SubscriptionTeardown      SubscriptionTeardownProvisioner
	ServerAdmin               ServerAdminInspector
	ServiceController         ManagedServiceController
	Journal                   ServerJournalReader
	Updates                   ServerUpdateManager
	Security                  ServerSecurityManager
	HostPower                 HostPowerController
	DatabaseAdmin             DatabaseAdministrator
	HostingToolkit            HostingToolkitProvisioner
	ServerBackups             ServerBackupManager
	Fail2Ban                  Fail2BanManager
}

type Dispatcher struct {
	reloader                  ServiceReloader
	siteProvisioner           SiteProvisioner
	databaseProvisioner       DatabaseProvisioner
	certificateProvisioner    CertificateProvisioner
	customCertProvisioner     CustomCertificateProvisioner
	backupProvisioner         BackupProvisioner
	deleteBackupProvisioner   DeleteBackupProvisioner
	webmailProvisioner        WebmailProvisioner
	dnsProvisioner            DNSProvisioner
	reconciliationProvisioner ReconciliationProvisioner
	restoreProvisioner        RestoreProvisioner
	hostingStateProvisioner   HostingStateProvisioner
	siteRuntimeProvisioner    SiteRuntimeProvisioner
	usageCollector            UsageCollector
	fileManager               FileManager
	subscriptionAccounts      SubscriptionAccountProvisioner
	mail                      MailProvisioner
	mailQueue                 MailQueueReader
	applications              ApplicationProvisioner
	subscriptionTeardown      SubscriptionTeardownProvisioner
	serverAdmin               ServerAdminInspector
	serviceController         ManagedServiceController
	journal                   ServerJournalReader
	updates                   ServerUpdateManager
	security                  ServerSecurityManager
	hostPower                 HostPowerController
	databaseAdmin             DatabaseAdministrator
	hostingToolkit            HostingToolkitProvisioner
	serverBackups             ServerBackupManager
	fail2ban                  Fail2BanManager
	allowed                   map[string]struct{}

	mu            sync.Mutex
	responses     map[string]*responseEntry
	responseOrder []string
}

type responseEntry struct {
	done chan struct{}
	resp types.Response
}

func NewDispatcher(reloader ServiceReloader, opts Options) *Dispatcher {
	allowed := make(map[string]struct{}, len(opts.AllowedServices))
	for _, service := range opts.AllowedServices {
		allowed[service] = struct{}{}
	}
	if len(allowed) == 0 {
		for _, service := range []string{"nginx", "php8.3-fpm", "php8.2-fpm"} {
			allowed[service] = struct{}{}
		}
	}

	customCertProvisioner, _ := opts.CertificateProvisioner.(CustomCertificateProvisioner)
	dispatcher := &Dispatcher{
		reloader:                  reloader,
		siteProvisioner:           opts.SiteProvisioner,
		databaseProvisioner:       opts.DatabaseProvisioner,
		certificateProvisioner:    opts.CertificateProvisioner,
		customCertProvisioner:     customCertProvisioner,
		backupProvisioner:         opts.BackupProvisioner,
		deleteBackupProvisioner:   opts.DeleteBackupProvisioner,
		webmailProvisioner:        opts.WebmailProvisioner,
		dnsProvisioner:            opts.DNSProvisioner,
		reconciliationProvisioner: opts.ReconciliationProvisioner,
		restoreProvisioner:        opts.RestoreProvisioner,
		hostingStateProvisioner:   opts.HostingStateProvisioner,
		siteRuntimeProvisioner:    opts.SiteRuntimeProvisioner,
		usageCollector:            opts.UsageCollector,
		fileManager:               opts.FileManager,
		subscriptionAccounts:      opts.SubscriptionAccounts,
		mail:                      opts.Mail,
		applications:              opts.Applications,
		subscriptionTeardown:      opts.SubscriptionTeardown,
		hostingToolkit:            opts.HostingToolkit,
		serverAdmin:               opts.ServerAdmin,
		serviceController:         opts.ServiceController,
		journal:                   opts.Journal,
		updates:                   opts.Updates,
		security:                  opts.Security,
		hostPower:                 opts.HostPower,
		databaseAdmin:             opts.DatabaseAdmin,
		serverBackups:             opts.ServerBackups,
		fail2ban:                  opts.Fail2Ban,
		allowed:                   allowed,
		responses:                 make(map[string]*responseEntry),
	}
	if reader, ok := opts.Mail.(MailQueueReader); ok {
		dispatcher.mailQueue = reader
	}
	return dispatcher
}

func (d *Dispatcher) Dispatch(ctx context.Context, req types.Request) types.Response {
	if strings.TrimSpace(req.ID) == "" {
		return validationResponse(req.ID, "id is required")
	}

	d.mu.Lock()
	if cached, ok := d.responses[req.ID]; ok {
		d.mu.Unlock()
		<-cached.done
		return cached.resp
	}
	entry := &responseEntry{done: make(chan struct{})}
	d.responses[req.ID] = entry
	d.mu.Unlock()

	resp := d.dispatch(ctx, req)

	d.mu.Lock()
	entry.resp = resp
	close(entry.done)
	d.responseOrder = append(d.responseOrder, req.ID)
	for len(d.responseOrder) > maxCachedResponses {
		oldest := d.responseOrder[0]
		d.responseOrder = d.responseOrder[1:]
		delete(d.responses, oldest)
	}
	d.mu.Unlock()
	return resp
}

func (d *Dispatcher) dispatch(ctx context.Context, req types.Request) types.Response {
	switch req.Op {
	case types.OpPing:
		if err := validateNoFields(req.Data); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, map[string]bool{"pong": true})
	case types.OpCollectUsage:
		var payload types.CollectUsageReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.usageCollector == nil {
			return errorResponse(req.ID, "usage collector is not configured")
		}
		result, err := d.usageCollector.CollectUsage(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpRuntimeCapabilities:
		if err := validateNoFields(req.Data); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.usageCollector == nil {
			return errorResponse(req.ID, "usage collector is not configured")
		}
		result, err := d.usageCollector.RuntimeCapabilities(ctx)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpInspectServer:
		if err := validateNoFields(req.Data); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.serverAdmin == nil {
			return errorResponse(req.ID, "server inspection is not configured")
		}
		result, err := d.serverAdmin.InspectServer(ctx)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpInspectManagedServices:
		var payload types.InspectManagedServicesReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.serverAdmin == nil {
			return errorResponse(req.ID, "service inspection is not configured")
		}
		result, err := d.serverAdmin.InspectManagedServices(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpInspectTime:
		if err := validateNoFields(req.Data); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.serverAdmin == nil {
			return errorResponse(req.ID, "time inspection is not configured")
		}
		result, err := d.serverAdmin.InspectTime(ctx)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpInspectPHP:
		if err := validateNoFields(req.Data); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.serverAdmin == nil {
			return errorResponse(req.ID, "PHP inspection is not configured")
		}
		result, err := d.serverAdmin.InspectPHP(ctx)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpControlManagedService:
		var payload types.ControlManagedServiceReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.serviceController == nil {
			return errorResponse(req.ID, "service control is not configured")
		}
		result, err := d.serviceController.ControlManagedService(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpReadJournal:
		var payload types.ReadJournalReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.journal == nil {
			return errorResponse(req.ID, "journal access is not configured")
		}
		result, err := d.journal.ReadJournal(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpInspectUpdates:
		if err := validateNoFields(req.Data); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.updates == nil {
			return errorResponse(req.ID, "update inspection is not configured")
		}
		result, err := d.updates.InspectUpdates(ctx)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpApplyUpdates:
		var payload types.ApplyUpdatesReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.updates == nil {
			return errorResponse(req.ID, "update management is not configured")
		}
		result, err := d.updates.ApplyUpdates(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpApplyFail2BanPolicy:
		var payload types.ApplyFail2BanPolicyReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fail2ban == nil {
			return errorResponse(req.ID, "fail2ban management is not configured")
		}
		result, err := d.fail2ban.ApplyFail2BanPolicy(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpListSecurityBans:
		if err := validateNoFields(req.Data); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fail2ban == nil {
			return errorResponse(req.ID, "fail2ban management is not configured")
		}
		result, err := d.fail2ban.ListSecurityBans(ctx)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpUnbanSecurityAddress:
		var payload types.UnbanSecurityAddressReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fail2ban == nil {
			return errorResponse(req.ID, "fail2ban management is not configured")
		}
		result, err := d.fail2ban.UnbanSecurityAddress(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpCreateServerBackup:
		var payload types.CreateServerBackupReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.serverBackups == nil {
			return errorResponse(req.ID, "server backups are not configured")
		}
		result, err := d.serverBackups.CreateServerBackup(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpVerifyServerBackup:
		var payload types.VerifyServerBackupReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.serverBackups == nil {
			return errorResponse(req.ID, "server backups are not configured")
		}
		result, err := d.serverBackups.VerifyServerBackup(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpPruneServerBackups:
		var payload types.PruneServerBackupsReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.serverBackups == nil {
			return errorResponse(req.ID, "server backups are not configured")
		}
		result, err := d.serverBackups.PruneServerBackups(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpTestBackupDestination:
		var payload types.TestBackupDestinationReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.serverBackups == nil {
			return errorResponse(req.ID, "server backups are not configured")
		}
		result, err := d.serverBackups.TestBackupDestination(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpInspectServerSecurity:
		if err := validateNoFields(req.Data); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.security == nil {
			return errorResponse(req.ID, "server security inspection is not configured")
		}
		result, err := d.security.InspectServerSecurity(ctx)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpStageServerSecurity:
		var payload types.StageServerSecurityReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.security == nil {
			return errorResponse(req.ID, "server security staging is not configured")
		}
		result, err := d.security.StageServerSecurity(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpConfirmServerSecurity, types.OpRevertServerSecurity:
		var payload types.SecurityOperationReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.security == nil {
			return errorResponse(req.ID, "server security staging is not configured")
		}
		var result types.StagedSecurityResult
		var err error
		if req.Op == types.OpConfirmServerSecurity {
			result, err = d.security.ConfirmServerSecurity(ctx, payload.OperationID)
		} else {
			result, err = d.security.RevertServerSecurity(ctx, payload.OperationID)
		}
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpControlHostPower:
		var payload types.HostPowerReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.hostPower == nil {
			return errorResponse(req.ID, "host power control is not configured")
		}
		result, err := d.hostPower.ControlHostPower(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpInspectDatabaseAdmin:
		var payload types.InspectDatabaseAdminReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.databaseAdmin == nil {
			return errorResponse(req.ID, "database administration is not configured")
		}
		result, err := d.databaseAdmin.InspectDatabaseAdmin(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpManageDatabaseAdmin:
		var payload types.ManageDatabaseAdminReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.databaseAdmin == nil {
			return errorResponse(req.ID, "database administration is not configured")
		}
		result, err := d.databaseAdmin.ManageDatabaseAdmin(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpListFiles:
		var payload types.FileListReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if err := validateFileSiteRef(payload.SiteID, payload.Username, payload.Domain); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fileManager == nil {
			return errorResponse(req.ID, "file manager is not configured")
		}
		result, err := d.fileManager.ListFiles(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpSearchFiles:
		var payload types.FileSearchReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if err := validateFileSiteRef(payload.SiteID, payload.Username, payload.Domain); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fileManager == nil {
			return errorResponse(req.ID, "file manager is not configured")
		}
		result, err := d.fileManager.SearchFiles(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpReadFile:
		var payload types.FileReadReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if err := validateFileSiteRef(payload.SiteID, payload.Username, payload.Domain); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fileManager == nil {
			return errorResponse(req.ID, "file manager is not configured")
		}
		result, err := d.fileManager.ReadFile(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpWriteFile:
		var payload types.FileWriteReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if err := validateFileSiteRef(payload.SiteID, payload.Username, payload.Domain); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fileManager == nil {
			return errorResponse(req.ID, "file manager is not configured")
		}
		result, err := d.fileManager.WriteFile(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpCreateFileEntry:
		var payload types.FileCreateReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if err := validateFileSiteRef(payload.SiteID, payload.Username, payload.Domain); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fileManager == nil {
			return errorResponse(req.ID, "file manager is not configured")
		}
		result, err := d.fileManager.CreateEntry(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpCopyFiles, types.OpMoveFiles, types.OpDeleteFiles:
		var payload types.FileBatchReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if err := validateFileSiteRef(payload.SiteID, payload.Username, payload.Domain); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fileManager == nil {
			return errorResponse(req.ID, "file manager is not configured")
		}
		var result types.FileMutationResult
		var err error
		switch req.Op {
		case types.OpCopyFiles:
			result, err = d.fileManager.CopyFiles(ctx, payload)
		case types.OpMoveFiles:
			result, err = d.fileManager.MoveFiles(ctx, payload)
		default:
			result, err = d.fileManager.DeleteFiles(ctx, payload)
		}
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpArchiveFiles:
		var payload types.FileArchiveReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if err := validateFileSiteRef(payload.SiteID, payload.Username, payload.Domain); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fileManager == nil {
			return errorResponse(req.ID, "file manager is not configured")
		}
		result, err := d.fileManager.ArchiveFiles(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpExtractArchive:
		var payload types.FileExtractReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if err := validateFileSiteRef(payload.SiteID, payload.Username, payload.Domain); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fileManager == nil {
			return errorResponse(req.ID, "file manager is not configured")
		}
		result, err := d.fileManager.ExtractArchive(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpSetFileMode:
		var payload types.FileModeReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if err := validateFileSiteRef(payload.SiteID, payload.Username, payload.Domain); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fileManager == nil {
			return errorResponse(req.ID, "file manager is not configured")
		}
		result, err := d.fileManager.SetFileMode(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpImportFileTransfer:
		var payload types.FileTransferImportReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if err := validateFileSiteRef(payload.SiteID, payload.Username, payload.Domain); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fileManager == nil {
			return errorResponse(req.ID, "file manager is not configured")
		}
		result, err := d.fileManager.ImportTransfer(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpExportFileTransfer:
		var payload types.FileTransferExportReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if err := validateFileSiteRef(payload.SiteID, payload.Username, payload.Domain); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.fileManager == nil {
			return errorResponse(req.ID, "file manager is not configured")
		}
		result, err := d.fileManager.ExportTransfer(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpReloadService:
		var payload types.ReloadServiceReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if _, ok := d.allowed[payload.Name]; !ok {
			return validationResponse(req.ID, "service is not allowed")
		}
		if d.reloader == nil {
			return errorResponse(req.ID, "service reloader is not configured")
		}
		if err := d.reloader.ReloadService(ctx, payload.Name); err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, map[string]any{"service": payload.Name, "reloaded": true})
	case types.OpEnsureSubscriptionAccount:
		var payload types.EnsureSubscriptionAccountReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.subscriptionAccounts == nil {
			return errorResponse(req.ID, "subscription account provisioner is not configured")
		}
		result, err := d.subscriptionAccounts.EnsureSubscriptionAccount(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpApplyScheduledTasks:
		var payload types.ApplyScheduledTasksReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.subscriptionAccounts == nil {
			return errorResponse(req.ID, "subscription account provisioner is not configured")
		}
		if err := d.subscriptionAccounts.ApplyScheduledTasks(ctx, payload); err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, map[string]any{"applied": true})
	case types.OpMigrateSubscriptionAccount:
		var payload types.MigrateSubscriptionAccountReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.subscriptionAccounts == nil {
			return errorResponse(req.ID, "subscription account provisioner is not configured")
		}
		result, err := d.subscriptionAccounts.MigrateSubscriptionAccount(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpCleanupLegacyHomes:
		var payload types.CleanupLegacyHomesReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.subscriptionAccounts == nil {
			return errorResponse(req.ID, "subscription account provisioner is not configured")
		}
		result, err := d.subscriptionAccounts.CleanupLegacyHomes(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpTeardownSubscription:
		var payload types.TeardownSubscriptionReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.subscriptionTeardown == nil {
			return errorResponse(req.ID, "subscription teardown provisioner is not configured")
		}
		result, err := d.subscriptionTeardown.TeardownSubscription(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpConfigureMail:
		var payload types.ConfigureMailReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.mail == nil {
			return errorResponse(req.ID, "mail provisioner is not configured")
		}
		result, err := d.mail.ConfigureMail(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpCollectMailQueue:
		if err := validateNoFields(req.Data); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.mail == nil {
			return errorResponse(req.ID, "mail provisioner is not configured")
		}
		result, err := d.mail.CollectMailQueue(ctx)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpQueryMailQueue:
		var payload types.MailQueueQueryReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.mailQueue == nil {
			return errorResponse(req.ID, "mail queue inspection is not configured")
		}
		result, err := d.mailQueue.QueryMailQueue(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpInspectQueuedMail:
		var payload types.InspectQueuedMailReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.mailQueue == nil {
			return errorResponse(req.ID, "mail queue inspection is not configured")
		}
		result, err := d.mailQueue.InspectQueuedMail(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpGetMailStatus:
		if err := validateNoFields(req.Data); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.mail == nil {
			return errorResponse(req.ID, "mail provisioner is not configured")
		}
		result, err := d.mail.MailStatus(ctx)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpEnsureApplication:
		var payload types.EnsureApplicationReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.applications == nil {
			return errorResponse(req.ID, "application provisioner is not configured")
		}
		if err := d.applications.EnsureApplication(ctx, payload); err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, map[string]any{"applied": true})
	case types.OpDeployApplicationGeneration:
		var payload types.EnsureApplicationReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		runtime, ok := d.applications.(ApplicationRuntimeProvisioner)
		if !ok {
			return errorResponse(req.ID, "application provisioner is not configured")
		}
		result, err := runtime.DeployApplicationGeneration(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpGetApplicationStatus:
		var payload types.ApplicationControlReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		runtime, ok := d.applications.(ApplicationRuntimeProvisioner)
		if !ok {
			return errorResponse(req.ID, "application provisioner is not configured")
		}
		result, err := runtime.ApplicationStatus(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpControlApplication:
		var payload types.ApplicationControlReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		runtime, ok := d.applications.(ApplicationRuntimeProvisioner)
		if !ok {
			return errorResponse(req.ID, "application provisioner is not configured")
		}
		result, err := runtime.ControlApplication(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpReadApplicationLog:
		var payload types.ApplicationLogReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		runtime, ok := d.applications.(ApplicationRuntimeProvisioner)
		if !ok {
			return errorResponse(req.ID, "application provisioner is not configured")
		}
		result, err := runtime.ReadApplicationLog(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpCreateSite:
		var payload types.CreateSiteReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.siteProvisioner == nil {
			return errorResponse(req.ID, "site provisioner is not configured")
		}
		if err := d.siteProvisioner.CreateSite(ctx, payload); err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, map[string]any{"domain": payload.Domain, "provisioned": true})
	case types.OpCreateDatabase:
		var payload types.CreateDatabaseReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.databaseProvisioner == nil {
			return errorResponse(req.ID, "database provisioner is not configured")
		}
		if err := d.databaseProvisioner.CreateDatabase(ctx, payload); err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, map[string]any{"engine": payload.Engine, "db_name": payload.DBName, "db_user": payload.DBUser, "created": true})
	case types.OpIssueCert:
		var payload types.IssueCertReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.certificateProvisioner == nil {
			return errorResponse(req.ID, "certificate provisioner is not configured")
		}
		result, err := d.certificateProvisioner.IssueCert(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpInstallCustomCert:
		var payload types.InstallCustomCertReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.customCertProvisioner == nil {
			return errorResponse(req.ID, "certificate provisioner is not configured")
		}
		result, err := d.customCertProvisioner.InstallCustomCert(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpCreateBackup:
		var payload types.CreateBackupReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.backupProvisioner == nil {
			return errorResponse(req.ID, "backup provisioner is not configured")
		}
		result, err := d.backupProvisioner.CreateBackup(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpDeleteBackup:
		var payload types.DeleteBackupReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.deleteBackupProvisioner == nil {
			return errorResponse(req.ID, "delete backup provisioner is not configured")
		}
		result, err := d.deleteBackupProvisioner.DeleteBackup(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpRestoreBackup:
		var payload types.RestoreBackupReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.restoreProvisioner == nil {
			return errorResponse(req.ID, "restore provisioner is not configured")
		}
		result, err := d.restoreProvisioner.RestoreBackup(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpConfigureWebmail:
		var payload types.ConfigureWebmailReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.webmailProvisioner == nil {
			return errorResponse(req.ID, "webmail provisioner is not configured")
		}
		result, err := d.webmailProvisioner.ConfigureWebmail(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpConfigureDNSZone:
		var payload types.ConfigureDNSZoneReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.dnsProvisioner == nil {
			return errorResponse(req.ID, "dns provisioner is not configured")
		}
		result, err := d.dnsProvisioner.ConfigureDNSZone(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpReconcileSystem:
		var payload types.ReconcileSystemReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.reconciliationProvisioner == nil {
			return errorResponse(req.ID, "reconciliation provisioner is not configured")
		}
		result, err := d.reconciliationProvisioner.ReconcileSystem(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpSetHostingState:
		var payload types.SetHostingStateReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.hostingStateProvisioner == nil {
			return errorResponse(req.ID, "hosting state provisioner is not configured")
		}
		if err := d.hostingStateProvisioner.SetHostingState(ctx, payload); err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, map[string]any{"domain": payload.Domain, "state": payload.State})
	case types.OpApplySiteRuntime:
		var payload types.ApplySiteRuntimeReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.siteRuntimeProvisioner == nil {
			return errorResponse(req.ID, "site runtime provisioner is not configured")
		}
		if err := d.siteRuntimeProvisioner.ApplySiteRuntime(ctx, payload); err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, map[string]any{"domain": payload.Domain, "state": payload.State, "php_version": payload.DesiredPHPVersion})
	case types.OpEnsureFTPS:
		var payload types.EnsureFTPSReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.hostingToolkit == nil {
			return errorResponse(req.ID, "hosting toolkit is not configured")
		}
		result, err := d.hostingToolkit.EnsureFTPS(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpFTPSStatus:
		if err := validateNoFields(req.Data); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.hostingToolkit == nil {
			return errorResponse(req.ID, "hosting toolkit is not configured")
		}
		result, err := d.hostingToolkit.FTPSStatus(ctx)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpReadSiteLog:
		var payload types.SiteLogRequest
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.hostingToolkit == nil {
			return errorResponse(req.ID, "hosting toolkit is not configured")
		}
		result, err := d.hostingToolkit.ReadSiteLog(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpRunScheduledTask:
		var payload types.RunScheduledTaskReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.hostingToolkit == nil {
			return errorResponse(req.ID, "hosting toolkit is not configured")
		}
		result, err := d.hostingToolkit.RunScheduledTask(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpEnsureValkey:
		var payload types.EnsureValkeyReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.hostingToolkit == nil {
			return errorResponse(req.ID, "hosting toolkit is not configured")
		}
		result, err := d.hostingToolkit.EnsureValkey(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpValkeyStatus:
		var payload types.ValkeyStatusReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.hostingToolkit == nil {
			return errorResponse(req.ID, "hosting toolkit is not configured")
		}
		result, err := d.hostingToolkit.ValkeyStatus(ctx, payload.SubscriptionID)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpEnsureGitRepository:
		var payload types.EnsureGitRepositoryReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.hostingToolkit == nil {
			return errorResponse(req.ID, "Git provisioner is not configured")
		}
		result, err := d.hostingToolkit.EnsureGitRepository(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpEnsureProtectedDirectories:
		var payload types.EnsureProtectedDirectoriesReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.hostingToolkit == nil {
			return errorResponse(req.ID, "protected-directory provisioner is not configured")
		}
		result, err := d.hostingToolkit.EnsureProtectedDirectories(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	case types.OpRunStagingOperation:
		var payload types.RunStagingOperationReq
		if err := decodeStrict(req.Data, &payload); err != nil {
			return validationResponse(req.ID, err.Error())
		}
		if d.hostingToolkit == nil {
			return errorResponse(req.ID, "staging provisioner is not configured")
		}
		result, err := d.hostingToolkit.RunStagingOperation(ctx, payload)
		if err != nil {
			return errorResponse(req.ID, err.Error())
		}
		return okResponse(req.ID, result)
	default:
		return validationResponse(req.ID, fmt.Sprintf("unknown op %q", req.Op))
	}
}

func validateNoFields(raw json.RawMessage) error {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("invalid data: %w", err)
	}
	for name := range fields {
		return fmt.Errorf("unexpected field %q", name)
	}
	return nil
}

func validateFileSiteRef(siteID int64, username, domain string) error {
	if siteID <= 0 || strings.TrimSpace(username) == "" || strings.TrimSpace(domain) == "" {
		return fmt.Errorf("validated site_id, username, and domain are required")
	}
	return nil
}

func decodeStrict(raw json.RawMessage, dst any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("data is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid data: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("invalid data: multiple json values")
	}
	return nil
}

func okResponse(id string, data any) types.Response {
	encoded, err := json.Marshal(data)
	if err != nil {
		return errorResponse(id, fmt.Sprintf("encode response: %v", err))
	}
	return types.Response{ID: id, OK: true, Data: encoded}
}

func validationResponse(id, msg string) types.Response {
	return types.Response{ID: id, OK: false, Error: "validation error: " + msg}
}

func errorResponse(id, msg string) types.Response {
	return types.Response{ID: id, OK: false, Error: msg}
}
