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

type UsageCollector interface {
	CollectUsage(ctx context.Context, req types.CollectUsageReq) (types.CollectUsageResult, error)
	RuntimeCapabilities(ctx context.Context) (types.RuntimeCapabilities, error)
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
}

type Dispatcher struct {
	reloader                  ServiceReloader
	siteProvisioner           SiteProvisioner
	databaseProvisioner       DatabaseProvisioner
	certificateProvisioner    CertificateProvisioner
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

	return &Dispatcher{
		reloader:                  reloader,
		siteProvisioner:           opts.SiteProvisioner,
		databaseProvisioner:       opts.DatabaseProvisioner,
		certificateProvisioner:    opts.CertificateProvisioner,
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
		allowed:                   allowed,
		responses:                 make(map[string]*responseEntry),
	}
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
	case types.OpListFiles:
		var payload types.FileListReq
		if err := decodeStrict(req.Data, &payload); err != nil {
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
