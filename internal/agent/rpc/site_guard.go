package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nakroteck/nakpanel/internal/types"
	"os"
	"strings"
)

type SiteIdentityGuard interface {
	WithSites(context.Context, []types.SiteIdentity, func(context.Context) error) error
	WithCreation(context.Context, []types.SiteIdentity, func(context.Context) error) error
	Removed(types.SiteIdentity) (bool, error)
	LookupSite(int64) (types.SiteIdentity, error)
}
type preparedSiteGuard struct {
	request    types.Request
	identities []types.SiteIdentity
	create     bool
}

func guardIdentity(siteID, subID int64, username, domain string) types.SiteIdentity {
	return types.SiteIdentity{SiteID: siteID, SubscriptionID: subID, Username: username, Domain: domain}
}
func guardOne[T any](req types.Request, identity func(T) types.SiteIdentity, create bool) (preparedSiteGuard, error) {
	var payload T
	if err := decodeStrict(req.Data, &payload); err != nil {
		return preparedSiteGuard{}, err
	}
	return preparedSiteGuard{request: req, identities: []types.SiteIdentity{identity(payload)}, create: create}, nil
}
func guardShared[T any](req types.Request, payload T, ids []types.SiteIdentity, create bool) (preparedSiteGuard, error) {
	data, err := json.Marshal(payload)
	req.Data = data
	return preparedSiteGuard{request: req, identities: ids, create: create}, err
}
func guardFilter[T any](values []T, registry SiteIdentityGuard, identity func(T) types.SiteIdentity) ([]T, []types.SiteIdentity, error) {
	kept := make([]T, 0, len(values))
	ids := []types.SiteIdentity{}
	for _, value := range values {
		id := identity(value)
		removed, err := registry.Removed(id)
		if err != nil {
			return nil, nil, err
		}
		if !removed {
			kept = append(kept, value)
			ids = append(ids, id)
		}
	}
	return kept, ids, nil
}
func guardAccount(req types.Request, p types.EnsureSubscriptionAccountReq, registry SiteIdentityGuard) (preparedSiteGuard, error) {
	domains, ids, err := guardFilter(p.Domains, registry, func(domain types.SubscriptionDomain) types.SiteIdentity {
		return guardIdentity(domain.SiteID, p.SubscriptionID, p.Username, domain.Domain)
	})
	if err != nil {
		return preparedSiteGuard{}, err
	}
	p.Domains = domains
	tasks, taskIDs, err := guardFilter(p.Tasks, registry, func(task types.ScheduledTask) types.SiteIdentity {
		return guardIdentity(task.SiteID, p.SubscriptionID, p.Username, task.Domain)
	})
	if err != nil {
		return preparedSiteGuard{}, err
	}
	p.Tasks = tasks
	for _, id := range taskIDs {
		if id.Domain != "" {
			ids = append(ids, id)
		}
	}
	kept := make([]types.SFTPAccessIdentity, 0, len(p.SFTPIdentities))
	for _, identity := range p.SFTPIdentities {
		if strings.HasPrefix(identity.RelativeRoot, "domains/") {
			domain := strings.Split(strings.TrimPrefix(identity.RelativeRoot, "domains/"), "/")[0]
			removed, err := registry.Removed(guardIdentity(identity.SiteID, p.SubscriptionID, p.Username, domain))
			if err != nil {
				return preparedSiteGuard{}, err
			}
			if removed {
				continue
			}
		}
		kept = append(kept, identity)
	}
	p.SFTPIdentities = kept
	return guardShared(req, p, ids, true)
}
func prepareSiteGuard(req types.Request, registry SiteIdentityGuard) (preparedSiteGuard, error) {
	switch req.Op {
	case types.OpCreateSite:
		return guardOne[types.CreateSiteReq](req, func(p types.CreateSiteReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, p.SubscriptionID, p.Username, p.Domain)
		}, true)
	case types.OpIssueCert:
		return guardOne[types.IssueCertReq](req, func(p types.IssueCertReq) types.SiteIdentity { return guardIdentity(p.SiteID, 0, p.Username, p.Domain) }, false)
	case types.OpInstallCustomCert:
		return guardOne[types.InstallCustomCertReq](req, func(p types.InstallCustomCertReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, 0, p.Username, p.Domain)
		}, false)
	case types.OpRestoreBackup:
		return guardOne[types.RestoreBackupReq](req, func(p types.RestoreBackupReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, p.SubscriptionID, p.Username, p.Domain)
		}, false)
	case types.OpCreateBackup:
		return guardOne[types.CreateBackupReq](req, func(p types.CreateBackupReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, p.SubscriptionID, p.Username, p.Domain)
		}, false)
	case types.OpConfigureWebmail:
		return guardOne[types.ConfigureWebmailReq](req, func(p types.ConfigureWebmailReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, p.SubscriptionID, "", p.Domain)
		}, false)
	case types.OpSetHostingState:
		return guardOne[types.SetHostingStateReq](req, func(p types.SetHostingStateReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, 0, p.Username, p.Domain)
		}, false)
	case types.OpApplySiteRuntime:
		return guardOne[types.ApplySiteRuntimeReq](req, func(p types.ApplySiteRuntimeReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, 0, p.Username, p.Domain)
		}, false)
	case types.OpRunScheduledTask:
		return guardOne[types.RunScheduledTaskReq](req, func(p types.RunScheduledTaskReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, p.SubscriptionID, p.Username, p.Domain)
		}, false)
	case types.OpEnsureGitRepository:
		return guardOne[types.EnsureGitRepositoryReq](req, func(p types.EnsureGitRepositoryReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, 0, p.Username, p.Domain)
		}, false)
	case types.OpEnsureProtectedDirectories:
		return guardOne[types.EnsureProtectedDirectoriesReq](req, func(p types.EnsureProtectedDirectoriesReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, 0, p.Username, p.Domain)
		}, false)
	case types.OpReadSiteLog:
		return guardOne[types.SiteLogRequest](req, func(p types.SiteLogRequest) types.SiteIdentity {
			return guardIdentity(p.SiteID, 0, p.Username, p.Domain)
		}, false)
	case types.OpListFiles:
		return guardOne[types.FileListReq](req, func(p types.FileListReq) types.SiteIdentity { return guardIdentity(p.SiteID, 0, p.Username, p.Domain) }, false)
	case types.OpSearchFiles:
		return guardOne[types.FileSearchReq](req, func(p types.FileSearchReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, 0, p.Username, p.Domain)
		}, false)
	case types.OpReadFile:
		return guardOne[types.FileReadReq](req, func(p types.FileReadReq) types.SiteIdentity { return guardIdentity(p.SiteID, 0, p.Username, p.Domain) }, false)
	case types.OpWriteFile:
		return guardOne[types.FileWriteReq](req, func(p types.FileWriteReq) types.SiteIdentity { return guardIdentity(p.SiteID, 0, p.Username, p.Domain) }, false)
	case types.OpCreateFileEntry:
		return guardOne[types.FileCreateReq](req, func(p types.FileCreateReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, 0, p.Username, p.Domain)
		}, false)
	case types.OpCopyFiles, types.OpMoveFiles, types.OpDeleteFiles:
		return guardOne[types.FileBatchReq](req, func(p types.FileBatchReq) types.SiteIdentity { return guardIdentity(p.SiteID, 0, p.Username, p.Domain) }, false)
	case types.OpArchiveFiles:
		return guardOne[types.FileArchiveReq](req, func(p types.FileArchiveReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, 0, p.Username, p.Domain)
		}, false)
	case types.OpExtractArchive:
		return guardOne[types.FileExtractReq](req, func(p types.FileExtractReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, 0, p.Username, p.Domain)
		}, false)
	case types.OpSetFileMode:
		return guardOne[types.FileModeReq](req, func(p types.FileModeReq) types.SiteIdentity { return guardIdentity(p.SiteID, 0, p.Username, p.Domain) }, false)
	case types.OpImportFileTransfer:
		return guardOne[types.FileTransferImportReq](req, func(p types.FileTransferImportReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, 0, p.Username, p.Domain)
		}, false)
	case types.OpExportFileTransfer:
		return guardOne[types.FileTransferExportReq](req, func(p types.FileTransferExportReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, 0, p.Username, p.Domain)
		}, false)
	case types.OpEnsureApplication, types.OpDeployApplicationGeneration:
		return guardOne[types.EnsureApplicationReq](req, func(p types.EnsureApplicationReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, p.SubscriptionID, p.Username, p.Domain)
		}, false)
	case types.OpGetApplicationStatus, types.OpControlApplication:
		return guardOne[types.ApplicationControlReq](req, func(p types.ApplicationControlReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, p.SubscriptionID, p.Username, p.Domain)
		}, false)
	case types.OpReadApplicationLog:
		return guardOne[types.ApplicationLogReq](req, func(p types.ApplicationLogReq) types.SiteIdentity {
			return guardIdentity(p.SiteID, p.SubscriptionID, p.Username, p.Domain)
		}, false)
	case types.OpDeployPHPRelease:
		return guardOne[types.DeployPHPReleaseReq](req, func(p types.DeployPHPReleaseReq) types.SiteIdentity {
			return guardIdentity(p.Application.SiteID, p.Application.SubscriptionID, p.Application.Username, p.Application.Domain)
		}, false)
	case types.OpRollbackPHPRelease:
		return guardOne[types.RollbackPHPReleaseReq](req, func(p types.RollbackPHPReleaseReq) types.SiteIdentity {
			return guardIdentity(p.Application.SiteID, p.Application.SubscriptionID, p.Application.Username, p.Application.Domain)
		}, false)
	case types.OpReconcilePHPApplication:
		return guardOne[types.ReconcilePHPApplicationReq](req, func(p types.ReconcilePHPApplicationReq) types.SiteIdentity {
			return guardIdentity(p.Application.SiteID, p.Application.SubscriptionID, p.Application.Username, p.Application.Domain)
		}, false)
	case types.OpReconcilePHPWorkers:
		return guardOne[types.ReconcilePHPWorkersReq](req, func(p types.ReconcilePHPWorkersReq) types.SiteIdentity {
			return guardIdentity(p.Application.SiteID, p.Application.SubscriptionID, p.Application.Username, p.Application.Domain)
		}, false)
	case types.OpRunWordPress:
		return guardOne[types.WordPressOperationReq](req, func(p types.WordPressOperationReq) types.SiteIdentity {
			return guardIdentity(p.Site.SiteID, p.Site.SubscriptionID, p.Site.Username, p.Site.Domain)
		}, false)
	case types.OpGenerateWebStatistics, types.OpReadWebStatistics:
		return guardOne[types.WebStatisticsRequest](req, func(p types.WebStatisticsRequest) types.SiteIdentity {
			return guardIdentity(p.SiteID, 0, p.Username, p.Domain)
		}, false)
	case types.OpRunStagingOperation:
		var p types.RunStagingOperationReq
		if err := decodeStrict(req.Data, &p); err != nil {
			return preparedSiteGuard{}, err
		}
		return preparedSiteGuard{request: req, identities: []types.SiteIdentity{guardIdentity(p.SourceSiteID, 0, p.Username, p.SourceDomain), guardIdentity(p.TargetSiteID, 0, p.Username, p.TargetDomain)}}, nil
	case types.OpConfigureDNSZone:
		var p types.ConfigureDNSZoneReq
		if err := decodeStrict(req.Data, &p); err != nil {
			return preparedSiteGuard{}, err
		}
		records := make([]types.DNSRecord, 0, len(p.Records))
		ids := []types.SiteIdentity{guardIdentity(p.SiteID, p.SubscriptionID, "", p.Domain)}
		for _, record := range p.Records {
			identity := guardIdentity(record.OwnerSiteID, 0, "", p.Domain)
			if record.OwnerSiteID == 0 && record.Host != "@" {
				identity.Domain = strings.TrimSuffix(record.Host, ".") + "." + p.Domain
			}
			removed, err := registry.Removed(identity)
			if err != nil {
				return preparedSiteGuard{}, err
			}
			if removed {
				continue
			}
			if record.OwnerSiteID > 0 {
				owner, err := registry.LookupSite(record.OwnerSiteID)
				if err != nil {
					if !errors.Is(err, os.ErrNotExist) {
						return preparedSiteGuard{}, err
					}
				} else {
					if (p.SubscriptionID > 0 && owner.SubscriptionID != p.SubscriptionID) || (owner.Domain != p.Domain && !strings.HasSuffix(owner.Domain, "."+p.Domain)) {
						return preparedSiteGuard{}, errors.New("DNS record owner differs from its hosted zone")
					}
					ids = append(ids, owner)
				}
			}
			records = append(records, record)
		}
		p.Records = records
		return guardShared(req, p, ids, false)
	case types.OpReconcileSystem:
		var p types.ReconcileSystemReq
		if err := decodeStrict(req.Data, &p); err != nil {
			return preparedSiteGuard{}, err
		}
		values, ids, err := guardFilter(p.Sites, registry, func(site types.ReconcileSiteReq) types.SiteIdentity {
			return guardIdentity(site.SiteID, site.SubscriptionID, site.Username, site.Domain)
		})
		if err != nil {
			return preparedSiteGuard{}, err
		}
		p.Sites = values
		for i := range p.Sites {
			if p.Sites[i].DNSZone != nil {
				nestedData, _ := json.Marshal(p.Sites[i].DNSZone)
				nested, err := prepareSiteGuard(types.Request{Op: types.OpConfigureDNSZone, Data: nestedData}, registry)
				if err != nil {
					return preparedSiteGuard{}, err
				}
				var zone types.ConfigureDNSZoneReq
				if err = json.Unmarshal(nested.request.Data, &zone); err != nil {
					return preparedSiteGuard{}, err
				}
				p.Sites[i].DNSZone = &zone
				ids = append(ids, nested.identities...)
			}
		}
		return guardShared(req, p, ids, true)
	case types.OpEnsureSubscriptionAccount:
		var p types.EnsureSubscriptionAccountReq
		if err := decodeStrict(req.Data, &p); err != nil {
			return preparedSiteGuard{}, err
		}
		return guardAccount(req, p, registry)
	case types.OpApplyScheduledTasks:
		var p types.ApplyScheduledTasksReq
		if err := decodeStrict(req.Data, &p); err != nil {
			return preparedSiteGuard{}, err
		}
		values, ids, err := guardFilter(p.Tasks, registry, func(task types.ScheduledTask) types.SiteIdentity {
			return guardIdentity(task.SiteID, p.SubscriptionID, p.Username, task.Domain)
		})
		if err != nil {
			return preparedSiteGuard{}, err
		}
		p.Tasks = values
		scoped := []types.SiteIdentity{}
		for _, id := range ids {
			if id.Domain != "" {
				scoped = append(scoped, id)
			}
		}
		return guardShared(req, p, scoped, false)
	case types.OpConfigureMail:
		var p types.ConfigureMailReq
		if err := decodeStrict(req.Data, &p); err != nil {
			return preparedSiteGuard{}, err
		}
		values, ids, err := guardFilter(p.Domains, registry, func(domain types.MailDomainConfig) types.SiteIdentity {
			return guardIdentity(domain.SiteID, domain.SubscriptionID, "", domain.Domain)
		})
		if err != nil {
			return preparedSiteGuard{}, err
		}
		p.Domains = values
		return guardShared(req, p, ids, false)
	case types.OpEnsureFTPS:
		var p types.EnsureFTPSReq
		if err := decodeStrict(req.Data, &p); err != nil {
			return preparedSiteGuard{}, err
		}
		values, ids, err := guardFilter(p.Accounts, registry, func(account types.EnsureFTPSAccount) types.SiteIdentity {
			return guardIdentity(account.SiteID, 0, account.Username, account.Domain)
		})
		if err != nil {
			return preparedSiteGuard{}, err
		}
		p.Accounts = values
		scoped := []types.SiteIdentity{}
		for _, id := range ids {
			if id.Domain != "" {
				scoped = append(scoped, id)
			}
		}
		return guardShared(req, p, scoped, false)
	case types.OpCollectUsage:
		var p types.CollectUsageReq
		if err := decodeStrict(req.Data, &p); err != nil {
			return preparedSiteGuard{}, err
		}
		values, ids, err := guardFilter(p.Sites, registry, func(site types.SiteUsageInput) types.SiteIdentity {
			return guardIdentity(site.SiteID, p.SubscriptionID, site.Username, site.Domain)
		})
		if err != nil {
			return preparedSiteGuard{}, err
		}
		p.Sites = values
		return guardShared(req, p, ids, false)
	case types.OpMigrateSubscriptionAccount:
		var p types.MigrateSubscriptionAccountReq
		if err := decodeStrict(req.Data, &p); err != nil {
			return preparedSiteGuard{}, err
		}
		values, ids, err := guardFilter(p.Sites, registry, func(site types.LegacySiteMigration) types.SiteIdentity {
			return guardIdentity(site.SiteID, p.SubscriptionID, p.Username, site.Domain)
		})
		if err != nil {
			return preparedSiteGuard{}, err
		}
		p.Sites = values
		return guardShared(req, p, ids, true)
	case types.OpCreateDatabase:
		var p types.CreateDatabaseReq
		if err := decodeStrict(req.Data, &p); err != nil {
			return preparedSiteGuard{}, err
		}
		if p.SiteID > 0 {
			id, err := registry.LookupSite(p.SiteID)
			if err != nil {
				return preparedSiteGuard{}, err
			}
			return preparedSiteGuard{request: req, identities: []types.SiteIdentity{id}}, nil
		}
		return preparedSiteGuard{request: req}, nil
	// Node/account operations do not carry a hosted-site intent. Their existing
	// fixed-service, account-state and database-ownership controls remain mandatory.
	case types.OpSiteServiceDependencies, types.OpPing, types.OpRuntimeCapabilities, types.OpInspectServer, types.OpInspectManagedServices, types.OpInspectTime, types.OpInspectPHP,
		types.OpControlManagedService, types.OpReadJournal, types.OpInspectUpdates, types.OpApplyUpdates, types.OpApplyFail2BanPolicy, types.OpListSecurityBans, types.OpUnbanSecurityAddress,
		types.OpCreateServerBackup, types.OpVerifyServerBackup, types.OpPruneServerBackups, types.OpTestBackupDestination, types.OpInspectServerSecurity, types.OpStageServerSecurity,
		types.OpConfirmServerSecurity, types.OpRevertServerSecurity, types.OpControlHostPower, types.OpInspectDatabaseAdmin, types.OpManageDatabaseAdmin, types.OpReloadService,
		types.OpCleanupLegacyHomes, types.OpTeardownSubscription, types.OpTeardownSite, types.OpCollectMailQueue, types.OpQueryMailQueue, types.OpInspectQueuedMail, types.OpGetMailStatus,
		types.OpWebStatisticsStatus, types.OpDeleteBackup, types.OpFTPSStatus, types.OpEnsureValkey, types.OpValkeyStatus:
		return preparedSiteGuard{request: req}, nil
	default:
		return preparedSiteGuard{}, errors.New("agent operation has no website-removal classification")
	}
}
func (d *Dispatcher) dispatch(ctx context.Context, req types.Request) types.Response {
	if d.siteGuard == nil {
		return d.dispatchUnchecked(ctx, req)
	}
	prepared, err := prepareSiteGuard(req, d.siteGuard)
	if err != nil {
		return validationResponse(req.ID, err.Error())
	}
	var response types.Response
	work := func(leaseCtx context.Context) error {
		// Re-filter after acquiring leases: a removal may have completed while waiting.
		current, err := prepareSiteGuard(req, d.siteGuard)
		if err != nil {
			return err
		}
		response = d.dispatchUnchecked(leaseCtx, current.request)
		return nil
	}
	if len(prepared.identities) == 0 {
		return d.dispatchUnchecked(ctx, prepared.request)
	}
	if prepared.create {
		err = d.siteGuard.WithCreation(ctx, prepared.identities, work)
	} else {
		err = d.siteGuard.WithSites(ctx, prepared.identities, work)
	}
	if err != nil {
		return validationResponse(req.ID, err.Error())
	}
	return response
}
