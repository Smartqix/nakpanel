package provision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"golang.org/x/crypto/bcrypt"
)

func (m *Manager) accountServices() (controlquota.AccountServiceStore, error) {
	store, ok := m.quotaStore.(controlquota.AccountServiceStore)
	if !ok {
		return nil, errors.New("subscription services are not configured")
	}
	return store, nil
}

func (m *Manager) SetSubscriptionPolicy(ctx context.Context, actor auth.SessionUser, subscriptionID int64, patch json.RawMessage) error {
	if actor.Role == auth.RoleClient {
		return ErrForbidden
	}
	if err := m.canManageSubscription(ctx, actor, subscriptionID); err != nil {
		return err
	}
	store, err := m.accountServices()
	if err != nil {
		return err
	}
	return store.SetSubscriptionPolicy(ctx, subscriptionID, actor.ID, patch, actor.Role == auth.RoleAdmin)
}

func (m *Manager) SetSitePolicy(ctx context.Context, actor auth.SessionUser, siteID int64, patch json.RawMessage) error {
	store, err := m.accountServices()
	if err != nil {
		return err
	}
	domainStore, ok := m.quotaStore.(controlquota.DomainSettingsStore)
	if !ok {
		return errors.New("domain settings are not configured")
	}
	domain, err := domainStore.SiteDomain(ctx, siteID)
	if err != nil {
		return err
	}
	if err := m.canManageDomain(ctx, actor, domain); err != nil {
		return err
	}
	return store.SetSitePolicy(ctx, siteID, actor.ID, patch)
}

func (m *Manager) ResetSitePolicy(ctx context.Context, actor auth.SessionUser, siteID int64, scope string) error {
	store, err := m.accountServices()
	if err != nil {
		return err
	}
	domainStore, ok := m.quotaStore.(controlquota.DomainSettingsStore)
	if !ok {
		return errors.New("domain settings are not configured")
	}
	domain, err := domainStore.SiteDomain(ctx, siteID)
	if err != nil {
		return err
	}
	if err := m.canManageDomain(ctx, actor, domain); err != nil {
		return err
	}
	return store.ResetSitePolicy(ctx, siteID, actor.ID, scope)
}

func (m *Manager) UpsertSFTPIdentity(ctx context.Context, actor auth.SessionUser, subscriptionID int64, input types.SFTPIdentityInput) (int64, error) {
	store, err := m.authorizedAccountServices(ctx, actor, subscriptionID)
	if err != nil {
		return 0, err
	}
	return store.UpsertSFTPIdentity(ctx, subscriptionID, actor.ID, input)
}

func (m *Manager) UpsertScheduledTask(ctx context.Context, actor auth.SessionUser, subscriptionID int64, input types.ScheduledTaskInput) (int64, error) {
	store, err := m.authorizedAccountServices(ctx, actor, subscriptionID)
	if err != nil {
		return 0, err
	}
	return store.UpsertScheduledTask(ctx, subscriptionID, actor.ID, input)
}

func (m *Manager) UpsertMailDomain(ctx context.Context, actor auth.SessionUser, subscriptionID int64, input types.MailDomainInput) (int64, error) {
	store, err := m.authorizedAccountServices(ctx, actor, subscriptionID)
	if err != nil {
		return 0, err
	}
	return store.UpsertMailDomain(ctx, subscriptionID, actor.ID, input)
}

func (m *Manager) UpsertMailbox(ctx context.Context, actor auth.SessionUser, subscriptionID int64, input types.MailboxInput) (int64, error) {
	store, err := m.authorizedAccountServices(ctx, actor, subscriptionID)
	if err != nil {
		return 0, err
	}
	return store.UpsertMailbox(ctx, subscriptionID, actor.ID, input)
}

func (m *Manager) UpsertMailAlias(ctx context.Context, actor auth.SessionUser, subscriptionID int64, input types.MailAliasInput) (int64, error) {
	store, err := m.authorizedAccountServices(ctx, actor, subscriptionID)
	if err != nil {
		return 0, err
	}
	return store.UpsertMailAlias(ctx, subscriptionID, actor.ID, input)
}

func (m *Manager) UpsertApplication(ctx context.Context, actor auth.SessionUser, subscriptionID int64, input types.ApplicationInput) (int64, error) {
	store, err := m.authorizedAccountServices(ctx, actor, subscriptionID)
	if err != nil {
		return 0, err
	}
	return store.UpsertApplication(ctx, subscriptionID, actor.ID, input)
}

func (m *Manager) SetApplicationAction(ctx context.Context, actor auth.SessionUser, subscriptionID, applicationID int64, action string) error {
	store, err := m.authorizedAccountServices(ctx, actor, subscriptionID)
	if err != nil {
		return err
	}
	lifecycle, ok := store.(interface {
		SetApplicationAction(context.Context, int64, int64, string) error
	})
	if !ok {
		return errors.New("application lifecycle is not configured")
	}
	return lifecycle.SetApplicationAction(ctx, subscriptionID, applicationID, action)
}

func (m *Manager) UpsertApplicationPreset(ctx context.Context, actor auth.SessionUser, input types.ApplicationPresetInput) (int64, error) {
	if actor.Role != auth.RoleAdmin && actor.Role != auth.RoleReseller {
		return 0, ErrForbidden
	}
	store, err := m.accountServices()
	if err != nil {
		return 0, err
	}
	return store.UpsertApplicationPreset(ctx, actor.ID, string(actor.Role), input)
}

func (m *Manager) UpsertProtectedDirectory(ctx context.Context, actor auth.SessionUser, subscriptionID int64, input types.ProtectedDirectoryInput) (int64, string, error) {
	store, err := m.authorizedAccountServices(ctx, actor, subscriptionID)
	if err != nil {
		return 0, "", err
	}
	password := input.Password
	if input.ID == 0 && password == "" {
		password, err = m.passwordGenerator()
		if err != nil {
			return 0, "", err
		}
	}
	passwordHash := ""
	if password != "" {
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if hashErr != nil {
			return 0, "", fmt.Errorf("hash protected-directory password: %w", hashErr)
		}
		passwordHash = string(hash)
	}
	input.Password = ""
	id, err := store.UpsertProtectedDirectory(ctx, subscriptionID, actor.ID, input, passwordHash)
	if err != nil {
		return 0, "", err
	}
	return id, password, nil
}

func (m *Manager) UpsertFTPAccount(ctx context.Context, actor auth.SessionUser, subscriptionID int64, input types.FTPAccountInput) (int64, string, error) {
	store, err := m.authorizedAccountServices(ctx, actor, subscriptionID)
	if err != nil {
		return 0, "", err
	}
	password := input.Password
	if input.ID == 0 && password == "" {
		password, err = m.passwordGenerator()
		if err != nil {
			return 0, "", err
		}
	}
	hash := ""
	if password != "" {
		hash, err = sha512_crypt.New().Generate([]byte(password), nil)
		if err != nil {
			return 0, "", fmt.Errorf("hash FTPS password: %w", err)
		}
	}
	input.Password = ""
	id, err := store.UpsertFTPAccount(ctx, subscriptionID, actor.ID, input, hash)
	if err != nil {
		return 0, "", err
	}
	return id, password, nil
}

func (m *Manager) UpsertGitRepository(ctx context.Context, actor auth.SessionUser, subscriptionID, siteID int64, input types.GitRepositoryInput) (int64, error) {
	store, err := m.authorizedAccountServices(ctx, actor, subscriptionID)
	if err != nil {
		return 0, err
	}
	return store.UpsertGitRepository(ctx, subscriptionID, actor.ID, siteID, input)
}

type gitDeploymentStore interface {
	QueueGitDeployment(context.Context, int64, int64) (int64, error)
	SetGitWebhook(context.Context, int64, int64, string) error
	TriggerGitWebhook(context.Context, int64, string) error
}

func (m *Manager) QueueGitDeployment(ctx context.Context, actor auth.SessionUser, subscriptionID, siteID int64) (int64, error) {
	if _, err := m.authorizedAccountServices(ctx, actor, subscriptionID); err != nil {
		return 0, err
	}
	store, ok := m.quotaStore.(gitDeploymentStore)
	if !ok {
		return 0, errors.New("Git deployment is not configured")
	}
	return store.QueueGitDeployment(ctx, subscriptionID, siteID)
}

func (m *Manager) RotateGitWebhook(ctx context.Context, actor auth.SessionUser, subscriptionID, siteID int64) (string, error) {
	if _, err := m.authorizedAccountServices(ctx, actor, subscriptionID); err != nil {
		return "", err
	}
	store, ok := m.quotaStore.(gitDeploymentStore)
	if !ok {
		return "", errors.New("Git webhooks are not configured")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	if err := store.SetGitWebhook(ctx, subscriptionID, siteID, hex.EncodeToString(sum[:])); err != nil {
		return "", err
	}
	return token, nil
}

func (m *Manager) TriggerGitWebhook(ctx context.Context, repositoryID int64, token string) error {
	store, ok := m.quotaStore.(gitDeploymentStore)
	if !ok {
		return errors.New("Git webhooks are not configured")
	}
	sum := sha256.Sum256([]byte(token))
	return store.TriggerGitWebhook(ctx, repositoryID, hex.EncodeToString(sum[:]))
}

func (m *Manager) QueueStagingOperation(ctx context.Context, actor auth.SessionUser, input types.StagingOperationInput) (int64, error) {
	store, ok := m.quotaStore.(controlquota.StagingStore)
	if !ok {
		return 0, errors.New("staging is not configured")
	}
	domainStore, ok := m.quotaStore.(controlquota.DomainSettingsStore)
	if !ok {
		return 0, errors.New("domain settings are not configured")
	}
	for _, siteID := range []int64{input.SourceSiteID, input.TargetSiteID} {
		domain, err := domainStore.SiteDomain(ctx, siteID)
		if err != nil {
			return 0, err
		}
		if err := m.canManageDomain(ctx, actor, domain); err != nil {
			return 0, err
		}
	}
	return store.QueueStagingOperation(ctx, actor.ID, input)
}

func (m *Manager) ConfigureValkey(ctx context.Context, actor auth.SessionUser, subscriptionID int64, input types.ValkeyInput) (string, error) {
	store, err := m.authorizedAccountServices(ctx, actor, subscriptionID)
	if err != nil {
		return "", err
	}
	credential := ""
	hash := ""
	if input.RotateCredential {
		credential, err = m.passwordGenerator()
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256([]byte(credential))
		hash = fmt.Sprintf("%x", sum[:])
	}
	if err := store.UpsertValkey(ctx, subscriptionID, actor.ID, input, hash); err != nil {
		return "", err
	}
	return credential, nil
}

func (m *Manager) ReadSiteLog(ctx context.Context, actor auth.SessionUser, siteID int64, req types.SiteLogRequest) (types.SiteLogResult, error) {
	if m.hostingToolkitAgent == nil {
		return types.SiteLogResult{}, errors.New("site log service is not configured")
	}
	domainStore, ok := m.quotaStore.(controlquota.DomainSettingsStore)
	if !ok {
		return types.SiteLogResult{}, errors.New("domain settings are not configured")
	}
	domain, err := domainStore.SiteDomain(ctx, siteID)
	if err != nil {
		return types.SiteLogResult{}, err
	}
	if err := m.canManageDomain(ctx, actor, domain); err != nil {
		return types.SiteLogResult{}, err
	}
	policyStore, ok := m.quotaStore.(interface {
		EffectiveSitePolicy(context.Context, int64) (types.HostingPolicy, error)
	})
	if !ok {
		return types.SiteLogResult{}, errors.New("site policy service is not configured")
	}
	effective, err := policyStore.EffectiveSitePolicy(ctx, siteID)
	if err != nil {
		return types.SiteLogResult{}, err
	}
	if !effective.Permissions.Logs {
		return types.SiteLogResult{}, errors.New("log access is disabled by the subscription policy")
	}
	username, authoritativeDomain, err := domainStore.SiteRuntimeIdentity(ctx, siteID)
	if err != nil {
		return types.SiteLogResult{}, err
	}
	req.SiteID, req.Username, req.Domain = siteID, username, authoritativeDomain
	return m.hostingToolkitAgent.ReadSiteLog(ctx, req)
}

func (m *Manager) RunScheduledTask(ctx context.Context, actor auth.SessionUser, subscriptionID, taskID int64) (types.ScheduledTaskRun, error) {
	if m.hostingToolkitAgent == nil {
		return types.ScheduledTaskRun{}, errors.New("scheduled task runner is not configured")
	}
	store, err := m.authorizedAccountServices(ctx, actor, subscriptionID)
	if err != nil {
		return types.ScheduledTaskRun{}, err
	}
	req, err := store.ScheduledTaskRunRequest(ctx, subscriptionID, taskID)
	if err != nil {
		return types.ScheduledTaskRun{}, err
	}
	if req.SiteID == 0 {
		return types.ScheduledTaskRun{}, errors.New("Run Now requires a domain-scoped task")
	}
	runID, err := store.CreateScheduledTaskRun(ctx, taskID)
	if err != nil {
		return types.ScheduledTaskRun{}, err
	}
	result, runErr := m.hostingToolkitAgent.RunScheduledTask(ctx, req)
	if runErr != nil {
		result = types.RunScheduledTaskResult{Status: "failed", ExitCode: -1, Output: runErr.Error()}
	}
	if finishErr := store.FinishScheduledTaskRun(ctx, runID, result); finishErr != nil {
		return types.ScheduledTaskRun{}, errors.Join(runErr, finishErr)
	}
	return types.ScheduledTaskRun{ID: runID, TaskID: taskID, Status: result.Status, Output: result.Output}, runErr
}

func (m *Manager) DeleteSubscriptionService(ctx context.Context, actor auth.SessionUser, subscriptionID int64, kind string, id int64) error {
	store, err := m.authorizedAccountServices(ctx, actor, subscriptionID)
	if err != nil {
		return err
	}
	switch kind {
	case "sftp":
		return store.DeleteSFTPIdentity(ctx, subscriptionID, id)
	case "task":
		return store.DeleteScheduledTask(ctx, subscriptionID, id)
	case "mail":
		return store.DeleteMailDomain(ctx, subscriptionID, id)
	case "mailbox":
		return store.DeleteMailbox(ctx, subscriptionID, id)
	case "mail_alias":
		return store.DeleteMailAlias(ctx, subscriptionID, id)
	case "application":
		return store.DeleteApplication(ctx, subscriptionID, id)
	case "ftp":
		return store.DeleteFTPAccount(ctx, subscriptionID, id)
	case "protected":
		return store.DeleteProtectedDirectory(ctx, subscriptionID, id)
	default:
		return errors.New("unsupported subscription service")
	}
}

func (m *Manager) authorizedAccountServices(ctx context.Context, actor auth.SessionUser, subscriptionID int64) (controlquota.AccountServiceStore, error) {
	if err := m.canManageSubscription(ctx, actor, subscriptionID); err != nil {
		return nil, err
	}
	return m.accountServices()
}
