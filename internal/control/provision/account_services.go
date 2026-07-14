package provision

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
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
