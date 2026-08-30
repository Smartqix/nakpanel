package phpapp

import (
	"context"
	"errors"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type Manager struct {
	store        ManagerStore
	access       AccessPolicy
	capabilities CapabilityReader
}

func NewManager(store ManagerStore, access AccessPolicy, capabilities CapabilityReader) *Manager {
	return &Manager{store: store, access: access, capabilities: capabilities}
}

func (m *Manager) authorizeSite(ctx context.Context, actor auth.SessionUser, siteID int64) (SiteIdentity, error) {
	if m == nil || m.store == nil || m.access == nil || siteID <= 0 {
		return SiteIdentity{}, ErrNotFound
	}
	identity, err := m.store.SiteIdentity(ctx, siteID)
	if errors.Is(err, ErrNotFound) {
		return SiteIdentity{}, ErrNotFound
	}
	if err != nil {
		return SiteIdentity{}, err
	}
	ok, err := m.access.CanManagePHP(ctx, actor, identity.Domain)
	if err != nil {
		return SiteIdentity{}, err
	}
	if !ok {
		return SiteIdentity{}, ErrNotFound
	}
	return identity, nil
}

func (m *Manager) runtime(ctx context.Context, version string) (types.PHPRuntimeCapability, error) {
	if m.capabilities == nil {
		return types.PHPRuntimeCapability{}, ErrRuntimeUnavailable
	}
	capabilities, err := m.capabilities.RuntimeCapabilities(ctx)
	if err != nil {
		return types.PHPRuntimeCapability{}, err
	}
	return readyPHPRuntime(capabilities, version)
}

func (m *Manager) Workspace(ctx context.Context, actor auth.SessionUser, siteID int64) (Workspace, error) {
	identity, err := m.authorizeSite(ctx, actor, siteID)
	if err != nil {
		return Workspace{}, err
	}
	workspace, err := m.store.Workspace(ctx, identity.ID)
	if err != nil {
		return Workspace{}, err
	}
	if m.capabilities != nil {
		capabilities, capabilityErr := m.capabilities.RuntimeCapabilities(ctx)
		if capabilityErr == nil {
			for _, runtime := range capabilities.PHPRuntimes {
				if runtime.Version == workspace.Application.PHPVersion {
					workspace.Runtime = runtime
					break
				}
			}
		}
	}
	return workspace, nil
}

func (m *Manager) ConfigureApplication(ctx context.Context, actor auth.SessionUser, siteID int64, input ConfigureApplicationInput) (types.PHPApplicationSpec, error) {
	identity, err := m.authorizeSite(ctx, actor, siteID)
	if err != nil {
		return types.PHPApplicationSpec{}, err
	}
	runtime, err := m.runtime(ctx, input.PHPVersion)
	if err != nil {
		return types.PHPApplicationSpec{}, err
	}
	return m.store.ConfigureApplication(ctx, actor.ID, identity.ID, input, runtime)
}

func (m *Manager) QueueDeployment(ctx context.Context, actor auth.SessionUser, siteID int64, input DeploymentInput) (types.PHPDeployment, error) {
	identity, err := m.authorizeSite(ctx, actor, siteID)
	if err != nil {
		return types.PHPDeployment{}, err
	}
	runtime, err := m.runtime(ctx, identity.PHPVersion)
	if err != nil {
		return types.PHPDeployment{}, err
	}
	return m.store.QueueDeployment(ctx, actor.ID, identity.ID, input, runtime)
}

func (m *Manager) QueueRollback(ctx context.Context, actor auth.SessionUser, siteID, targetDeploymentID int64) (types.PHPDeployment, error) {
	identity, err := m.authorizeSite(ctx, actor, siteID)
	if err != nil {
		return types.PHPDeployment{}, err
	}
	runtime, err := m.runtime(ctx, identity.PHPVersion)
	if err != nil {
		return types.PHPDeployment{}, err
	}
	return m.store.QueueRollback(ctx, actor.ID, identity.ID, targetDeploymentID, runtime)
}

func (m *Manager) UpsertEnvironment(ctx context.Context, actor auth.SessionUser, siteID int64, input EnvironmentInput) (types.PHPEnvironmentVariable, error) {
	identity, err := m.authorizeSite(ctx, actor, siteID)
	if err != nil {
		return types.PHPEnvironmentVariable{}, err
	}
	return m.store.UpsertEnvironment(ctx, actor.ID, identity.ID, input)
}
func (m *Manager) DeleteEnvironment(ctx context.Context, actor auth.SessionUser, siteID int64, name string) error {
	identity, err := m.authorizeSite(ctx, actor, siteID)
	if err != nil {
		return err
	}
	return m.store.DeleteEnvironment(ctx, actor.ID, identity.ID, name)
}
func (m *Manager) UpsertWorker(ctx context.Context, actor auth.SessionUser, siteID int64, input WorkerInput) (types.PHPWorker, error) {
	identity, err := m.authorizeSite(ctx, actor, siteID)
	if err != nil {
		return types.PHPWorker{}, err
	}
	return m.store.UpsertWorker(ctx, actor.ID, identity.ID, input)
}
func (m *Manager) DeleteWorker(ctx context.Context, actor auth.SessionUser, siteID, workerID int64) error {
	identity, err := m.authorizeSite(ctx, actor, siteID)
	if err != nil {
		return err
	}
	return m.store.DeleteWorker(ctx, actor.ID, identity.ID, workerID)
}
func (m *Manager) SetWorkerState(ctx context.Context, actor auth.SessionUser, siteID, workerID int64, state string) error {
	identity, err := m.authorizeSite(ctx, actor, siteID)
	if err != nil {
		return err
	}
	return m.store.SetWorkerState(ctx, actor.ID, identity.ID, workerID, state)
}
func (m *Manager) RequestReconcile(ctx context.Context, actor auth.SessionUser, siteID int64) error {
	identity, err := m.authorizeSite(ctx, actor, siteID)
	if err != nil {
		return err
	}
	return m.store.RequestReconcile(ctx, actor.ID, identity.ID)
}
