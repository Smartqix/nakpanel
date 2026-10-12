package provision

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/gitremote"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (m *Manager) PrepareGitKey(ctx context.Context, actor auth.SessionUser, subscriptionID, siteID int64, remote string) (string, error) {
	if _, err := m.authorizedAccountServices(ctx, actor, subscriptionID); err != nil {
		return "", err
	}
	remote, err := gitremote.Normalize(remote)
	if err != nil {
		return "", err
	}
	store, ok := m.quotaStore.(interface {
		GitKeyRequest(context.Context, int64, int64) (types.EnsureGitRepositoryReq, error)
	})
	if !ok {
		return "", errors.New("Git key service is unavailable")
	}
	agent, ok := m.hostingToolkitAgent.(interface {
		EnsureGitRepository(context.Context, types.EnsureGitRepositoryReq) (types.EnsureGitRepositoryResult, error)
	})
	if !ok {
		return "", errors.New("Git agent is unavailable")
	}
	req, err := store.GitKeyRequest(ctx, subscriptionID, siteID)
	if err != nil {
		return "", err
	}
	req.RemoteURL = remote
	result, err := agent.EnsureGitRepository(ctx, req)
	if err != nil {
		return "", errors.New("Could not prepare the SSH key. Check agent status and retry.")
	}
	if result.DeployPublicKey == "" {
		return "", errors.New("The agent did not return a public key")
	}
	return result.DeployPublicKey, nil
}
