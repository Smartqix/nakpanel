package provision

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
	"testing"
)

type keyStore struct {
	fakeMailServiceStore
	denied bool
	calls  int
}

func (s *keyStore) GitKeyRequest(context.Context, int64, int64) (types.EnsureGitRepositoryReq, error) {
	s.calls++
	if s.denied {
		return types.EnsureGitRepositoryReq{}, errors.New("Git is disabled")
	}
	return types.EnsureGitRepositoryReq{SiteID: 58, Username: "nps39", Domain: "example.test", Action: "key", Mode: "remote", State: "active", Branch: "main", DeployTarget: "."}, nil
}

type keyAgent struct {
	calls int
	req   types.EnsureGitRepositoryReq
}

func (a *keyAgent) EnsureGitRepository(_ context.Context, req types.EnsureGitRepositoryReq) (types.EnsureGitRepositoryResult, error) {
	a.calls++
	a.req = req
	return types.EnsureGitRepositoryResult{DeployPublicKey: "public"}, nil
}
func (*keyAgent) ReadSiteLog(context.Context, types.SiteLogRequest) (types.SiteLogResult, error) {
	return types.SiteLogResult{}, nil
}
func (*keyAgent) RunScheduledTask(context.Context, types.RunScheduledTaskReq) (types.RunScheduledTaskResult, error) {
	return types.RunScheduledTaskResult{}, nil
}
func (*keyAgent) FTPSStatus(context.Context) (types.FTPSStatus, error) {
	return types.FTPSStatus{}, nil
}
func (*keyAgent) ValkeyStatus(context.Context, int64) (types.ValkeyStatus, error) {
	return types.ValkeyStatus{}, nil
}

func TestGitKeyPreparationDenialAndAuthoritativeIdentity(t *testing.T) {
	store, agent := &keyStore{}, &keyAgent{}
	m := &Manager{quotaStore: store, hostingToolkitAgent: agent}
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	store.denied = true
	if _, err := m.PrepareGitKey(context.Background(), actor, 39, 58, "git@github.com:team/repo.git"); err == nil || agent.calls != 0 {
		t.Fatal("denied request reached agent")
	}
	store.denied = false
	key, err := m.PrepareGitKey(context.Background(), actor, 39, 58, "git@github.com:team/repo.git")
	if err != nil || key != "public" || agent.req.Username != "nps39" || agent.req.Action != "key" || agent.req.RepositoryID != 0 || agent.req.Deploy {
		t.Fatalf("incorrect key request: %+v %v", agent.req, err)
	}
}
