package phpapp

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeManagerStore struct {
	site       SiteIdentity
	lookupErr  error
	writes     int
	configured types.PHPApplicationSpec
	workspace  Workspace
}

func (s *fakeManagerStore) SiteIdentity(context.Context, int64) (SiteIdentity, error) {
	return s.site, s.lookupErr
}
func (s *fakeManagerStore) Workspace(context.Context, int64) (Workspace, error) {
	return s.workspace, nil
}
func (s *fakeManagerStore) ConfigureApplication(_ context.Context, _, _ int64, input ConfigureApplicationInput, _ types.PHPRuntimeCapability) (types.PHPApplicationSpec, error) {
	s.writes++
	return s.configured, nil
}
func (s *fakeManagerStore) QueueDeployment(context.Context, int64, int64, DeploymentInput, types.PHPRuntimeCapability) (types.PHPDeployment, error) {
	s.writes++
	return types.PHPDeployment{}, nil
}
func (s *fakeManagerStore) QueueRollback(context.Context, int64, int64, int64, types.PHPRuntimeCapability) (types.PHPDeployment, error) {
	s.writes++
	return types.PHPDeployment{}, nil
}
func (s *fakeManagerStore) UpsertEnvironment(context.Context, int64, int64, EnvironmentInput) (types.PHPEnvironmentVariable, error) {
	s.writes++
	return types.PHPEnvironmentVariable{}, nil
}
func (s *fakeManagerStore) DeleteEnvironment(context.Context, int64, int64, string) error {
	s.writes++
	return nil
}
func (s *fakeManagerStore) UpsertWorker(context.Context, int64, int64, WorkerInput) (types.PHPWorker, error) {
	s.writes++
	return types.PHPWorker{}, nil
}
func (s *fakeManagerStore) DeleteWorker(context.Context, int64, int64, int64) error {
	s.writes++
	return nil
}
func (s *fakeManagerStore) SetWorkerState(context.Context, int64, int64, int64, string) error {
	s.writes++
	return nil
}
func (s *fakeManagerStore) RequestReconcile(context.Context, int64, int64) error {
	s.writes++
	return nil
}

type fakePHPAccess struct {
	allowed bool
	err     error
}

func (a fakePHPAccess) CanManagePHP(context.Context, auth.SessionUser, string) (bool, error) {
	return a.allowed, a.err
}

type fakeCapabilities struct {
	value types.RuntimeCapabilities
	err   error
}

func (c fakeCapabilities) RuntimeCapabilities(context.Context) (types.RuntimeCapabilities, error) {
	return c.value, c.err
}

func TestManagerReturnsNotFoundWithoutMutationForCrossTenantSite(t *testing.T) {
	store := &fakeManagerStore{site: SiteIdentity{ID: 7, Domain: "owned.test", PHPVersion: "8.4"}}
	manager := NewManager(store, fakePHPAccess{allowed: false}, fakeCapabilities{})
	_, err := manager.ConfigureApplication(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, 7, ConfigureApplicationInput{HostingMode: types.PHPHostingModeClassic, PHPVersion: "8.4"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ConfigureApplication error = %v, want ErrNotFound", err)
	}
	if store.writes != 0 {
		t.Fatalf("store writes = %d after access denial", store.writes)
	}
}

func TestManagerRejectsUnreadyRuntimeBeforeMutation(t *testing.T) {
	store := &fakeManagerStore{site: SiteIdentity{ID: 7, Domain: "owned.test", PHPVersion: "8.5"}}
	manager := NewManager(store, fakePHPAccess{allowed: true}, fakeCapabilities{value: types.RuntimeCapabilities{
		PHPRuntimes: []types.PHPRuntimeCapability{{Version: "8.5", Ready: false}},
	}})
	_, err := manager.ConfigureApplication(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, 7, ConfigureApplicationInput{HostingMode: types.PHPHostingModeClassic, PHPVersion: "8.5"})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("ConfigureApplication error = %v, want runtime unavailable", err)
	}
	if store.writes != 0 {
		t.Fatalf("store writes = %d after capability gate", store.writes)
	}
}

func TestWorkspaceReportsExactUnreadyRuntimeDiagnostics(t *testing.T) {
	runtime := types.PHPRuntimeCapability{Version: "8.5", Ready: false, ValidationErrors: []string{"FPM probe failed"}}
	store := &fakeManagerStore{
		site:      SiteIdentity{ID: 7, Domain: "owned.test", PHPVersion: "8.5"},
		workspace: Workspace{Application: types.PHPApplicationSpec{PHPVersion: "8.5"}},
	}
	manager := NewManager(store, fakePHPAccess{allowed: true}, fakeCapabilities{value: types.RuntimeCapabilities{
		PHPRuntimes: []types.PHPRuntimeCapability{runtime},
	}})
	workspace, err := manager.Workspace(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, 7)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Runtime.Version != "8.5" || workspace.Runtime.Ready || len(workspace.Runtime.ValidationErrors) != 1 {
		t.Fatalf("workspace runtime = %#v; want detailed unready runtime", workspace.Runtime)
	}
}
