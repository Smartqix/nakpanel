package provision

import (
	"context"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type phpLogStore struct {
	*fakeQuotaStore
	redactorCalled bool
}

func (s *phpLogStore) SiteDomain(context.Context, int64) (string, error) {
	return "example.test", nil
}
func (s *phpLogStore) SiteRuntimeIdentity(context.Context, int64) (string, string, error) {
	return "npaccount", "example.test", nil
}
func (s *phpLogStore) UpdateSiteSettings(context.Context, types.UpdateSiteSettingsReq) error {
	return nil
}
func (s *phpLogStore) UpdateSitePHPSettings(context.Context, types.UpdateSitePHPSettingsReq) error {
	return nil
}
func (s *phpLogStore) SetTLSAutoRenew(context.Context, int64, bool) error { return nil }
func (s *phpLogStore) EffectiveSitePolicy(context.Context, int64) (types.HostingPolicy, error) {
	return types.HostingPolicy{Permissions: types.HostingPermissionPolicy{Logs: true}}, nil
}
func (s *phpLogStore) RedactPHPEnvironmentSecrets(_ context.Context, _ int64, lines []string) ([]string, error) {
	s.redactorCalled = true
	for index := range lines {
		lines[index] = strings.ReplaceAll(lines[index], "deployment-secret", "[REDACTED]")
	}
	return lines, nil
}

type phpLogAgent struct{}

func (phpLogAgent) ReadSiteLog(context.Context, types.SiteLogRequest) (types.SiteLogResult, error) {
	return types.SiteLogResult{Source: types.SiteLogPHPWorker, Lines: []string{"worker echoed deployment-secret"}}, nil
}
func (phpLogAgent) RunScheduledTask(context.Context, types.RunScheduledTaskReq) (types.RunScheduledTaskResult, error) {
	return types.RunScheduledTaskResult{}, nil
}
func (phpLogAgent) FTPSStatus(context.Context) (types.FTPSStatus, error) {
	return types.FTPSStatus{}, nil
}
func (phpLogAgent) ValkeyStatus(context.Context, int64) (types.ValkeyStatus, error) {
	return types.ValkeyStatus{}, nil
}

func TestPhase30SiteLogsRedactReferencedEnvironmentSecrets(t *testing.T) {
	store := &phpLogStore{fakeQuotaStore: &fakeQuotaStore{}}
	manager := NewManager(nil, WithQuotaStore(store), WithAccessPolicy(fakeAccessPolicy{allow: true}), WithHostingToolkitAgent(phpLogAgent{}))
	result, err := manager.ReadSiteLog(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, 7,
		types.SiteLogRequest{Source: types.SiteLogPHPWorker})
	if err != nil {
		t.Fatal(err)
	}
	if !store.redactorCalled || len(result.Lines) != 1 || strings.Contains(result.Lines[0], "deployment-secret") {
		t.Fatalf("Phase 30 log secret redaction = called %v lines %#v", store.redactorCalled, result.Lines)
	}
}
