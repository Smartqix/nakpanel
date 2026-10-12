package provision

import (
	"context"
	"errors"
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

type taskLogStore struct {
	*phpLogStore
	requestedSite         int64
	denyLogs              bool
	output                string
	readErr, redactionErr error
}

func (s *taskLogStore) EffectiveSitePolicy(ctx context.Context, siteID int64) (types.HostingPolicy, error) {
	if s.denyLogs {
		return types.HostingPolicy{}, nil
	}
	return s.phpLogStore.EffectiveSitePolicy(ctx, siteID)
}

func (s *taskLogStore) ReadScheduledTaskLog(_ context.Context, siteID int64, req types.SiteLogRequest) (types.SiteLogResult, error) {
	s.requestedSite = siteID
	if s.readErr != nil {
		return types.SiteLogResult{}, s.readErr
	}
	output := s.output
	if output == "" {
		output = "recorded Run Now output"
	}
	return types.SiteLogResult{Source: types.SiteLogTask, Lines: []string{output}, NextCursor: 81, Rotated: true, Truncated: true}, nil
}

func (s *taskLogStore) RedactPHPEnvironmentSecrets(ctx context.Context, siteID int64, lines []string) ([]string, error) {
	if s.redactionErr != nil {
		return nil, s.redactionErr
	}
	return s.phpLogStore.RedactPHPEnvironmentSecrets(ctx, siteID, lines)
}

func TestTaskLogRedactsRegisteredPHPSecretAndPreservesRawCursor(t *testing.T) {
	store := &taskLogStore{phpLogStore: &phpLogStore{fakeQuotaStore: &fakeQuotaStore{}}, output: "task echoed deployment-secret"}
	m := NewManager(nil, WithQuotaStore(store), WithAccessPolicy(fakeAccessPolicy{allow: true}))
	result, err := m.ReadSiteLog(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, 7, types.SiteLogRequest{Source: types.SiteLogTask})
	if err != nil || !store.redactorCalled || len(result.Lines) != 1 || strings.Contains(result.Lines[0], "deployment-secret") || !strings.Contains(result.Lines[0], "[REDACTED]") {
		t.Fatalf("task secret exposed: %#v err=%v", result, err)
	}
	if result.NextCursor != 81 || !result.Rotated || !result.Truncated {
		t.Fatalf("redaction changed raw stream position: %#v", result)
	}
}

func TestTaskLogReadAndRedactionErrorsFailClosed(t *testing.T) {
	for _, redaction := range []bool{false, true} {
		want := errors.New("registered secret read unavailable")
		store := &taskLogStore{phpLogStore: &phpLogStore{fakeQuotaStore: &fakeQuotaStore{}}, output: "task echoed deployment-secret"}
		if redaction {
			store.redactionErr = want
		} else {
			store.readErr = want
		}
		m := NewManager(nil, WithQuotaStore(store), WithAccessPolicy(fakeAccessPolicy{allow: true}))
		result, err := m.ReadSiteLog(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, 7, types.SiteLogRequest{Source: types.SiteLogTask})
		if !errors.Is(err, want) || len(result.Lines) != 0 {
			t.Fatalf("failure returned task contents: redaction=%v result=%#v err=%v", redaction, result, err)
		}
	}
}

func TestTaskLogReadsAuthoritativeRecordedRuns(t *testing.T) {
	store := &taskLogStore{phpLogStore: &phpLogStore{fakeQuotaStore: &fakeQuotaStore{}}}
	m := NewManager(nil, WithQuotaStore(store), WithAccessPolicy(fakeAccessPolicy{allow: true}), WithHostingToolkitAgent(phpLogAgent{}))
	result, err := m.ReadSiteLog(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, 7, types.SiteLogRequest{SiteID: 99, Source: types.SiteLogTask, LineLimit: 20, ByteLimit: 4096})
	if err != nil || store.requestedSite != 7 || result.Source != types.SiteLogTask || len(result.Lines) != 1 || result.Lines[0] != "recorded Run Now output" {
		t.Fatalf("task log did not read trusted recorded runs: site=%d result=%#v err=%v", store.requestedSite, result, err)
	}
}

func TestTaskLogAuthorizationAndPolicyCannotBeBypassed(t *testing.T) {
	for _, denyPolicy := range []bool{false, true} {
		store := &taskLogStore{phpLogStore: &phpLogStore{fakeQuotaStore: &fakeQuotaStore{}}, denyLogs: denyPolicy}
		m := NewManager(nil, WithQuotaStore(store), WithAccessPolicy(fakeAccessPolicy{allow: denyPolicy}))
		_, err := m.ReadSiteLog(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, 7, types.SiteLogRequest{Source: types.SiteLogTask})
		if err == nil || store.requestedSite != 0 {
			t.Fatalf("task log access bypassed: policy=%v readSite=%d err=%v", denyPolicy, store.requestedSite, err)
		}
	}
}

func TestRecordedTaskLogsDoNotRequireLiveAgent(t *testing.T) {
	store := &taskLogStore{phpLogStore: &phpLogStore{fakeQuotaStore: &fakeQuotaStore{}}}
	m := NewManager(nil, WithQuotaStore(store), WithAccessPolicy(fakeAccessPolicy{allow: true}))
	if _, err := m.ReadSiteLog(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, 7, types.SiteLogRequest{Source: types.SiteLogTask}); err != nil {
		t.Fatalf("recorded task logs required live agent: %v", err)
	}
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
