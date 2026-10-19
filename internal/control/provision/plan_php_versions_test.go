package provision

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type planPHPStoreFixture struct {
	fakePlanAdminStore
	commands []controlquota.PlanPHPVersionsCommand
}

func (s *planPHPStoreFixture) PreviewPlanPHPVersions(_ context.Context, cmd controlquota.PlanPHPVersionsCommand) (controlquota.PlanPHPVersionsPreview, error) {
	s.commands = append(s.commands, cmd)
	return controlquota.PlanPHPVersionsPreview{PlanID: cmd.PlanID, Revision: s.plan.Revision, Preview: types.PlanPreview{Allowed: true}}, nil
}
func (s *planPHPStoreFixture) UpdatePlanPHPVersions(_ context.Context, cmd controlquota.PlanPHPVersionsCommand) (controlquota.PlanPHPVersionsResult, error) {
	s.commands = append(s.commands, cmd)
	return controlquota.PlanPHPVersionsResult{PlanID: cmd.PlanID, Revision: s.plan.Revision + 1, Changed: true, SyncState: "pending"}, nil
}

func TestPlanPHPVersionsReadinessAllLifecycles(t *testing.T) {
	for _, lifecycle := range []types.PlanLifecycleStatus{types.PlanLifecycleActive, types.PlanLifecycleDraft, types.PlanLifecycleRetired} {
		for _, hosting := range []bool{false, true} {
			for _, noop := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/hosting=%t/noop=%t", lifecycle, hosting, noop), func(t *testing.T) {
					stored := "8.3"
					if noop {
						stored = "8.5"
					}
					store := &planPHPStoreFixture{fakePlanAdminStore: fakePlanAdminStore{plan: controlquota.Plan{ID: 5, Name: "Stored raw plan", Revision: 3, LifecycleStatus: lifecycle, IsActive: lifecycle == types.PlanLifecycleActive, HostingEnabled: hosting, PHPAllowlist: stored, DefaultPHPVersion: stored}}}
					m := NewManager(nil, WithQuotaStore(store), WithRuntimeCapabilities(fakeRuntimeCapabilities{result: types.RuntimeCapabilities{PHPVersions: []string{"8.3", "8.5"}, PHPRuntimes: []types.PHPRuntimeCapability{{Version: "8.3", Ready: true}, {Version: "8.5", Ready: false}}}}))
					actor := auth.SessionUser{ID: 1, Email: "provider@example.test", Role: auth.RoleAdmin}
					input := controlquota.PlanPHPVersionsInput{ExpectedRevision: 3, PHPVersions: []string{"8.5"}, DefaultPHPVersion: "8.5", ChangeReason: "Explicit maintenance"}
					_, err := m.UpdatePlanPHPVersions(context.Background(), actor, 5, input)
					var readiness *controlquota.PlanPHPReadinessError
					if !errors.As(err, &readiness) || len(store.commands) != 0 {
						t.Fatalf("unready request reached store: %v %+v", err, store.commands)
					}
					preview, err := m.PreviewPlanPHPVersions(context.Background(), actor, 5, input)
					if err != nil || preview.Preview.Allowed || len(preview.Blockers) == 0 {
						t.Fatalf("preview hid unready blocker: %+v %v", preview, err)
					}
					if store.plan.LifecycleStatus != lifecycle || store.readinessCalls != 0 || store.saved.Name != "" {
						t.Fatal("narrow API mutated lifecycle/readiness/full plan")
					}
				})
			}
		}
	}
}

func TestPlanPHPVersionsMissingReadinessFailsClosed(t *testing.T) {
	for _, mode := range []string{"missing", "empty", "failed"} {
		t.Run(mode, func(t *testing.T) {
			store := &planPHPStoreFixture{fakePlanAdminStore: fakePlanAdminStore{plan: controlquota.Plan{ID: 5, Name: "Draft", Revision: 3, LifecycleStatus: types.PlanLifecycleDraft, PHPAllowlist: "8.5", DefaultPHPVersion: "8.5"}}}
			m := NewManager(nil, WithQuotaStore(store))
			if mode != "missing" {
				caps := fakeRuntimeCapabilities{}
				if mode == "failed" {
					caps.err = errors.New("private unavailable dependency")
				}
				m = NewManager(nil, WithQuotaStore(store), WithRuntimeCapabilities(caps))
			}
			input := controlquota.PlanPHPVersionsInput{ExpectedRevision: 3, PHPVersions: []string{"8.5"}, DefaultPHPVersion: "8.5", ChangeReason: "Current intent still requires readiness"}
			_, err := m.UpdatePlanPHPVersions(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, 5, input)
			var readiness *controlquota.PlanPHPReadinessError
			if !errors.As(err, &readiness) || readiness.Cause == nil || len(store.commands) != 0 {
				t.Fatalf("unavailable authoritative inventory reached writer: %v", err)
			}
		})
	}
}

func TestPlanPHPVersionsScopeAndFreshCommand(t *testing.T) {
	store := &planPHPStoreFixture{fakePlanAdminStore: fakePlanAdminStore{plan: controlquota.Plan{ID: 5, Name: "Owned draft", Revision: 3, LifecycleStatus: types.PlanLifecycleDraft, PHPAllowlist: "8.3", DefaultPHPVersion: "8.3"}, providerResellerID: 7}}
	m := NewManager(nil, WithQuotaStore(store), WithAccessPolicy(fakeAccessPolicy{allow: false}), WithRuntimeCapabilities(fakeRuntimeCapabilities{result: types.RuntimeCapabilities{PHPVersions: []string{"8.5"}}}))
	input := controlquota.PlanPHPVersionsInput{ExpectedRevision: 3, PHPVersions: []string{"8.5"}, DefaultPHPVersion: "8.5", ChangeReason: "Explicit maintenance"}
	for _, role := range []auth.Role{auth.RoleClient, auth.RoleReseller} {
		if _, err := m.UpdatePlanPHPVersions(context.Background(), auth.SessionUser{ID: 2, Role: role}, 5, input); !errors.Is(err, ErrForbidden) || len(store.commands) != 0 {
			t.Fatalf("scope bypass: %s %v", role, err)
		}
	}
	actor := auth.SessionUser{ID: 1, Email: "provider@example.test", Role: auth.RoleAdmin}
	if _, err := m.UpdatePlanPHPVersions(context.Background(), actor, 5, input); err != nil {
		t.Fatal(err)
	}
	cmd := store.commands[0]
	if cmd.Actor != actor || cmd.Scope.ActorUserID != 1 || cmd.Scope.Role != "admin" || len(cmd.ReadyPHPVersions) != 1 || cmd.ReadyPHPVersions[0] != "8.5" {
		t.Fatalf("lost authenticated command binding: %+v", cmd)
	}
}
