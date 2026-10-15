package provision

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type planSyncStoreFixture struct {
	fakePlanAdminStore
	calls int
}

func (s *planSyncStoreFixture) PlanSynchronization(context.Context, int64) (types.PlanSynchronization, error) {
	s.calls++
	return types.PlanSynchronization{PlanID: 5, Revision: 3}, nil
}

func TestPlanSynchronizationRejectsCrossProviderBeforeRead(t *testing.T) {
	store := &planSyncStoreFixture{}
	manager := NewManager(nil, WithQuotaStore(store), WithAccessPolicy(fakeAccessPolicy{allow: false}))
	for _, role := range []auth.Role{auth.RoleReseller, auth.RoleClient} {
		_, err := manager.PlanSynchronization(context.Background(), auth.SessionUser{ID: 2, Role: role}, 5)
		if !errors.Is(err, ErrForbidden) || store.calls != 0 {
			t.Fatalf("unauthorized read: calls=%d err=%v", store.calls, err)
		}
	}
	got, err := manager.PlanSynchronization(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, 5)
	if err != nil || got.Revision != 3 || store.calls != 1 {
		t.Fatalf("admin read: %+v %v", got, err)
	}
}

func TestZeroWordPressCapacityCannotReachPlanStore(t *testing.T) {
	store := &fakePlanAdminStore{}
	manager := NewManager(nil, WithQuotaStore(store), WithRuntimeCapabilities(fakeRuntimeCapabilities{
		result: types.RuntimeCapabilities{PHPVersions: []string{"8.4"}, WPCLIAvailable: true},
	}))
	plan := controlquota.Plan{Name: "WordPress", LifecycleStatus: types.PlanLifecycleActive,
		HostingPolicy: types.HostingPolicy{SchemaVersion: 5, Permissions: types.HostingPermissionPolicy{WordPressToolkit: true}}}
	_, err := manager.UpsertPlan(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, plan)
	if err == nil || !strings.Contains(err.Error(), "zero") || store.saved.Name != "" {
		t.Fatalf("contradictory plan saved: %+v %v", store.saved, err)
	}
	plan.HostingPolicy.Resources.MaxWordPressSites = 5
	if _, err = manager.UpsertPlan(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, plan); err != nil {
		t.Fatal(err)
	}
	if store.saved.HostingPolicy.Resources.MaxWordPressSites != 5 {
		t.Fatal("five-installation allowance lost")
	}
}
