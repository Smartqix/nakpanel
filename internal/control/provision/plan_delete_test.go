package provision

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
)

type planDeletionStoreFixture struct {
	fakePlanAdminStore
	planID, resellerID int64
	unrestricted       bool
}

func (s *planDeletionStoreFixture) DeletePlan(_ context.Context, planID, resellerID int64, unrestricted bool) error {
	s.planID, s.resellerID, s.unrestricted = planID, resellerID, unrestricted
	return nil
}

func TestDeletePlanEnforcesActorAndProviderScope(t *testing.T) {
	for _, tc := range []struct {
		name        string
		role        auth.Role
		allowed     bool
		resellerID  int64
		wantAllowed bool
	}{
		{"admin", auth.RoleAdmin, false, 0, true},
		{"owner", auth.RoleReseller, true, 7, true},
		{"foreign", auth.RoleReseller, false, 7, false},
		{"missing provider", auth.RoleReseller, true, 0, false},
		{"client", auth.RoleClient, true, 7, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &planDeletionStoreFixture{fakePlanAdminStore: fakePlanAdminStore{providerResellerID: tc.resellerID}}
			manager := NewManager(nil, WithQuotaStore(store), WithAccessPolicy(fakeAccessPolicy{allow: tc.allowed}))
			err := manager.DeletePlan(context.Background(), auth.SessionUser{ID: 3, Role: tc.role}, 42)
			if !tc.wantAllowed {
				if !errors.Is(err, ErrForbidden) || store.planID != 0 {
					t.Fatalf("unauthorized deletion: err=%v store=%+v", err, store)
				}
				return
			}
			if err != nil || store.planID != 42 || store.resellerID != tc.resellerID || store.unrestricted != (tc.role == auth.RoleAdmin) {
				t.Fatalf("wrong deletion scope: err=%v store=%+v", err, store)
			}
		})
	}
}
