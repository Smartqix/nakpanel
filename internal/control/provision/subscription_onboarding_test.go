package provision

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type onboardingAdminStore struct {
	controlquota.AdminStore
	request types.CreateSubscriptionReq
	called  bool
}

func (s *onboardingAdminStore) ProviderScopeForUser(context.Context, auth.SessionUser) (types.ProviderScope, error) {
	return types.ProviderScope{ResellerID: 9}, nil
}

func (s *onboardingAdminStore) CreateSubscription(_ context.Context, req types.CreateSubscriptionReq) (types.SubscriptionSummary, error) {
	s.request, s.called = req, true
	return types.SubscriptionSummary{ID: 77}, nil
}

func TestNewCustomerSubscriptionUsesActorProviderScope(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller} {
		t.Run(string(role), func(t *testing.T) {
			store := &onboardingAdminStore{}
			manager := NewManager(nil, WithQuotaStore(store), WithAccessPolicy(selectiveBulkAccessPolicy{fakeAccessPolicy: fakeAccessPolicy{allow: true}, deniedCustomerID: 0}))
			customer := types.CreateCustomerReq{Email: "owner@example.test", ResellerID: 999}
			_, err := manager.CreateSubscription(context.Background(), auth.SessionUser{ID: 3, Role: role}, types.CreateSubscriptionReq{PlanID: 10, NewCustomer: &customer})
			want := int64(0)
			if role == auth.RoleReseller {
				want = 9
			}
			if err != nil || !store.called || store.request.NewCustomer.ResellerID != want || customer.ResellerID != 999 {
				t.Fatalf("request=%+v called=%v customer=%+v error=%v", store.request, store.called, customer, err)
			}
		})
	}
}

func TestNewCustomerSubscriptionStillAuthorizesPlan(t *testing.T) {
	store := &onboardingAdminStore{}
	manager := NewManager(nil, WithQuotaStore(store), WithAccessPolicy(fakeAccessPolicy{allow: false}))
	_, err := manager.CreateSubscription(context.Background(), auth.SessionUser{ID: 3, Role: auth.RoleReseller}, types.CreateSubscriptionReq{PlanID: 10, NewCustomer: &types.CreateCustomerReq{Email: "owner@example.test"}})
	if !errors.Is(err, ErrForbidden) || store.called {
		t.Fatalf("called=%v error=%v", store.called, err)
	}
}
