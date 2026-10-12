package quota

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type managedHandoffRecorder struct {
	sites []int64
	err   error
}

func (r *managedHandoffRecorder) ReconcileSiteApplication(_ context.Context, siteID int64) error {
	r.sites = append(r.sites, siteID)
	return r.err
}

func TestManagedAccountConvergenceRequiresOwnerHandoff(t *testing.T) {
	domains := []types.SubscriptionDomain{{SiteID: 7, HostingMode: types.PHPHostingModeManaged, ActiveDeploymentID: 91}, {SiteID: 8, HostingMode: types.PHPHostingModeClassic}}
	worker := NewConvergeSubscriptionWorker(nil, nil)
	if err := worker.reconcileManagedDomains(context.Background(), domains); err == nil {
		t.Fatal("managed runtime could be acknowledged without its owner")
	}
	owner := &managedHandoffRecorder{}
	worker.SetApplicationReconciler(owner)
	if err := worker.reconcileManagedDomains(context.Background(), domains); err != nil {
		t.Fatal(err)
	}
	if len(owner.sites) != 1 || owner.sites[0] != 7 {
		t.Fatalf("wrong owner handoff: %v", owner.sites)
	}
	owner.err = errors.New("owner enqueue failed")
	if err := worker.reconcileManagedDomains(context.Background(), domains); err == nil {
		t.Fatal("owner failure was hidden")
	}
}
