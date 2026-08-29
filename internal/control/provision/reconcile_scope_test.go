package provision

import (
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestRetainCapturedReconcileIntentNeverExpandsGlobalJob(t *testing.T) {
	captured := ReconcileSystemArgs{
		ScopeKey:  "system",
		Sites:     []types.ReconcileSiteReq{{SiteID: 1}},
		Databases: []types.ReconcileDatabaseReq{{DatabaseID: 2}},
	}
	currentSites := []types.ReconcileSiteReq{{SiteID: 1}, {SiteID: 3}}
	currentDatabases := []types.ReconcileDatabaseReq{{DatabaseID: 2}, {DatabaseID: 4}}

	sites, databases := retainCapturedReconcileIntent(captured, currentSites, currentDatabases)
	if len(sites) != 1 || sites[0].SiteID != 1 {
		t.Fatalf("refreshed sites = %+v, want only captured site 1", sites)
	}
	if len(databases) != 1 || databases[0].DatabaseID != 2 {
		t.Fatalf("refreshed databases = %+v, want only captured database 2", databases)
	}
}

func TestRetainCapturedSiteReconcileDropsDatabases(t *testing.T) {
	captured := ReconcileSystemArgs{
		ScopeKey: "site:1",
		Sites:    []types.ReconcileSiteReq{{SiteID: 1}},
	}
	sites, databases := retainCapturedReconcileIntent(
		captured,
		[]types.ReconcileSiteReq{{SiteID: 1}, {SiteID: 3}},
		[]types.ReconcileDatabaseReq{{DatabaseID: 2}},
	)
	if len(sites) != 1 || sites[0].SiteID != 1 || len(databases) != 0 {
		t.Fatalf("site-scoped refresh = sites %+v databases %+v", sites, databases)
	}
}
