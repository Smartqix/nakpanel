package ops

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestTeardownSiteDatabaseOwnershipBeforeStop(t *testing.T) {
	f := newSiteTeardownFixture(t)
	f.request.DeleteDatabaseIDs = []int64{50}
	if _, err := NewSiteTeardownProvisioner(f.opts).TeardownSite(context.Background(), f.request); err == nil {
		t.Fatal("unverified database accepted before stop")
	}
	if len(f.runner.calls) != 0 {
		t.Fatal("services changed before database ownership verification")
	}
}

func TestTeardownSiteRejectsForeignResourceParents(t *testing.T) {
	f := newSiteTeardownFixture(t)
	f.request.Snapshot.Resources = []types.SiteRemovalResource{{Kind: "php_application", ID: 10, SiteID: 2}, {Kind: "php_worker", ID: 20, ParentID: 11, SiteID: 2}}
	if _, err := NewSiteTeardownProvisioner(f.opts).TeardownSite(context.Background(), f.request); err == nil {
		t.Fatal("foreign PHP worker parent accepted")
	}
	if len(f.runner.calls) != 0 {
		t.Fatal("runtime changed before parent validation")
	}
}

func TestTeardownSiteKeepsCollidingLegacyLogPaths(t *testing.T) {
	f := newSiteTeardownFixture(t)
	id := types.SiteIdentity{SiteID: 4, SubscriptionID: 2, Username: "nps2", Domain: "child-addon.test"}
	if err := f.opts.IdentityRegistry.WithCreation(context.Background(), []types.SiteIdentity{id}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	parent := types.SiteIdentity{SiteID: 5, SubscriptionID: 2, Username: "nps2", Domain: "child.addon.test"}
	if err := f.opts.IdentityRegistry.WithCreation(context.Background(), []types.SiteIdentity{parent}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	plan, err := NewSitePlan(types.CreateSiteReq{SiteID: 5, SubscriptionID: 2, Username: "nps2", Domain: parent.Domain, PHPVersion: "8.4", SharedAccount: true}, f.opts.Paths)
	if err != nil {
		t.Fatal(err)
	}
	writeRemovalFixture(t, filepath.Join(plan.Docroot, "index.php"))
	writeRemovalFixture(t, plan.NginxAccessLog)
	writeRemovalFixture(t, plan.NginxAccessLog+".1")
	f.request.Snapshot.Sites = []types.SiteRemovalSite{{SiteID: 5, SubscriptionID: 2, CustomerID: 1, Username: "nps2", Domain: parent.Domain, PHPVersion: "8.4"}}
	f.request.Snapshot.Databases = nil
	f.request.Snapshot.Backups = nil
	p := NewSiteTeardownProvisioner(f.opts)
	if _, err = p.TeardownSite(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
	f.request.Stage = types.RemovalHosting
	if _, err = p.TeardownSite(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{plan.NginxAccessLog, plan.NginxAccessLog + ".1"} {
		if data, err := os.ReadFile(path); err != nil || string(data) != "fixture-original" {
			t.Fatalf("surviving colliding logs removed: %s %v", path, err)
		}
	}
}

func TestTeardownSiteLargeJournalRecovery(t *testing.T) {
	f := newSiteTeardownFixture(t)
	p := NewSiteTeardownProvisioner(f.opts)
	path := filepath.Join(f.opts.IdentityRegistry.root, "removal-10.json")
	j, err := p.readRemovalJournal(path, f.request)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2000; i++ {
		j.Checkpoints = append(j.Checkpoints, "artifact:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	}
	if err = p.writeRemovalJournal(path, j); err != nil {
		t.Fatal(err)
	}
	if _, err = p.readRemovalJournal(path, f.request); err != nil {
		t.Fatalf("valid bounded journal not recoverable: %v", err)
	}
}

func TestTeardownSiteRemovesExactLegacyPool(t *testing.T) {
	f := newSiteTeardownFixture(t)
	legacy, err := NewSitePlan(types.CreateSiteReq{Username: "nps2", Domain: "addon.test", PHPVersion: "8.4", SharedAccount: true}, f.opts.Paths)
	if err != nil {
		t.Fatal(err)
	}
	writeRemovalFixture(t, legacy.PHPFPMConfig)
	f.opts.Paths.PHPRunDir = filepath.Join(f.opts.Paths.HomeRoot, "../legacy-run")
	p := NewSiteTeardownProvisioner(f.opts)
	if _, err = p.TeardownSite(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
	f.request.Stage = types.RemovalHosting
	if _, err = p.TeardownSite(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(legacy.PHPFPMConfig); !os.IsNotExist(err) {
		t.Fatalf("legacy pool survives: %v", err)
	}
}
