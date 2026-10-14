package ops

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/types"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func registryFixture(t *testing.T) (*SiteIdentityRegistry, types.SiteIdentity) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	r := NewSiteIdentityRegistry(filepath.Join(parent, "sites"))
	identity := types.SiteIdentity{SiteID: 1, SubscriptionID: 2, Username: "nps2", Domain: "addon.test"}
	if err := r.WithCreation(context.Background(), []types.SiteIdentity{identity}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	return r, identity
}
func TestSiteIdentityTombstoneRejectsOldCreate(t *testing.T) {
	r, id := registryFixture(t)
	ctx := context.Background()
	if err := r.MarkRemoved(ctx, 4, 1, []types.SiteIdentity{id}); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := r.WithCreation(ctx, []types.SiteIdentity{id}, func(context.Context) error { called = true; return nil }); !errors.Is(err, ErrSiteIdentityRemoved) || called {
		t.Fatalf("old create allowed: %v called=%v", err, called)
	}
	restarted := NewSiteIdentityRegistry(r.root)
	if err := restarted.WithSites(ctx, []types.SiteIdentity{id}, func(context.Context) error { return nil }); !errors.Is(err, ErrSiteIdentityRemoved) {
		t.Fatalf("restart lost tombstone: %v", err)
	}
}

func TestSiteIdentityDirectProvisionerCannotResurrect(t *testing.T) {
	registry, id := registryFixture(t)
	if err := registry.MarkRemoved(context.Background(), 7, 1, []types.SiteIdentity{id}); err != nil {
		t.Fatal(err)
	}
	provisioner := NewSiteProvisioner(SiteProvisionerOptions{IdentityRegistry: registry})
	err := provisioner.CreateSite(context.Background(), types.CreateSiteReq{SiteID: id.SiteID, SubscriptionID: id.SubscriptionID, Username: id.Username, Domain: id.Domain, PHPVersion: "8.4"})
	if !errors.Is(err, ErrSiteIdentityRemoved) {
		t.Fatalf("direct stale provisioner call: %v", err)
	}
}
func TestSiteIdentityRemovedHostnameRequiresNewID(t *testing.T) {
	r, id := registryFixture(t)
	ctx := context.Background()
	replacement := id
	replacement.SiteID = 10
	if err := r.MarkRemoved(ctx, 4, 1, []types.SiteIdentity{id}); err != nil {
		t.Fatal(err)
	}
	if err := r.WithCreation(ctx, []types.SiteIdentity{replacement}, func(context.Context) error { return nil }); err == nil {
		t.Fatal("replacement claimed before cleanup completed")
	}
	if err := r.CompleteRemoval(ctx, 4, []types.SiteIdentity{id}); err != nil {
		t.Fatal(err)
	}
	if err := r.WithCreation(ctx, []types.SiteIdentity{replacement}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	legacy := types.SiteIdentity{Username: id.Username, Domain: id.Domain}
	if err := r.WithSites(ctx, []types.SiteIdentity{legacy}, func(context.Context) error { return nil }); err == nil {
		t.Fatal("legacy request adopted replacement")
	}
}
func TestSiteIdentityCleanupReplayPreservesReplacement(t *testing.T) {
	r, id := registryFixture(t)
	ctx := context.Background()
	r.MarkRemoved(ctx, 4, 1, []types.SiteIdentity{id})
	r.CompleteRemoval(ctx, 4, []types.SiteIdentity{id})
	replacement := id
	replacement.SiteID = 10
	if err := r.WithCreation(ctx, []types.SiteIdentity{replacement}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := r.MarkRemoved(ctx, 4, 2, []types.SiteIdentity{id}); err != nil {
		t.Fatal(err)
	}
	if err := r.WithSites(ctx, []types.SiteIdentity{replacement}, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("replay changed replacement: %v", err)
	}
	if err := r.MarkRemoved(ctx, 999, 1, []types.SiteIdentity{id}); err == nil {
		t.Fatal("different operation adopted removal")
	}
}
func TestSiteIdentityConcurrentMutationAndRemoval(t *testing.T) {
	r, id := registryFixture(t)
	ctx := context.Background()
	entered := make(chan struct{})
	release := make(chan struct{})
	mutation := make(chan error, 1)
	go func() {
		mutation <- r.WithSites(ctx, []types.SiteIdentity{id}, func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	removed := make(chan error, 1)
	go func() { removed <- NewSiteIdentityRegistry(r.root).MarkRemoved(ctx, 4, 1, []types.SiteIdentity{id}) }()
	select {
	case err := <-removed:
		t.Fatalf("removal did not wait for lease: %v", err)
	case <-time.After(40 * time.Millisecond):
	}
	close(release)
	if err := <-mutation; err != nil {
		t.Fatal(err)
	}
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
}
func TestSiteIdentityNestedLeaseAndSymlinkSafety(t *testing.T) {
	r, id := registryFixture(t)
	if err := r.WithSites(context.Background(), []types.SiteIdentity{id}, func(ctx context.Context) error {
		return r.WithSites(ctx, []types.SiteIdentity{id}, func(context.Context) error { return nil })
	}); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	root := filepath.Join(t.TempDir(), "registry")
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}
	if err := NewSiteIdentityRegistry(root).WithCreation(context.Background(), []types.SiteIdentity{id}, func(context.Context) error { return nil }); err == nil {
		t.Fatal("registry symlink accepted")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) > 0 {
		t.Fatal("escaped registry root")
	}
}

func TestSiteIdentityRejectsWritableRegistryRecords(t *testing.T) {
	registry, id := registryFixture(t)
	if err := os.Chmod(filepath.Join(registry.root, "site-1.json"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := registry.WithSites(context.Background(), []types.SiteIdentity{id}, func(context.Context) error { return nil }); err == nil {
		t.Fatal("writable identity record trusted")
	}
}

func TestSiteIdentityAccountTeardownReplayKeepsReplacement(t *testing.T) {
	registry, id := registryFixture(t)
	calls := 0
	work := func(context.Context) error { calls++; return nil }
	if err := registry.WithAccountRemoval(context.Background(), id.SubscriptionID, []types.SiteIdentity{id}, work); err != nil {
		t.Fatal(err)
	}
	replacement := id
	replacement.SiteID = 20
	replacement.SubscriptionID = 3
	replacement.Username = "nps3"
	if err := registry.WithCreation(context.Background(), []types.SiteIdentity{replacement}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := registry.WithAccountRemoval(context.Background(), id.SubscriptionID, []types.SiteIdentity{id}, work); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("completed account teardown repeated physical cleanup")
	}
	if err := registry.WithSites(context.Background(), []types.SiteIdentity{replacement}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestSiteIdentitySharedReferencesPreservePositiveLease(t *testing.T) {
	registry, id := registryFixture(t)
	legacy := types.SiteIdentity{Domain: id.Domain}
	err := registry.WithCreation(context.Background(), []types.SiteIdentity{id, legacy}, func(ctx context.Context) error {
		return registry.WithSites(ctx, []types.SiteIdentity{id}, func(context.Context) error { return nil })
	})
	if err != nil {
		t.Fatalf("shared reference weakened leased identity: %v", err)
	}
}

func TestSiteIdentityInvalidAccountIntentDoesNotFenceLiveSite(t *testing.T) {
	for _, bad := range []string{"home", "database"} {
		t.Run(bad, func(t *testing.T) {
			registry, id := registryFixture(t)
			home := filepath.Join(t.TempDir(), "home")
			request := types.TeardownSubscriptionReq{SubscriptionID: id.SubscriptionID, Username: id.Username, HomePath: filepath.Join(home, id.Username), SiteIDs: []int64{id.SiteID}, Domains: []string{id.Domain}}
			if bad == "home" {
				request.HomePath = "/another-account"
			} else {
				request.DatabaseNames = []string{"bad;statement"}
			}
			provisioner := NewSubscriptionTeardownProvisioner(SubscriptionTeardownOptions{IdentityRegistry: registry, HomeRoot: home})
			if _, err := provisioner.TeardownSubscription(context.Background(), request); err == nil {
				t.Fatal("invalid intent accepted")
			}
			if err := registry.WithSites(context.Background(), []types.SiteIdentity{id}, func(context.Context) error { return nil }); err != nil {
				t.Fatalf("invalid intent fenced live website: %v", err)
			}
		})
	}
}
