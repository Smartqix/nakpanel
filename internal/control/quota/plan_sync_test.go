package quota

import (
	"context"
	"testing"

	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
)

func TestPlanSynchronizationSeparatesSnapshotsServicesAndExclusions(t *testing.T) {
	db := removaldb.New(t, "")
	ctx := context.Background()
	for _, query := range []string{
		"UPDATE plans SET revision=4 WHERE id=1",
		"UPDATE subscriptions SET plan_id=1,sync_mode='synced',sync_status='in_sync',sync_error='' WHERE id=1",
		"UPDATE subscription_entitlements SET source_revision=3 WHERE subscription_id=1",
		"UPDATE subscription_system_accounts SET convergence_status='in_sync',desired_revision=2,applied_revision=2,last_error='' WHERE subscription_id=1",
		"UPDATE subscriptions SET plan_id=1,sync_mode='locked',sync_status='in_sync' WHERE id=2",
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	store := NewSQLStore(db)
	view, err := store.PlanSynchronization(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if view.Pending != 1 || view.Excluded != 1 || view.Subscriptions[0].State != "pending" {
		t.Fatalf("stale snapshot: %+v", view)
	}
	if _, err = db.Exec("UPDATE subscription_entitlements SET source_revision=4 WHERE subscription_id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE subscription_system_accounts SET convergence_status='pending',desired_revision=3 WHERE subscription_id=1"); err != nil {
		t.Fatal(err)
	}
	view, err = store.PlanSynchronization(ctx, 1)
	if err != nil || view.Subscriptions[0].State != "applying" {
		t.Fatalf("services not applied: %+v %v", view, err)
	}
	if _, err = db.Exec("UPDATE subscription_system_accounts SET convergence_status='failed',last_error='Quota setup failed' WHERE subscription_id=1"); err != nil {
		t.Fatal(err)
	}
	view, err = store.PlanSynchronization(ctx, 1)
	if err != nil || view.Failed != 1 || view.State != "failed" || view.Subscriptions[0].Error != "Quota setup failed" {
		t.Fatalf("failure hidden: %+v %v", view, err)
	}
	if _, err = db.Exec("UPDATE subscription_system_accounts SET convergence_status='in_sync',applied_revision=3,last_error='' WHERE subscription_id=1"); err != nil {
		t.Fatal(err)
	}
	view, err = store.PlanSynchronization(ctx, 1)
	if err != nil || view.Synced != 1 || view.Excluded != 1 || view.State != "in_sync" {
		t.Fatalf("complete: %+v %v", view, err)
	}
}

func TestPlanSyncCopiesWordPressPermissionAndCapacity(t *testing.T) {
	db := removaldb.New(t, "")
	ctx := context.Background()
	store := NewSQLStore(db)
	var planID int64
	if err := db.QueryRow("SELECT plan_id FROM subscriptions WHERE id=1").Scan(&planID); err != nil {
		t.Fatal(err)
	}
	plan, err := store.GetPlan(ctx, planID)
	if err != nil {
		t.Fatal(err)
	}
	plan.HostingPolicy.Permissions.WordPressToolkit = true
	plan.HostingPolicy.Resources.MaxWordPressSites = 5
	saved, err := store.UpsertPlan(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := store.EffectiveSubscriptionPolicy(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Permissions.WordPressToolkit || policy.Resources.MaxWordPressSites != 5 {
		t.Fatalf("WordPress contract not synchronized: %+v", policy)
	}
	var revision int
	if err = db.QueryRow("SELECT source_revision FROM subscription_entitlements WHERE subscription_id=1").Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if revision != saved.Revision {
		t.Fatalf("snapshot revision %d != plan revision %d", revision, saved.Revision)
	}
}
