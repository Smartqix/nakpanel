package workspace

import (
	"context"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"testing"
)

func TestSiteRemovalOwnershipWithoutEntitlementGate(t *testing.T) {
	db := removaldb.New(t, "")
	siteID := removaldb.Site(t, db, 2, "owned.test", nil)
	if _, err := db.Exec("UPDATE subscription_entitlements SET max_sites=0,hosting_enabled=false WHERE subscription_id=2"); err != nil {
		t.Fatal(err)
	}
	policy := NewStore(db)
	allowed, err := policy.CanRemoveSite(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, siteID)
	if err != nil || !allowed {
		t.Fatalf("revoked hosting blocked cleanup: %v %v", allowed, err)
	}
	if _, err := db.Exec("UPDATE customers SET status='suspended' WHERE id=(SELECT customer_id FROM subscriptions WHERE id=2)"); err != nil {
		t.Fatal(err)
	}
	allowed, err = policy.CanRemoveSite(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, siteID)
	if err != nil || allowed {
		t.Fatalf("suspended client cleanup allowed: %v %v", allowed, err)
	}
}

func TestSiteRemovalResellerScopeIncludesSuspendedCustomer(t *testing.T) {
	db := removaldb.New(t, "")
	siteID := removaldb.Site(t, db, 2, "owned.test", nil)
	var user, reseller int64
	if err := db.QueryRow("INSERT INTO users(email,password_hash,role) VALUES('reseller-removal@test.invalid','fixture','reseller') RETURNING id").Scan(&user); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("INSERT INTO reseller_accounts(login_user_id,email) VALUES($1,'reseller-removal@test.invalid') RETURNING id", user).Scan(&reseller); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO reseller_subscriptions(reseller_id,reseller_plan_id,status) SELECT $1,id,'active' FROM reseller_plans ORDER BY id LIMIT 1", reseller); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE customers SET reseller_id=$1,status='suspended' WHERE id=(SELECT customer_id FROM subscriptions WHERE id=2)", reseller); err != nil {
		t.Fatal(err)
	}
	policy := NewStore(db)
	allowed, err := policy.CanRemoveSite(context.Background(), auth.SessionUser{ID: user, Role: auth.RoleReseller}, siteID)
	if err != nil || !allowed {
		t.Fatalf("own reseller cleanup=%v %v", allowed, err)
	}
	allowed, err = policy.CanRemoveSite(context.Background(), auth.SessionUser{ID: 999, Role: auth.RoleReseller}, siteID)
	if err != nil || allowed {
		t.Fatalf("foreign reseller cleanup=%v %v", allowed, err)
	}
}
