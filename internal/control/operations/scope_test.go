package operations_test

import (
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"testing"
)

func TestResourceScopeUsesCurrentOwnershipAndRole(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	cases := []struct {
		actor    auth.SessionUser
		resource operations.Resource
		want     bool
	}{
		{admin, operations.Resource{Kind: operations.ResourceServer}, true},
		{client, operations.Resource{Kind: operations.ResourceServer}, false},
		{client, operations.Resource{Kind: operations.ResourceSite, ID: 51}, true},
		{client, operations.Resource{Kind: operations.ResourceSite, ID: 91}, false},
		{auth.SessionUser{ID: 100, Role: auth.RoleReseller}, operations.Resource{Kind: operations.ResourceSubscription, ID: 42}, true},
		{auth.SessionUser{ID: 100, Role: auth.RoleReseller}, operations.Resource{Kind: operations.ResourceSubscription, ID: 99}, false},
		{auth.SessionUser{ID: 11, Role: auth.RoleAdmin}, operations.Resource{Kind: operations.ResourceSite, ID: 91}, false},
		{auth.SessionUser{}, operations.Resource{Kind: operations.ResourceSite, ID: 51}, false},
	}
	for _, tc := range cases {
		got, err := s.CanView(ctx, tc.actor, tc.resource)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("%#v %#v: got %v want %v", tc.actor, tc.resource, got, tc.want)
		}
	}
	if _, err := db.Exec(`DELETE FROM sites WHERE id=51`); err != nil {
		t.Fatal(err)
	}
	got, err := s.CanView(ctx, client, operations.Resource{Kind: operations.ResourceSite, ID: 51})
	if err != nil || got {
		t.Fatalf("deleted resource visible: %v %v", got, err)
	}
}

func TestPrivateSecurityNotificationIsNotVisibleToOtherAdministrator(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	var id int64
	if err := db.QueryRow(`INSERT INTO notifications(recipient_user_id,kind,title,body,dedupe_key) VALUES(1,'login_new_device','New login','Security message','login:1') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkNotificationRead(ctx, auth.SessionUser{ID: 2, Role: auth.RoleAdmin}, id); err == nil {
		t.Fatal("another administrator read a personal security message")
	}
	if err := s.MarkNotificationRead(ctx, admin, id); err != nil {
		t.Fatal(err)
	}
}
