package operations_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
)

func TestNotificationDetailIsScopedAndReadOnly(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	var id int64
	if err := db.QueryRow(`INSERT INTO notifications(subscription_id,kind,severity,title,body,dedupe_key) VALUES(42,'threshold','warning','Storage warning','Complete safe message','details:42') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, actor := range []auth.SessionUser{admin, client, {ID: 100, Role: auth.RoleReseller}} {
		page, err := s.Page(ctx, actor, "inbox", operations.Filter{})
		if err != nil || len(page.Notifications) != 1 {
			t.Fatalf("list: %+v %v", page, err)
		}
		got, err := s.Notification(ctx, actor, id, operations.Resource{})
		if err != nil || !reflect.DeepEqual(got, page.Notifications[0]) || got.Target != "Example subscription" || got.Summary != "Complete safe message" {
			t.Fatalf("detail differs from safe list: %+v %v", got, err)
		}
	}
	for _, tc := range []struct {
		actor auth.SessionUser
		scope operations.Resource
	}{
		{auth.SessionUser{ID: 22, Role: auth.RoleClient}, operations.Resource{}},
		{auth.SessionUser{ID: 200, Role: auth.RoleReseller}, operations.Resource{}},
		{auth.SessionUser{ID: 11, Role: auth.RoleAdmin}, operations.Resource{}},
		{admin, operations.Resource{Kind: operations.ResourceCustomer, ID: 20}},
	} {
		if _, err := s.Notification(ctx, tc.actor, id, tc.scope); !errors.Is(err, operations.ErrNotFound) {
			t.Fatalf("cross-scope detail exposed: %v", err)
		}
	}
	var receipts, resolved int
	if err := db.QueryRow(`SELECT count(*) FROM notification_receipts`).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("GET wrote receipts", receipts, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM notifications WHERE resolved_at IS NOT NULL`).Scan(&resolved); err != nil || resolved != 0 {
		t.Fatal("GET resolved notification", resolved, err)
	}
	if err := s.ArchiveNotification(ctx, client, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Notification(ctx, client, id, operations.Resource{Kind: operations.ResourceCustomer, ID: 10}); err != nil {
		t.Fatal("authorized archived detail should remain readable", err)
	}
	if _, err := db.Exec(`UPDATE subscriptions SET customer_id=20 WHERE id=42`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Notification(ctx, client, id, operations.Resource{}); !errors.Is(err, operations.ErrNotFound) {
		t.Fatal("transferred record remains visible", err)
	}
	if _, err := s.Notification(ctx, admin, 0, operations.Resource{}); !errors.Is(err, operations.ErrInvalid) {
		t.Fatal("invalid ID accepted", err)
	}
	if _, err := s.Notification(ctx, admin, id, operations.Resource{Kind: "unknown", ID: 1}); !errors.Is(err, operations.ErrInvalid) {
		t.Fatal("invalid scope accepted", err)
	}
}

func TestNotificationSearchUsesPublishedProjection(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	if _, err := db.Exec(`INSERT INTO notifications(subscription_id,kind,severity,title,body,dedupe_key) VALUES
 (42,'threshold','warning','Disk warning','Allowed body sentinel','search:allowed'),
 (42,'server_backup_failed','critical','Backup warning','hidden-secret-sentinel','search:hidden')`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		query string
		count int
	}{{"Allowed body sentinel", 1}, {"Example subscription", 2}, {"Disk warning", 1}, {"hidden-secret-sentinel", 0}} {
		p, err := s.Page(ctx, client, "inbox", operations.Filter{Search: tc.query})
		if err != nil || len(p.Notifications) != tc.count {
			t.Fatalf("query %q count %d: %+v %v", tc.query, tc.count, p, err)
		}
	}
}
