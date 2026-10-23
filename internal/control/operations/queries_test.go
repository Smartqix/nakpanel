package operations_test

import (
	"errors"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"testing"
)

func TestScopedCountsPaginationAndDetailAgree(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	for i := 0; i < 12; i++ {
		o := observation(fmt.Sprintf("failure-%d", i), 51)
		o.Condition = fmt.Sprintf("policy-%d", i)
		if _, err := s.ObserveIssue(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	foreign, err := s.ObserveIssue(ctx, observation("foreign", 91))
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Page(ctx, client, "issues", operations.Filter{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Issues) != 5 || first.Counts.OpenIssues != 12 || first.NextBefore == 0 {
		t.Fatalf("page size changed counts: %#v", first)
	}
	second, err := s.Page(ctx, client, "issues", operations.Filter{Limit: 5, Before: first.NextBefore})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Issues) != 5 || second.Issues[0].ID >= first.Issues[4].ID || second.Counts.OpenIssues != 12 {
		t.Fatalf("pagination overlap: %#v %#v", first, second)
	}
	if _, err = s.Issue(ctx, client, foreign.ID); !errors.Is(err, operations.ErrNotFound) {
		t.Fatalf("foreign issue detail: %v", err)
	}
	provider, err := s.Page(ctx, auth.SessionUser{ID: 100, Role: auth.RoleReseller}, "issues", operations.Filter{Limit: 50})
	if err != nil || provider.Counts.OpenIssues != 12 {
		t.Fatalf("reseller counts: %#v %v", provider, err)
	}
	if _, err = db.Exec(`UPDATE subscriptions SET customer_id=20 WHERE id=42`); err != nil {
		t.Fatal(err)
	}
	after, err := s.Page(ctx, client, "issues", operations.Filter{})
	if err != nil || after.Counts.OpenIssues != 0 || len(after.Issues) != 0 {
		t.Fatalf("ownership transfer leaked rows: %#v %v", after, err)
	}
}

func TestTaskCountsDoNotDependOnEightRecentRows(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	for i := 0; i < 13; i++ {
		_, err := s.CreateOperation(ctx, operations.NewOperation{Key: fmt.Sprintf("job:%d", i), Kind: "create_backup", Resource: operations.Resource{Kind: operations.ResourceSite, ID: 51}, Title: "Create backup", Trigger: "scheduled"})
		if err != nil {
			t.Fatal(err)
		}
	}
	p, err := s.Page(ctx, client, "tasks", operations.Filter{Limit: 8})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tasks) != 8 || p.Counts.ActiveTasks != 13 {
		t.Fatalf("active count was truncated: %#v", p)
	}
	denied, err := s.Page(ctx, auth.SessionUser{ID: 22, Role: auth.RoleClient}, "tasks", operations.Filter{})
	if err != nil || denied.Counts.ActiveTasks != 0 {
		t.Fatalf("foreign active count: %#v %v", denied, err)
	}
}

func TestQuickTasksKeepOlderActiveWorkAheadOfRoutineCompletions(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	var activeID, failedID int64
	for i := 0; i < 12; i++ {
		op, err := s.CreateOperation(ctx, operations.NewOperation{Key: fmt.Sprintf("priority:%d", i), Kind: "create_backup", Resource: operations.Resource{Kind: operations.ResourceSite, ID: 51}, Title: "Create backup", Trigger: "scheduled"})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			activeID = op.ID
			continue
		}
		a, err := s.StartAttempt(ctx, op.ID, int64(700+i))
		if err != nil {
			t.Fatal(err)
		}
		state := operations.StateSucceeded
		if i == 1 {
			state = operations.StateFailed
			failedID = op.ID
		}
		if err = s.FinishAttempt(ctx, a.ID, state, ""); err != nil {
			t.Fatal(err)
		}
	}
	p, err := s.Page(ctx, client, "tasks", operations.Filter{Limit: 8, ActiveFirst: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tasks) != 2 || p.Tasks[0].ID != activeID || p.Tasks[1].ID != failedID || p.Counts.ActiveTasks != 1 {
		t.Fatalf("routine jobs dominated quick view: %#v", p)
	}
}

func TestScopeSearchAndUnreadCounts(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	if _, err := s.ObserveIssue(ctx, observation("one", 51)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ObserveIssue(ctx, observation("two", 52)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO notifications(subscription_id,kind,severity,title,body,dedupe_key) VALUES(42,'threshold','warning','Usage','Usage is high','quota:42')`); err != nil {
		t.Fatal(err)
	}
	p, err := s.Page(ctx, client, "issues", operations.Filter{Resource: operations.Resource{Kind: operations.ResourceSite, ID: 51}})
	if err != nil || len(p.Issues) != 1 || p.Counts.OpenIssues != 1 {
		t.Fatalf("site filter: %#v %v", p, err)
	}
	p, err = s.Page(ctx, client, "inbox", operations.Filter{Resource: operations.Resource{Kind: operations.ResourceSubscription, ID: 42}})
	if err != nil || len(p.Notifications) != 1 || p.Counts.Unread != 1 {
		t.Fatalf("subscription inbox: %#v %v", p, err)
	}
	if err = s.MarkAllNotificationsRead(ctx, client, operations.Filter{}); err != nil {
		t.Fatal(err)
	}
	p, err = s.Page(ctx, client, "inbox", operations.Filter{})
	if err != nil || p.Counts.Unread != 0 || p.Counts.OpenIssues != 2 {
		t.Fatalf("mark all read resolved issues: %#v %v", p, err)
	}
	other, err := s.Page(ctx, admin, "inbox", operations.Filter{})
	if err != nil || other.Counts.Unread != 1 {
		t.Fatalf("mark all read affected another user: %#v %v", other, err)
	}
	p, err = s.Page(ctx, client, "issues", operations.Filter{Search: "no match"})
	if err != nil || len(p.Issues) != 0 {
		t.Fatalf("search: %#v %v", p, err)
	}
}
