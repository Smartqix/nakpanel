package operations_test

import (
	"encoding/json"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"strings"
	"testing"
)

func TestFeedIncludesTerminalPresentationMetadata(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	op, err := s.CreateOperation(ctx, operations.NewOperation{Key: "manual-result", Kind: "create_backup", Resource: operations.Resource{Kind: operations.ResourceSite, ID: 51}, Title: "Backup", Trigger: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.StartAttempt(ctx, op.ID, 900)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FinishAttempt(ctx, a.ID, operations.StateSucceeded, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO operation_events(event_key,resource_kind,resource_id,kind,operation_id,summary) VALUES('manual-result','site',51,'task.succeeded',$1,'Backup completed')`, op.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Dispatch(ctx, 100); err != nil {
		t.Fatal(err)
	}
	feed, err := s.Feed(ctx, client, 0, operations.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(feed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"operation_kind":"create_backup"`) || !strings.Contains(string(data), `"trigger":"manual"`) {
		t.Fatalf("terminal result cannot be classified for presentation: %s", data)
	}
}

func TestDispatchReplayAndLateCommitCannotLoseTransitions(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	early, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer early.Rollback()
	a, err := s.ObserveIssueTx(ctx, early, observation("early-uncommitted", 51))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.ObserveIssue(ctx, observation("later-committed", 52))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Dispatch(ctx, 100); err != nil {
		t.Fatal(err)
	}
	first, err := s.Feed(ctx, client, 0, operations.Filter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 1 || first.Events[0].IssueID != b.ID {
		t.Fatalf("published uncommitted source: %#v", first)
	}
	if err = early.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DispatchTx(ctx, tx, 100); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	beforeReplay, err := s.Feed(ctx, client, first.Cursor, operations.Filter{})
	if err != nil || len(beforeReplay.Events) != 0 {
		t.Fatalf("dispatch survived rollback: %#v %v", beforeReplay, err)
	}
	if _, err = s.Dispatch(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Dispatch(ctx, 100); err != nil {
		t.Fatal(err)
	}
	second, err := s.Feed(ctx, client, first.Cursor, operations.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Events) != 1 || second.Events[0].IssueID != a.ID || second.Cursor <= first.Cursor {
		t.Fatalf("late commit was skipped or duplicated: %#v", second)
	}
	foreign, err := s.Feed(ctx, auth.SessionUser{ID: 22, Role: auth.RoleClient}, 0, operations.Filter{})
	if err != nil || len(foreign.Events) != 0 {
		t.Fatalf("cross-tenant feed: %#v %v", foreign, err)
	}
}

func TestCursorPaginationRetainsEveryTransition(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	for i := 0; i < 12; i++ {
		o := observation(string(rune('a'+i)), 51)
		if _, err := s.ObserveIssue(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Dispatch(ctx, 100); err != nil {
		t.Fatal(err)
	}
	var cursor int64
	seen := map[int64]bool{}
	for i := 0; i < 5; i++ {
		f, err := s.Feed(ctx, client, cursor, operations.Filter{Limit: 5})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range f.Events {
			if seen[e.ID] {
				t.Fatal("duplicate transition")
			}
			seen[e.ID] = true
		}
		cursor = f.Cursor
		if !f.More {
			break
		}
	}
	if len(seen) != 12 {
		t.Fatalf("lost transitions between polls: %d", len(seen))
	}
}
