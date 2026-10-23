package operations_test

import (
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"strings"
	"testing"
	"time"
)

func receiptFor(i operations.Issue) operations.VerificationReceipt {
	return operations.VerificationReceipt{Token: operations.VerificationToken{IssueID: i.ID, Generation: i.Generation, LatestEventID: i.LatestEventID, IntentRevision: i.IntentRevision}, IntentHash: strings.Repeat("b", 64), Source: "archive_checksum", SourceID: 10, Checksum: strings.Repeat("a", 64), SizeBytes: 4096, ObservedAt: time.Now().UTC().Add(time.Millisecond), Summary: "Managed archive checksum verified"}
}
func TestOldVerifierCannotCloseNewerFailureOrChangedIntent(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	a, err := s.ObserveIssue(ctx, observation("first", 51))
	if err != nil {
		t.Fatal(err)
	}
	old := receiptFor(a)
	newer, err := s.ObserveIssue(ctx, observation("newer-failure", 51))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = s.ResolveVerifiedTx(ctx, tx, old, old.IntentHash, 3); !errors.Is(err, operations.ErrConflict) {
		t.Fatalf("stale success resolved newer failure: %v", err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	current := receiptFor(newer)
	if err = s.ResolveVerifiedTx(ctx, tx, current, strings.Repeat("c", 64), 4); !errors.Is(err, operations.ErrConflict) {
		t.Fatalf("changed intent accepted: %v", err)
	}
}
func TestVerifiedRecoveryPreservesFailureAndLinksRecurrence(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	i, err := s.ObserveIssue(ctx, observation("failure", 51))
	if err != nil {
		t.Fatal(err)
	}
	r := receiptFor(i)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ResolveVerifiedTx(ctx, tx, r, r.IntentHash, 3); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ResolveVerifiedTx(ctx, tx, r, r.IntentHash, 3); err != nil {
		t.Fatal("receipt replay:", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	p, err := s.Page(ctx, client, "issues", operations.Filter{})
	if err != nil || p.Counts.OpenIssues != 0 {
		t.Fatalf("verified incident remained open: %#v %v", p, err)
	}
	recurrence, err := s.ObserveIssue(ctx, observation("recurrence", 51))
	if err != nil {
		t.Fatal(err)
	}
	if recurrence.ID == i.ID {
		t.Fatal("recurrence overwrote resolved incident")
	}
	var previous int64
	if err = db.QueryRow(`SELECT previous_issue_id FROM issues WHERE id=$1`, recurrence.ID).Scan(&previous); err != nil || previous != i.ID {
		t.Fatalf("recurrence link: %d %v", previous, err)
	}
	var events int
	if err = db.QueryRow(`SELECT count(*) FROM operation_events WHERE issue_id=$1 AND kind='issue.resolved'`, i.ID).Scan(&events); err != nil || events != 1 {
		t.Fatalf("duplicate recovery events: %d %v", events, err)
	}
}
func TestUnknownAndStaleEvidenceNeverResolves(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	i, err := s.ObserveIssue(ctx, observation("failure", 51))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []string{"unknown", "stale", "future"} {
		r := receiptFor(i)
		switch test {
		case "unknown":
			r.Source = ""
		case "stale":
			r.ObservedAt = time.Now().Add(-time.Hour)
		case "future":
			r.ObservedAt = time.Now().Add(time.Hour)
		}
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		err = s.ResolveVerifiedTx(ctx, tx, r, r.IntentHash, 3)
		tx.Rollback()
		if err == nil {
			t.Fatalf("%s evidence resolved an issue", test)
		}
	}
}

func TestNewFailureInvalidatesCheckingState(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	i, err := s.ObserveIssue(ctx, observation("checking-first", 51))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetCheckingTx(ctx, tx, i, i.IntentRevision); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	next, err := s.ObserveIssue(ctx, observation("checking-new-failure", 51))
	if err != nil {
		t.Fatal(err)
	}
	if next.LastCheckStatus == "checking" || next.State == "checking" {
		t.Fatal("new failure retained stale checking indicator")
	}
}
