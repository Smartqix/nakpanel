package operations_test

import (
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"testing"
	"time"
)

func TestConditionPollingDoesNotInflateIncidentsAndAllowsRecurrence(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	sample := operations.ConditionSample{Resource: operations.Resource{Kind: operations.ResourceSite, ID: 51}, Kind: "backup", Condition: "protection", Signature: "current-policy", Unhealthy: true, Severity: "critical", Title: "Backup overdue", Summary: "No verified recent archive", ObservedAt: time.Now().UTC()}
	apply := func(sample operations.ConditionSample) {
		t.Helper()
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err = s.ObserveConditionTx(ctx, tx, sample); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	apply(sample)
	apply(sample)
	p, err := s.Page(ctx, client, "issues", operations.Filter{})
	if err != nil || len(p.Issues) != 1 || p.Issues[0].Occurrences != 1 {
		t.Fatalf("polling created duplicate incidents: %#v %v", p, err)
	}
	healthy := sample
	healthy.Unhealthy = false
	healthy.Signature = "fresh-archive"
	apply(healthy)
	p, err = s.Page(ctx, client, "issues", operations.Filter{})
	if err != nil || p.Counts.OpenIssues != 1 {
		t.Fatal("metadata change resolved without an independent verifier")
	}
	apply(sample)
	p, err = s.Page(ctx, client, "issues", operations.Filter{})
	if err != nil || p.Issues[0].Occurrences != 2 {
		t.Fatalf("repeated condition edge was lost: %#v %v", p, err)
	}
}
