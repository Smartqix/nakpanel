package provision

import (
	"context"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"testing"
	"time"
)

func TestConditionDeadlinesAndDetectionWithoutAnyFailedJob(t *testing.T) {
	monday := time.Date(2026, 10, 19, 3, 0, 0, 0, time.UTC)
	daily, err := backupDeadline("daily", monday)
	if err != nil || !daily.Equal(time.Date(2026, 10, 20, 2, 30, 0, 0, time.UTC)) {
		t.Fatalf("daily grace: %v %v", daily, err)
	}
	weekly, err := backupDeadline("weekly", monday)
	if err != nil || !weekly.Equal(time.Date(2026, 10, 25, 2, 30, 0, 0, time.UTC)) {
		t.Fatalf("weekly grace: %v %v", weekly, err)
	}
	if _, err = backupDeadline("invalid schedule", monday); err == nil {
		t.Fatal("unknown schedule treated as healthy")
	}
	db, m, _, actor, siteID := operationsFixture(t)
	ctx := context.Background()
	if _, err = db.Exec(`UPDATE sites SET created_at=now()-interval '3 days',tls_expires_at=now()+interval '7 days',tls_status='active' WHERE id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	if err = m.DetectConditions(ctx); err != nil {
		t.Fatal(err)
	}
	if err = m.DetectConditions(ctx); err != nil {
		t.Fatal(err)
	}
	p, err := m.Store.Page(ctx, actor, "issues", operations.Filter{})
	if err != nil || p.Counts.OpenIssues != 2 {
		t.Fatalf("non-job issues missing: %#v %v", p, err)
	}
	for _, i := range p.Issues {
		if i.Occurrences != 1 {
			t.Fatal("polling inflated occurrence counts")
		}
	}
	if _, err = db.Exec(`UPDATE sites SET tls_expires_at=now()+interval '90 days' WHERE id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	if err = m.DetectConditions(ctx); err != nil {
		t.Fatal(err)
	}
	p, err = m.Store.Page(ctx, actor, "issues", operations.Filter{})
	if err != nil || p.Counts.OpenIssues != 2 {
		t.Fatal("certificate metadata alone resolved a TLS issue")
	}
}
