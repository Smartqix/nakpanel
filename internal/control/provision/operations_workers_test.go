package provision

import (
	"context"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"testing"
)

func TestOperationsSweepQueuesBoundedIndependentChecks(t *testing.T) {
	db, m, agent, actor, siteID := operationsFixture(t)
	ctx := context.Background()
	if _, err := db.Exec(`UPDATE sites SET created_at=now()-interval '3 days' WHERE id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	if err := m.SweepChecks(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.SweepChecks(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM river_job WHERE kind='verify_operation_issue'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("deduped issue check: %d %v", count, err)
	}
	p, err := m.Page(ctx, actor, "issues", operations.Filter{})
	if err != nil || len(p.Issues) != 1 {
		t.Fatal(p, err)
	}
	pre, err := m.Preflight(ctx, actor, p.Issues[0].ID)
	if err != nil || !pre.Allowed {
		t.Fatal(pre, err)
	}
	started, err := m.Recover(ctx, actor, p.Issues[0].ID, pre.Confirmation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE backups SET status='active',archive_path='/var/lib/nakpanel/backups/current.tar',checksum_sha256=$1,size_bytes=$2,completed_at=now() WHERE site_id=$3`, agent.checksum, agent.size, siteID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE river_job SET state='completed',attempt=1,finalized_at=now() WHERE id=$1`, started.JobID); err != nil {
		t.Fatal(err)
	}
	if err = m.VerifyLatestArchive(ctx, siteID); err != nil {
		t.Fatal(err)
	}
	var status string
	if err = db.QueryRow(`SELECT last_check_status FROM backup_readiness_checks`).Scan(&status); err != nil || status != "verified" {
		t.Fatal(status, err)
	}
	agent.fail = true
	if err = m.VerifyLatestArchive(ctx, siteID); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT last_check_status FROM backup_readiness_checks`).Scan(&status); err != nil || status != "unknown" {
		t.Fatal(status, err)
	}
}
