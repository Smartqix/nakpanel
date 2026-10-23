package provision

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"github.com/nakroteck/nakpanel/internal/testutil/operationsdb"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
	"strings"
	"testing"
	"time"
)

type operationsProbeAgent struct {
	checksum string
	size     int64
	fail     bool
	last     types.ReadBackupChunkReq
}

func (a *operationsProbeAgent) Ping(context.Context) (types.Response, error) {
	return types.Response{OK: true}, nil
}
func (a *operationsProbeAgent) ReadBackupChunk(_ context.Context, r types.ReadBackupChunkReq) (types.ReadBackupChunkResult, error) {
	a.last = r
	if a.fail {
		return types.ReadBackupChunkResult{}, errors.New("unavailable")
	}
	return types.ReadBackupChunkResult{SHA256: a.checksum, Size: a.size, BackupID: r.BackupID, Offset: r.Offset, Data: []byte{0}}, nil
}
func (a *operationsProbeAgent) InspectServer(context.Context) (types.ServerInventory, error) {
	return types.ServerInventory{OperatingSystem: "Ubuntu 26.04 LTS", Filesystems: []types.FilesystemState{{Mountpoint: "/", AvailableBytes: 1 << 30, AvailableInodes: 10000}}, CheckedAt: time.Now().UTC()}, nil
}
func (a *operationsProbeAgent) RuntimeCapabilities(context.Context) (types.RuntimeCapabilities, error) {
	return types.RuntimeCapabilities{}, nil
}
func (a *operationsProbeAgent) InspectSiteReadiness(context.Context, types.InspectSiteReadinessReq) (types.SiteReadinessResult, error) {
	return types.SiteReadinessResult{}, errors.New("unavailable")
}
func (a *operationsProbeAgent) MailStatus(context.Context) (types.MailServerStatus, error) {
	return types.MailServerStatus{}, errors.New("unavailable")
}

func operationsFixture(t *testing.T) (*sql.DB, *OperationsManager, *operationsProbeAgent, auth.SessionUser, int64) {
	t.Helper()
	db := operationsdb.New(t)
	driver := riverdatabasesql.New(db)
	m, err := rivermigrate.New(driver, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Migrate(context.Background(), rivermigrate.DirectionUp, nil); err != nil {
		t.Fatal(err)
	}
	if err = operations.InstallRecorder(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	queue, err := river.NewClient(driver, &river.Config{})
	if err != nil {
		t.Fatal(err)
	}
	siteID := removaldb.Site(t, db, 1, "studio.example", nil)
	agent := &operationsProbeAgent{checksum: strings.Repeat("a", 64), size: 4096}
	return db, NewOperationsManager(db, queue, agent), agent, auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, siteID
}

func TestOperationsRecoveryUsesCurrentIntentAndIndependentArchiveCheck(t *testing.T) {
	db, m, agent, actor, siteID := operationsFixture(t)
	ctx := context.Background()
	issue, err := m.Store.ObserveIssue(ctx, operations.Observation{EventKey: "failed-backup", Resource: operations.Resource{Kind: operations.ResourceSite, ID: siteID}, Kind: "backup", Condition: "protection", Severity: "critical", Title: "Backup is overdue", Summary: "No current verified archive", ObservedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := m.Preflight(ctx, actor, issue.ID)
	if err != nil || !preflight.Allowed {
		t.Fatalf("preflight: %#v %v", preflight, err)
	}
	started, err := m.Recover(ctx, actor, issue.ID, preflight.Confirmation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Recover(ctx, actor, issue.ID, preflight.Confirmation); !errors.Is(err, operations.ErrConflict) {
		t.Fatalf("duplicate retry: %v", err)
	}
	var argsJSON []byte
	if err = db.QueryRow(`SELECT args FROM river_job WHERE id=$1`, started.JobID).Scan(&argsJSON); err != nil {
		t.Fatal(err)
	}
	var args CreateBackupArgs
	if err = json.Unmarshal(argsJSON, &args); err != nil || args.SiteID != siteID || args.Domain != "studio.example" {
		t.Fatalf("not current intent: %#v %v", args, err)
	}
	if _, err = db.Exec(`UPDATE backups SET status='active',archive_path='/var/lib/nakpanel/backups/studio.example-current.tar.gz',size_bytes=4096,checksum_sha256=repeat('a',64),completed_at=now() WHERE id=$1`, args.BackupID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE river_job SET state='completed',attempt=1,attempted_at=now(),finalized_at=now() WHERE id=$1`, started.JobID); err != nil {
		t.Fatal(err)
	}
	agent.fail = true
	if err = m.VerifyIssue(ctx, issue.ID); err == nil {
		t.Fatal("worker completion resolved an issue without independent archive evidence")
	}
	unverified, err := m.Store.Issue(ctx, actor, issue.ID)
	if err != nil || unverified.ResolvedAt != nil {
		t.Fatalf("failed verification resolved issue: %#v %v", unverified, err)
	}
	agent.fail = false
	if err = m.VerifyIssue(ctx, issue.ID); err != nil {
		t.Fatal(err)
	}
	resolved, err := m.Store.Issue(ctx, actor, issue.ID)
	if err != nil || resolved.ResolvedAt == nil || agent.last.BackupID != args.BackupID || agent.last.Offset != 0 {
		t.Fatalf("recovery was not independently verified: %#v %v", resolved, err)
	}
	var current string
	if err = db.QueryRow(`SELECT state FROM operations WHERE id=$1`, started.OperationID).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if current != "succeeded" {
		t.Fatal("completed worker result was lost")
	}
}

func TestRecoveryRejectsChangedPolicySuspensionAndNonAdministrator(t *testing.T) {
	for _, reason := range []string{"policy", "suspension", "role", "removal"} {
		t.Run(reason, func(t *testing.T) {
			db, m, _, actor, siteID := operationsFixture(t)
			ctx := context.Background()
			i, err := m.Store.ObserveIssue(ctx, operations.Observation{EventKey: "failure", Resource: operations.Resource{Kind: operations.ResourceSite, ID: siteID}, Kind: "backup", Condition: "protection", Severity: "critical", Title: "Backup overdue", Summary: "Review policy", ObservedAt: time.Now().UTC()})
			if err != nil {
				t.Fatal(err)
			}
			p, err := m.Preflight(ctx, actor, i.ID)
			if err != nil || !p.Allowed {
				t.Fatalf("preflight: %#v %v", p, err)
			}
			switch reason {
			case "policy":
				_, err = db.Exec(`UPDATE subscription_entitlements SET allow_backups=false WHERE subscription_id=1`)
			case "suspension":
				_, err = db.Exec(`UPDATE subscriptions SET status='suspended' WHERE id=1`)
			case "role":
				actor.Role = auth.RoleClient
			case "removal":
				_, err = db.Exec(`UPDATE sites SET removal_state='removing' WHERE id=$1`, siteID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = m.Recover(ctx, actor, i.ID, p.Confirmation); err == nil {
				t.Fatalf("%s stale retry was accepted", reason)
			}
			var n int
			if err = db.QueryRow(`SELECT count(*) FROM river_job WHERE kind='create_backup'`).Scan(&n); err != nil || n != 0 {
				t.Fatalf("denied retry left queued work: %d %v", n, err)
			}
		})
	}
}

func TestOperationsRecoveryRejectsDestructiveKindAndRefreshesQueuedIntent(t *testing.T) {
	db, m, _, actor, id := operationsFixture(t)
	ctx := context.Background()
	issue, err := m.ObserveIssue(ctx, operations.Observation{EventKey: "restore-failed", Resource: operations.Resource{Kind: operations.ResourceSite, ID: id}, Kind: "restore", Condition: "restore", Severity: "critical", Title: "Restore failed", Summary: "Review existing data before changing it", ObservedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	p, err := m.Preflight(ctx, actor, issue.ID)
	if err != nil || p.Allowed || p.Reason == "" {
		t.Fatal("destructive retry exposed", p, err)
	}
	var backupID int64
	if err = db.QueryRow(`INSERT INTO backups(owner_user_id,customer_id,subscription_id,site_id,target_kind,target_name,status) SELECT owner_user_id,customer_id,subscription_id,id,'site',domain,'pending' FROM sites WHERE id=$1 RETURNING id`, id).Scan(&backupID); err != nil {
		t.Fatal(err)
	}
	store := NewSQLPhase6StatusStore(db)
	refreshed, err := store.RefreshBackupIntent(ctx, CreateBackupArgs{BackupID: backupID, SiteID: id, Domain: "stale.example", Username: "stale", Docroot: "/stale"})
	if err != nil || refreshed.Domain != "studio.example" || refreshed.Username == "stale" || refreshed.Docroot == "/stale" {
		t.Fatal(refreshed, err)
	}
	if _, err = db.Exec(`UPDATE subscriptions SET status='suspended' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RefreshBackupIntent(ctx, CreateBackupArgs{BackupID: backupID, SiteID: id}); err == nil {
		t.Fatal("suspended queued request admitted")
	}
}

func TestOperationsRetryKeepsOriginalFailedAttempt(t *testing.T) {
	db, m, _, actor, id := operationsFixture(t)
	ctx := context.Background()
	var backupID int64
	if err := db.QueryRow(`INSERT INTO backups(owner_user_id,customer_id,subscription_id,site_id,target_kind,target_name,status) SELECT owner_user_id,customer_id,subscription_id,id,'site',domain,'failed' FROM sites WHERE id=$1 RETURNING id`, id).Scan(&backupID); err != nil {
		t.Fatal(err)
	}
	job, err := m.queue.Insert(ctx, CreateBackupArgs{BackupID: backupID, SiteID: id, SubscriptionID: 1, Domain: "studio.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE river_job SET state='running',attempt=1,attempted_at=now() WHERE id=$1`, job.Job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE river_job SET state='discarded',finalized_at=now() WHERE id=$1`, job.Job.ID); err != nil {
		t.Fatal(err)
	}
	page, err := m.Page(ctx, actor, "issues", operations.Filter{})
	if err != nil || len(page.Issues) != 1 {
		t.Fatal(page, err)
	}
	i := page.Issues[0]
	pre, err := m.Preflight(ctx, actor, i.ID)
	if err != nil || !pre.Allowed {
		t.Fatal(pre, err)
	}
	started, err := m.Recover(ctx, actor, i.ID, pre.Confirmation)
	if err != nil || started.OperationID != i.OperationID || started.JobID == job.Job.ID {
		t.Fatal(started, err)
	}
	detail, err := m.Operation(ctx, actor, started.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	var failed, queued int
	for _, a := range detail.Attempts {
		if a.State == operations.StateFailed {
			failed++
		}
		if a.State == operations.StateQueued {
			queued++
		}
	}
	if failed != 1 || queued != 1 {
		t.Fatalf("attempt history was rewritten: %#v", detail.Attempts)
	}
}

func TestOperationsCorrelatesDomainFailureNoticeWithoutDuplicateInboxEntry(t *testing.T) {
	db, m, _, actor, id := operationsFixture(t)
	ctx := context.Background()
	job, err := m.queue.Insert(ctx, CreateBackupArgs{SiteID: id, SubscriptionID: 1, Domain: "studio.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE river_job SET state='running',attempt=1,attempted_at=now() WHERE id=$1`, job.Job.ID); err != nil {
		t.Fatal(err)
	}
	err = (&operations.JobContextMiddleware{}).Work(ctx, job.Job, func(workCtx context.Context) error {
		tx, err := db.BeginTx(workCtx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var notificationID int64
		if err = tx.QueryRowContext(workCtx, `INSERT INTO notifications(subscription_id,kind,severity,title,body,dedupe_key) VALUES(1,'maintenance_failed','critical','Backup failed','Existing data was preserved','current-source-failure') RETURNING id`).Scan(&notificationID); err != nil {
			return err
		}
		if err = operations.EnqueueNotificationTx(workCtx, tx, notificationID); err != nil {
			return err
		}
		return tx.Commit()
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE river_job SET state='discarded',finalized_at=now() WHERE id=$1`, job.Job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Dispatch(ctx, 100); err != nil {
		t.Fatal(err)
	}
	p, err := m.Page(ctx, actor, "inbox", operations.Filter{})
	if err != nil || len(p.Notifications) != 1 || p.Notifications[0].IssueID == 0 || p.Notifications[0].OperationID == 0 {
		t.Fatalf("duplicate or unlinked source notice: %#v %v", p, err)
	}
}
