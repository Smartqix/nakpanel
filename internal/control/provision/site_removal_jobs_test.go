package provision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type removalAgentFixture struct{ calls []types.SiteRemovalStage }

func (a *removalAgentFixture) TeardownSite(_ context.Context, req types.TeardownSiteReq) (types.TeardownSiteResult, error) {
	a.calls = append(a.calls, req.Stage)
	return types.TeardownSiteResult{OperationID: req.OperationID, Revision: req.Revision, Checkpoints: []string{string(req.Stage)}}, nil
}

type failingRemovalAgent struct {
	removalAgentFixture
	fail types.SiteRemovalStage
}

func (a *failingRemovalAgent) TeardownSite(ctx context.Context, req types.TeardownSiteReq) (types.TeardownSiteResult, error) {
	if req.Stage == a.fail {
		return types.TeardownSiteResult{}, errors.New("private fixture failure")
	}
	return a.removalAgentFixture.TeardownSite(ctx, req)
}

func TestSiteRemovalEachFailedStageRetainsIntentAndRequiresRetry(t *testing.T) {
	for _, stage := range []types.SiteRemovalStage{types.RemovalStopServices, types.RemovalHosting, types.RemovalShared, types.RemovalFinalize} {
		t.Run(string(stage), func(t *testing.T) {
			db, s, actor, req := removalServiceFixture(t)
			op, err := s.RemoveSiteFor(context.Background(), actor, req)
			if err != nil {
				t.Fatal(err)
			}
			agent := &failingRemovalAgent{fail: stage}
			w := NewRemoveSiteWorker(s, agent, &removalSharedFixture{})
			if err = w.Work(context.Background(), &river.Job[RemoveSiteArgs]{Args: RemoveSiteArgs{OperationID: op.ID, Revision: op.Revision}}); err == nil {
				t.Fatal("failed stage reported success")
			}
			var state, message string
			if err = db.QueryRow("SELECT state,last_error FROM site_removal_operations WHERE id=$1", op.ID).Scan(&state, &message); err != nil || state != "failed" || message == "" || strings.Contains(message, "private fixture") {
				t.Fatal(state, message, err)
			}
			var count int
			if err = db.QueryRow("SELECT count(*) FROM sites WHERE id=$1 AND removal_state='failed'", op.SiteID).Scan(&count); err != nil || count != 1 {
				t.Fatal("reserved intent lost", count, err)
			}
			retry, err := s.RetrySiteRemovalFor(context.Background(), actor, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			agent.fail = ""
			if err = w.Work(context.Background(), &river.Job[RemoveSiteArgs]{Args: RemoveSiteArgs{OperationID: op.ID, Revision: retry.Revision}}); err != nil {
				t.Fatal("retry failed", err)
			}
		})
	}
}

func TestSiteRemovalDuplicateWorkerDoesNotDispatch(t *testing.T) {
	db, s, actor, req := removalServiceFixture(t)
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	key := fmt.Sprintf("nakpanel:site-removal:%d", op.ID)
	if _, err = connection.ExecContext(context.Background(), "SELECT pg_advisory_lock(hashtextextended($1,0))", key); err != nil {
		t.Fatal(err)
	}
	defer connection.ExecContext(context.Background(), "SELECT pg_advisory_unlock(hashtextextended($1,0))", key)
	agent := &removalAgentFixture{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = NewRemoveSiteWorker(s, agent, &removalSharedFixture{}).Work(ctx, &river.Job[RemoveSiteArgs]{Args: RemoveSiteArgs{OperationID: op.ID, Revision: op.Revision}})
	var snooze *river.JobSnoozeError
	if !errors.As(err, &snooze) || len(agent.calls) != 0 {
		t.Fatal("duplicate physical worker dispatched", err)
	}
}

func TestSiteRemovalSweepRestoresInterruptedWork(t *testing.T) {
	db, s, actor, req := removalServiceFixture(t)
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("DELETE FROM river_job WHERE kind='remove_site'"); err != nil {
		t.Fatal(err)
	}
	if err = NewSweepSiteRemovalsWorker(s).Work(context.Background(), &river.Job[SweepSiteRemovalsArgs]{}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow("SELECT count(*) FROM river_job WHERE kind='remove_site' AND args->>'operation_id'=$1 AND args->>'revision'=$2", fmt.Sprint(op.ID), fmt.Sprint(op.Revision)).Scan(&count); err != nil || count != 1 {
		t.Fatal("interrupted work not restored", count, err)
	}
}

func TestSiteRemovalWaitsForRunningTargetJobs(t *testing.T) {
	db, s, actor, req := removalServiceFixture(t)
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(CreateSiteArgs{SiteID: op.SiteID, Domain: op.Domain})
	if _, err = db.Exec(`INSERT INTO river_job(kind,args,state,queue,max_attempts,attempt,attempted_at,attempted_by) VALUES('create_site',$1,'running','default',3,1,now(),ARRAY['fixture'])`, payload); err != nil {
		t.Fatal(err)
	}
	ready, err := s.drainSiteJobs(context.Background(), op)
	if err != nil || ready {
		t.Fatalf("running target not awaited: %v %v", ready, err)
	}
}

func TestSiteRemovalDoesNotCancelSiblingJobs(t *testing.T) {
	db, s, actor, req := removalServiceFixture(t)
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{op.SiteID, 1} {
		payload, _ := json.Marshal(CreateSiteArgs{SiteID: id})
		if _, err = db.Exec(`INSERT INTO river_job(kind,args,state,queue,max_attempts) VALUES('create_site',$1,'available','default',3)`, payload); err != nil {
			t.Fatal(err)
		}
	}
	ready, err := s.drainSiteJobs(context.Background(), op)
	if err != nil || !ready {
		t.Fatal(ready, err)
	}
	var count int
	db.QueryRow("SELECT count(*) FROM river_job WHERE kind='create_site' AND state='available' AND args->>'site_id'='1'").Scan(&count)
	if count != 1 {
		t.Fatal("sibling job cancelled")
	}
	db.QueryRow("SELECT count(*) FROM river_job WHERE kind='create_site' AND state='cancelled' AND args->>'site_id'=$1", fmt.Sprint(op.SiteID)).Scan(&count)
	if count != 1 {
		t.Fatal("target job not cancelled")
	}
}

func TestSiteRemovalDoesNotCancelSiblingRecoveryProofRestore(t *testing.T) {
	db, s, actor, req := removalServiceFixture(t)
	if _, err := db.Exec(`INSERT INTO databases(owner_user_id,customer_id,subscription_id,site_id,engine,db_name,db_user,status) SELECT owner_user_id,customer_id,subscription_id,id,'mariadb','fixture_db','fixture_user','active' FROM sites WHERE id=$1`, req.SiteID); err != nil {
		t.Fatal(err)
	}
	var siblingID, backupID int64
	if err := db.QueryRow(`SELECT id FROM sites WHERE domain='primary.test'`).Scan(&siblingID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO backups(owner_user_id,customer_id,subscription_id,site_id,target_kind,target_name,status,archive_path,checksum_sha256,database_names) SELECT owner_user_id,customer_id,subscription_id,id,'site',domain,'active','/var/lib/nakpanel/backups/sibling-proof.tar.gz',$2,ARRAY['fixture_db'] FROM sites WHERE id=$1 RETURNING id`, siblingID, strings.Repeat("a", 64)).Scan(&backupID); err != nil {
		t.Fatal(err)
	}
	p, err := s.PreviewSiteRemoval(context.Background(), actor, req.SiteID)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Snapshot.Backups) != 1 || p.Snapshot.Backups[0].SiteID != siblingID {
		t.Fatal("sibling proof fixture missing")
	}
	req.PreviewDigest = p.Digest
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range []string{fmt.Sprintf(`{"backup_id":%d}`, backupID), fmt.Sprintf(`{"backup_id":%d,"site_id":%d,"domain":"primary.test"}`, backupID, siblingID)} {
		if _, err = db.Exec(`INSERT INTO river_job(kind,args,state,queue,max_attempts) VALUES('restore_backup',$1,'available','default',3)`, payload); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(`UPDATE backups SET status='deleting' WHERE id=$1`, backupID); err == nil {
		t.Fatal("proof archive metadata entered retention during approved removal")
	}
	if _, err = db.Exec(`INSERT INTO river_job(kind,args,state,queue,max_attempts) VALUES('maintenance_delete_backup',$1,'available','default',3)`, fmt.Sprintf(`{"backup_id":%d}`, backupID)); err != nil {
		t.Fatal(err)
	}
	ready, err := s.drainSiteJobs(context.Background(), op)
	if err != nil || !ready {
		t.Fatal(ready, err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM river_job WHERE kind='restore_backup' AND state='available'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("sibling proof restore cancelled: %d %v", count, err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM river_job WHERE kind='maintenance_delete_backup' AND state='cancelled'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("proof archive pruning was not fenced", count, err)
	}
	called := false
	payload := []byte(fmt.Sprintf(`{"backup_id":%d}`, backupID))
	if err = NewSiteJobFence(db).Work(context.Background(), &rivertype.JobRow{Kind: "maintenance_delete_backup", EncodedArgs: payload}, func(context.Context) error { called = true; return nil }); err == nil || called {
		t.Fatal("late pruning job can remove an approved recovery proof")
	}
}

func TestSiteRemovalStaleWorkersDoNotCallAgent(t *testing.T) {
	_, s, actor, req := removalServiceFixture(t)
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	agent := &removalAgentFixture{}
	w := NewRemoveSiteWorker(s, agent, nil)
	if err = w.Work(context.Background(), &river.Job[RemoveSiteArgs]{Args: RemoveSiteArgs{OperationID: op.ID, Revision: op.Revision + 1}}); err != nil {
		t.Fatal(err)
	}
	if len(agent.calls) != 0 {
		t.Fatal("stale worker called agent")
	}
}

type removalSharedFixture struct{ fail bool }

func (s *removalSharedFixture) Converge(_ context.Context, op types.SiteRemovalOperation) (types.TeardownSiteResult, error) {
	if s.fail {
		return types.TeardownSiteResult{}, errors.New("fixture convergence failure")
	}
	return types.TeardownSiteResult{OperationID: op.ID, Revision: op.Revision, Checkpoints: []string{"surviving-access", "surviving-mail"}}, nil
}

func TestSiteRemovalRetryUsesSameScope(t *testing.T) {
	db, s, actor, req := removalServiceFixture(t)
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	agent := &removalAgentFixture{}
	shared := &removalSharedFixture{fail: true}
	worker := NewRemoveSiteWorker(s, agent, shared)
	if err = worker.Work(context.Background(), &river.Job[RemoveSiteArgs]{Args: RemoveSiteArgs{OperationID: op.ID, Revision: op.Revision}}); err == nil {
		t.Fatal("shared failure ignored")
	}
	var state string
	db.QueryRow("SELECT state FROM site_removal_operations WHERE id=$1", op.ID).Scan(&state)
	if state != "failed" {
		t.Fatal("failure not reserved", state)
	}
	retry, err := s.RetrySiteRemovalFor(context.Background(), actor, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Snapshot.Digest() != op.Snapshot.Digest() {
		t.Fatal("retry changed scope")
	}
	shared.fail = false
	if err = worker.Work(context.Background(), &river.Job[RemoveSiteArgs]{Args: RemoveSiteArgs{OperationID: op.ID, Revision: retry.Revision}}); err != nil {
		t.Fatal("retry", err)
	}
	db.QueryRow("SELECT state FROM site_removal_operations WHERE id=$1", op.ID).Scan(&state)
	if state != "completed" {
		t.Fatal("retry incomplete", state)
	}
}

func TestSiteRemovalTerminalJobsRequireManualRetry(t *testing.T) {
	db, s, actor, req := removalServiceFixture(t)
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE river_job SET state='discarded',finalized_at=now() WHERE kind='remove_site'"); err != nil {
		t.Fatal(err)
	}
	sweep := NewSweepSiteRemovalsWorker(s)
	for i := 0; i < 2; i++ {
		if err = sweep.Work(context.Background(), &river.Job[SweepSiteRemovalsArgs]{}); err != nil {
			t.Fatal(err)
		}
	}
	var state string
	db.QueryRow("SELECT state FROM site_removal_operations WHERE id=$1", op.ID).Scan(&state)
	if state != "failed" {
		t.Fatal("terminal work not failed", state)
	}
	var count int
	db.QueryRow("SELECT count(*) FROM river_job WHERE kind='remove_site'").Scan(&count)
	if count != 1 {
		t.Fatal("failed removal resubmitted automatically", count)
	}
}

func TestSiteRemovalDrainDeletesOnlyCancelledPrivateTLSStaging(t *testing.T) {
	db, s, actor, req := removalServiceFixture(t)
	op, err := s.RemoveSiteFor(context.Background(), actor, req)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	s.options.TLSStagingDirectory = root
	target := filepath.Join(root, "custom-target.json")
	sibling := filepath.Join(root, "custom-sibling.json")
	for _, path := range []string{target, sibling} {
		if err := os.WriteFile(path, []byte("private-fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		siteID int64
		path   string
	}{{op.SiteID, target}, {1, sibling}} {
		payload, _ := json.Marshal(InstallCustomCertArgs{SiteID: item.siteID, StagingPath: item.path})
		if _, err = db.Exec(`INSERT INTO river_job(kind,args,state,queue,max_attempts) VALUES('install_custom_cert',$1,'available','default',3)`, payload); err != nil {
			t.Fatal(err)
		}
	}
	ready, err := s.drainSiteJobs(context.Background(), op)
	if err != nil || !ready {
		t.Fatal(ready, err)
	}
	if _, err = os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("cancelled key staging remains", err)
	}
	if _, err = os.Stat(sibling); err != nil {
		t.Fatal("sibling key staging changed", err)
	}
}
