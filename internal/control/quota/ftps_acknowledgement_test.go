package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type ftpsAcknowledgementAgent struct{ SubscriptionConvergenceAgent }

func (*ftpsAcknowledgementAgent) EnsureSubscriptionAccount(context.Context, types.EnsureSubscriptionAccountReq) (types.Response, error) {
	return types.Response{OK: true, Data: json.RawMessage(`{"linux_uid":1234}`)}, nil
}

func TestFTPSAcknowledgementRetainsEditFromEarlierStartedTransaction(t *testing.T) {
	db := taskLogPostgres(t)
	_, err := db.Exec(`CREATE TEMP TABLE ftp_accounts(id bigint,convergence_status text,last_error text,updated_at timestamptz,
subscription_id bigint DEFAULT 42,site_id bigint,name text DEFAULT 'login',password_hash text DEFAULT '$6$hash',enabled boolean DEFAULT true);
INSERT INTO ftp_accounts(id,convergence_status,last_error,updated_at) VALUES(17,'pending','',now()-interval '2 seconds');`)
	if err != nil {
		t.Fatal(err)
	}
	var capturedVersion string
	if err := db.QueryRow(`SELECT ` + ftpsIntentVersionSQL + ` FROM ftp_accounts ftp WHERE id=17`).Scan(&capturedVersion); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now()
	// now() is the intent transaction's start time, not its commit time.
	if _, err := db.Exec(`UPDATE ftp_accounts SET last_error='new intent',updated_at=$1 WHERE id=17`, cutoff.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := acknowledgeFTPSConvergence(context.Background(), db, []ftpsAccountVersion{{ID: 17, Version: capturedVersion}}, "in_sync", ""); err != nil {
		t.Fatal(err)
	}
	var state, message string
	if err := db.QueryRow(`SELECT convergence_status,last_error FROM ftp_accounts WHERE id=17`).Scan(&state, &message); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || message != "new intent" {
		t.Fatalf("stale snapshot acknowledged a later committed edit: state=%s message=%s", state, message)
	}
}

func TestFTPSAcknowledgementOnlyUpdatesCapturedUnchangedRows(t *testing.T) {
	db := taskLogPostgres(t)
	if _, err := db.Exec(`CREATE TEMP TABLE ftp_accounts(id bigint,convergence_status text,last_error text,updated_at timestamptz DEFAULT now(),
subscription_id bigint DEFAULT 42,site_id bigint,name text DEFAULT 'login',password_hash text DEFAULT '$6$hash',enabled boolean DEFAULT true);
INSERT INTO ftp_accounts(id,convergence_status,last_error) VALUES(17,'pending',''),(18,'pending','');`); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := db.QueryRow(`SELECT ` + ftpsIntentVersionSQL + ` FROM ftp_accounts ftp WHERE id=17`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	versions := []ftpsAccountVersion{{ID: 17, Version: version}}
	if err := acknowledgeFTPSConvergence(context.Background(), db, versions, "in_sync", ""); err != nil {
		t.Fatal(err)
	}
	var ready, pending int
	if err := db.QueryRow(`SELECT COUNT(*) FILTER(WHERE convergence_status='in_sync'),COUNT(*) FILTER(WHERE convergence_status='pending') FROM ftp_accounts`).Scan(&ready, &pending); err != nil {
		t.Fatal(err)
	}
	if ready != 1 || pending != 1 {
		t.Fatalf("captured row or unobserved row changed incorrectly: ready=%d pending=%d", ready, pending)
	}
	// A later apply whose rollback fails must not leave false readiness.
	if err := acknowledgeFTPSConvergence(context.Background(), db, versions, "failed", "rollback failed"); err != nil {
		t.Fatal(err)
	}
	var message string
	if err := db.QueryRow(`SELECT last_error FROM ftp_accounts WHERE id=17 AND convergence_status='failed'`).Scan(&message); err != nil || message != "rollback failed" {
		t.Fatalf("runtime failure retained false readiness: message=%s error=%v", message, err)
	}
}

func TestFTPSNodeWideLockSerializesUntilCommitAndRollback(t *testing.T) {
	db := taskLogPostgres(t)
	db.SetMaxOpenConns(2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, rollback := range []bool{false, true} {
		first, err := lockFTPSTx(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		defer first.Rollback()
		acquired := make(chan error, 1)
		go func() {
			second, err := lockFTPSTx(ctx, db)
			if err == nil {
				err = second.Rollback()
			}
			acquired <- err
		}()
		select {
		case err := <-acquired:
			t.Fatalf("second node-wide apply bypassed lock: %v", err)
		case <-time.After(30 * time.Millisecond):
		}
		if rollback {
			err = first.Rollback()
		} else {
			err = first.Commit()
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := <-acquired; err != nil {
			t.Fatal(err)
		}
	}
}

func TestFTPSSuccessAcknowledgesIntentAfterEarlierFailure(t *testing.T) {
	db := taskLogPostgres(t)
	if _, err := db.Exec(`CREATE TEMP TABLE ftp_accounts(id bigint,convergence_status text,last_error text,updated_at timestamptz DEFAULT now(),
subscription_id bigint DEFAULT 42,site_id bigint,name text DEFAULT 'login',password_hash text DEFAULT '$6$hash',enabled boolean DEFAULT true);
INSERT INTO ftp_accounts(id,convergence_status,last_error) VALUES(17,'pending','');`); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := db.QueryRow(`SELECT ` + ftpsIntentVersionSQL + ` FROM ftp_accounts ftp WHERE id=17`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	versions := []ftpsAccountVersion{{ID: 17, Version: version}}
	if err := acknowledgeFTPSConvergence(context.Background(), db, versions, "failed", "earlier failure"); err != nil {
		t.Fatal(err)
	}
	if err := acknowledgeFTPSConvergence(context.Background(), db, versions, "in_sync", ""); err != nil {
		t.Fatal(err)
	}
	var state, message string
	if err := db.QueryRow(`SELECT convergence_status,last_error FROM ftp_accounts WHERE id=17`).Scan(&state, &message); err != nil {
		t.Fatal(err)
	}
	if state != "in_sync" || message != "" {
		t.Fatalf("newer successful apply lost to earlier failure: state=%s message=%s", state, message)
	}
}

func (*ftpsAcknowledgementAgent) ApplyScheduledTasks(context.Context, types.ApplyScheduledTasksReq) (types.Response, error) {
	return types.Response{OK: true}, nil
}
func (*ftpsAcknowledgementAgent) EnsureFTPS(context.Context, types.EnsureFTPSReq) (types.EnsureFTPSResult, error) {
	return types.EnsureFTPSResult{Changed: true}, nil
}

func TestFTPSAcknowledgementDoesNotMarkUncapturedOrUpdatedAccountsReady(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	policy := runnableValkeyPolicy()
	policy.SchemaVersion = 1
	policy.PHP = types.HostingPHPPolicy{DefaultVersion: "8.4", AllowedVersions: []string{"8.4"}}
	policy.DNS = types.HostingDNSPolicy{Mode: "authoritative", DefaultTTL: 3600}
	policy.Mail.DMARCPolicy = "none"
	policy.Access.ShellMode = "sftp"
	raw, _ := json.Marshal(policy)
	mock.ExpectQuery("SELECT migration_status").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"migration"}).AddRow("complete"))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT account.subscription_id").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"sub", "user", "home", "revision", "state"}).AddRow(42, "npaccount", "/home/npaccount", 7, "active"))
	columns := make([]string, 31)
	for i := range columns {
		columns[i] = fmt.Sprint(i)
	}
	mock.ExpectQuery("SELECT subscription_id,plan_name").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows(columns).AddRow(42, "plan", 1024, 1, 1, 1024, 0, false, true, 1, "8.4", 4, 128, 1024, 1, 1024, 1, "block", 80, 80, 1, 1, 1, 0, true, "8.4", true, true, true, []byte(`{}`), raw))
	mock.ExpectQuery("SELECT e.hosting_policy").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"policy", "patch"}).AddRow(raw, []byte(`{}`)))
	for _, query := range []string{"SELECT site.id,site.domain", "SELECT id,name,public_key", "SELECT task.id,COALESCE"} {
		mock.ExpectQuery(query).WillReturnRows(sqlmock.NewRows([]string{"empty"}))
	}
	mock.ExpectQuery("SELECT instance.subscription_id").WithArgs(int64(42)).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery("SELECT COUNT").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	for _, query := range []string{"SELECT application.id", "SELECT volume.application_id", "SELECT repository.id"} {
		mock.ExpectQuery(query).WillReturnRows(sqlmock.NewRows([]string{"empty"}))
	}
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectCommit()
	mock.ExpectExec("UPDATE scheduled_tasks").WithArgs(int64(42)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock\(7443,21\)`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT ftp.id,ftp.subscription_id").WillReturnRows(sqlmock.NewRows([]string{"id", "sub", "user", "site", "domain", "name", "hash", "enabled", "version"}).AddRow(17, 42, "npaccount", 0, "", "existing", "$6$hash", true, "123"))
	mock.ExpectQuery("SELECT subscription_id,plan_name").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows(columns).AddRow(42, "plan", 1024, 1, 1, 1024, 0, false, true, 1, "8.4", 4, 128, 1024, 1, 1024, 1, "block", 80, 80, 1, 1, 1, 0, true, "8.4", true, true, true, []byte(`{}`), raw))
	mock.ExpectQuery("SELECT e.hosting_policy").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"policy", "patch"}).AddRow(raw, []byte(`{}`)))
	mock.ExpectExec(`(?s)UPDATE ftp_accounts.*WHERE ftp.id=applied.id AND .*::text=applied.version`).WithArgs("in_sync", "", `[{"id":17,"version":"123"}]`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE subscription_system_accounts").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	worker := &ConvergeSubscriptionWorker{db: db, agent: &ftpsAcknowledgementAgent{}, river: &river.Client[*sql.Tx]{}}
	if err := worker.Work(context.Background(), &river.Job[ConvergeSubscriptionArgs]{Args: ConvergeSubscriptionArgs{SubscriptionID: 42, Revision: 7}}); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
