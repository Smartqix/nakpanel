package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type shutdownOrderAgent struct {
	SubscriptionConvergenceAgent
	events        []string
	failCache     bool
	accountStates []string
}

func (a *shutdownOrderAgent) EnsureSubscriptionAccount(_ context.Context, req types.EnsureSubscriptionAccountReq) (types.Response, error) {
	a.events = append(a.events, "account")
	a.accountStates = append(a.accountStates, req.State)
	return types.Response{}, errors.New("injected account setup failure")
}

func (a *shutdownOrderAgent) EnsureValkey(_ context.Context, req types.EnsureValkeyReq) (types.EnsureValkeyResult, error) {
	a.events = append(a.events, "cache:"+req.State)
	if a.failCache {
		return types.EnsureValkeyResult{}, errors.New("injected cache stop failure")
	}
	return types.EnsureValkeyResult{SocketPath: "/run/cache.sock"}, nil
}

func TestValkeyShutdownPrecedesFailingAccountConvergence(t *testing.T) {
	for _, test := range []struct {
		name, state string
		failCache   bool
	}{{"revoked", "active", false}, {"suspended", "suspended", false}, {"cache failure still attempts suspended FPM", "suspended", true}} {
		t.Run(test.name, func(t *testing.T) {
			accountState := test.state
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
			if accountState == "active" {
				policy.Permissions.Valkey = false
			}
			raw, _ := json.Marshal(policy)
			mock.ExpectQuery("SELECT migration_status").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"migration"}).AddRow("complete"))
			mock.ExpectBegin()
			mock.ExpectQuery("SELECT account.subscription_id").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"sub", "user", "home", "revision", "state"}).AddRow(42, "npaccount", "/home/npaccount", 7, accountState))
			columns := make([]string, 31)
			for i := range columns {
				columns[i] = fmt.Sprint(i)
			}
			mock.ExpectQuery("SELECT subscription_id,plan_name").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows(columns).AddRow(42, "plan", 1024, 1, 1, 1024, 0, false, true, 1, "8.4", 4, 128, 1024, 1, 1024, 1, "block", 80, 80, 1, 1, 1, 0, true, "8.4", true, true, true, []byte(`{}`), raw))
			mock.ExpectQuery("SELECT e.hosting_policy").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"policy", "patch"}).AddRow(raw, []byte(`{}`)))
			for _, query := range []string{"SELECT site.id,site.domain", "SELECT id,name,public_key", "SELECT task.id,COALESCE", "SELECT ftp.id,ftp.subscription_id"} {
				mock.ExpectQuery(query).WillReturnRows(sqlmock.NewRows([]string{"empty"}))
			}
			mock.ExpectQuery("SELECT instance.subscription_id").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"sub", "user", "state", "memory", "clients", "idle", "cpu", "process", "acl", "flush"}).AddRow(42, "npaccount", "enabled", 128, 64, 300, 25, 64, strings.Repeat("a", 64), false))
			mock.ExpectQuery("SELECT valkey_capacity_mb").WillReturnRows(sqlmock.NewRows([]string{"capacity"}).AddRow(0))
			mock.ExpectQuery("SELECT COUNT").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
			for _, query := range []string{"SELECT application.id", "SELECT volume.application_id", "SELECT repository.id"} {
				mock.ExpectQuery(query).WillReturnRows(sqlmock.NewRows([]string{"empty"}))
			}
			mock.ExpectCommit()
			mock.ExpectExec(`(?s)UPDATE valkey_instances.*desired_revision=\$2`).WillReturnResult(sqlmock.NewResult(0, 1))
			if !test.failCache {
				mock.ExpectBegin()
				mock.ExpectCommit()
			}
			mock.ExpectBegin()
			mock.ExpectExec(`UPDATE subscription_system_accounts`).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()
			agent := &shutdownOrderAgent{failCache: test.failCache}
			worker := &ConvergeSubscriptionWorker{db: db, agent: agent, river: &river.Client[*sql.Tx]{}}
			err = worker.Work(context.Background(), &river.Job[ConvergeSubscriptionArgs]{Args: ConvergeSubscriptionArgs{SubscriptionID: 42, Revision: 7}})
			if err == nil || !strings.Contains(err.Error(), "injected account setup failure") {
				t.Fatalf("unexpected convergence error: %v", err)
			}
			wantEvents := 2
			if test.failCache {
				wantEvents = 3
				if !strings.Contains(err.Error(), "injected cache stop failure") {
					t.Fatal("cache failure was dropped")
				}
			}
			if len(agent.events) != wantEvents || !strings.HasPrefix(agent.events[0], "cache:") || agent.events[len(agent.events)-1] != "account" {
				t.Fatalf("cache shutdown bypassed by account failure: %v", agent.events)
			}
			if test.failCache && (len(agent.accountStates) != 1 || agent.accountStates[0] != "suspended") {
				t.Fatalf("error recovery used an activation path: %v", agent.accountStates)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
