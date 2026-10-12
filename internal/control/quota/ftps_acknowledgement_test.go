package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type ftpsAcknowledgementAgent struct{ SubscriptionConvergenceAgent }

func (*ftpsAcknowledgementAgent) EnsureSubscriptionAccount(context.Context, types.EnsureSubscriptionAccountReq) (types.Response, error) {
	return types.Response{OK: true, Data: json.RawMessage(`{"linux_uid":1234}`)}, nil
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
	mock.ExpectQuery("SELECT ftp.id,ftp.subscription_id").WillReturnRows(sqlmock.NewRows([]string{"id", "sub", "user", "site", "domain", "name", "hash", "enabled"}).AddRow(17, 42, "npaccount", 0, "", "existing", "$6$hash", true))
	mock.ExpectQuery("SELECT instance.subscription_id").WithArgs(int64(42)).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery("SELECT COUNT").WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	for _, query := range []string{"SELECT application.id", "SELECT volume.application_id", "SELECT repository.id"} {
		mock.ExpectQuery(query).WillReturnRows(sqlmock.NewRows([]string{"empty"}))
	}
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectCommit()
	mock.ExpectExec("UPDATE scheduled_tasks").WithArgs(int64(42)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE ftp_accounts.*WHERE id=ANY\(\$3\) AND updated_at<=\$4`).WithArgs("in_sync", "", "{17}", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
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
