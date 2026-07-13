package maintenance

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type deleteAgent struct {
	calls    []types.DeleteBackupReq
	response types.Response
	err      error
}

func (a *deleteAgent) DeleteBackup(_ context.Context, req types.DeleteBackupReq) (types.Response, error) {
	a.calls = append(a.calls, req)
	return a.response, a.err
}

func TestMaintenanceArgsUseIsolatedQueue(t *testing.T) {
	args := []interface{ InsertOpts() river.InsertOpts }{RenewCertsArgs{}, ScheduledBackupsArgs{Window: "2026-07-12"}, PruneBackupsArgs{}, PruneSiteArgs{SiteID: 1}, DeleteBackupArgs{BackupID: 1}, ReconcileArgs{Scope: "system"}}
	for _, arg := range args {
		opts := arg.InsertOpts()
		if opts.Queue != Queue {
			t.Fatalf("%T queue=%q, want %q", arg, opts.Queue, Queue)
		}
		if !opts.UniqueOpts.ByArgs {
			t.Fatalf("%T is not unique by args", arg)
		}
	}
}

func TestDeleteBackupUsesTrackedRowPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	agent := &deleteAgent{response: types.Response{OK: true, Data: json.RawMessage(`{"deleted":true}`)}}
	service := NewService(db, nil, agent)
	mock.ExpectQuery("SELECT id FROM users").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(99)))
	mock.ExpectQuery("UPDATE backups backup SET status='deleting'").WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"archive_path", "customer_id", "subscription_id"}).AddRow("/var/lib/nakpanel/backups/site.tar.gz", int64(2), int64(3)))
	mock.ExpectBegin()
	mock.ExpectExec("DELETE FROM backups").WithArgs(int64(7)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO audit_events").WithArgs(int64(99), int64(2), int64(3), "backup.deleted", "backup", int64(7), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	if err = service.deleteBackup(context.Background(), 7); err != nil {
		t.Fatalf("deleteBackup error: %v", err)
	}
	if len(agent.calls) != 1 || agent.calls[0].ArchivePath != "/var/lib/nakpanel/backups/site.tar.gz" {
		t.Fatalf("agent calls=%#v", agent.calls)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteBackupCannotReachAgentWithoutTrackedRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	agent := &deleteAgent{}
	service := NewService(db, nil, agent)
	mock.ExpectQuery("SELECT id FROM users").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(99)))
	mock.ExpectQuery("UPDATE backups backup SET status='deleting'").WithArgs(int64(404)).WillReturnRows(sqlmock.NewRows([]string{"archive_path", "customer_id", "subscription_id"}))
	if err = service.deleteBackup(context.Background(), 404); err != nil {
		t.Fatalf("deleteBackup error: %v", err)
	}
	if len(agent.calls) != 0 {
		t.Fatalf("agent was called with %#v", agent.calls)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAutomatedFailureCreatesNotificationDeliveryAndAudit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service := NewService(db, nil, nil)
	mock.ExpectBegin()
	mock.ExpectExec("WITH recipient AS").WithArgs(int64(2), int64(3), "Certificate renewal failed", "acme failed", "maintenance:cert:7").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO audit_events").WithArgs(int64(99), int64(2), int64(3), "certificate.renew_failed", "site", int64(7), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	err = service.ReportCertificate(context.Background(), provision.IssueCertArgs{SiteID: 7, CustomerID: 2, SubscriptionID: 3, ActorUserID: 99, Automated: true}, errors.New("acme failed"))
	if err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
