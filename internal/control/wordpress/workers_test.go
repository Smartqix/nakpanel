package wordpress

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type wordpressSecretStore struct {
	deletedScope string
	deletedName  string
}

type recordingWordPressRiver struct {
	args []river.JobArgs
}

func (r *recordingWordPressRiver) InsertTx(_ context.Context, _ *sql.Tx, args river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	r.args = append(r.args, args)
	return &rivertype.JobInsertResult{}, nil
}

func (*wordpressSecretStore) PutSecretTx(context.Context, *sql.Tx, serveradmin.PutSecretParams) (serveradmin.SecretReference, error) {
	return serveradmin.SecretReference{}, nil
}

func (*wordpressSecretStore) GetSecret(context.Context, string, string) ([]byte, serveradmin.SecretReference, error) {
	return nil, serveradmin.SecretReference{}, nil
}

func (s *wordpressSecretStore) DeleteSecretTx(_ context.Context, _ *sql.Tx, scope, name string) error {
	s.deletedScope, s.deletedName = scope, name
	return nil
}

func TestWordPressFailureRedactsCredentials(t *testing.T) {
	credentials := &types.WordPressCredentials{DatabasePassword: "database-secret-value", AdminPassword: "admin-secret-value"}
	err := redactWordPressFailure(errors.New("database-secret-value and admin-secret-value\nfailed"), credentials)
	if strings.Contains(err.Error(), "database-secret-value") || strings.Contains(err.Error(), "admin-secret-value") || strings.ContainsAny(err.Error(), "\r\n") {
		t.Fatalf("redacted error leaked a credential: %q", err)
	}
}

func TestWordPressInventoryPresenceRequiresObservedCollection(t *testing.T) {
	if wordpressInventoryPresent(types.WordPressInventory{CoreVersion: "7.1"}) {
		t.Fatal("uncollected partial inventory was treated as authoritative")
	}
	if !wordpressInventoryPresent(types.WordPressInventory{CoreVersion: "7.1", CollectedAt: time.Now().UTC()}) {
		t.Fatal("collected inventory was ignored")
	}
}

func TestSuccessfulCredentialMutationRetiresRetrySecret(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(regexp.QuoteMeta("UPDATE wordpress_instances SET admin_secret_id=NULL,admin_secret_scope=NULL WHERE id=$1 AND admin_secret_id IS NOT NULL")).
		WithArgs(int64(7)).WillReturnResult(sqlmock.NewResult(0, 1))
	secrets := &wordpressSecretStore{}
	store := &SQLStore{secrets: secrets}
	if err = store.retireAdminSecret(context.Background(), tx, 7); err != nil {
		t.Fatal(err)
	}
	if secrets.deletedScope != "wordpress.instance.7" || secrets.deletedName != "admin" {
		t.Fatalf("deleted secret = %q/%q", secrets.deletedScope, secrets.deletedName)
	}
	mock.ExpectRollback()
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestWordPressUpdateRequiresCompletedBackup(t *testing.T) {
	loaded := loadedOperation{operation: Operation{Kind: types.WordPressActionUpdate}, backupStatus: "pending",
		identity: SiteIdentity{HostingMode: types.PHPHostingModeClassic}, policy: types.HostingPolicy{Permissions: types.HostingPermissionPolicy{WordPressToolkit: true}, Resources: types.HostingResourcePolicy{MaxWordPressSites: 1}},
		subscriptionStatus: "active", customerStatus: "active", siteStatus: "active", providerActive: true}
	if !errors.Is(loaded.validate(), errDependencyPending) {
		t.Fatalf("validate = %v, want pending dependency", loaded.validate())
	}
	loaded.backupStatus = "active"
	if err := loaded.validate(); err != nil {
		t.Fatalf("completed backup validation: %v", err)
	}
}

func TestWordPressInstallWaitsForSiteProvisioning(t *testing.T) {
	loaded := loadedOperation{
		operation:          Operation{Kind: types.WordPressActionInstall},
		identity:           SiteIdentity{HostingMode: types.PHPHostingModeClassic},
		policy:             types.HostingPolicy{Permissions: types.HostingPermissionPolicy{WordPressToolkit: true}, Resources: types.HostingResourcePolicy{MaxWordPressSites: 1}},
		subscriptionStatus: "active", customerStatus: "active", siteStatus: "active", providerActive: true,
		siteProvisionStatus: "pending", databaseStatus: "active",
	}
	if err := loaded.validate(); !errors.Is(err, errDependencyPending) {
		t.Fatalf("pending site validation = %v", err)
	}
	loaded.siteProvisionStatus = "failed"
	if err := loaded.validate(); err == nil || !strings.Contains(err.Error(), "site provisioning failed") {
		t.Fatalf("failed site validation = %v", err)
	}
	loaded.siteProvisionStatus = "active"
	if err := loaded.validate(); err != nil {
		t.Fatalf("active site validation = %v", err)
	}
}

func TestUninstallWorkerAllowsProviderCleanupWithoutLiveEntitlement(t *testing.T) {
	loaded := loadedOperation{
		instance:  Instance{ID: 3, SiteID: 7, SubscriptionID: 5, DatabaseManaged: false},
		operation: Operation{ID: 8, Kind: types.WordPressActionUninstall},
		identity:  SiteIdentity{SiteID: 7, SubscriptionID: 5, HostingMode: types.PHPHostingModeClassic},
		policy:    types.HostingPolicy{}, subscriptionStatus: "suspended", customerStatus: "suspended", siteStatus: "suspended",
	}
	if err := loaded.validate(); err != nil {
		t.Fatalf("provider cleanup validation = %v", err)
	}
}

func TestUninstallWorkerRequiresManagedDatabaseInBackupManifest(t *testing.T) {
	loaded := loadedOperation{
		instance:     Instance{ID: 3, SiteID: 7, SubscriptionID: 5, DatabaseID: 11, DatabaseManaged: true},
		operation:    Operation{ID: 8, Kind: types.WordPressActionUninstall, BackupID: 13, BackupRequested: true, DatabaseRemovalRequested: true},
		identity:     SiteIdentity{SiteID: 7, SubscriptionID: 5, HostingMode: types.PHPHostingModeClassic},
		databaseName: "wp_s7_deadbeef", databaseUser: "wp_u7_deadbeef", databaseStatus: "active",
		backupStatus: "active", backupSiteID: 7, backupSubscriptionID: 5, backupArchive: "/backup.tar.zst",
		backupChecksum: strings.Repeat("a", 64), backupSize: 4096, backupDatabases: []string{"other_database"},
	}
	if err := loaded.validate(); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("validate = %v, want backup manifest rejection", err)
	}
	loaded.backupDatabases = []string{"wp_s7_deadbeef"}
	if err := loaded.validate(); err != nil {
		t.Fatalf("covered managed database validation: %v", err)
	}
}

func TestUninstallOperationRequestContainsOnlyDerivedDatabaseIdentity(t *testing.T) {
	loaded := loadedOperation{
		instance:     Instance{ID: 3, SiteID: 7, SubscriptionID: 5, DesiredRevision: 9},
		operation:    Operation{ID: 8, Kind: types.WordPressActionUninstall, BackupID: 13, DatabaseRemovalRequested: true},
		identity:     SiteIdentity{SiteID: 7, SubscriptionID: 5, Username: "npdemo", Domain: "example.test", PHPVersion: "8.4", HostingMode: types.PHPHostingModeClassic},
		databaseName: "wp_s7_deadbeef", databaseUser: "wp_u7_deadbeef",
	}
	req := operationRequest(loaded)
	if req.Removal == nil || !req.Removal.DeleteDatabase || req.Removal.DatabaseName != "wp_s7_deadbeef" {
		t.Fatalf("request = %#v", req)
	}
	encoded, _ := json.Marshal(req)
	for _, forbidden := range []string{"password", "archive_path", "/home/"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("request exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestOperationRequestCarriesObservedTLSState(t *testing.T) {
	loaded := loadedOperation{
		instance:  Instance{ID: 3, SiteID: 7, SubscriptionID: 5},
		operation: Operation{ID: 8, Kind: types.WordPressActionInstall},
		identity:  SiteIdentity{Domain: "example.test", TLSActive: true},
	}
	if req := operationRequest(loaded); !req.Site.TLSActive {
		t.Fatal("agent request lost observed TLS state")
	}
}

func TestSweepRequeuesInterruptedRemoval(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	riverRecorder := &recordingWordPressRiver{}
	store := &SQLStore{db: db, river: riverRecorder}
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(interruptedUninstallSweepSQL)).
		WillReturnRows(sqlmock.NewRows([]string{"instance_id", "operation_id", "desired_revision"}).AddRow(int64(3), int64(8), int64(9)))
	mock.ExpectQuery("SELECT instance.id,instance.subscription_id,instance.desired_revision").
		WillReturnRows(sqlmock.NewRows([]string{"id", "subscription_id", "revision"}))
	mock.ExpectCommit()
	if err = store.EnqueueRefreshDue(context.Background(), time.Hour, 20); err != nil {
		t.Fatal(err)
	}
	if len(riverRecorder.args) != 1 {
		t.Fatalf("queued jobs = %d, want 1", len(riverRecorder.args))
	}
	args, ok := riverRecorder.args[0].(OperationArgs)
	if !ok || args.InstanceID != 3 || args.OperationID != 8 || args.DesiredRevision != 9 {
		t.Fatalf("queued args = %#v", riverRecorder.args[0])
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestWordPressDependencyWaitSnoozesWithoutConsumingRetryBudget(t *testing.T) {
	worker := NewOperationWorker(nil, nil)
	job := &river.Job[OperationArgs]{JobRow: &rivertype.JobRow{Attempt: 5, MaxAttempts: 5}}
	err := worker.fail(context.Background(), job, loadedOperation{}, errDependencyPending)
	var snooze *river.JobSnoozeError
	if !errors.As(err, &snooze) {
		t.Fatalf("fail error = %T %v, want JobSnoozeError", err, err)
	}
	if snooze.Duration != wordpressDependencyPollInterval {
		t.Fatalf("snooze duration = %s, want %s", snooze.Duration, wordpressDependencyPollInterval)
	}
	if snooze.Duration <= 0 || snooze.Duration > time.Minute {
		t.Fatalf("snooze duration = %s, want a bounded positive poll interval", snooze.Duration)
	}
}

func TestWordPressMaintenanceRequestUsesPersistedDesiredState(t *testing.T) {
	loaded := loadedOperation{
		instance:  Instance{ID: 3, SiteID: 4, SubscriptionID: 5, MaintenanceMode: false, DesiredRevision: 7},
		operation: Operation{ID: 8, Kind: types.WordPressActionMaintenance, Maintenance: false},
		identity:  SiteIdentity{SiteID: 4, SubscriptionID: 5, Username: "npdemo", Domain: "example.test", PHPVersion: "8.4", HostingMode: types.PHPHostingModeClassic},
		policy:    types.HostingPolicy{SchemaVersion: 4, Permissions: types.HostingPermissionPolicy{Hosting: true, WordPressToolkit: true}, Resources: types.HostingResourcePolicy{MaxWordPressSites: 1}},
	}
	req := operationRequest(loaded)
	if req.Maintenance {
		t.Fatalf("maintenance request toggled stale observed state instead of honoring desired false: %#v", req)
	}
}

func TestWordPressNotificationsUseCurrentSchemaAndResolve(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(regexp.QuoteMeta("WITH recipient AS (SELECT login_user_id,reseller_id,email FROM customers WHERE id=$1), upserted AS (")).
		WithArgs(int64(5), int64(3), "wordpress_operation_failed", "critical", "WordPress operation failed", "safe failure", "wordpress:7:operation-failed").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err = upsertWordPressNotificationTx(context.Background(), tx, 3, 5, "wordpress_operation_failed", "critical", "WordPress operation failed", "safe failure", wordpressNotificationKey(7, "operation-failed")); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(regexp.QuoteMeta("UPDATE notifications SET resolved_at=now(),updated_at=now() WHERE dedupe_key=$1 AND resolved_at IS NULL")).
		WithArgs("wordpress:7:operation-failed").WillReturnResult(sqlmock.NewResult(0, 1))
	if err = resolveWordPressNotificationTx(context.Background(), tx, wordpressNotificationKey(7, "operation-failed")); err != nil {
		t.Fatal(err)
	}
	mock.ExpectRollback()
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
