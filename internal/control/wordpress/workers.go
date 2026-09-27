package wordpress

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type Agent interface {
	RunWordPress(context.Context, types.WordPressOperationReq) (types.WordPressOperationResult, error)
}

type loadedOperation struct {
	instance                                                            Instance
	operation                                                           Operation
	identity                                                            SiteIdentity
	policy                                                              types.HostingPolicy
	customerID                                                          int64
	databaseName, databaseUser                                          string
	databaseStatus, backupStatus                                        string
	backupArchive, backupChecksum                                       string
	backupSize, backupSiteID, backupSubscriptionID                      int64
	backupDatabases                                                     []string
	subscriptionStatus, customerStatus, siteStatus, siteProvisionStatus string
	providerActive                                                      bool
}

var workerLocks sync.Map

func lockWorker(instanceID int64) func() {
	value, _ := workerLocks.LoadOrStore(instanceID, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	return lock.Unlock
}

func (s *SQLStore) loadForWorker(ctx context.Context, args OperationArgs) (loadedOperation, bool, error) {
	var loaded loadedOperation
	if s == nil || s.db == nil {
		return loaded, false, errors.New("WordPress database is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return loaded, false, err
	}
	defer tx.Rollback()
	var inventoryJSON, securityJSON, resultJSON []byte
	var backupDatabases pq.StringArray
	var scannedAt, startedAt, finishedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT
instance.id,instance.subscription_id,instance.site_id,COALESCE(instance.database_id,0),
instance.admin_user,instance.admin_email,instance.site_title,instance.installed_version,instance.update_policy,
instance.maintenance_mode,instance.database_managed,instance.inventory,instance.security,instance.checksum_status,instance.desired_state,
instance.observed_state,instance.desired_revision,instance.applied_revision,instance.convergence_status,
instance.last_error,instance.last_scanned_at,instance.created_at,instance.updated_at,
operation.id,operation.subscription_id,operation.instance_id,COALESCE(operation.requested_by_user_id,0),operation.kind,
operation.target_type,operation.target_slug,operation.requested_version,operation.maintenance_enabled,
operation.backup_requested,operation.database_removal_requested,COALESCE(operation.backup_id,0),
operation.desired_revision,operation.status,operation.result,operation.output,operation.last_error,
operation.started_at,operation.finished_at,operation.created_at,
subscription.customer_id,account.username,site.domain,application.php_version,application.hosting_mode,(site.tls_status='active'),
COALESCE(database.db_name,''),COALESCE(database.db_user,''),COALESCE(database.status,''),
COALESCE(backup.status,''),COALESCE(backup.archive_path,''),COALESCE(backup.checksum_sha256,''),COALESCE(backup.size_bytes,0),
COALESCE(backup.site_id,0),COALESCE(backup.subscription_id,0),COALESCE(backup.database_names,'{}'::text[]),
subscription.status,customer.status,site.desired_status,site.status,
CASE WHEN customer.reseller_id IS NULL THEN TRUE ELSE EXISTS (
 SELECT 1 FROM reseller_accounts reseller JOIN reseller_subscriptions allocation
 ON allocation.reseller_id=reseller.id AND allocation.status='active'
 WHERE reseller.id=customer.reseller_id AND reseller.status='active') END
FROM wordpress_instances instance
JOIN wordpress_operations operation ON operation.instance_id=instance.id
JOIN sites site ON site.id=instance.site_id
JOIN subscriptions subscription ON subscription.id=instance.subscription_id
JOIN customers customer ON customer.id=subscription.customer_id
JOIN subscription_system_accounts account ON account.subscription_id=subscription.id
JOIN php_applications application ON application.site_id=site.id
LEFT JOIN databases database ON database.id=instance.database_id
LEFT JOIN backups backup ON backup.id=operation.backup_id
WHERE instance.id=$1 AND operation.id=$2`, args.InstanceID, args.OperationID).Scan(
		&loaded.instance.ID, &loaded.instance.SubscriptionID, &loaded.instance.SiteID, &loaded.instance.DatabaseID,
		&loaded.instance.AdminUser, &loaded.instance.AdminEmail, &loaded.instance.SiteTitle,
		&loaded.instance.InstalledVersion, &loaded.instance.UpdatePolicy, &loaded.instance.MaintenanceMode, &loaded.instance.DatabaseManaged,
		&inventoryJSON, &securityJSON, &loaded.instance.ChecksumStatus, &loaded.instance.DesiredState,
		&loaded.instance.ObservedState, &loaded.instance.DesiredRevision, &loaded.instance.AppliedRevision,
		&loaded.instance.ConvergenceStatus, &loaded.instance.LastError, &scannedAt,
		&loaded.instance.CreatedAt, &loaded.instance.UpdatedAt,
		&loaded.operation.ID, &loaded.operation.SubscriptionID, &loaded.operation.InstanceID,
		&loaded.operation.RequestedByUserID, &loaded.operation.Kind, &loaded.operation.TargetType,
		&loaded.operation.TargetSlug, &loaded.operation.RequestedVersion, &loaded.operation.Maintenance,
		&loaded.operation.BackupRequested, &loaded.operation.DatabaseRemovalRequested, &loaded.operation.BackupID,
		&loaded.operation.DesiredRevision, &loaded.operation.Status, &resultJSON, &loaded.operation.Output,
		&loaded.operation.LastError, &startedAt, &finishedAt, &loaded.operation.CreatedAt,
		&loaded.customerID, &loaded.identity.Username, &loaded.identity.Domain, &loaded.identity.PHPVersion,
		&loaded.identity.HostingMode, &loaded.identity.TLSActive, &loaded.databaseName, &loaded.databaseUser, &loaded.databaseStatus,
		&loaded.backupStatus, &loaded.backupArchive, &loaded.backupChecksum, &loaded.backupSize,
		&loaded.backupSiteID, &loaded.backupSubscriptionID, &backupDatabases,
		&loaded.subscriptionStatus, &loaded.customerStatus, &loaded.siteStatus, &loaded.siteProvisionStatus, &loaded.providerActive)
	if errors.Is(err, sql.ErrNoRows) {
		return loaded, true, nil
	}
	if err != nil {
		return loaded, false, err
	}
	loaded.identity.SiteID, loaded.identity.SubscriptionID, loaded.identity.CustomerID = loaded.instance.SiteID, loaded.instance.SubscriptionID, loaded.customerID
	loaded.backupDatabases = append([]string(nil), backupDatabases...)
	if loaded.instance.DesiredRevision != args.DesiredRevision || loaded.operation.DesiredRevision != args.DesiredRevision || loaded.operation.Status == "succeeded" || loaded.operation.Status == "cancelled" {
		return loaded, true, nil
	}
	_ = json.Unmarshal(inventoryJSON, &loaded.instance.Inventory)
	_ = json.Unmarshal(securityJSON, &loaded.instance.Security)
	_ = json.Unmarshal(resultJSON, &loaded.operation.Result)
	if scannedAt.Valid {
		loaded.instance.LastScannedAt = scannedAt.Time
	}
	if startedAt.Valid {
		loaded.operation.StartedAt = startedAt.Time
	}
	if finishedAt.Valid {
		loaded.operation.FinishedAt = finishedAt.Time
	}
	if loaded.operation.Kind != types.WordPressActionUninstall {
		loaded.policy, err = controlquota.EffectiveSitePolicyTx(ctx, tx, loaded.instance.SiteID)
		if err != nil {
			return loaded, false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return loaded, false, err
	}
	return loaded, false, nil
}

func (loaded loadedOperation) validate() error {
	if loaded.identity.HostingMode != types.PHPHostingModeClassic {
		return ErrNotClassic
	}
	if loaded.operation.Kind == types.WordPressActionUninstall {
		if loaded.operation.BackupRequested {
			switch loaded.backupStatus {
			case "active":
			case "failed":
				return errors.New("WordPress safety backup failed")
			default:
				return errDependencyPending
			}
			if loaded.operation.BackupID <= 0 || loaded.backupSiteID != loaded.instance.SiteID ||
				loaded.backupSubscriptionID != loaded.instance.SubscriptionID || loaded.backupArchive == "" ||
				loaded.backupChecksum == "" || loaded.backupSize <= 0 {
				return errors.New("WordPress safety backup is incomplete or belongs to another site")
			}
		}
		if loaded.operation.DatabaseRemovalRequested {
			if !loaded.operation.BackupRequested || !loaded.instance.DatabaseManaged || loaded.instance.DatabaseID <= 0 ||
				loaded.databaseStatus != "active" || !stringSliceContains(loaded.backupDatabases, loaded.databaseName) {
				return errors.New("WordPress managed database is not covered by the backup manifest")
			}
		}
		return nil
	}
	if !loaded.policy.Permissions.WordPressToolkit || loaded.policy.Resources.MaxWordPressSites == 0 {
		return ErrDisabled
	}
	if loaded.subscriptionStatus != "active" || loaded.customerStatus != "active" || loaded.siteStatus != "active" || !loaded.providerActive {
		return ErrInactive
	}
	if loaded.operation.Kind == types.WordPressActionInstall {
		switch loaded.siteProvisionStatus {
		case "active":
		case "failed":
			return errors.New("WordPress site provisioning failed")
		default:
			return errDependencyPending
		}
		switch loaded.databaseStatus {
		case "active":
		case "failed":
			return errors.New("WordPress database provisioning failed")
		default:
			return errDependencyPending
		}
	}
	if loaded.operation.Kind == types.WordPressActionUpdate {
		switch loaded.backupStatus {
		case "active":
		case "failed":
			return errors.New("WordPress safety backup failed")
		default:
			return errDependencyPending
		}
	}
	return nil
}

var errDependencyPending = errors.New("WordPress operation dependency is still pending")

const wordpressDependencyPollInterval = 15 * time.Second

type OperationWorker struct {
	river.WorkerDefaults[OperationArgs]
	store *SQLStore
	agent Agent
}

func NewOperationWorker(store *SQLStore, agent Agent) *OperationWorker {
	return &OperationWorker{store: store, agent: agent}
}

func (w *OperationWorker) Work(ctx context.Context, job *river.Job[OperationArgs]) error {
	unlock := lockWorker(job.Args.InstanceID)
	defer unlock()
	loaded, stale, err := w.store.loadForWorker(ctx, job.Args)
	if stale {
		return nil
	}
	if err != nil {
		return w.fail(ctx, job, loaded, err)
	}
	if err = loaded.validate(); err != nil {
		return w.fail(ctx, job, loaded, err)
	}
	if w.agent == nil {
		return w.fail(ctx, job, loaded, errors.New("WordPress agent is unavailable"))
	}
	claimed, err := w.store.markRunning(ctx, job.Args)
	if err != nil || !claimed {
		return err
	}
	req := operationRequest(loaded)
	credentials, err := w.credentials(ctx, loaded)
	if err != nil {
		return w.fail(ctx, job, loaded, err)
	}
	if credentials != nil {
		req.Credentials = credentials
		defer clearWordPressCredentials(credentials)
	}
	result, err := w.agent.RunWordPress(ctx, req)
	if err != nil {
		return w.fail(ctx, job, loaded, redactWordPressFailure(err, credentials))
	}
	if result.Action != loaded.operation.Kind {
		return w.fail(ctx, job, loaded, errors.New("agent returned an invalid WordPress result"))
	}
	if err = w.store.completeOperation(ctx, loaded, result); err != nil {
		return err
	}
	return nil
}

func operationRequest(loaded loadedOperation) types.WordPressOperationReq {
	req := types.WordPressOperationReq{
		OperationID: loaded.operation.ID, Action: loaded.operation.Kind,
		TargetType: loaded.operation.TargetType, TargetSlug: loaded.operation.TargetSlug,
		RequestedVersion: loaded.operation.RequestedVersion,
		Maintenance:      loaded.operation.Maintenance,
		Site: types.WordPressSiteSpec{InstanceID: loaded.instance.ID, SubscriptionID: loaded.instance.SubscriptionID,
			SiteID: loaded.instance.SiteID, DesiredRevision: loaded.instance.DesiredRevision,
			Username: loaded.identity.Username, Domain: loaded.identity.Domain, PHPVersion: loaded.identity.PHPVersion,
			TLSActive:   loaded.identity.TLSActive,
			HostingMode: loaded.identity.HostingMode, Policy: loaded.policy},
	}
	if loaded.operation.Kind == types.WordPressActionUninstall {
		req.Removal = &types.WordPressRemovalSpec{
			DeleteDatabase: loaded.operation.DatabaseRemovalRequested,
			DatabaseName:   loaded.databaseName,
			DatabaseUser:   loaded.databaseUser,
		}
	}
	return req
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (w *OperationWorker) credentials(ctx context.Context, loaded loadedOperation) (*types.WordPressCredentials, error) {
	if loaded.operation.Kind != types.WordPressActionInstall && loaded.operation.Kind != types.WordPressActionPasswordReset {
		return nil, nil
	}
	if w.store.secrets == nil {
		return nil, errors.New("WordPress secret store is unavailable")
	}
	adminPassword, _, err := w.store.secrets.GetSecret(ctx, wordpressSecretScope(loaded.instance.ID), "admin")
	if err != nil {
		return nil, err
	}
	credentials := &types.WordPressCredentials{AdminUser: loaded.instance.AdminUser, AdminEmail: loaded.instance.AdminEmail,
		AdminPassword: string(adminPassword), SiteTitle: loaded.instance.SiteTitle}
	clear(adminPassword)
	if loaded.operation.Kind == types.WordPressActionInstall {
		databasePassword, _, loadErr := w.store.secrets.GetSecret(ctx, "database", fmt.Sprintf("provision-%d", loaded.instance.DatabaseID))
		if loadErr != nil {
			clearWordPressCredentials(credentials)
			return nil, loadErr
		}
		credentials.DatabaseName, credentials.DatabaseUser, credentials.DatabasePassword = loaded.databaseName, loaded.databaseUser, string(databasePassword)
		clear(databasePassword)
	}
	return credentials, nil
}

func clearWordPressCredentials(value *types.WordPressCredentials) {
	if value == nil {
		return
	}
	value.DatabasePassword, value.AdminPassword = "", ""
}

func redactWordPressFailure(err error, credentials *types.WordPressCredentials) error {
	message := boundedError(err)
	if credentials != nil {
		for _, secret := range []string{credentials.DatabasePassword, credentials.AdminPassword} {
			if secret != "" {
				message = strings.ReplaceAll(message, secret, "[redacted]")
			}
		}
	}
	return errors.New(message)
}

func finalAttempt(job *river.Job[OperationArgs]) bool {
	return job != nil && job.JobRow != nil && job.MaxAttempts > 0 && job.Attempt >= job.MaxAttempts
}

func terminalError(err error) bool {
	return errors.Is(err, ErrDisabled) || errors.Is(err, ErrInactive) || errors.Is(err, ErrNotClassic) ||
		strings.Contains(err.Error(), "failed") || strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "invalid")
}

func (w *OperationWorker) fail(ctx context.Context, job *river.Job[OperationArgs], loaded loadedOperation, cause error) error {
	if errors.Is(cause, errDependencyPending) {
		return river.JobSnooze(wordpressDependencyPollInterval)
	}
	terminal := terminalError(cause) || finalAttempt(job)
	if terminal && w.store != nil {
		if err := w.store.failOperation(ctx, job.Args, loaded, cause); err != nil {
			return errors.Join(cause, err)
		}
		return river.JobCancel(cause)
	}
	return cause
}

func (s *SQLStore) markRunning(ctx context.Context, args OperationArgs) (bool, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE wordpress_operations SET status='running',started_at=COALESCE(started_at,now()),last_error=''
WHERE id=$1 AND instance_id=$2 AND desired_revision=$3 AND status IN ('pending','waiting_backup','running')`, args.OperationID, args.InstanceID, args.DesiredRevision)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func (s *SQLStore) completeOperation(ctx context.Context, loaded loadedOperation, result types.WordPressOperationResult) error {
	if loaded.operation.Kind == types.WordPressActionUninstall {
		return s.completeUninstallOperation(ctx, loaded, result)
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return err
	}
	inventoryJSON, err := json.Marshal(result.Inventory)
	if err != nil {
		return err
	}
	securityJSON, err := json.Marshal(result.Security)
	if err != nil {
		return err
	}
	output := boundedError(errors.New(result.Output))
	if result.Output == "" {
		output = ""
	}
	hasInventory := wordpressInventoryPresent(result.Inventory)
	checksum := "unknown"
	if result.Security.CoreChecksumsValid {
		checksum = "valid"
	} else if len(result.Security.Findings) > 0 {
		checksum = "failed"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var customerID int64
	err = tx.QueryRowContext(ctx, `SELECT subscription.customer_id FROM wordpress_instances instance
JOIN subscriptions subscription ON subscription.id=instance.subscription_id WHERE instance.id=$1 FOR UPDATE OF instance`, loaded.instance.ID).Scan(&customerID)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE wordpress_operations SET status='succeeded',result=$4,output=$5,last_error='',finished_at=now()
WHERE id=$1 AND instance_id=$2 AND desired_revision=$3 AND status='running'`, loaded.operation.ID, loaded.instance.ID, loaded.instance.DesiredRevision, resultJSON, output); err != nil {
		return err
	}
	maintenance := loaded.instance.MaintenanceMode
	if loaded.operation.Kind == types.WordPressActionMaintenance {
		maintenance = loaded.operation.Maintenance
	}
	version := result.Inventory.CoreVersion
	if version == "" {
		version = loaded.instance.InstalledVersion
	}
	if _, err = tx.ExecContext(ctx, `UPDATE wordpress_instances SET installed_version=$2,maintenance_mode=$3,
inventory=CASE WHEN $11 THEN $4::jsonb ELSE inventory END,
plugins=CASE WHEN $11 THEN COALESCE($4::jsonb->'plugins','[]'::jsonb) ELSE plugins END,
themes=CASE WHEN $11 THEN COALESCE($4::jsonb->'themes','[]'::jsonb) ELSE themes END,
security=CASE WHEN $5::jsonb='{}'::jsonb THEN security ELSE $5::jsonb END,checksum_status=$6,
observed_state='healthy',applied_revision=$7,convergence_status='in_sync',last_error='',
admin_user=CASE WHEN $8='' THEN admin_user ELSE $8 END,
admin_email=CASE WHEN $9='' THEN admin_email ELSE $9 END,
site_title=CASE WHEN $10='' THEN site_title ELSE $10 END,
last_scanned_at=CASE WHEN $11 THEN now() ELSE last_scanned_at END,updated_at=now()
WHERE id=$1 AND desired_revision=$7`, loaded.instance.ID, version, maintenance, inventoryJSON, securityJSON, checksum,
		loaded.instance.DesiredRevision, result.Inventory.AdminUser, result.Inventory.AdminEmail, result.Inventory.SiteTitle, hasInventory); err != nil {
		return err
	}
	if loaded.operation.Kind == types.WordPressActionInstall || loaded.operation.Kind == types.WordPressActionPasswordReset {
		if err = s.retireAdminSecret(ctx, tx, loaded.instance.ID); err != nil {
			return err
		}
	}
	if err = auditWordPressTx(ctx, tx, 0, customerID, loaded.instance.SubscriptionID, "wordpress."+string(loaded.operation.Kind)+".succeeded", loaded.instance.ID, map[string]any{"operation_id": loaded.operation.ID}); err != nil {
		return err
	}
	if err = resolveWordPressNotificationTx(ctx, tx, wordpressNotificationKey(loaded.instance.ID, "operation-failed")); err != nil {
		return err
	}
	if !result.Security.CoreChecksumsValid || len(result.Security.Findings) > 0 {
		message := "WordPress security checks need attention."
		if len(result.Security.Findings) > 0 {
			message = strings.Join(result.Security.Findings, "; ")
		}
		if err = upsertWordPressNotificationTx(ctx, tx, loaded.instance.SubscriptionID, customerID, "wordpress_security_failed", "critical", "WordPress security checks failed", message, wordpressNotificationKey(loaded.instance.ID, "security")); err != nil {
			return err
		}
	} else if err = resolveWordPressNotificationTx(ctx, tx, wordpressNotificationKey(loaded.instance.ID, "security")); err != nil {
		return err
	}
	if result.Inventory.UpdatesAvailable > 0 {
		message := fmt.Sprintf("%d WordPress update(s) are available.", result.Inventory.UpdatesAvailable)
		if err = upsertWordPressNotificationTx(ctx, tx, loaded.instance.SubscriptionID, customerID, "wordpress_update_available", "warning", "WordPress updates available", message, wordpressNotificationKey(loaded.instance.ID, "updates")); err != nil {
			return err
		}
	} else if err = resolveWordPressNotificationTx(ctx, tx, wordpressNotificationKey(loaded.instance.ID, "updates")); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) completeUninstallOperation(ctx context.Context, loaded loadedOperation, result types.WordPressOperationResult) error {
	if result.Removal == nil || !result.Removal.FilesRemoved {
		return errors.New("agent did not confirm WordPress file removal")
	}
	if loaded.operation.DatabaseRemovalRequested && !result.Removal.DatabaseRemoved {
		return errors.New("agent did not confirm WordPress database removal")
	}
	result.Removal.BackupID = loaded.operation.BackupID
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return err
	}
	output := boundedError(errors.New(result.Output))
	if result.Output == "" {
		output = ""
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var customerID, databaseID int64
	var secretScope string
	err = tx.QueryRowContext(ctx, `SELECT subscription.customer_id,COALESCE(instance.database_id,0),COALESCE(instance.admin_secret_scope,'')
FROM wordpress_instances instance JOIN subscriptions subscription ON subscription.id=instance.subscription_id
WHERE instance.id=$1 AND instance.desired_revision=$2 AND instance.desired_state='absent' FOR UPDATE OF instance`,
		loaded.instance.ID, loaded.instance.DesiredRevision).Scan(&customerID, &databaseID, &secretScope)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBusy
	}
	if err != nil {
		return err
	}
	operationResult, err := tx.ExecContext(ctx, `UPDATE wordpress_operations SET status='succeeded',result=$4,output=$5,last_error='',finished_at=now()
WHERE id=$1 AND instance_id=$2 AND desired_revision=$3 AND status='running'`,
		loaded.operation.ID, loaded.instance.ID, loaded.instance.DesiredRevision, resultJSON, output)
	if err != nil {
		return err
	}
	if affected, _ := operationResult.RowsAffected(); affected != 1 {
		return ErrBusy
	}
	if _, err = tx.ExecContext(ctx, `UPDATE wordpress_instances SET database_id=NULL,database_managed=false,
admin_secret_id=NULL,admin_secret_scope=NULL,admin_user='',admin_email='',site_title='',installed_version='',
maintenance_mode=false,inventory='{}',plugins='[]',themes='[]',security='{}',checksum_status='unknown',
observed_state='removed',applied_revision=$2,convergence_status='in_sync',last_error='',last_scanned_at=NULL,updated_at=now()
WHERE id=$1 AND desired_revision=$2`, loaded.instance.ID, loaded.instance.DesiredRevision); err != nil {
		return err
	}
	if loaded.operation.DatabaseRemovalRequested {
		if databaseID <= 0 || databaseID != loaded.instance.DatabaseID {
			return errors.New("managed WordPress database changed during removal")
		}
		databaseResult, deleteErr := tx.ExecContext(ctx, `DELETE FROM databases WHERE id=$1 AND subscription_id=$2 AND site_id=$3`,
			databaseID, loaded.instance.SubscriptionID, loaded.instance.SiteID)
		if deleteErr != nil {
			return deleteErr
		}
		if affected, _ := databaseResult.RowsAffected(); affected != 1 {
			return errors.New("managed WordPress database intent was not removed")
		}
		if s.secrets == nil {
			return errors.New("WordPress secret store is unavailable")
		}
		if err = s.secrets.DeleteSecretTx(ctx, tx, "database", fmt.Sprintf("provision-%d", databaseID)); err != nil {
			return err
		}
	}
	if secretScope != "" {
		if s.secrets == nil {
			return errors.New("WordPress secret store is unavailable")
		}
		if err = s.secrets.DeleteSecretTx(ctx, tx, secretScope, "admin"); err != nil {
			return err
		}
	}
	for _, key := range []string{"operation-failed", "security", "updates"} {
		if err = resolveWordPressNotificationTx(ctx, tx, wordpressNotificationKey(loaded.instance.ID, key)); err != nil {
			return err
		}
	}
	if err = auditWordPressTx(ctx, tx, 0, customerID, loaded.instance.SubscriptionID, "wordpress.uninstall.completed", loaded.instance.ID,
		map[string]any{"operation_id": loaded.operation.ID, "backup_id": loaded.operation.BackupID,
			"database_removed": loaded.operation.DatabaseRemovalRequested}); err != nil {
		return err
	}
	if s.river == nil {
		return errors.New("WordPress cleanup queue is unavailable")
	}
	if _, err = s.river.InsertTx(ctx, tx, CleanupRemovalArgs{
		InstanceID: loaded.instance.ID, OperationID: loaded.operation.ID, DesiredRevision: loaded.instance.DesiredRevision,
	}, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func wordpressInventoryPresent(inventory types.WordPressInventory) bool {
	return !inventory.CollectedAt.IsZero()
}

func (s *SQLStore) retireAdminSecret(ctx context.Context, tx *sql.Tx, instanceID int64) error {
	if s == nil || s.secrets == nil || tx == nil || instanceID <= 0 {
		return errors.New("WordPress secret store is unavailable")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE wordpress_instances SET admin_secret_id=NULL,admin_secret_scope=NULL WHERE id=$1 AND admin_secret_id IS NOT NULL`, instanceID); err != nil {
		return err
	}
	return s.secrets.DeleteSecretTx(ctx, tx, wordpressSecretScope(instanceID), "admin")
}

func (s *SQLStore) failOperation(ctx context.Context, args OperationArgs, loaded loadedOperation, cause error) error {
	message := boundedError(cause)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE wordpress_operations SET status='failed',last_error=$4,finished_at=now()
WHERE id=$1 AND instance_id=$2 AND desired_revision=$3 AND status IN ('pending','waiting_backup','running')`, args.OperationID, args.InstanceID, args.DesiredRevision, message); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE wordpress_instances SET observed_state='failed',convergence_status='failed',last_error=$3,updated_at=now()
WHERE id=$1 AND desired_revision=$2`, args.InstanceID, args.DesiredRevision, message); err != nil {
		return err
	}
	if loaded.customerID > 0 {
		if err = upsertWordPressNotificationTx(ctx, tx, loaded.instance.SubscriptionID, loaded.customerID,
			"wordpress_operation_failed", "critical", "WordPress operation failed", message,
			wordpressNotificationKey(args.InstanceID, "operation-failed")); err != nil {
			return err
		}
		if err = auditWordPressTx(ctx, tx, 0, loaded.customerID, loaded.instance.SubscriptionID, "wordpress.operation.failed", args.InstanceID, map[string]any{"operation_id": args.OperationID, "error": message}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func wordpressNotificationKey(instanceID int64, kind string) string {
	return fmt.Sprintf("wordpress:%d:%s", instanceID, kind)
}

func upsertWordPressNotificationTx(ctx context.Context, tx *sql.Tx, subscriptionID, customerID int64, kind, severity, title, body, key string) error {
	_, err := tx.ExecContext(ctx, `WITH recipient AS (SELECT login_user_id,reseller_id,email FROM customers WHERE id=$1), upserted AS (
INSERT INTO notifications(recipient_user_id,customer_id,reseller_id,subscription_id,kind,severity,title,body,dedupe_key)
SELECT login_user_id,$1,reseller_id,$2,$3,$4,$5,$6,$7 FROM recipient
ON CONFLICT(dedupe_key) WHERE resolved_at IS NULL DO UPDATE SET severity=EXCLUDED.severity,title=EXCLUDED.title,body=EXCLUDED.body,updated_at=now()
RETURNING id) INSERT INTO notification_deliveries(notification_id,channel,recipient)
SELECT upserted.id,'smtp',recipient.email FROM upserted CROSS JOIN recipient WHERE recipient.email<>''
ON CONFLICT(notification_id,channel,recipient) DO NOTHING`, customerID, subscriptionID, kind, severity, title, boundedError(errors.New(body)), key)
	return err
}

func resolveWordPressNotificationTx(ctx context.Context, tx *sql.Tx, key string) error {
	_, err := tx.ExecContext(ctx, `UPDATE notifications SET resolved_at=now(),updated_at=now() WHERE dedupe_key=$1 AND resolved_at IS NULL`, key)
	return err
}

type SweepWorker struct {
	river.WorkerDefaults[SweepArgs]
	store *SQLStore
}

type CleanupRemovalWorker struct {
	river.WorkerDefaults[CleanupRemovalArgs]
	store *SQLStore
	agent Agent
}

func NewCleanupRemovalWorker(store *SQLStore, agent Agent) *CleanupRemovalWorker {
	return &CleanupRemovalWorker{store: store, agent: agent}
}

func (w *CleanupRemovalWorker) Work(ctx context.Context, job *river.Job[CleanupRemovalArgs]) error {
	if w == nil || w.store == nil || w.store.db == nil || w.agent == nil {
		return errors.New("WordPress removal cleanup is unavailable")
	}
	var req types.WordPressOperationReq
	err := w.store.db.QueryRowContext(ctx, `SELECT instance.id,instance.subscription_id,instance.site_id,instance.desired_revision,
operation.id,account.username,site.domain,application.php_version,application.hosting_mode
FROM wordpress_instances instance JOIN wordpress_operations operation ON operation.instance_id=instance.id
JOIN sites site ON site.id=instance.site_id
JOIN subscription_system_accounts account ON account.subscription_id=instance.subscription_id
JOIN php_applications application ON application.site_id=site.id
WHERE instance.id=$1 AND operation.id=$2 AND instance.desired_revision=$3
AND operation.desired_revision=$3 AND instance.desired_state='absent' AND instance.observed_state='removed'
AND operation.kind='uninstall' AND operation.status='succeeded'`,
		job.Args.InstanceID, job.Args.OperationID, job.Args.DesiredRevision).Scan(
		&req.Site.InstanceID, &req.Site.SubscriptionID, &req.Site.SiteID, &req.Site.DesiredRevision,
		&req.OperationID, &req.Site.Username, &req.Site.Domain, &req.Site.PHPVersion, &req.Site.HostingMode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	req.Action = types.WordPressActionUninstall
	req.Removal = &types.WordPressRemovalSpec{Finalize: true}
	result, err := w.agent.RunWordPress(ctx, req)
	if err != nil {
		return err
	}
	if result.Action != types.WordPressActionUninstall || result.Removal == nil || !result.Removal.FilesRemoved {
		return errors.New("agent returned an invalid WordPress cleanup result")
	}
	return nil
}

func NewSweepWorker(store *SQLStore) *SweepWorker { return &SweepWorker{store: store} }

func (w *SweepWorker) Work(ctx context.Context, _ *river.Job[SweepArgs]) error {
	return w.store.EnqueueRefreshDue(ctx, 6*time.Hour, 200)
}

const interruptedUninstallSweepSQL = `SELECT instance.id,operation.id,instance.desired_revision
FROM wordpress_instances instance
JOIN LATERAL (
    SELECT id,desired_revision,status FROM wordpress_operations
    WHERE instance_id=instance.id AND kind='uninstall'
    ORDER BY id DESC LIMIT 1
) operation ON operation.desired_revision=instance.desired_revision
WHERE instance.desired_state='absent'
  AND instance.observed_state IN ('removing','failed')
  AND operation.status IN ('pending','waiting_backup','running')
  AND NOT EXISTS (
      SELECT 1 FROM river_job
      WHERE kind='wordpress_operation'
        AND state IN ('available','pending','retryable','running','scheduled')
        AND args->>'instance_id'=instance.id::text
        AND args->>'desired_revision'=instance.desired_revision::text
  )
FOR UPDATE OF instance SKIP LOCKED`

func (s *SQLStore) enqueueInterruptedUninstallsTx(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, interruptedUninstallSweepSQL)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := make([]OperationArgs, 0)
	for rows.Next() {
		var item OperationArgs
		if err = rows.Scan(&item.InstanceID, &item.OperationID, &item.DesiredRevision); err != nil {
			return err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, item := range items {
		if _, err = s.river.InsertTx(ctx, tx, item, nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLStore) EnqueueRefreshDue(ctx context.Context, staleAfter time.Duration, limit int) error {
	if s == nil || s.db == nil || s.river == nil {
		return errors.New("WordPress sweep is unavailable")
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.enqueueInterruptedUninstallsTx(ctx, tx); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT instance.id,instance.subscription_id,instance.desired_revision
FROM wordpress_instances instance WHERE instance.desired_state='present' AND instance.observed_state='healthy'
AND (instance.last_scanned_at IS NULL OR instance.last_scanned_at < $1)
AND NOT EXISTS(SELECT 1 FROM wordpress_operations operation WHERE operation.instance_id=instance.id AND operation.status IN ('pending','waiting_backup','running'))
ORDER BY instance.last_scanned_at NULLS FIRST,instance.id LIMIT $2 FOR UPDATE OF instance SKIP LOCKED`, time.Now().UTC().Add(-staleAfter), limit)
	if err != nil {
		return err
	}
	type due struct{ id, subscriptionID, revision int64 }
	items := make([]due, 0)
	for rows.Next() {
		var item due
		if err = rows.Scan(&item.id, &item.subscriptionID, &item.revision); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, item := range items {
		item.revision++
		if _, err = tx.ExecContext(ctx, `UPDATE wordpress_instances SET desired_revision=$2,convergence_status='pending',updated_at=now() WHERE id=$1`, item.id, item.revision); err != nil {
			return err
		}
		var operationID int64
		if err = tx.QueryRowContext(ctx, `INSERT INTO wordpress_operations(subscription_id,instance_id,kind,desired_revision)
VALUES($1,$2,'refresh',$3) RETURNING id`, item.subscriptionID, item.id, item.revision).Scan(&operationID); err != nil {
			return err
		}
		if _, err = s.river.InsertTx(ctx, tx, OperationArgs{InstanceID: item.id, OperationID: operationID, DesiredRevision: item.revision}, nil); err != nil {
			return err
		}
	}
	return tx.Commit()
}
