package wordpress

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type RiverInserter interface {
	InsertTx(context.Context, *sql.Tx, river.JobArgs, *river.InsertOpts) (*rivertype.JobInsertResult, error)
}

type SecretStore interface {
	PutSecretTx(context.Context, *sql.Tx, serveradmin.PutSecretParams) (serveradmin.SecretReference, error)
	GetSecret(context.Context, string, string) ([]byte, serveradmin.SecretReference, error)
	DeleteSecretTx(context.Context, *sql.Tx, string, string) error
}

type SQLStore struct {
	db      *sql.DB
	river   RiverInserter
	secrets SecretStore
}

const wordpressUsageCountSQL = `SELECT count(*) FROM wordpress_instances
WHERE subscription_id=$1 AND observed_state<>'removed' AND id<>$2
AND NOT (database_id IS NULL AND installed_version='' AND observed_state='failed' AND convergence_status='failed')`

func countWordPressUsage(ctx context.Context, tx *sql.Tx, subscriptionID, excludeInstanceID int64) (int, error) {
	var used int
	err := tx.QueryRowContext(ctx, wordpressUsageCountSQL, subscriptionID, excludeInstanceID).Scan(&used)
	return used, err
}

func NewSQLStore(db *sql.DB, riverClient RiverInserter, secrets SecretStore) *SQLStore {
	return &SQLStore{db: db, river: riverClient, secrets: secrets}
}

func (s *SQLStore) SetRiverClient(client RiverInserter) { s.river = client }

func (s *SQLStore) PreflightNewSite(ctx context.Context, subscriptionID int64) error {
	if s == nil || s.db == nil || subscriptionID <= 0 {
		return ErrNotFound
	}
	var subscriptionStatus, customerStatus string
	var providerActive bool
	err := s.db.QueryRowContext(ctx, `SELECT subscription.status,customer.status,
CASE WHEN customer.reseller_id IS NULL THEN TRUE ELSE EXISTS (
 SELECT 1 FROM reseller_accounts reseller JOIN reseller_subscriptions allocation
 ON allocation.reseller_id=reseller.id AND allocation.status='active'
 WHERE reseller.id=customer.reseller_id AND reseller.status='active') END
FROM subscriptions subscription JOIN customers customer ON customer.id=subscription.customer_id
WHERE subscription.id=$1`, subscriptionID).Scan(&subscriptionStatus, &customerStatus, &providerActive)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if subscriptionStatus != "active" || customerStatus != "active" || !providerActive {
		return ErrInactive
	}
	policy, err := controlquota.NewSQLStore(s.db).EffectiveSubscriptionPolicy(ctx, subscriptionID)
	if err != nil {
		return err
	}
	if !policy.Permissions.WordPressToolkit || policy.Resources.MaxWordPressSites == 0 {
		return ErrDisabled
	}
	var used int
	if err := s.db.QueryRowContext(ctx, wordpressUsageCountSQL, subscriptionID, int64(0)).Scan(&used); err != nil {
		return err
	}
	if policy.Resources.MaxWordPressSites >= 0 && used >= policy.Resources.MaxWordPressSites {
		return ErrLimitReached
	}
	if _, err := controlquota.CheckDatabaseForSubscription(ctx, controlquota.NewSQLStore(s.db), subscriptionID); err != nil {
		if errors.Is(err, controlquota.ErrExceeded) {
			return ErrDatabaseLimit
		}
		return err
	}
	return nil
}

func (s *SQLStore) SiteIdentity(ctx context.Context, siteID int64) (SiteIdentity, error) {
	if s == nil || s.db == nil || siteID <= 0 {
		return SiteIdentity{}, ErrNotFound
	}
	var item SiteIdentity
	err := s.db.QueryRowContext(ctx, `SELECT site.id,site.subscription_id,subscription.customer_id,
account.username,site.domain,application.php_version,application.hosting_mode
FROM sites site JOIN subscriptions subscription ON subscription.id=site.subscription_id
JOIN subscription_system_accounts account ON account.subscription_id=subscription.id
JOIN php_applications application ON application.site_id=site.id WHERE site.id=$1`, siteID).Scan(
		&item.SiteID, &item.SubscriptionID, &item.CustomerID, &item.Username,
		&item.Domain, &item.PHPVersion, &item.HostingMode,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return SiteIdentity{}, ErrNotFound
	}
	return item, err
}

func (s *SQLStore) Workspace(ctx context.Context, siteID int64) (Workspace, error) {
	if s == nil || s.db == nil {
		return Workspace{}, errors.New("WordPress database is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Workspace{}, err
	}
	defer tx.Rollback()
	policy, err := controlquota.EffectiveSitePolicyTx(ctx, tx, siteID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Workspace{}, ErrNotFound
		}
		return Workspace{}, err
	}
	workspace := Workspace{Policy: policy, LoadedAt: time.Now().UTC(), Available: true}
	var hostingMode types.PHPHostingMode
	var subscriptionStatus, customerStatus, siteStatus string
	var providerActive bool
	err = tx.QueryRowContext(ctx, siteLifecycleSQL, siteID).Scan(&hostingMode, &subscriptionStatus, &customerStatus, &siteStatus, &providerActive)
	if err != nil {
		return Workspace{}, err
	}
	switch {
	case hostingMode != types.PHPHostingModeClassic:
		workspace.Available, workspace.Reason = false, ErrNotClassic.Error()
	case !policy.Permissions.WordPressToolkit || policy.Resources.MaxWordPressSites == 0:
		workspace.Available, workspace.Reason = false, ErrDisabled.Error()
	case subscriptionStatus != "active" || customerStatus != "active" || siteStatus != "active" || !providerActive:
		workspace.Available, workspace.Reason = false, ErrInactive.Error()
	}
	instance, err := loadInstance(tx.QueryRowContext(ctx, instanceSelect+` WHERE instance.site_id=$1`, siteID))
	if errors.Is(err, sql.ErrNoRows) {
		if err = tx.Commit(); err != nil {
			return Workspace{}, err
		}
		return workspace, nil
	}
	if err != nil {
		return Workspace{}, err
	}
	if hiddenFailedReservation(instance) {
		workspace.Reason = instance.LastError
		if err = tx.Commit(); err != nil {
			return Workspace{}, err
		}
		return workspace, nil
	}
	workspace.Instance = &instance
	workspace.Operations, err = loadOperations(ctx, tx, instance.ID, 100)
	if err != nil {
		return Workspace{}, err
	}
	if err = tx.Commit(); err != nil {
		return Workspace{}, err
	}
	return workspace, nil
}

const siteLifecycleSQL = `SELECT application.hosting_mode,subscription.status,customer.status,site.desired_status,
CASE WHEN customer.reseller_id IS NULL THEN TRUE ELSE EXISTS (
 SELECT 1 FROM reseller_accounts reseller JOIN reseller_subscriptions allocation
 ON allocation.reseller_id=reseller.id AND allocation.status='active'
 WHERE reseller.id=customer.reseller_id AND reseller.status='active') END
FROM sites site JOIN subscriptions subscription ON subscription.id=site.subscription_id
JOIN customers customer ON customer.id=subscription.customer_id
JOIN php_applications application ON application.site_id=site.id WHERE site.id=$1`

func (s *SQLStore) lockAndValidateSite(ctx context.Context, tx *sql.Tx, identity SiteIdentity) (types.HostingPolicy, error) {
	if err := controlquota.LockSubscriptionMutationTx(ctx, tx, identity.SubscriptionID); err != nil {
		return types.HostingPolicy{}, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('nakpanel:wordpress-site:' || $1::bigint::text,0))`, identity.SiteID); err != nil {
		return types.HostingPolicy{}, err
	}
	var hostingMode types.PHPHostingMode
	var subscriptionStatus, customerStatus, siteStatus string
	var providerActive bool
	if err := tx.QueryRowContext(ctx, siteLifecycleSQL+` FOR SHARE OF site,subscription,customer,application`, identity.SiteID).
		Scan(&hostingMode, &subscriptionStatus, &customerStatus, &siteStatus, &providerActive); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return types.HostingPolicy{}, ErrNotFound
		}
		return types.HostingPolicy{}, err
	}
	if hostingMode != types.PHPHostingModeClassic {
		return types.HostingPolicy{}, ErrNotClassic
	}
	if subscriptionStatus != "active" || customerStatus != "active" || siteStatus != "active" || !providerActive {
		return types.HostingPolicy{}, ErrInactive
	}
	policy, err := controlquota.EffectiveSitePolicyTx(ctx, tx, identity.SiteID)
	if err != nil {
		return types.HostingPolicy{}, err
	}
	if !policy.Permissions.WordPressToolkit || policy.Resources.MaxWordPressSites == 0 {
		return types.HostingPolicy{}, ErrDisabled
	}
	return policy, nil
}

func (s *SQLStore) ReserveInstall(ctx context.Context, actorID int64, identity SiteIdentity, input InstallInput) (Instance, Operation, error) {
	if s == nil || s.db == nil || s.river == nil || s.secrets == nil {
		return Instance{}, Operation{}, errors.New("WordPress persistence is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Instance{}, Operation{}, err
	}
	defer tx.Rollback()
	policy, err := s.lockAndValidateSite(ctx, tx, identity)
	if err != nil {
		return Instance{}, Operation{}, err
	}
	instance, loadErr := loadInstance(tx.QueryRowContext(ctx, instanceSelect+` WHERE instance.site_id=$1 FOR UPDATE OF instance`, identity.SiteID))
	if errors.Is(loadErr, sql.ErrNoRows) {
		used, usageErr := countWordPressUsage(ctx, tx, identity.SubscriptionID, 0)
		if usageErr != nil {
			return Instance{}, Operation{}, usageErr
		}
		if policy.Resources.MaxWordPressSites >= 0 && used >= policy.Resources.MaxWordPressSites {
			return Instance{}, Operation{}, ErrLimitReached
		}
		err = tx.QueryRowContext(ctx, `INSERT INTO wordpress_instances(subscription_id,site_id,admin_user,admin_email,site_title)
VALUES($1,$2,$3,$4,$5) RETURNING id,subscription_id,site_id,admin_user,admin_email,site_title,
desired_state,observed_state,desired_revision,applied_revision,convergence_status,created_at,updated_at`,
			identity.SubscriptionID, identity.SiteID, input.AdminUser, input.AdminEmail, input.Title).Scan(
			&instance.ID, &instance.SubscriptionID, &instance.SiteID, &instance.AdminUser, &instance.AdminEmail,
			&instance.SiteTitle, &instance.DesiredState, &instance.ObservedState, &instance.DesiredRevision,
			&instance.AppliedRevision, &instance.ConvergenceStatus, &instance.CreatedAt, &instance.UpdatedAt)
	} else if loadErr != nil {
		return Instance{}, Operation{}, loadErr
	} else if !reusableForInstall(instance) {
		return Instance{}, Operation{}, ErrBusy
	} else {
		used, usageErr := countWordPressUsage(ctx, tx, identity.SubscriptionID, instance.ID)
		if usageErr != nil {
			return Instance{}, Operation{}, usageErr
		}
		if policy.Resources.MaxWordPressSites >= 0 && used >= policy.Resources.MaxWordPressSites {
			return Instance{}, Operation{}, ErrLimitReached
		}
		var busy bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM wordpress_operations WHERE instance_id=$1 AND status IN ('pending','waiting_backup','running'))`, instance.ID).Scan(&busy); err != nil {
			return Instance{}, Operation{}, err
		}
		if busy {
			return Instance{}, Operation{}, ErrBusy
		}
		instance.AdminUser, instance.AdminEmail, instance.SiteTitle = input.AdminUser, input.AdminEmail, input.Title
		instance.DesiredState, instance.ObservedState, instance.ConvergenceStatus = "present", "pending", "pending"
		instance.DesiredRevision++
		_, err = tx.ExecContext(ctx, `UPDATE wordpress_instances SET admin_user=$2,admin_email=$3,site_title=$4,
database_id=NULL,database_managed=false,installed_version='',maintenance_mode=false,inventory='{}',plugins='[]',themes='[]',security='{}',
checksum_status='unknown',desired_state='present',observed_state='pending',desired_revision=$5,convergence_status='pending',last_error='',last_scanned_at=NULL,updated_at=now()
WHERE id=$1`, instance.ID, instance.AdminUser, instance.AdminEmail, instance.SiteTitle, instance.DesiredRevision)
	}
	if err != nil {
		return Instance{}, Operation{}, err
	}
	var operation Operation
	err = tx.QueryRowContext(ctx, `INSERT INTO wordpress_operations(subscription_id,instance_id,requested_by_user_id,kind,requested_version,desired_revision)
VALUES($1,$2,NULLIF($3,0),'install',$4,$5) RETURNING id,subscription_id,instance_id,
COALESCE(requested_by_user_id,0),kind,target_type,target_slug,requested_version,COALESCE(backup_id,0),desired_revision,status,created_at`,
		identity.SubscriptionID, instance.ID, actorID, input.Version, instance.DesiredRevision).Scan(
		&operation.ID, &operation.SubscriptionID, &operation.InstanceID, &operation.RequestedByUserID,
		&operation.Kind, &operation.TargetType, &operation.TargetSlug, &operation.RequestedVersion,
		&operation.BackupID, &operation.DesiredRevision, &operation.Status, &operation.CreatedAt)
	if err != nil {
		return Instance{}, Operation{}, err
	}
	if err = auditWordPressTx(ctx, tx, actorID, identity.CustomerID, identity.SubscriptionID, "wordpress.install.requested", instance.ID, map[string]any{"site_id": identity.SiteID}); err != nil {
		return Instance{}, Operation{}, err
	}
	if err = tx.Commit(); err != nil {
		return Instance{}, Operation{}, err
	}
	return instance, operation, nil
}

func hiddenFailedReservation(instance Instance) bool {
	return instance.ID > 0 && instance.DatabaseID == 0 && instance.InstalledVersion == "" &&
		instance.ObservedState == "failed" && instance.ConvergenceStatus == "failed"
}

func reusableForInstall(instance Instance) bool {
	return hiddenFailedReservation(instance) || (instance.ID > 0 && instance.ObservedState == "removed")
}

func retryableInstall(instance Instance) bool {
	return instance.ID > 0 && instance.DatabaseID > 0 && instance.InstalledVersion == "" &&
		instance.ObservedState == "failed" && instance.ConvergenceStatus == "failed"
}

func wordpressSecretScope(instanceID int64) string {
	return fmt.Sprintf("wordpress.instance.%d", instanceID)
}

func (s *SQLStore) CompleteInstallReservation(ctx context.Context, instanceID, operationID, databaseID int64, adminPassword string) error {
	if s == nil || s.db == nil || s.river == nil || s.secrets == nil {
		return errors.New("WordPress persistence is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var subscriptionID, revision, actorID int64
	err = tx.QueryRowContext(ctx, `SELECT instance.subscription_id,instance.desired_revision,COALESCE(operation.requested_by_user_id,0)
FROM wordpress_instances instance JOIN wordpress_operations operation ON operation.instance_id=instance.id
WHERE instance.id=$1 AND operation.id=$2 AND operation.status='pending' FOR UPDATE OF instance,operation`, instanceID, operationID).
		Scan(&subscriptionID, &revision, &actorID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBusy
	}
	if err != nil {
		return err
	}
	reference, err := s.secrets.PutSecretTx(ctx, tx, serveradmin.PutSecretParams{
		Scope: wordpressSecretScope(instanceID), Name: "admin", Plaintext: []byte(adminPassword),
		Metadata: []byte(fmt.Sprintf(`{"wordpress_instance_id":%d}`, instanceID)), ActorUserID: actorID,
	})
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE wordpress_instances SET database_id=$2,database_managed=true,admin_secret_id=$3,
admin_secret_scope=$4,updated_at=now() WHERE id=$1 AND subscription_id=$5`,
		instanceID, databaseID, reference.ID, reference.Scope, subscriptionID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrNotFound
	}
	if _, err = s.river.InsertTx(ctx, tx, OperationArgs{InstanceID: instanceID, OperationID: operationID, DesiredRevision: revision}, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) FailReservation(ctx context.Context, instanceID, operationID int64, cause error) error {
	message := boundedError(cause)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE wordpress_operations SET status='failed',last_error=$3,finished_at=now()
WHERE id=$1 AND instance_id=$2 AND status IN ('pending','waiting_backup','running')`, operationID, instanceID, message); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE wordpress_instances SET observed_state='failed',convergence_status='failed',last_error=$2,updated_at=now() WHERE id=$1`, instanceID, message); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) ReserveUninstall(ctx context.Context, actor auth.SessionUser, identity SiteIdentity, input UninstallInput) (Instance, Operation, error) {
	if s == nil || s.db == nil || s.river == nil {
		return Instance{}, Operation{}, errors.New("WordPress persistence is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Instance{}, Operation{}, err
	}
	defer tx.Rollback()
	if err = controlquota.LockSubscriptionMutationTx(ctx, tx, identity.SubscriptionID); err != nil {
		return Instance{}, Operation{}, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('nakpanel:wordpress-site:' || $1::bigint::text,0))`, identity.SiteID); err != nil {
		return Instance{}, Operation{}, err
	}
	var hostingMode types.PHPHostingMode
	var subscriptionStatus, customerStatus, siteStatus string
	var providerActive bool
	if err = tx.QueryRowContext(ctx, siteLifecycleSQL+` FOR SHARE OF site,subscription,customer,application`, identity.SiteID).
		Scan(&hostingMode, &subscriptionStatus, &customerStatus, &siteStatus, &providerActive); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Instance{}, Operation{}, ErrNotFound
		}
		return Instance{}, Operation{}, err
	}
	if hostingMode != types.PHPHostingModeClassic {
		return Instance{}, Operation{}, ErrNotClassic
	}
	if actor.Role == auth.RoleClient && (subscriptionStatus != "active" || customerStatus != "active" || siteStatus != "active" || !providerActive) {
		return Instance{}, Operation{}, ErrInactive
	}
	instance, err := loadInstance(tx.QueryRowContext(ctx, instanceSelect+` WHERE instance.site_id=$1 FOR UPDATE OF instance`, identity.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, Operation{}, ErrNotFound
	}
	if err != nil {
		return Instance{}, Operation{}, err
	}
	if instance.InstalledVersion == "" || instance.ObservedState == "removed" {
		return Instance{}, Operation{}, ErrNotFound
	}
	var busy bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM wordpress_operations WHERE instance_id=$1 AND status IN ('pending','waiting_backup','running'))`, instance.ID).Scan(&busy); err != nil {
		return Instance{}, Operation{}, err
	}
	if busy {
		return Instance{}, Operation{}, ErrBusy
	}
	if input.DeleteDatabase {
		if !instance.DatabaseManaged || instance.DatabaseID <= 0 {
			return Instance{}, Operation{}, ErrInvalidInput
		}
		var databaseID int64
		if err = tx.QueryRowContext(ctx, `SELECT id FROM databases WHERE id=$1 AND subscription_id=$2 AND site_id=$3 FOR UPDATE`,
			instance.DatabaseID, identity.SubscriptionID, identity.SiteID).Scan(&databaseID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return Instance{}, Operation{}, ErrInvalidInput
			}
			return Instance{}, Operation{}, err
		}
	}
	instance.DesiredRevision++
	if _, err = tx.ExecContext(ctx, `UPDATE wordpress_instances SET desired_state='absent',observed_state='removing',
desired_revision=$2,convergence_status='pending',last_error='',updated_at=now() WHERE id=$1`, instance.ID, instance.DesiredRevision); err != nil {
		return Instance{}, Operation{}, err
	}
	status := "pending"
	if input.CreateBackup {
		status = "waiting_backup"
	}
	var operation Operation
	err = tx.QueryRowContext(ctx, `INSERT INTO wordpress_operations(subscription_id,instance_id,requested_by_user_id,kind,
backup_requested,database_removal_requested,desired_revision,status)
VALUES($1,$2,NULLIF($3,0),'uninstall',$4,$5,$6,$7)
RETURNING id,subscription_id,instance_id,COALESCE(requested_by_user_id,0),kind,backup_requested,
database_removal_requested,COALESCE(backup_id,0),desired_revision,status,created_at`,
		identity.SubscriptionID, instance.ID, actor.ID, input.CreateBackup, input.DeleteDatabase, instance.DesiredRevision, status).Scan(
		&operation.ID, &operation.SubscriptionID, &operation.InstanceID, &operation.RequestedByUserID, &operation.Kind,
		&operation.BackupRequested, &operation.DatabaseRemovalRequested, &operation.BackupID,
		&operation.DesiredRevision, &operation.Status, &operation.CreatedAt)
	if err != nil {
		return Instance{}, Operation{}, err
	}
	if !input.CreateBackup {
		if _, err = s.river.InsertTx(ctx, tx, OperationArgs{InstanceID: instance.ID, OperationID: operation.ID, DesiredRevision: instance.DesiredRevision}, nil); err != nil {
			return Instance{}, Operation{}, err
		}
	}
	if err = auditWordPressTx(ctx, tx, actor.ID, identity.CustomerID, identity.SubscriptionID, "wordpress.uninstall.requested", instance.ID,
		map[string]any{"site_id": identity.SiteID, "backup_requested": input.CreateBackup, "database_removal_requested": input.DeleteDatabase}); err != nil {
		return Instance{}, Operation{}, err
	}
	if err = tx.Commit(); err != nil {
		return Instance{}, Operation{}, err
	}
	instance.DesiredState, instance.ObservedState, instance.ConvergenceStatus = "absent", "removing", "pending"
	return instance, operation, nil
}

func (s *SQLStore) FailUninstallReservation(ctx context.Context, instanceID, operationID int64, cause error) error {
	if s == nil || s.db == nil {
		return errors.New("WordPress persistence is unavailable")
	}
	message := boundedError(cause)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE wordpress_operations SET status='failed',last_error=$3,finished_at=now()
WHERE id=$1 AND instance_id=$2 AND kind='uninstall' AND status='waiting_backup'`, operationID, instanceID, message)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrBusy
	}
	if _, err = tx.ExecContext(ctx, `UPDATE wordpress_instances SET desired_state='present',observed_state='healthy',
applied_revision=desired_revision,convergence_status='in_sync',last_error='',updated_at=now() WHERE id=$1 AND desired_state='absent'`, instanceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) ReserveOperation(ctx context.Context, actorID int64, identity SiteIdentity, input OperationInput) (Instance, Operation, error) {
	if s == nil || s.db == nil || s.river == nil {
		return Instance{}, Operation{}, errors.New("WordPress persistence is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Instance{}, Operation{}, err
	}
	defer tx.Rollback()
	policy, err := s.lockAndValidateSite(ctx, tx, identity)
	if err != nil {
		return Instance{}, Operation{}, err
	}
	instance, err := loadInstance(tx.QueryRowContext(ctx, instanceSelect+` WHERE instance.site_id=$1 FOR UPDATE OF instance`, identity.SiteID))
	if errors.Is(err, sql.ErrNoRows) && input.Action == types.WordPressActionDiscover {
		used, usageErr := countWordPressUsage(ctx, tx, identity.SubscriptionID, 0)
		if usageErr != nil {
			return Instance{}, Operation{}, usageErr
		}
		if policy.Resources.MaxWordPressSites >= 0 && used >= policy.Resources.MaxWordPressSites {
			return Instance{}, Operation{}, ErrLimitReached
		}
		err = tx.QueryRowContext(ctx, `INSERT INTO wordpress_instances(subscription_id,site_id)
VALUES($1,$2) RETURNING id,subscription_id,site_id,admin_user,admin_email,site_title,desired_state,
observed_state,desired_revision,applied_revision,convergence_status,created_at,updated_at`, identity.SubscriptionID, identity.SiteID).Scan(
			&instance.ID, &instance.SubscriptionID, &instance.SiteID, &instance.AdminUser, &instance.AdminEmail,
			&instance.SiteTitle, &instance.DesiredState, &instance.ObservedState, &instance.DesiredRevision,
			&instance.AppliedRevision, &instance.ConvergenceStatus, &instance.CreatedAt, &instance.UpdatedAt)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, Operation{}, ErrNotFound
	}
	if err != nil {
		return Instance{}, Operation{}, err
	}
	var busy bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM wordpress_operations WHERE instance_id=$1 AND status IN ('pending','waiting_backup','running'))`, instance.ID).Scan(&busy); err != nil {
		return Instance{}, Operation{}, err
	}
	if busy {
		return Instance{}, Operation{}, ErrBusy
	}
	if input.Action == types.WordPressActionDiscover && reusableForInstall(instance) {
		used, usageErr := countWordPressUsage(ctx, tx, identity.SubscriptionID, instance.ID)
		if usageErr != nil {
			return Instance{}, Operation{}, usageErr
		}
		if policy.Resources.MaxWordPressSites >= 0 && used >= policy.Resources.MaxWordPressSites {
			return Instance{}, Operation{}, ErrLimitReached
		}
	}
	if input.Action == types.WordPressActionInstall {
		if !retryableInstall(instance) {
			return Instance{}, Operation{}, ErrBusy
		}
		if err = tx.QueryRowContext(ctx, `SELECT requested_version FROM wordpress_operations
WHERE instance_id=$1 AND kind='install' AND requested_version<>'' ORDER BY id DESC LIMIT 1`, instance.ID).Scan(&input.RequestedVersion); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return Instance{}, Operation{}, ErrBusy
			}
			return Instance{}, Operation{}, err
		}
	} else if input.Action != types.WordPressActionDiscover && instance.InstalledVersion == "" {
		return Instance{}, Operation{}, ErrNotFound
	}
	instance.DesiredRevision++
	if _, err = tx.ExecContext(ctx, `UPDATE wordpress_instances SET desired_revision=$2,convergence_status='pending',last_error='',updated_at=now() WHERE id=$1`, instance.ID, instance.DesiredRevision); err != nil {
		return Instance{}, Operation{}, err
	}
	status := "pending"
	if input.Action == types.WordPressActionUpdate {
		status = "waiting_backup"
	}
	var operation Operation
	err = tx.QueryRowContext(ctx, `INSERT INTO wordpress_operations(subscription_id,instance_id,requested_by_user_id,kind,target_type,target_slug,
	requested_version,maintenance_enabled,desired_revision,status) VALUES($1,$2,NULLIF($3,0),$4,$5,$6,$7,$8,$9,$10)
	RETURNING id,subscription_id,instance_id,COALESCE(requested_by_user_id,0),kind,target_type,target_slug,
	requested_version,maintenance_enabled,COALESCE(backup_id,0),desired_revision,status,created_at`, identity.SubscriptionID, instance.ID,
		actorID, input.Action, input.TargetType, input.TargetSlug, input.RequestedVersion, input.Maintenance, instance.DesiredRevision, status).Scan(
		&operation.ID, &operation.SubscriptionID, &operation.InstanceID, &operation.RequestedByUserID,
		&operation.Kind, &operation.TargetType, &operation.TargetSlug, &operation.RequestedVersion,
		&operation.Maintenance, &operation.BackupID, &operation.DesiredRevision, &operation.Status, &operation.CreatedAt)
	if err != nil {
		return Instance{}, Operation{}, err
	}
	if input.Action == types.WordPressActionPasswordReset {
		if s.secrets == nil {
			return Instance{}, Operation{}, errors.New("WordPress secret store is unavailable")
		}
		if _, err = s.secrets.PutSecretTx(ctx, tx, serveradmin.PutSecretParams{Scope: wordpressSecretScope(instance.ID), Name: "admin",
			Plaintext: []byte(input.AdminPassword), Metadata: []byte(fmt.Sprintf(`{"wordpress_instance_id":%d}`, instance.ID)), ActorUserID: actorID}); err != nil {
			return Instance{}, Operation{}, err
		}
	}
	if input.Action != types.WordPressActionUpdate {
		if _, err = s.river.InsertTx(ctx, tx, OperationArgs{InstanceID: instance.ID, OperationID: operation.ID, DesiredRevision: instance.DesiredRevision}, nil); err != nil {
			return Instance{}, Operation{}, err
		}
	}
	if err = auditWordPressTx(ctx, tx, actorID, identity.CustomerID, identity.SubscriptionID, "wordpress."+string(input.Action)+".requested", instance.ID, map[string]any{"site_id": identity.SiteID}); err != nil {
		return Instance{}, Operation{}, err
	}
	if err = tx.Commit(); err != nil {
		return Instance{}, Operation{}, err
	}
	return instance, operation, nil
}

func (s *SQLStore) AttachBackupAndEnqueue(ctx context.Context, operationID, backupID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var instanceID, revision int64
	err = tx.QueryRowContext(ctx, `UPDATE wordpress_operations SET backup_id=$2 WHERE id=$1 AND status='waiting_backup'
RETURNING instance_id,desired_revision`, operationID, backupID).Scan(&instanceID, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBusy
	}
	if err != nil {
		return err
	}
	if _, err = s.river.InsertTx(ctx, tx, OperationArgs{InstanceID: instanceID, OperationID: operationID, DesiredRevision: revision}, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) Detach(ctx context.Context, actorID int64, identity SiteIdentity) error {
	if s == nil || s.db == nil || s.secrets == nil {
		return errors.New("WordPress persistence is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = s.lockAndValidateSite(ctx, tx, identity); err != nil {
		return err
	}
	var instanceID int64
	var secretScope sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT id,admin_secret_scope FROM wordpress_instances WHERE site_id=$1 FOR UPDATE`, identity.SiteID).Scan(&instanceID, &secretScope)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var busy bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM wordpress_operations WHERE instance_id=$1 AND status IN ('pending','waiting_backup','running'))`, instanceID).Scan(&busy); err != nil {
		return err
	}
	if busy {
		return ErrBusy
	}
	if err = auditWordPressTx(ctx, tx, actorID, identity.CustomerID, identity.SubscriptionID, "wordpress.detached", instanceID, map[string]any{"site_id": identity.SiteID, "files_deleted": false, "database_deleted": false}); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM wordpress_instances WHERE id=$1 AND subscription_id=$2`, instanceID, identity.SubscriptionID); err != nil {
		return err
	}
	if secretScope.Valid {
		if err = s.secrets.DeleteSecretTx(ctx, tx, secretScope.String, "admin"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const instanceSelect = `SELECT instance.id,instance.subscription_id,instance.site_id,COALESCE(instance.database_id,0),
instance.admin_user,instance.admin_email,instance.site_title,instance.installed_version,instance.update_policy,
	instance.maintenance_mode,instance.database_managed,instance.inventory,instance.security,instance.checksum_status,instance.desired_state,
instance.observed_state,instance.desired_revision,instance.applied_revision,instance.convergence_status,
instance.last_error,instance.last_scanned_at,instance.created_at,instance.updated_at FROM wordpress_instances instance`

func loadInstance(row interface{ Scan(...any) error }) (Instance, error) {
	var item Instance
	var inventoryJSON, securityJSON []byte
	var scannedAt sql.NullTime
	err := row.Scan(&item.ID, &item.SubscriptionID, &item.SiteID, &item.DatabaseID, &item.AdminUser,
		&item.AdminEmail, &item.SiteTitle, &item.InstalledVersion, &item.UpdatePolicy, &item.MaintenanceMode,
		&item.DatabaseManaged, &inventoryJSON, &securityJSON, &item.ChecksumStatus, &item.DesiredState, &item.ObservedState,
		&item.DesiredRevision, &item.AppliedRevision, &item.ConvergenceStatus, &item.LastError,
		&scannedAt, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return item, err
	}
	if err = json.Unmarshal(inventoryJSON, &item.Inventory); err != nil {
		return item, err
	}
	if err = json.Unmarshal(securityJSON, &item.Security); err != nil {
		return item, err
	}
	if scannedAt.Valid {
		item.LastScannedAt = scannedAt.Time
	}
	return item, nil
}

func loadOperations(ctx context.Context, tx *sql.Tx, instanceID int64, limit int) ([]Operation, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,subscription_id,instance_id,COALESCE(requested_by_user_id,0),kind,
target_type,target_slug,requested_version,backup_requested,database_removal_requested,COALESCE(backup_id,0),desired_revision,status,result,output,last_error,
started_at,finished_at,created_at FROM wordpress_operations WHERE instance_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2`, instanceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Operation, 0)
	for rows.Next() {
		var item Operation
		var resultJSON []byte
		var started, finished sql.NullTime
		if err = rows.Scan(&item.ID, &item.SubscriptionID, &item.InstanceID, &item.RequestedByUserID, &item.Kind,
			&item.TargetType, &item.TargetSlug, &item.RequestedVersion, &item.BackupRequested,
			&item.DatabaseRemovalRequested, &item.BackupID, &item.DesiredRevision,
			&item.Status, &resultJSON, &item.Output, &item.LastError, &started, &finished, &item.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(resultJSON, &item.Result)
		if started.Valid {
			item.StartedAt = started.Time
		}
		if finished.Valid {
			item.FinishedAt = finished.Time
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func auditWordPressTx(ctx context.Context, tx *sql.Tx, actorID, customerID, subscriptionID int64, action string, targetID int64, metadata map[string]any) error {
	payload, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,actor_label,customer_id,subscription_id,action,target_type,target_id,metadata)
VALUES(NULLIF($1,0),CASE WHEN $1=0 THEN 'wordpress-worker' ELSE NULL END,NULLIF($2,0),NULLIF($3,0),$4,'wordpress_instance',$5,$6)`,
		actorID, customerID, subscriptionID, action, targetID, payload)
	return err
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		if r < 32 {
			return -1
		}
		return r
	}, err.Error())
	if len(value) > 1000 {
		value = value[:1000]
	}
	return value
}
