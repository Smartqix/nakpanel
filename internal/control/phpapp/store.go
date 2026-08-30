package phpapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

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
	DeleteSecretTx(context.Context, *sql.Tx, string, string) error
	GetSecret(context.Context, string, string) ([]byte, serveradmin.SecretReference, error)
}

const rollbackTargetSelect = deploymentSelect + ` WHERE deployment.id=$1 AND deployment.application_id=$2
AND deployment.resolved_revision<>'' AND deployment.status IN ('healthy','retired') FOR UPDATE`

type SQLStore struct {
	db      *sql.DB
	river   RiverInserter
	secrets SecretStore
}

func NewSQLStore(db *sql.DB, riverClient RiverInserter, secrets SecretStore) *SQLStore {
	return &SQLStore{db: db, river: riverClient, secrets: secrets}
}

func (s *SQLStore) SetRiverClient(client RiverInserter) { s.river = client }

func (s *SQLStore) SiteIdentity(ctx context.Context, siteID int64) (SiteIdentity, error) {
	if s == nil || s.db == nil || siteID <= 0 {
		return SiteIdentity{}, ErrNotFound
	}
	var identity SiteIdentity
	err := s.db.QueryRowContext(ctx, `SELECT site.id,application.id,site.subscription_id,subscription.customer_id,site.domain,application.php_version
FROM sites site JOIN subscriptions subscription ON subscription.id=site.subscription_id
JOIN php_applications application ON application.site_id=site.id WHERE site.id=$1`, siteID).Scan(
		&identity.ID, &identity.ApplicationID, &identity.SubscriptionID, &identity.CustomerID, &identity.Domain, &identity.PHPVersion,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return SiteIdentity{}, ErrNotFound
	}
	return identity, err
}

type applicationRecord struct {
	spec                 types.PHPApplicationSpec
	customerID           int64
	observedState        string
	convergenceStatus    string
	observedMessage      string
	lastError            string
	activeDeploymentID   int64
	previousDeploymentID int64
	appliedRevision      int64
	subscriptionStatus   string
	customerStatus       string
	siteStatus           string
	providerActive       bool
}

func lifecycleState(record applicationRecord) LifecycleState {
	return LifecycleState{
		SubscriptionStatus: record.subscriptionStatus,
		CustomerStatus:     record.customerStatus,
		SiteStatus:         record.siteStatus,
		ProviderActive:     record.providerActive,
	}
}

func scanApplication(row interface{ Scan(...any) error }) (applicationRecord, error) {
	var record applicationRecord
	var shared []byte
	err := row.Scan(
		&record.spec.ApplicationID, &record.spec.SubscriptionID, &record.spec.SiteID,
		&record.customerID, &record.spec.Username, &record.spec.Domain,
		&record.spec.HostingMode, &record.spec.PHPVersion, &record.spec.RepositoryID,
		&record.spec.RepositoryRef, &record.spec.FrameworkProfile, &record.spec.PublicPath,
		&record.spec.HealthPath, &shared, &record.spec.Composer.Install,
		&record.spec.Composer.AllowScripts, &record.spec.Composer.AllowPlugins,
		&record.spec.ReleaseRetention, &record.spec.DesiredState, &record.observedState,
		&record.activeDeploymentID, &record.previousDeploymentID,
		&record.spec.DesiredRevision, &record.appliedRevision, &record.convergenceStatus,
		&record.observedMessage, &record.lastError, &record.subscriptionStatus,
		&record.customerStatus, &record.siteStatus, &record.providerActive,
	)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(shared, &record.spec.SharedPaths); err != nil {
		return record, fmt.Errorf("decode PHP application shared paths: %w", err)
	}
	return record, nil
}

const applicationSelect = `SELECT application.id,application.subscription_id,application.site_id,
subscription.customer_id,account.username,site.domain,application.hosting_mode,application.php_version,
COALESCE(application.repository_id,0),application.repository_ref,application.framework_profile,
application.public_path,application.health_path,application.shared_paths,application.composer_install,
application.composer_allow_scripts,application.composer_allow_plugins,application.release_retention,
application.desired_state,application.observed_state,COALESCE(application.active_deployment_id,0),
COALESCE(application.previous_deployment_id,0),application.desired_revision,application.applied_revision,
application.convergence_status,application.observed_message,application.last_error,subscription.status,
customer.status,site.desired_status,
CASE WHEN customer.reseller_id IS NULL THEN TRUE ELSE EXISTS (
 SELECT 1 FROM reseller_accounts reseller JOIN reseller_subscriptions allocation
 ON allocation.reseller_id=reseller.id AND allocation.status='active'
 WHERE reseller.id=customer.reseller_id AND reseller.status='active') END
FROM php_applications application
JOIN sites site ON site.id=application.site_id
JOIN subscriptions subscription ON subscription.id=application.subscription_id
JOIN customers customer ON customer.id=subscription.customer_id
JOIN subscription_system_accounts account ON account.subscription_id=application.subscription_id `

func (s *SQLStore) Workspace(ctx context.Context, siteID int64) (Workspace, error) {
	if s == nil || s.db == nil {
		return Workspace{}, errors.New("PHP application database is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Workspace{}, err
	}
	defer tx.Rollback()
	record, err := scanApplication(tx.QueryRowContext(ctx, applicationSelect+` WHERE site.id=$1`, siteID))
	if errors.Is(err, sql.ErrNoRows) {
		return Workspace{}, ErrNotFound
	}
	if err != nil {
		return Workspace{}, err
	}
	record.spec.Policy, err = controlquota.EffectiveSitePolicyTx(ctx, tx, siteID)
	if err != nil {
		return Workspace{}, err
	}
	record.spec.Workers, err = loadWorkerSpecsTx(ctx, tx, record.spec.ApplicationID)
	if err != nil {
		return Workspace{}, err
	}
	workspace := Workspace{
		Application: record.spec, Policy: record.spec.Policy, ObservedState: record.observedState,
		ConvergenceStatus: record.convergenceStatus, ObservedMessage: record.observedMessage,
		LastError: record.lastError, AppliedRevision: record.appliedRevision,
		ActiveDeploymentID: record.activeDeploymentID, PreviousDeploymentID: record.previousDeploymentID,
		Lifecycle: lifecycleState(record),
		LoadedAt:  time.Now().UTC(),
	}
	workspace.Deployments, err = loadDeploymentsTx(ctx, tx, record.spec.ApplicationID, 100)
	if err != nil {
		return Workspace{}, err
	}
	workspace.Environment, err = loadEnvironmentMetadataTx(ctx, tx, record.spec.ApplicationID)
	if err != nil {
		return Workspace{}, err
	}
	workspace.Workers, err = loadWorkersTx(ctx, tx, record.spec.ApplicationID)
	if err != nil {
		return Workspace{}, err
	}
	if err := tx.Commit(); err != nil {
		return Workspace{}, err
	}
	return workspace, nil
}

func (s *SQLStore) lockApplicationTx(ctx context.Context, tx *sql.Tx, siteID int64) (applicationRecord, error) {
	var applicationID, subscriptionID int64
	err := tx.QueryRowContext(ctx, `SELECT id,subscription_id FROM php_applications WHERE site_id=$1`, siteID).Scan(&applicationID, &subscriptionID)
	if errors.Is(err, sql.ErrNoRows) {
		return applicationRecord{}, ErrNotFound
	}
	if err != nil {
		return applicationRecord{}, err
	}
	if err = controlquota.LockSubscriptionMutationTx(ctx, tx, subscriptionID); err != nil {
		return applicationRecord{}, err
	}
	if err = lockPHPApplicationMutationTx(ctx, tx, applicationID); err != nil {
		return applicationRecord{}, err
	}
	record, err := scanApplication(tx.QueryRowContext(ctx, applicationSelect+` WHERE site.id=$1 FOR UPDATE OF application,site,subscription,customer,account`, siteID))
	if errors.Is(err, sql.ErrNoRows) {
		return record, ErrNotFound
	}
	if err != nil {
		return record, err
	}
	if record.spec.ApplicationID != applicationID || record.spec.SubscriptionID != subscriptionID {
		return record, ErrRevisionConflict
	}
	record.spec.Policy, err = controlquota.EffectiveSitePolicyTx(ctx, tx, siteID)
	if err != nil {
		return record, err
	}
	record.spec.Workers, err = loadWorkerSpecsTx(ctx, tx, record.spec.ApplicationID)
	return record, err
}

func lockPHPApplicationMutationTx(ctx context.Context, tx *sql.Tx, applicationID int64) error {
	if applicationID <= 0 {
		return ErrNotFound
	}
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('nakpanel:php-application:' || $1::bigint::text,0))`, applicationID)
	return err
}

func requireActive(record applicationRecord) error {
	if record.subscriptionStatus != "active" || record.customerStatus != "active" ||
		record.siteStatus != "active" || !record.providerActive || record.spec.DesiredState != "active" {
		return ErrInactive
	}
	return nil
}

func recheckRuntime(runtime types.PHPRuntimeCapability, version string) error {
	if runtime.Version != version || !runtime.Ready {
		return fmt.Errorf("%w: PHP %s is not ready", ErrRuntimeUnavailable, version)
	}
	return nil
}

func persistedApplicationConfiguration(record applicationRecord) ConfigureApplicationInput {
	return ConfigureApplicationInput{
		HostingMode: record.spec.HostingMode, PHPVersion: record.spec.PHPVersion,
		RepositoryID: record.spec.RepositoryID, RepositoryRef: record.spec.RepositoryRef,
		FrameworkProfile: record.spec.FrameworkProfile, PublicPath: record.spec.PublicPath,
		HealthPath: record.spec.HealthPath, SharedPaths: append([]string(nil), record.spec.SharedPaths...),
		ReleaseRetention: record.spec.ReleaseRetention, Composer: record.spec.Composer,
	}
}

func validatePersistedManagedApplication(record applicationRecord, runtime types.PHPRuntimeCapability) error {
	if record.spec.HostingMode != types.PHPHostingModeManaged {
		return errors.New("managed PHP deployment is not configured")
	}
	if _, err := validateApplicationConfiguration(persistedApplicationConfiguration(record), record.spec.Policy, record.spec.HostingMode); err != nil {
		return err
	}
	return recheckRuntime(runtime, record.spec.PHPVersion)
}

func validateRollbackTarget(record applicationRecord, target types.PHPDeployment) error {
	if target.ApplicationID != record.spec.ApplicationID || target.ID <= 0 {
		return ErrNotFound
	}
	if target.ID == record.activeDeploymentID {
		return errors.New("rollback target is already active")
	}
	if target.ResolvedRevision == "" || (target.Status != "healthy" && target.Status != "retired") {
		return errors.New("rollback target is not a retained healthy release")
	}
	return nil
}

func supersedeDeploymentIntentsTx(ctx context.Context, tx *sql.Tx, applicationID int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE php_deployments SET status='failed',
last_error='superseded by a newer application revision',finished_at=COALESCE(finished_at,now())
WHERE application_id=$1 AND status IN ('pending','preparing','validating','activating')`, applicationID)
	return err
}

func (s *SQLStore) ConfigureApplication(ctx context.Context, actorID, siteID int64, input ConfigureApplicationInput, runtime types.PHPRuntimeCapability) (types.PHPApplicationSpec, error) {
	tx, err := s.beginMutation(ctx)
	if err != nil {
		return types.PHPApplicationSpec{}, err
	}
	defer tx.Rollback()
	record, err := s.lockApplicationTx(ctx, tx, siteID)
	if err != nil {
		return types.PHPApplicationSpec{}, err
	}
	if err = requireActive(record); err != nil {
		return types.PHPApplicationSpec{}, err
	}
	input, err = validateApplicationConfiguration(input, record.spec.Policy, record.spec.HostingMode)
	if err != nil {
		return types.PHPApplicationSpec{}, invalidInput(err)
	}
	if err = recheckRuntime(runtime, input.PHPVersion); err != nil {
		return types.PHPApplicationSpec{}, err
	}
	if input.HostingMode == types.PHPHostingModeManaged {
		var exists bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM git_repositories WHERE id=$1 AND site_id=$2)`, input.RepositoryID, siteID).Scan(&exists); err != nil {
			return types.PHPApplicationSpec{}, err
		}
		if !exists {
			return types.PHPApplicationSpec{}, ErrNotFound
		}
	}
	shared, err := json.Marshal(input.SharedPaths)
	if err != nil {
		return types.PHPApplicationSpec{}, err
	}
	if err = supersedeDeploymentIntentsTx(ctx, tx, record.spec.ApplicationID); err != nil {
		return types.PHPApplicationSpec{}, err
	}
	var revision int64
	err = tx.QueryRowContext(ctx, `UPDATE php_applications SET hosting_mode=$2,php_version=$3,
repository_id=NULLIF($4,0),repository_ref=$5,framework_profile=COALESCE(NULLIF($6,''),'plain'),
public_path=$7,health_path=COALESCE(NULLIF($8,''),'/'),shared_paths=$9,composer_install=$10,
composer_allow_scripts=$11,composer_allow_plugins=$12,release_retention=CASE WHEN $13=0 THEN release_retention ELSE $13 END,
desired_revision=desired_revision+1,convergence_status='pending',last_error='',updated_at=now()
WHERE id=$1 RETURNING desired_revision`, record.spec.ApplicationID, input.HostingMode, input.PHPVersion,
		input.RepositoryID, input.RepositoryRef, input.FrameworkProfile, input.PublicPath, input.HealthPath,
		shared, input.Composer.Install, input.Composer.AllowScripts, input.Composer.AllowPlugins, input.ReleaseRetention).Scan(&revision)
	if err != nil {
		return types.PHPApplicationSpec{}, err
	}
	if err = s.enqueueTx(ctx, tx, ReconcilePHPApplicationArgs{ApplicationID: record.spec.ApplicationID, DesiredRevision: revision}); err != nil {
		return types.PHPApplicationSpec{}, err
	}
	if err = auditTx(ctx, tx, actorID, record.customerID, record.spec.SubscriptionID, "php.application.configure", "php_application", record.spec.ApplicationID,
		map[string]any{"hosting_mode": input.HostingMode, "php_version": input.PHPVersion, "repository_id": input.RepositoryID, "revision": revision}); err != nil {
		return types.PHPApplicationSpec{}, err
	}
	if err = tx.Commit(); err != nil {
		return types.PHPApplicationSpec{}, err
	}
	return s.applicationSpec(ctx, siteID)
}

func (s *SQLStore) QueueDeployment(ctx context.Context, actorID, siteID int64, input DeploymentInput, runtime types.PHPRuntimeCapability) (types.PHPDeployment, error) {
	tx, err := s.beginMutation(ctx)
	if err != nil {
		return types.PHPDeployment{}, err
	}
	defer tx.Rollback()
	record, err := s.lockApplicationTx(ctx, tx, siteID)
	if err != nil {
		return types.PHPDeployment{}, err
	}
	if err = requireActive(record); err != nil {
		return types.PHPDeployment{}, err
	}
	if err = validatePersistedManagedApplication(record, runtime); err != nil {
		return types.PHPDeployment{}, err
	}
	input.RequestedRevision = strings.TrimSpace(input.RequestedRevision)
	if input.RequestedRevision == "" {
		input.RequestedRevision = record.spec.RepositoryRef
	}
	if !gitRefPattern.MatchString(input.RequestedRevision) || strings.Contains(input.RequestedRevision, "..") {
		return types.PHPDeployment{}, invalidInput(errors.New("requested Git revision is invalid"))
	}
	if err = supersedeDeploymentIntentsTx(ctx, tx, record.spec.ApplicationID); err != nil {
		return types.PHPDeployment{}, err
	}
	var deploymentID, releaseNumber, revision int64
	err = tx.QueryRowContext(ctx, `INSERT INTO php_deployments(subscription_id,application_id,requested_by_user_id,requested_revision,release_number,previous_deployment_id)
SELECT $1,$2,NULLIF($3,0),$4,COALESCE(MAX(release_number),0)+1,NULLIF($5,0) FROM php_deployments WHERE application_id=$2
RETURNING id,release_number`, record.spec.SubscriptionID, record.spec.ApplicationID, actorID, input.RequestedRevision, record.activeDeploymentID).Scan(&deploymentID, &releaseNumber)
	if err != nil {
		return types.PHPDeployment{}, err
	}
	err = tx.QueryRowContext(ctx, `UPDATE php_applications SET desired_revision=desired_revision+1,convergence_status='pending',last_error='',updated_at=now() WHERE id=$1 RETURNING desired_revision`, record.spec.ApplicationID).Scan(&revision)
	if err != nil {
		return types.PHPDeployment{}, err
	}
	args := DeployPHPReleaseArgs{ApplicationID: record.spec.ApplicationID, DeploymentID: deploymentID, DesiredRevision: revision}
	if err = s.enqueueTx(ctx, tx, args); err != nil {
		return types.PHPDeployment{}, err
	}
	if err = auditTx(ctx, tx, actorID, record.customerID, record.spec.SubscriptionID, "php.deployment.queued", "php_deployment", deploymentID,
		map[string]any{"application_id": record.spec.ApplicationID, "release_number": releaseNumber, "revision": revision}); err != nil {
		return types.PHPDeployment{}, err
	}
	if err = tx.Commit(); err != nil {
		return types.PHPDeployment{}, err
	}
	return s.deployment(ctx, deploymentID)
}

func (s *SQLStore) QueueRollback(ctx context.Context, actorID, siteID, targetID int64, runtime types.PHPRuntimeCapability) (types.PHPDeployment, error) {
	if targetID <= 0 {
		return types.PHPDeployment{}, ErrNotFound
	}
	tx, err := s.beginMutation(ctx)
	if err != nil {
		return types.PHPDeployment{}, err
	}
	defer tx.Rollback()
	record, err := s.lockApplicationTx(ctx, tx, siteID)
	if err != nil {
		return types.PHPDeployment{}, err
	}
	if err = requireActive(record); err != nil {
		return types.PHPDeployment{}, err
	}
	if err = validatePersistedManagedApplication(record, runtime); err != nil {
		return types.PHPDeployment{}, err
	}
	if targetID == record.activeDeploymentID {
		return types.PHPDeployment{}, fmt.Errorf("%w: rollback target is already active", ErrRevisionConflict)
	}
	target, err := scanDeployment(tx.QueryRowContext(ctx, rollbackTargetSelect, targetID, record.spec.ApplicationID))
	if errors.Is(err, sql.ErrNoRows) {
		return types.PHPDeployment{}, ErrNotFound
	}
	if err != nil {
		return types.PHPDeployment{}, err
	}
	if err = validateRollbackTarget(record, target); err != nil {
		return types.PHPDeployment{}, fmt.Errorf("%w: %v", ErrRevisionConflict, err)
	}
	if record.spec.ReleaseRetention > 0 {
		var latest int64
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(release_number),0) FROM php_deployments WHERE application_id=$1`, record.spec.ApplicationID).Scan(&latest); err != nil {
			return types.PHPDeployment{}, err
		}
		if latest-target.ReleaseNumber >= int64(record.spec.ReleaseRetention) && targetID != record.previousDeploymentID {
			return types.PHPDeployment{}, fmt.Errorf("%w: rollback target is outside retained releases", ErrRevisionConflict)
		}
	}
	if err = supersedeDeploymentIntentsTx(ctx, tx, record.spec.ApplicationID); err != nil {
		return types.PHPDeployment{}, err
	}
	var intentID, releaseNumber, revision int64
	err = tx.QueryRowContext(ctx, `INSERT INTO php_deployments(subscription_id,application_id,requested_by_user_id,requested_revision,release_number,previous_deployment_id,status)
SELECT $1,$2,NULLIF($3,0),$4,COALESCE(MAX(release_number),0)+1,NULLIF($5,0),'pending' FROM php_deployments WHERE application_id=$2
RETURNING id,release_number`, record.spec.SubscriptionID, record.spec.ApplicationID, actorID, target.ResolvedRevision, record.activeDeploymentID).Scan(&intentID, &releaseNumber)
	if err != nil {
		return types.PHPDeployment{}, err
	}
	err = tx.QueryRowContext(ctx, `UPDATE php_applications SET desired_revision=desired_revision+1,convergence_status='pending',last_error='',updated_at=now() WHERE id=$1 RETURNING desired_revision`, record.spec.ApplicationID).Scan(&revision)
	if err != nil {
		return types.PHPDeployment{}, err
	}
	if err = s.enqueueTx(ctx, tx, RollbackPHPReleaseArgs{ApplicationID: record.spec.ApplicationID, DeploymentID: intentID, TargetDeploymentID: targetID, DesiredRevision: revision}); err != nil {
		return types.PHPDeployment{}, err
	}
	if err = auditTx(ctx, tx, actorID, record.customerID, record.spec.SubscriptionID, "php.deployment.rollback_queued", "php_deployment", intentID,
		map[string]any{"target_deployment_id": targetID, "release_number": releaseNumber, "revision": revision}); err != nil {
		return types.PHPDeployment{}, err
	}
	if err = tx.Commit(); err != nil {
		return types.PHPDeployment{}, err
	}
	return s.deployment(ctx, intentID)
}

func (s *SQLStore) beginMutation(ctx context.Context) (*sql.Tx, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("PHP application database is unavailable")
	}
	if s.river == nil {
		return nil, errors.New("PHP application job queue is unavailable")
	}
	return s.db.BeginTx(ctx, nil)
}

func (s *SQLStore) enqueueTx(ctx context.Context, tx *sql.Tx, args river.JobArgs) error {
	_, err := s.river.InsertTx(ctx, tx, args, nil)
	return err
}

func (s *SQLStore) applicationSpec(ctx context.Context, siteID int64) (types.PHPApplicationSpec, error) {
	record, err := scanApplication(s.db.QueryRowContext(ctx, applicationSelect+` WHERE site.id=$1`, siteID))
	if errors.Is(err, sql.ErrNoRows) {
		return types.PHPApplicationSpec{}, ErrNotFound
	}
	if err != nil {
		return types.PHPApplicationSpec{}, err
	}
	policyStore := controlquota.NewSQLStore(s.db)
	record.spec.Policy, err = policyStore.EffectiveSitePolicy(ctx, siteID)
	return record.spec, err
}

func (s *SQLStore) deployment(ctx context.Context, deploymentID int64) (types.PHPDeployment, error) {
	deployment, err := scanDeployment(s.db.QueryRowContext(ctx, deploymentSelect+` WHERE deployment.id=$1`, deploymentID))
	if errors.Is(err, sql.ErrNoRows) {
		return types.PHPDeployment{}, ErrNotFound
	}
	return deployment, err
}

func auditTx(ctx context.Context, tx *sql.Tx, actorID, customerID, subscriptionID int64, action, target string, targetID int64, metadata map[string]any) error {
	payload, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,actor_label,customer_id,subscription_id,action,target_type,target_id,metadata)
VALUES(NULLIF($1,0),CASE WHEN $1=0 THEN 'php-worker' ELSE NULL END,NULLIF($2,0),NULLIF($3,0),$4,$5,NULLIF($6,0),$7)`, actorID, customerID, subscriptionID, action, target, targetID, payload)
	return err
}

func nullableID(value int64) any {
	if value <= 0 {
		return nil
	}
	return value
}

var resolvedRevisionPattern = regexp.MustCompile(`^[a-f0-9]{40}([a-f0-9]{24})?$`)
