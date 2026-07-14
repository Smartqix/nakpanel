package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

const (
	HeavyQueue     = "heavy"
	MigrationQueue = "migration"
)

type ConvergeSubscriptionArgs struct {
	SubscriptionID int64 `json:"subscription_id" river:"unique"`
}

type ConvergePendingSubscriptionsArgs struct{}
type ConvergeApplicationArgs struct {
	ApplicationID int64 `json:"application_id" river:"unique"`
}

type SweepLegacyAccountMigrationsArgs struct{}
type SweepLegacyAccountCleanupArgs struct{}
type MigrateSubscriptionAccountArgs struct {
	SubscriptionID int64 `json:"subscription_id" river:"unique"`
}
type CleanupLegacyHomesArgs struct {
	SubscriptionID int64 `json:"subscription_id" river:"unique"`
}

func (SweepLegacyAccountCleanupArgs) Kind() string { return "sweep_legacy_account_cleanup" }
func (SweepLegacyAccountCleanupArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "maintenance", UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}
func (CleanupLegacyHomesArgs) Kind() string { return "cleanup_legacy_homes" }
func (CleanupLegacyHomesArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "maintenance", MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

func (SweepLegacyAccountMigrationsArgs) Kind() string { return "sweep_legacy_account_migrations" }
func (SweepLegacyAccountMigrationsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: MigrationQueue, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}
func (MigrateSubscriptionAccountArgs) Kind() string { return "migrate_subscription_account" }
func (MigrateSubscriptionAccountArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: MigrationQueue, MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

func (ConvergePendingSubscriptionsArgs) Kind() string { return "converge_pending_subscriptions" }
func (ConvergePendingSubscriptionsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

func (ConvergeSubscriptionArgs) Kind() string { return "converge_subscription" }
func (ConvergeSubscriptionArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

// ConfigureMailArgs reconciles Stalwart with every enabled mail domain: the
// worker lives in the provision package. River's unique gate must include
// the Running state, so a bare singleton would silently drop a change made
// while a reconciliation is already running — the revision gives every
// mutation its own job, and the idempotent worker makes extra runs free.
type ConfigureMailArgs struct {
	Revision int64 `json:"revision" river:"unique"`
}

func (ConfigureMailArgs) Kind() string { return "configure_mail" }
func (ConfigureMailArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

// NewConfigureMailArgs stamps the job with the mutation moment.
func NewConfigureMailArgs() ConfigureMailArgs {
	return ConfigureMailArgs{Revision: time.Now().UnixMilli()}
}

func (ConvergeApplicationArgs) Kind() string { return "converge_application" }
func (ConvergeApplicationArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: HeavyQueue, MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

type SubscriptionConvergenceAgent interface {
	EnsureSubscriptionAccount(context.Context, types.EnsureSubscriptionAccountReq) (types.Response, error)
	ApplyScheduledTasks(context.Context, types.ApplyScheduledTasksReq) (types.Response, error)
	EnsureApplication(context.Context, types.EnsureApplicationReq) (types.Response, error)
	MigrateSubscriptionAccount(context.Context, types.MigrateSubscriptionAccountReq) (types.Response, error)
	CleanupLegacyHomes(context.Context, types.CleanupLegacyHomesReq) (types.Response, error)
}

type ConvergeSubscriptionWorker struct {
	river.WorkerDefaults[ConvergeSubscriptionArgs]
	db    *sql.DB
	agent SubscriptionConvergenceAgent
	river *river.Client[*sql.Tx]
}

func (w *ConvergeSubscriptionWorker) SetRiverClient(client *river.Client[*sql.Tx]) { w.river = client }

type ConvergeApplicationWorker struct {
	river.WorkerDefaults[ConvergeApplicationArgs]
	db    *sql.DB
	agent SubscriptionConvergenceAgent
}

func NewConvergeApplicationWorker(db *sql.DB, agent SubscriptionConvergenceAgent) *ConvergeApplicationWorker {
	return &ConvergeApplicationWorker{db: db, agent: agent}
}

func (w *ConvergeApplicationWorker) Work(ctx context.Context, job *river.Job[ConvergeApplicationArgs]) error {
	if w.db == nil || w.agent == nil {
		return errors.New("application convergence is not configured")
	}
	var subscriptionID int64
	if err := w.db.QueryRowContext(ctx, `SELECT subscription_id FROM application_instances WHERE id=$1`, job.Args.ApplicationID).Scan(&subscriptionID); err != nil {
		return err
	}
	snapshot, err := loadSubscriptionConvergence(ctx, w.db, subscriptionID)
	if err != nil {
		return err
	}
	for _, application := range snapshot.Applications {
		if application.ApplicationID != job.Args.ApplicationID {
			continue
		}
		resp, workErr := w.agent.EnsureApplication(ctx, application)
		if workErr == nil && !resp.OK {
			workErr = errors.New(resp.Error)
		}
		if workErr != nil {
			_, markErr := w.db.ExecContext(ctx, `UPDATE application_instances SET convergence_status='failed',last_error=$2,updated_at=now() WHERE id=$1`, job.Args.ApplicationID, workErr.Error())
			return errors.Join(workErr, markErr)
		}
		if application.Remove {
			_, err = w.db.ExecContext(ctx, `DELETE FROM application_instances WHERE id=$1 AND delete_requested=true`, job.Args.ApplicationID)
			return err
		}
		_, err = w.db.ExecContext(ctx, `UPDATE application_instances SET applied_state=desired_state,convergence_status='in_sync',last_error='',updated_at=now() WHERE id=$1`, job.Args.ApplicationID)
		return err
	}
	return sql.ErrNoRows
}

func NewConvergeSubscriptionWorker(db *sql.DB, agent SubscriptionConvergenceAgent) *ConvergeSubscriptionWorker {
	return &ConvergeSubscriptionWorker{db: db, agent: agent}
}

type ConvergePendingSubscriptionsWorker struct {
	river.WorkerDefaults[ConvergePendingSubscriptionsArgs]
	db    *sql.DB
	river *river.Client[*sql.Tx]
}

func NewConvergePendingSubscriptionsWorker(db *sql.DB) *ConvergePendingSubscriptionsWorker {
	return &ConvergePendingSubscriptionsWorker{db: db}
}

type SweepLegacyAccountMigrationsWorker struct {
	river.WorkerDefaults[SweepLegacyAccountMigrationsArgs]
	db    *sql.DB
	river *river.Client[*sql.Tx]
}

type SweepLegacyAccountCleanupWorker struct {
	river.WorkerDefaults[SweepLegacyAccountCleanupArgs]
	db    *sql.DB
	river *river.Client[*sql.Tx]
}

func NewSweepLegacyAccountCleanupWorker(db *sql.DB) *SweepLegacyAccountCleanupWorker {
	return &SweepLegacyAccountCleanupWorker{db: db}
}
func (w *SweepLegacyAccountCleanupWorker) SetRiverClient(client *river.Client[*sql.Tx]) {
	w.river = client
}
func (w *SweepLegacyAccountCleanupWorker) Work(ctx context.Context, _ *river.Job[SweepLegacyAccountCleanupArgs]) error {
	if w.db == nil || w.river == nil {
		return errors.New("legacy account cleanup sweep is not configured")
	}
	rows, err := w.db.QueryContext(ctx, `SELECT subscription_id FROM subscription_system_accounts WHERE cleanup_after<=now() AND jsonb_array_length(legacy_homes)>0 ORDER BY id LIMIT 25`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var subscriptionID int64
		if err := rows.Scan(&subscriptionID); err != nil {
			return err
		}
		if _, err := w.river.Insert(ctx, CleanupLegacyHomesArgs{SubscriptionID: subscriptionID}, nil); err != nil {
			return err
		}
	}
	return rows.Err()
}

type CleanupLegacyHomesWorker struct {
	river.WorkerDefaults[CleanupLegacyHomesArgs]
	db    *sql.DB
	agent SubscriptionConvergenceAgent
}

func NewCleanupLegacyHomesWorker(db *sql.DB, agent SubscriptionConvergenceAgent) *CleanupLegacyHomesWorker {
	return &CleanupLegacyHomesWorker{db: db, agent: agent}
}
func (w *CleanupLegacyHomesWorker) Work(ctx context.Context, job *river.Job[CleanupLegacyHomesArgs]) error {
	if w.db == nil || w.agent == nil {
		return errors.New("legacy account cleanup is not configured")
	}
	var homePath string
	var homesRaw []byte
	if err := w.db.QueryRowContext(ctx, `SELECT home_path,legacy_homes FROM subscription_system_accounts WHERE subscription_id=$1 AND cleanup_after<=now() FOR UPDATE`, job.Args.SubscriptionID).Scan(&homePath, &homesRaw); err != nil {
		return err
	}
	var homes []string
	if err := json.Unmarshal(homesRaw, &homes); err != nil {
		return err
	}
	resp, err := w.agent.CleanupLegacyHomes(ctx, types.CleanupLegacyHomesReq{SubscriptionID: job.Args.SubscriptionID, ActiveHome: homePath, LegacyHomes: homes})
	if err != nil || !resp.OK {
		if err == nil {
			err = errors.New(resp.Error)
		}
		_, markErr := w.db.ExecContext(ctx, `UPDATE subscription_system_accounts SET migration_error=$2,updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID, err.Error())
		return errors.Join(err, markErr)
	}
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE subscription_system_accounts SET legacy_homes='[]'::jsonb,cleanup_after=NULL,migration_error='',updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata)
SELECT scheduler.id,sub.customer_id,sub.id,'subscription.legacy_homes_deleted','subscription',sub.id,jsonb_build_object('homes',$2::jsonb)
FROM subscriptions sub CROSS JOIN LATERAL(SELECT id FROM users WHERE email='scheduler@nakpanel.internal') scheduler WHERE sub.id=$1`, job.Args.SubscriptionID, homesRaw); err != nil {
		return err
	}
	return tx.Commit()
}

func NewSweepLegacyAccountMigrationsWorker(db *sql.DB) *SweepLegacyAccountMigrationsWorker {
	return &SweepLegacyAccountMigrationsWorker{db: db}
}
func (w *SweepLegacyAccountMigrationsWorker) SetRiverClient(client *river.Client[*sql.Tx]) {
	w.river = client
}
func (w *SweepLegacyAccountMigrationsWorker) Work(ctx context.Context, _ *river.Job[SweepLegacyAccountMigrationsArgs]) error {
	if w.db == nil || w.river == nil {
		return errors.New("legacy account migration sweep is not configured")
	}
	rows, err := w.db.QueryContext(ctx, `SELECT subscription_id FROM subscription_system_accounts
WHERE migration_status='legacy' OR (migration_status='failed' AND updated_at<now()-interval '15 minutes') ORDER BY id LIMIT 10`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if _, err := w.river.Insert(ctx, MigrateSubscriptionAccountArgs{SubscriptionID: id}, nil); err != nil {
			return err
		}
	}
	return rows.Err()
}

type MigrateSubscriptionAccountWorker struct {
	river.WorkerDefaults[MigrateSubscriptionAccountArgs]
	db    *sql.DB
	agent SubscriptionConvergenceAgent
	river *river.Client[*sql.Tx]
}

func NewMigrateSubscriptionAccountWorker(db *sql.DB, agent SubscriptionConvergenceAgent) *MigrateSubscriptionAccountWorker {
	return &MigrateSubscriptionAccountWorker{db: db, agent: agent}
}
func (w *MigrateSubscriptionAccountWorker) SetRiverClient(client *river.Client[*sql.Tx]) {
	w.river = client
}
func (w *MigrateSubscriptionAccountWorker) Work(ctx context.Context, job *river.Job[MigrateSubscriptionAccountArgs]) error {
	if w.db == nil || w.agent == nil || w.river == nil {
		return errors.New("legacy account migration is not configured")
	}
	snapshot, err := loadSubscriptionConvergence(ctx, w.db, job.Args.SubscriptionID)
	if err != nil {
		return err
	}
	rows, err := w.db.QueryContext(ctx, `SELECT id,domain,username,php_version FROM sites WHERE subscription_id=$1 ORDER BY id`, job.Args.SubscriptionID)
	if err != nil {
		return err
	}
	request := types.MigrateSubscriptionAccountReq{SubscriptionID: job.Args.SubscriptionID, Username: snapshot.Account.Username, HomePath: snapshot.Account.HomePath, Policy: snapshot.Account.Policy}
	for rows.Next() {
		var item types.LegacySiteMigration
		if err := rows.Scan(&item.SiteID, &item.Domain, &item.LegacyUsername, &item.PHPVersion); err != nil {
			rows.Close()
			return err
		}
		item.LegacyHome = "/home/" + item.LegacyUsername
		item.LegacyDocroot = item.LegacyHome + "/public_html"
		item.TargetDocroot = snapshot.Account.HomePath + "/domains/" + item.Domain + "/public_html"
		request.Sites = append(request.Sites, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(request.Sites) == 0 {
		_, err = w.db.ExecContext(ctx, `UPDATE subscription_system_accounts SET migration_status='complete',migrated_at=now(),convergence_status='pending',updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID)
		return err
	}
	if _, err = w.db.ExecContext(ctx, `UPDATE subscription_system_accounts SET migration_status='preflight',migration_error='',updated_at=now() WHERE subscription_id=$1 AND migration_status IN('legacy','failed','preflight')`, job.Args.SubscriptionID); err != nil {
		return err
	}
	if _, err = w.db.ExecContext(ctx, `UPDATE subscription_system_accounts SET migration_status='copying',updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID); err != nil {
		return err
	}
	resp, err := w.agent.MigrateSubscriptionAccount(ctx, request)
	if err != nil || !resp.OK {
		if err == nil {
			err = errors.New(resp.Error)
		}
		_, markErr := w.db.ExecContext(ctx, `UPDATE subscription_system_accounts SET migration_status='failed',migration_error=$2,updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID, err.Error())
		return errors.Join(err, markErr)
	}
	var result types.MigrateSubscriptionAccountResult
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return err
	}
	legacy, _ := json.Marshal(result.LegacyHomes)
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE sites site SET username=account.username,document_root=account.home_path||'/domains/'||site.domain||'/public_html',updated_at=now() FROM subscription_system_accounts account WHERE site.subscription_id=$1 AND account.subscription_id=site.subscription_id`, job.Args.SubscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE subscription_system_accounts SET migration_status='complete',migration_error='',legacy_homes=$2,migrated_at=now(),cleanup_after=now()+interval '7 days',convergence_status='pending',updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID, legacy); err != nil {
		return err
	}
	if _, err = w.river.InsertTx(ctx, tx, ConvergeSubscriptionArgs{SubscriptionID: job.Args.SubscriptionID}, nil); err != nil {
		return err
	}
	if err = wakeSubscriptionConvergenceTx(ctx, tx, job.Args.SubscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata)
SELECT scheduler.id,sub.customer_id,sub.id,'subscription.account_migrated','subscription',sub.id,jsonb_build_object('snapshot_path',$2::text)
FROM subscriptions sub CROSS JOIN LATERAL(SELECT id FROM users WHERE email='scheduler@nakpanel.internal') scheduler WHERE sub.id=$1`, job.Args.SubscriptionID, result.SnapshotPath); err != nil {
		return err
	}
	return tx.Commit()
}

func (w *ConvergePendingSubscriptionsWorker) SetRiverClient(client *river.Client[*sql.Tx]) {
	w.river = client
}

func (w *ConvergePendingSubscriptionsWorker) Work(ctx context.Context, _ *river.Job[ConvergePendingSubscriptionsArgs]) error {
	if w.db == nil || w.river == nil {
		return errors.New("pending subscription convergence is not configured")
	}
	rows, err := w.db.QueryContext(ctx, `SELECT subscription_id FROM subscription_system_accounts
WHERE convergence_status='pending' AND migration_status IN('pending','complete') ORDER BY id LIMIT 100`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if _, err := w.river.Insert(ctx, ConvergeSubscriptionArgs{SubscriptionID: id}, nil); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (w *ConvergeSubscriptionWorker) Work(ctx context.Context, job *river.Job[ConvergeSubscriptionArgs]) error {
	if w.db == nil || w.agent == nil || w.river == nil {
		return errors.New("subscription convergence is not configured")
	}
	var migrationStatus string
	if err := w.db.QueryRowContext(ctx, `SELECT migration_status FROM subscription_system_accounts WHERE subscription_id=$1`, job.Args.SubscriptionID).Scan(&migrationStatus); err != nil {
		return err
	}
	if migrationStatus != "pending" && migrationStatus != "complete" {
		return nil
	}
	snapshot, err := loadSubscriptionConvergence(ctx, w.db, job.Args.SubscriptionID)
	if err != nil {
		return err
	}
	resp, err := w.agent.EnsureSubscriptionAccount(ctx, snapshot.Account)
	if err != nil {
		return errors.Join(err, markAccountConvergence(ctx, w.db, job.Args.SubscriptionID, "failed", err.Error(), 0))
	}
	if !resp.OK {
		err = fmt.Errorf("agent account convergence failed: %s", resp.Error)
		return errors.Join(err, markAccountConvergence(ctx, w.db, job.Args.SubscriptionID, "failed", err.Error(), 0))
	}
	var result types.EnsureSubscriptionAccountResult
	if err = json.Unmarshal(resp.Data, &result); err != nil {
		return errors.Join(err, markAccountConvergence(ctx, w.db, job.Args.SubscriptionID, "failed", err.Error(), 0))
	}
	resp, err = w.agent.ApplyScheduledTasks(ctx, types.ApplyScheduledTasksReq{
		SubscriptionID: job.Args.SubscriptionID, Username: snapshot.Account.Username,
		HomePath: snapshot.Account.HomePath, Tasks: snapshot.Account.Tasks,
	})
	if err != nil || !resp.OK {
		if err == nil {
			err = errors.New(resp.Error)
		}
		_, _ = w.db.ExecContext(ctx, `UPDATE scheduled_tasks SET convergence_status='failed',last_error=$2,updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID, err.Error())
		return errors.Join(err, markAccountConvergence(ctx, w.db, job.Args.SubscriptionID, "failed", err.Error(), result.LinuxUID))
	}
	if _, err = w.db.ExecContext(ctx, `UPDATE scheduled_tasks SET convergence_status='in_sync',last_error='',updated_at=now() WHERE subscription_id=$1`, job.Args.SubscriptionID); err != nil {
		return errors.Join(err, markAccountConvergence(ctx, w.db, job.Args.SubscriptionID, "failed", err.Error(), result.LinuxUID))
	}
	if snapshot.MailDomainCount > 0 {
		// Mail is reconciled node-wide (one Stalwart config covers every
		// hosted domain), so hand off to the configure_mail singleton.
		if _, err = w.river.Insert(ctx, NewConfigureMailArgs(), nil); err != nil {
			return errors.Join(err, markAccountConvergence(ctx, w.db, job.Args.SubscriptionID, "failed", err.Error(), result.LinuxUID))
		}
	}
	for _, application := range snapshot.Applications {
		if _, err = w.river.Insert(ctx, ConvergeApplicationArgs{ApplicationID: application.ApplicationID}, nil); err != nil {
			return errors.Join(err, markAccountConvergence(ctx, w.db, job.Args.SubscriptionID, "failed", err.Error(), result.LinuxUID))
		}
	}
	return markAccountConvergence(ctx, w.db, job.Args.SubscriptionID, "in_sync", "", result.LinuxUID)
}

type convergenceSnapshot struct {
	Account         types.EnsureSubscriptionAccountReq
	MailDomainCount int
	Applications    []types.EnsureApplicationReq
}

func loadSubscriptionConvergence(ctx context.Context, db *sql.DB, subscriptionID int64) (convergenceSnapshot, error) {
	if subscriptionID <= 0 {
		return convergenceSnapshot{}, errors.New("subscription id is required")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return convergenceSnapshot{}, err
	}
	defer tx.Rollback()
	var account types.EnsureSubscriptionAccountReq
	var desiredState string
	err = tx.QueryRowContext(ctx, `SELECT account.subscription_id,account.username,account.home_path,
CASE WHEN sub.status='active' AND customer.status='active' THEN account.desired_state ELSE 'suspended' END
FROM subscription_system_accounts account
JOIN subscriptions sub ON sub.id=account.subscription_id
JOIN customers customer ON customer.id=sub.customer_id
WHERE account.subscription_id=$1`, subscriptionID).Scan(&account.SubscriptionID, &account.Username, &account.HomePath, &desiredState)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	account.State = desiredState
	entitlements, err := readSubscriptionEntitlementsTx(ctx, tx, subscriptionID)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	base := controlpolicy.DefaultFromEntitlements(entitlements)
	var storedPolicy, subscriptionPatch []byte
	err = tx.QueryRowContext(ctx, `SELECT e.hosting_policy,COALESCE(o.policy_patch,'{}'::jsonb)
FROM subscription_entitlements e LEFT JOIN subscription_policy_overrides o ON o.subscription_id=e.subscription_id
WHERE e.subscription_id=$1`, subscriptionID).Scan(&storedPolicy, &subscriptionPatch)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	if hasConfiguredPolicy(storedPolicy) {
		var configured types.HostingPolicy
		if err := json.Unmarshal(storedPolicy, &configured); err != nil {
			return convergenceSnapshot{}, err
		}
		base = configured
	}
	account.Policy, err = controlpolicy.Resolve(base, subscriptionPatch, nil)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT site.id,site.domain,site.document_root,
CASE WHEN $2='active' AND site.desired_status='active' THEN 'active' ELSE 'suspended' END,
COALESCE(o.policy_patch,'{}'::jsonb)
FROM sites site LEFT JOIN site_policy_overrides o ON o.site_id=site.id
WHERE site.subscription_id=$1 ORDER BY site.id`, subscriptionID, desiredState)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	for rows.Next() {
		var domain types.SubscriptionDomain
		var sitePatch []byte
		if err := rows.Scan(&domain.SiteID, &domain.Domain, &domain.DocumentRoot, &domain.State, &sitePatch); err != nil {
			rows.Close()
			return convergenceSnapshot{}, err
		}
		domain.Policy, err = controlpolicy.Resolve(account.Policy, nil, sitePatch)
		if err != nil {
			rows.Close()
			return convergenceSnapshot{}, fmt.Errorf("site %d policy: %w", domain.SiteID, err)
		}
		account.Domains = append(account.Domains, domain)
	}
	if err := rows.Close(); err != nil {
		return convergenceSnapshot{}, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,name,public_key,relative_root,enabled FROM sftp_access_identities WHERE subscription_id=$1 ORDER BY id`, subscriptionID)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	for rows.Next() {
		var identity types.SFTPAccessIdentity
		if err := rows.Scan(&identity.ID, &identity.Name, &identity.PublicKey, &identity.RelativeRoot, &identity.Enabled); err != nil {
			rows.Close()
			return convergenceSnapshot{}, err
		}
		account.SFTPIdentities = append(account.SFTPIdentities, identity)
	}
	rows.Close()
	rows, err = tx.QueryContext(ctx, `SELECT id,name,schedule,command,working_directory,timeout_seconds,enabled FROM scheduled_tasks WHERE subscription_id=$1 ORDER BY id`, subscriptionID)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	for rows.Next() {
		var task types.ScheduledTask
		if err := rows.Scan(&task.ID, &task.Name, &task.Schedule, &task.Command, &task.WorkingDirectory, &task.TimeoutSeconds, &task.Enabled); err != nil {
			rows.Close()
			return convergenceSnapshot{}, err
		}
		account.Tasks = append(account.Tasks, task)
	}
	rows.Close()
	snapshot := convergenceSnapshot{Account: account}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mail_domains WHERE subscription_id=$1`, subscriptionID).Scan(&snapshot.MailDomainCount); err != nil {
		return convergenceSnapshot{}, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,name,runtime,image_ref,desired_state,delete_requested,environment FROM application_instances WHERE subscription_id=$1 ORDER BY id`, subscriptionID)
	if err != nil {
		return convergenceSnapshot{}, err
	}
	for rows.Next() {
		var item types.EnsureApplicationReq
		var environment []byte
		if err := rows.Scan(&item.ApplicationID, &item.Name, &item.Runtime, &item.ImageRef, &item.DesiredState, &item.Remove, &environment); err != nil {
			rows.Close()
			return convergenceSnapshot{}, err
		}
		if err := json.Unmarshal(environment, &item.Environment); err != nil {
			rows.Close()
			return convergenceSnapshot{}, err
		}
		item.Username, item.Policy = account.Username, account.Policy
		snapshot.Applications = append(snapshot.Applications, item)
	}
	if err := rows.Close(); err != nil {
		return convergenceSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return convergenceSnapshot{}, err
	}
	return snapshot, nil
}

func hasConfiguredPolicy(raw []byte) bool {
	var value map[string]json.RawMessage
	return json.Unmarshal(raw, &value) == nil && (len(value) > 1 || value["resources"] != nil)
}

func markAccountConvergence(ctx context.Context, db *sql.DB, subscriptionID int64, status, message string, uid int) error {
	applied := "failed"
	if status == "in_sync" {
		applied = "active"
	}
	_, err := db.ExecContext(ctx, `UPDATE subscription_system_accounts
SET linux_uid=CASE WHEN $4>0 THEN $4 ELSE linux_uid END,applied_state=$2,convergence_status=$3,last_error=$5,updated_at=now()
WHERE subscription_id=$1`, subscriptionID, applied, status, uid, strings.TrimSpace(message))
	return err
}

func wakeSubscriptionConvergenceTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE river_job SET state='available',scheduled_at=now()
WHERE kind='converge_subscription' AND args->>'subscription_id'=CAST($1 AS bigint)::text AND state IN ('retryable','scheduled')`, subscriptionID)
	return err
}
