package provisioningapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type FinalizeAccountArgs struct {
	BillingAccountID int64  `json:"billing_account_id,omitempty" river:"unique"`
	PublicID         string `json:"public_id,omitempty" river:"unique"`
}

func (FinalizeAccountArgs) Kind() string { return "finalize_billing_account" }
func (FinalizeAccountArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{MaxAttempts: 20, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeJobStates()}}
}

type FinalizeAccountWorker struct {
	river.WorkerDefaults[FinalizeAccountArgs]
	db *sql.DB
}

func NewFinalizeAccountWorker(db *sql.DB) *FinalizeAccountWorker {
	return &FinalizeAccountWorker{db: db}
}

func (w *FinalizeAccountWorker) Work(ctx context.Context, job *river.Job[FinalizeAccountArgs]) error {
	if w.db == nil {
		return errors.New("billing account database is unavailable")
	}
	var id int64
	var publicID, accountStatus, siteStatus, accountError, siteError string
	err := w.db.QueryRowContext(ctx, `SELECT b.id,b.public_id,a.convergence_status,COALESCE(site.status,'failed'),a.last_error,COALESCE(site.last_error,'primary site is missing')
FROM billing_accounts b JOIN subscription_system_accounts a ON a.subscription_id=b.subscription_id
LEFT JOIN sites site ON site.id=b.primary_site_id
WHERE ($1::bigint>0 AND b.id=$1) OR ($1=0 AND b.public_id=$2)`, job.Args.BillingAccountID, job.Args.PublicID).Scan(&id, &publicID, &accountStatus, &siteStatus, &accountError, &siteError)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if accountStatus == "failed" || siteStatus == "failed" {
		message := accountError
		if message == "" {
			message = siteError
		}
		_, err = w.db.ExecContext(ctx, `UPDATE billing_accounts SET provisioning_state='failed',last_error=$2,updated_at=now() WHERE id=$1 AND provisioning_state='pending'`, id, message)
		if err == nil {
			_ = (&AccountService{DB: w.db}).enqueueWebhook(ctx, id, "account.provision_failed", "account.provision_failed:"+publicID)
		}
		return err
	}
	if accountStatus == "in_sync" && siteStatus == "active" {
		_, err = w.db.ExecContext(ctx, `UPDATE billing_accounts SET provisioning_state='active',last_error='',updated_at=now() WHERE id=$1 AND provisioning_state='pending'`, id)
		if err == nil {
			_ = (&AccountService{DB: w.db}).enqueueWebhook(ctx, id, "account.provisioned", "account.provisioned:"+publicID)
		}
		return err
	}
	return fmt.Errorf("account %s is still converging", publicID)
}

type TeardownAccountArgs struct {
	BillingAccountID int64 `json:"billing_account_id" river:"unique"`
}

func (TeardownAccountArgs) Kind() string { return "teardown_billing_account" }
func (TeardownAccountArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "heavy", MaxAttempts: 10, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeJobStates()}}
}

type AccountTeardown interface {
	TeardownSubscription(context.Context, types.TeardownSubscriptionReq) error
	DeleteBackup(context.Context, types.DeleteBackupReq) (types.Response, error)
	EnsureFTPS(context.Context, types.EnsureFTPSReq) (types.EnsureFTPSResult, error)
}

type TeardownAccountWorker struct {
	river.WorkerDefaults[TeardownAccountArgs]
	db    *sql.DB
	agent AccountTeardown
	river *river.Client[*sql.Tx]
}

func NewTeardownAccountWorker(db *sql.DB, agent AccountTeardown) *TeardownAccountWorker {
	return &TeardownAccountWorker{db: db, agent: agent}
}

func (w *TeardownAccountWorker) SetRiverClient(client *river.Client[*sql.Tx]) {
	w.river = client
}

const accountChildJobPredicate = `(
	j.args->>'subscription_id'=$1::bigint::text
	OR j.args->>'site_id' IN (SELECT id::text FROM sites WHERE subscription_id=$1::bigint)
	OR j.args->>'database_id' IN (SELECT id::text FROM databases WHERE subscription_id=$1::bigint)
	OR j.args->>'backup_id' IN (SELECT id::text FROM backups WHERE subscription_id=$1::bigint)
	OR (j.kind='restore_backup' AND j.args->>'restore_id' IN (
		SELECT restore.id::text FROM restore_runs restore
		JOIN backups backup ON backup.id=restore.backup_id
		WHERE backup.subscription_id=$1::bigint
	))
	OR (j.kind='configure_webmail' AND j.args->>'webmail_id' IN (
		SELECT webmail.id::text FROM webmail_hosts webmail
		JOIN sites site ON site.id=webmail.site_id
		WHERE site.subscription_id=$1::bigint
	))
	OR (j.kind='configure_dns_zone' AND j.args->>'zone_id' IN (
		SELECT zone.id::text FROM dns_zones zone
		JOIN sites site ON site.id=zone.site_id
		WHERE site.subscription_id=$1::bigint
	))
	OR (j.kind='converge_application' AND j.args->>'application_id' IN (
		SELECT id::text FROM application_instances WHERE subscription_id=$1::bigint
	))
	OR (j.kind IN ('deploy_php_release','rollback_php_release','reconcile_php_application','reconcile_php_workers')
		AND j.args->>'application_id' IN (
			SELECT id::text FROM php_applications WHERE subscription_id=$1::bigint
		))
	OR (j.kind='run_staging_operation' AND j.args->>'operation_id' IN (
		SELECT operation.id::text FROM staging_operations operation
		JOIN sites source ON source.id=operation.source_site_id
		WHERE source.subscription_id=$1::bigint
	))
	OR (j.kind='run_scheduled_task' AND j.args->>'run_id' IN (
		SELECT run.id::text FROM scheduled_task_runs run
		JOIN scheduled_tasks task ON task.id=run.task_id
		WHERE task.subscription_id=$1::bigint
	))
	OR (j.kind='finalize_billing_account' AND j.args->>'billing_account_id' IN (
		SELECT id::text FROM billing_accounts WHERE subscription_id=$1::bigint
	))
	OR (j.kind='reconcile_system' AND (
		EXISTS (
			SELECT 1 FROM jsonb_array_elements(COALESCE(j.args->'sites','[]'::jsonb)) site
			WHERE site->>'subscription_id'=$1::bigint::text
		)
		OR EXISTS (
			SELECT 1 FROM jsonb_array_elements(COALESCE(j.args->'databases','[]'::jsonb)) database
			WHERE database->>'subscription_id'=$1::bigint::text
		)
	))
)`

const phpEnvironmentSecretCleanupSQL = `WITH removed AS (
	DELETE FROM php_environment_bindings WHERE subscription_id=$1 RETURNING secret_id
)
DELETE FROM service_secrets WHERE id IN (SELECT secret_id FROM removed WHERE secret_id IS NOT NULL)`

func (w *TeardownAccountWorker) Work(ctx context.Context, job *river.Job[TeardownAccountArgs]) error {
	if w.db == nil {
		return errors.New("teardown database is unavailable")
	}
	if w.agent == nil {
		return errors.New("teardown agent is unavailable")
	}
	var subscriptionID int64
	var state, username, home string
	if err := w.db.QueryRowContext(ctx, `SELECT b.subscription_id,b.provisioning_state,a.username,a.home_path FROM billing_accounts b JOIN subscription_system_accounts a ON a.subscription_id=b.subscription_id WHERE b.id=$1`, job.Args.BillingAccountID).Scan(&subscriptionID, &state, &username, &home); errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	if state == "terminated" {
		return nil
	}
	if state != "terminating" {
		return errors.New("billing account is not terminating")
	}
	var childRunning bool
	runningQuery := fmt.Sprintf(`SELECT EXISTS(
SELECT 1 FROM river_job j
WHERE j.state='running' AND j.kind<>'teardown_billing_account' AND %s
)`, accountChildJobPredicate)
	if err := w.db.QueryRowContext(ctx, runningQuery, subscriptionID).Scan(&childRunning); err != nil {
		return err
	}
	if childRunning {
		return errors.New("account child provisioning is still running")
	}
	cancelQuery := fmt.Sprintf(`UPDATE river_job j SET state='cancelled',finalized_at=now()
WHERE j.state IN ('available','pending','retryable','scheduled')
  AND j.kind<>'teardown_billing_account'
  AND %s`, accountChildJobPredicate)
	if _, err := w.db.ExecContext(ctx, cancelQuery, subscriptionID); err != nil {
		return err
	}
	if err := w.db.QueryRowContext(ctx, runningQuery, subscriptionID).Scan(&childRunning); err != nil {
		return err
	}
	if childRunning {
		return errors.New("account child provisioning was claimed during teardown")
	}
	snapshot := types.TeardownSubscriptionReq{SubscriptionID: subscriptionID, Username: username, HomePath: home}
	siteRows, err := w.db.QueryContext(ctx, `SELECT id,domain FROM sites WHERE subscription_id=$1 ORDER BY id`, subscriptionID)
	if err != nil {
		return err
	}
	for siteRows.Next() {
		var siteID int64
		var domain string
		if err = siteRows.Scan(&siteID, &domain); err != nil {
			siteRows.Close()
			return err
		}
		snapshot.SiteIDs = append(snapshot.SiteIDs, siteID)
		snapshot.Domains = append(snapshot.Domains, domain)
	}
	if err = siteRows.Err(); err != nil {
		siteRows.Close()
		return err
	}
	siteRows.Close()
	snapshot.DatabaseNames, err = stringColumn(ctx, w.db, `SELECT db_name FROM databases WHERE subscription_id=$1 ORDER BY id`, subscriptionID)
	if err != nil {
		return err
	}
	snapshot.TaskIDs, err = int64Column(ctx, w.db, `SELECT id FROM scheduled_tasks WHERE subscription_id=$1 ORDER BY id`, subscriptionID)
	if err != nil {
		return err
	}
	snapshot.StagingOperationIDs, err = int64Column(ctx, w.db, `SELECT operation.id
FROM staging_operations operation
JOIN sites source ON source.id=operation.source_site_id
WHERE source.subscription_id=$1 ORDER BY operation.id`, subscriptionID)
	if err != nil {
		return err
	}
	snapshot.PHPApplicationIDs, err = int64Column(ctx, w.db, `SELECT id FROM php_applications WHERE subscription_id=$1 ORDER BY id`, subscriptionID)
	if err != nil {
		return err
	}
	snapshot.PHPWorkerIDs, err = int64Column(ctx, w.db, `SELECT id FROM php_workers WHERE subscription_id=$1 ORDER BY id`, subscriptionID)
	if err != nil {
		return err
	}
	deploymentRows, err := w.db.QueryContext(ctx, `SELECT deployment.id,application.site_id
FROM php_deployments deployment JOIN php_applications application ON application.id=deployment.application_id
WHERE deployment.subscription_id=$1 ORDER BY deployment.id`, subscriptionID)
	if err != nil {
		return err
	}
	for deploymentRows.Next() {
		var deployment types.TeardownPHPDeployment
		if err = deploymentRows.Scan(&deployment.DeploymentID, &deployment.SiteID); err != nil {
			deploymentRows.Close()
			return err
		}
		snapshot.PHPDeployments = append(snapshot.PHPDeployments, deployment)
	}
	if err = deploymentRows.Err(); err != nil {
		deploymentRows.Close()
		return err
	}
	deploymentRows.Close()
	if err = w.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM valkey_instances WHERE subscription_id=$1)`, subscriptionID).Scan(&snapshot.ValkeyPresent); err != nil {
		return err
	}
	applicationRows, err := w.db.QueryContext(ctx, `SELECT id,name FROM application_instances WHERE subscription_id=$1 ORDER BY id`, subscriptionID)
	if err != nil {
		return err
	}
	for applicationRows.Next() {
		var application types.TeardownApplication
		if err = applicationRows.Scan(&application.ID, &application.Name); err != nil {
			applicationRows.Close()
			return err
		}
		snapshot.Applications = append(snapshot.Applications, application)
	}
	if err = applicationRows.Err(); err != nil {
		applicationRows.Close()
		return err
	}
	applicationRows.Close()
	backupPaths, err := stringColumn(ctx, w.db, `SELECT archive_path FROM backups WHERE subscription_id=$1 AND archive_path<>'' ORDER BY id`, subscriptionID)
	if err != nil {
		return err
	}
	for _, archivePath := range backupPaths {
		response, deleteErr := w.agent.DeleteBackup(ctx, types.DeleteBackupReq{ArchivePath: archivePath})
		if deleteErr != nil {
			return deleteErr
		}
		if !response.OK {
			return errors.New(response.Error)
		}
	}
	if err := w.agent.TeardownSubscription(ctx, snapshot); err != nil {
		return err
	}
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Child tables cascade from sites/subscriptions where configured. Explicit deletes keep the tombstone subscription and billing identity.
	if _, err = tx.ExecContext(ctx, `SELECT set_config('nakpanel.account_teardown','on',true)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, phpEnvironmentSecretCleanupSQL, subscriptionID); err != nil {
		return err
	}
	for _, query := range []string{
		`DELETE FROM backups WHERE subscription_id=$1`,
		`DELETE FROM ftp_accounts WHERE subscription_id=$1`,
		`DELETE FROM valkey_instances WHERE subscription_id=$1`,
		`DELETE FROM scheduled_tasks WHERE subscription_id=$1`,
		`DELETE FROM application_instances WHERE subscription_id=$1`,
		`DELETE FROM mail_domains WHERE subscription_id=$1`,
		`DELETE FROM databases WHERE subscription_id=$1`,
		`DELETE FROM sites WHERE subscription_id=$1`,
		`DELETE FROM sftp_access_identities WHERE subscription_id=$1`,
	} {
		if _, err = tx.ExecContext(ctx, query, subscriptionID); err != nil {
			return err
		}
	}
	if w.river == nil {
		return errors.New("teardown River client is unavailable")
	}
	if _, err = w.river.InsertTx(ctx, tx, controlquota.NewConfigureMailArgs(), nil); err != nil {
		return fmt.Errorf("enqueue mail convergence after account teardown: %w", err)
	}
	{
		ftps := types.EnsureFTPSReq{Revision: time.Now().UnixNano(), State: "suspended"}
		rows, queryErr := tx.QueryContext(ctx, `SELECT ftp.id,account.username,COALESCE(ftp.site_id,0),COALESCE(site.domain,''),ftp.name,ftp.password_hash,
ftp.enabled AND sub.status='active' AND customer.status='active' AND (customer.reseller_id IS NULL OR reseller.status='active')
AND (customer.reseller_id IS NULL OR EXISTS (
    SELECT 1 FROM reseller_subscriptions allocation
    WHERE allocation.reseller_id=customer.reseller_id AND allocation.status='active'
))
FROM ftp_accounts ftp
JOIN subscriptions sub ON sub.id=ftp.subscription_id
JOIN customers customer ON customer.id=sub.customer_id
JOIN subscription_system_accounts account ON account.subscription_id=sub.id
LEFT JOIN sites site ON site.id=ftp.site_id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
ORDER BY ftp.id`)
		if queryErr != nil {
			return queryErr
		}
		for rows.Next() {
			var account types.EnsureFTPSAccount
			if err = rows.Scan(&account.ID, &account.Username, &account.SiteID, &account.Domain, &account.Name, &account.PasswordHash, &account.Enabled); err != nil {
				rows.Close()
				return err
			}
			if account.Enabled {
				ftps.State = "active"
			}
			ftps.Accounts = append(ftps.Accounts, account)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if _, err = w.agent.EnsureFTPS(ctx, ftps); err != nil {
			return fmt.Errorf("reconcile global FTPS after account teardown: %w", err)
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE subscription_system_accounts SET desired_state='terminated',applied_state='terminated',convergence_status='in_sync',last_error='',updated_at=now() WHERE subscription_id=$1`, subscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE subscriptions SET status='cancelled',updated_at=now() WHERE id=$1`, subscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE billing_accounts SET provisioning_state='terminated',terminated_at=now(),last_error='',updated_at=now() WHERE id=$1`, job.Args.BillingAccountID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_label,subscription_id,action,target_type,target_id,metadata) VALUES('system:billing-teardown',$1,'account.purged','billing_account',$2,jsonb_build_object('completed_at',$3::timestamptz))`, subscriptionID, job.Args.BillingAccountID, time.Now()); err != nil {
		return err
	}
	return tx.Commit()
}

func stringColumn(ctx context.Context, db *sql.DB, query string, arg any) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var value string
		if err = rows.Scan(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func int64Column(ctx context.Context, db *sql.DB, query string, arg any) ([]int64, error) {
	rows, err := db.QueryContext(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var value int64
		if err = rows.Scan(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}
func activeJobStates() []rivertype.JobState {
	return []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled}
}
