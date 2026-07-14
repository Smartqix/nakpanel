package provisioningapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

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
}

type TeardownAccountWorker struct {
	river.WorkerDefaults[TeardownAccountArgs]
	db    *sql.DB
	agent AccountTeardown
}

func NewTeardownAccountWorker(db *sql.DB, agent AccountTeardown) *TeardownAccountWorker {
	return &TeardownAccountWorker{db: db, agent: agent}
}
func (w *TeardownAccountWorker) Work(ctx context.Context, job *river.Job[TeardownAccountArgs]) error {
	if w.db == nil {
		return errors.New("teardown database is unavailable")
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
	if err := w.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM river_job j WHERE j.state='running' AND j.kind<>'teardown_billing_account' AND (j.args->>'subscription_id'=$1::bigint::text OR j.args->>'site_id' IN (SELECT id::text FROM sites WHERE subscription_id=$1::bigint)))`, subscriptionID).Scan(&childRunning); err != nil {
		return err
	}
	if childRunning {
		return errors.New("account child provisioning is still running")
	}
	if _, err := w.db.ExecContext(ctx, `UPDATE river_job SET state='cancelled',finalized_at=now() WHERE state IN ('available','pending','retryable','scheduled') AND kind<>'teardown_billing_account' AND (args->>'subscription_id'=$1::bigint::text OR args->>'site_id' IN (SELECT id::text FROM sites WHERE subscription_id=$1::bigint))`, subscriptionID); err != nil {
		return err
	}
	snapshot := types.TeardownSubscriptionReq{SubscriptionID: subscriptionID, Username: username, HomePath: home}
	snapshot.Domains, _ = stringColumn(ctx, w.db, `SELECT domain FROM sites WHERE subscription_id=$1 ORDER BY id`, subscriptionID)
	snapshot.DatabaseNames, _ = stringColumn(ctx, w.db, `SELECT db_name FROM databases WHERE subscription_id=$1 ORDER BY id`, subscriptionID)
	if w.agent != nil {
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
	}
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Child tables cascade from sites/subscriptions where configured. Explicit deletes keep the tombstone subscription and billing identity.
	for _, query := range []string{`DELETE FROM backups WHERE subscription_id=$1`, `DELETE FROM databases WHERE subscription_id=$1`, `DELETE FROM sites WHERE subscription_id=$1`, `DELETE FROM sftp_access_identities WHERE subscription_id=$1`, `DELETE FROM scheduled_tasks WHERE subscription_id=$1`, `DELETE FROM application_instances WHERE subscription_id=$1`, `DELETE FROM mail_domains WHERE subscription_id=$1`} {
		if _, err = tx.ExecContext(ctx, query, subscriptionID); err != nil {
			return err
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
func activeJobStates() []rivertype.JobState {
	return []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled}
}
