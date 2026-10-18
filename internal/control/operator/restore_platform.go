package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

// WaitRestoreConvergence waits for the actual reconciliation job and the PHP
// work it queued, rather than treating successful queue insertion as recovery.
func (s *Service) WaitRestoreConvergence(ctx context.Context, runID int64, timeout time.Duration, requiredJobs ...int64) error {
	if requiredJobs == nil {
		requiredJobs = []int64{}
	}
	requiredJSON, _ := json.Marshal(requiredJobs)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		var status, lastError, job string
		var total, ok int
		err := s.db.QueryRowContext(ctx, `SELECT r.status,r.sites_total,r.sites_ok,r.last_error,
COALESCE((SELECT state::text FROM river_job WHERE kind='reconcile_system' AND args->>'run_id'=r.id::text ORDER BY id DESC LIMIT 1),'missing')
FROM reconciliation_runs r WHERE r.id=$1`, runID).Scan(&status, &total, &ok, &lastError, &job)
		if err != nil {
			return fmt.Errorf("read restore reconciliation: %w", err)
		}
		if status == "failed" || job == "discarded" || job == "cancelled" || job == "missing" {
			return fmt.Errorf("restore reconciliation failed (run %d, state %s, job %s)", runID, status, job)
		}
		if status == "active" && job == "completed" {
			if total != ok || lastError != "" {
				return fmt.Errorf("restore reconciliation did not regenerate all sites (%d/%d)", ok, total)
			}
			var pending, failed, attention int
			err = s.db.QueryRowContext(ctx, `SELECT
(SELECT count(*) FROM river_job WHERE kind IN ('reconcile_php_application','reconcile_php_workers','converge_subscription','reconcile_applications','converge_application','configure_mail') AND (created_at >= (SELECT created_at FROM reconciliation_runs WHERE id=$1) OR id IN (SELECT jsonb_array_elements_text($2::jsonb)::bigint)) AND state NOT IN ('completed','discarded','cancelled')),
(SELECT count(*) FROM php_applications WHERE convergence_status='failed' OR last_error<>'') + (SELECT count(*) FROM php_workers WHERE convergence_status='failed' OR last_error<>'') + (SELECT count(*) FROM application_instances WHERE convergence_status='failed' OR last_error<>'') + (SELECT count(*) FROM subscription_system_accounts WHERE convergence_status='failed' OR last_error<>'') + (SELECT count(*) FROM river_job WHERE (created_at >= (SELECT created_at FROM reconciliation_runs WHERE id=$1) OR id IN (SELECT jsonb_array_elements_text($2::jsonb)::bigint)) AND kind IN ('reconcile_php_application','reconcile_php_workers','converge_subscription','converge_application','reconcile_applications') AND state IN ('discarded','cancelled')),
(SELECT count(*) FROM notifications WHERE resolved_at IS NULL AND dedupe_key LIKE 'maintenance:reconcile:%' AND created_at >= (SELECT created_at FROM reconciliation_runs WHERE id=$1))`, runID, string(requiredJSON)).Scan(&pending, &failed, &attention)
			if err != nil {
				return fmt.Errorf("read restore resource convergence: %w", err)
			}
			if failed > 0 {
				return fmt.Errorf("restore has %d failed runtime/account resources", failed)
			}
			if attention > 0 {
				return fmt.Errorf("restore has %d resources requiring attention", attention)
			}
			if pending == 0 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("restore convergence incomplete: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

// ValidateRestoredDatabases exercises the agent's actual MariaDB existence
// check. Its detection-only findings are fatal here even though ordinary
// reconciliation allows them for operator follow-up.
func (s *Service) ValidateRestoredDatabases(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id,customer_id,subscription_id,db_name FROM databases WHERE status='active' ORDER BY id`)
	if err != nil {
		return err
	}
	var req types.ReconcileSystemReq
	for rows.Next() {
		var db types.ReconcileDatabaseReq
		if err := rows.Scan(&db.DatabaseID, &db.CustomerID, &db.SubscriptionID, &db.Name); err != nil {
			rows.Close()
			return err
		}
		req.Databases = append(req.Databases, db)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	resp, err := s.agent.ReconcileSystem(ctx, req)
	if err != nil {
		return err
	}
	if !resp.OK {
		return errors.New("restored database validation failed")
	}
	var result types.ReconcileSystemResult
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return fmt.Errorf("decode restored database validation: %w", err)
	}
	if result.Failed > 0 || result.Attention > 0 {
		return fmt.Errorf("restored database validation reported %d failed and %d attention resources", result.Failed, result.Attention)
	}
	if len(result.Resources) != len(req.Databases) {
		return errors.New("restored database validation returned an incomplete inventory")
	}
	return nil
}

type restoreAccountRevision struct{ SubscriptionID, Revision int64 }

func restoreResourceJobs(accounts []restoreAccountRevision) []river.JobArgs {
	jobs := make([]river.JobArgs, 0, len(accounts)+1)
	for _, a := range accounts {
		jobs = append(jobs, controlquota.ConvergeSubscriptionArgs{SubscriptionID: a.SubscriptionID, Revision: a.Revision})
	}
	return append(jobs, controlquota.ReconcileApplicationsArgs{})
}

// QueueRestoreResources replays existing desired revisions through the normal
// account and container provisioning boundaries. It never increments revisions
// or rewrites selected PHP, grants, shell, FTPS, cache or application intent.
func (s *Service) QueueRestoreResources(ctx context.Context) ([]int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT subscription_id,desired_revision FROM subscription_system_accounts ORDER BY subscription_id`)
	if err != nil {
		return nil, err
	}
	var accounts []restoreAccountRevision
	for rows.Next() {
		var a restoreAccountRevision
		if err := rows.Scan(&a.SubscriptionID, &a.Revision); err != nil {
			rows.Close()
			return nil, err
		}
		accounts = append(accounts, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	var jobIDs []int64
	for _, args := range restoreResourceJobs(accounts) {
		inserted, err := s.river.InsertTx(ctx, tx, args, nil)
		if err != nil {
			return nil, err
		}
		jobIDs = append(jobIDs, inserted.Job.ID)
	}
	return jobIDs, tx.Commit()
}
