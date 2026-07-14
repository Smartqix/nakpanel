package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type SetHostingStateArgs struct {
	SiteID      int64  `json:"site_id" river:"unique"`
	SettingsKey string `json:"settings_key" river:"unique"`
	Username    string `json:"username"`
	Domain      string `json:"domain"`
	PHPVersion  string `json:"php_version"`
	State       string `json:"state"`
}

type SyncPlanArgs struct {
	PlanID int64 `json:"plan_id" river:"unique"`
}

type SyncAddonArgs struct {
	AddonID int64 `json:"addon_id" river:"unique"`
}

func (SyncPlanArgs) Kind() string { return "sync_plan_subscriptions" }
func (a SyncPlanArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable,
		rivertype.JobStatePending,
		rivertype.JobStateRetryable,
		rivertype.JobStateRunning,
		rivertype.JobStateScheduled,
	}}}
}

func (SyncAddonArgs) Kind() string { return "sync_addon_subscriptions" }
func (a SyncAddonArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable,
		rivertype.JobStatePending,
		rivertype.JobStateRetryable,
		rivertype.JobStateRunning,
		rivertype.JobStateScheduled,
	}}}
}

type SyncPlanWorker struct {
	river.WorkerDefaults[SyncPlanArgs]
	db *sql.DB
}

func NewSyncPlanWorker(db *sql.DB) *SyncPlanWorker { return &SyncPlanWorker{db: db} }

func (w *SyncPlanWorker) Work(ctx context.Context, job *river.Job[SyncPlanArgs]) error {
	if w.db == nil {
		return errors.New("plan synchronization database is not configured")
	}
	return NewSQLStore(w.db).SyncPlan(ctx, job.Args.PlanID)
}

type SyncAddonWorker struct {
	river.WorkerDefaults[SyncAddonArgs]
	db *sql.DB
}

func NewSyncAddonWorker(db *sql.DB) *SyncAddonWorker { return &SyncAddonWorker{db: db} }

func (w *SyncAddonWorker) Work(ctx context.Context, job *river.Job[SyncAddonArgs]) error {
	if w.db == nil {
		return errors.New("add-on synchronization database is not configured")
	}
	return NewSQLStore(w.db).SyncAddon(ctx, job.Args.AddonID)
}

func (SetHostingStateArgs) Kind() string { return "set_hosting_state" }
func (a SetHostingStateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled}}}
}

func siteSettingsKey(state, phpVersion string, httpsRedirect bool, limits types.SiteResourceLimits) string {
	encoded, _ := json.Marshal(limits)
	return fmt.Sprintf("%s|%s|%t|%s", state, phpVersion, httpsRedirect, encoded)
}

type HostingStateAgent interface {
	SetHostingState(context.Context, types.SetHostingStateReq) (types.Response, error)
}
type SiteRuntimeAgent interface {
	ApplySiteRuntime(context.Context, types.ApplySiteRuntimeReq) (types.Response, error)
}
type SetHostingStateWorker struct {
	river.WorkerDefaults[SetHostingStateArgs]
	agent HostingStateAgent
	db    *sql.DB
}

func NewSetHostingStateWorker(agent HostingStateAgent, db *sql.DB) *SetHostingStateWorker {
	return &SetHostingStateWorker{agent: agent, db: db}
}
func (w *SetHostingStateWorker) Work(ctx context.Context, job *river.Job[SetHostingStateArgs]) error {
	if w.agent == nil {
		return errors.New("hosting state agent is not configured")
	}
	state := job.Args.State
	for attempt := 0; attempt < 3; attempt++ {
		var err error
		state, err = w.desiredHostingState(ctx, job.Args.SiteID, state)
		if err != nil {
			return err
		}
		var resp types.Response
		var agentErr error
		runtimeReq := types.ApplySiteRuntimeReq{}
		runtimeAgent, useRuntime := w.agent.(SiteRuntimeAgent)
		if useRuntime && w.db != nil {
			runtimeReq, agentErr = w.siteRuntimeRequest(ctx, job.Args.SiteID, state)
			if agentErr == nil {
				state = runtimeReq.State
				resp, agentErr = runtimeAgent.ApplySiteRuntime(ctx, runtimeReq)
			}
		} else {
			resp, agentErr = w.agent.SetHostingState(ctx, types.SetHostingStateReq{Username: job.Args.Username, Domain: job.Args.Domain, PHPVersion: job.Args.PHPVersion, State: state})
		}
		if agentErr == nil && !resp.OK {
			agentErr = errors.New(resp.Error)
		}
		if agentErr != nil {
			w.recordHostingFailure(ctx, job.Args.SiteID, state, agentErr)
			return agentErr
		}
		if w.db == nil {
			return nil
		}
		latest, err := w.desiredHostingState(ctx, job.Args.SiteID, state)
		if err != nil {
			return err
		}
		if latest != state {
			state = latest
			continue
		}
		if useRuntime {
			_, err = w.db.ExecContext(ctx, `UPDATE sites SET status=$2,php_version=$3,https_redirect=$4,settings_status='in_sync',settings_error='',last_error='',updated_at=now() WHERE id=$1`, job.Args.SiteID, state, runtimeReq.DesiredPHPVersion, runtimeReq.HTTPSRedirect)
		} else {
			_, err = w.db.ExecContext(ctx, `UPDATE sites SET status=$2,last_error='',updated_at=now() WHERE id=$1`, job.Args.SiteID, state)
		}
		if err != nil {
			return err
		}
		metadata, marshalErr := json.Marshal(map[string]string{"state": state})
		if marshalErr != nil {
			return fmt.Errorf("encode hosting convergence audit: %w", marshalErr)
		}
		if _, auditErr := w.db.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata)
SELECT u.id,s.customer_id,s.subscription_id,'hosting.state_converged','site',s.id,$2::jsonb
FROM sites s CROSS JOIN LATERAL (SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1) u WHERE s.id=$1`, job.Args.SiteID, string(metadata)); auditErr != nil {
			return fmt.Errorf("record hosting convergence audit: %w", auditErr)
		}
		return nil
	}
	err := errors.New("hosting intent changed repeatedly during convergence")
	w.recordHostingFailure(ctx, job.Args.SiteID, state, err)
	return err
}

func (w *SetHostingStateWorker) desiredHostingState(ctx context.Context, siteID int64, fallback string) (string, error) {
	if w.db == nil {
		return fallback, nil
	}
	var state string
	err := w.db.QueryRowContext(ctx, `SELECT CASE WHEN s.desired_status='active' AND c.status='active' AND sub.status='active' AND (c.reseller_id IS NULL OR (ra.status='active' AND rs.id IS NOT NULL)) THEN 'active' ELSE 'suspended' END
FROM sites s JOIN subscriptions sub ON sub.id=s.subscription_id JOIN customers c ON c.id=sub.customer_id
LEFT JOIN reseller_accounts ra ON ra.id=c.reseller_id LEFT JOIN reseller_subscriptions rs ON rs.reseller_id=ra.id AND rs.status='active'
WHERE s.id=$1`, siteID).Scan(&state)
	return state, err
}

func (w *SetHostingStateWorker) siteRuntimeRequest(ctx context.Context, siteID int64, fallbackState string) (types.ApplySiteRuntimeReq, error) {
	var req types.ApplySiteRuntimeReq
	var tlsStatus string
	var documentRoot string
	tx, err := w.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return req, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `SELECT s.username,s.domain,s.document_root,s.php_version,s.desired_php_version,s.desired_https_redirect,s.tls_status,s.tls_cert_path,s.tls_key_path,
CASE WHEN s.desired_status='active' AND c.status='active' AND sub.status='active' AND (c.reseller_id IS NULL OR (ra.status='active' AND rs.id IS NOT NULL)) THEN 'active' ELSE 'suspended' END
FROM sites s JOIN subscriptions sub ON sub.id=s.subscription_id JOIN customers c ON c.id=sub.customer_id
LEFT JOIN reseller_accounts ra ON ra.id=c.reseller_id LEFT JOIN reseller_subscriptions rs ON rs.reseller_id=ra.id AND rs.status='active'
WHERE s.id=$1`, siteID).Scan(&req.Username, &req.Domain, &documentRoot, &req.CurrentPHPVersion, &req.DesiredPHPVersion, &req.HTTPSRedirect, &tlsStatus, &req.TLSCertPath, &req.TLSKeyPath, &req.State)
	if err != nil {
		return req, err
	}
	req.SharedAccount = IsSharedSiteDocumentRoot(req.Username, req.Domain, documentRoot)
	req.Limits, err = EffectiveSiteResourceLimitsTx(ctx, tx, siteID)
	if err != nil {
		return req, err
	}
	if req.State == "" {
		req.State = fallbackState
	}
	if tlsStatus != "active" {
		req.TLSCertPath = ""
		req.TLSKeyPath = ""
		req.HTTPSRedirect = false
	}
	return req, tx.Commit()
}

func (w *SetHostingStateWorker) recordHostingFailure(ctx context.Context, siteID int64, state string, convergenceErr error) {
	if w.db == nil {
		return
	}
	_, _ = w.db.ExecContext(ctx, `UPDATE sites SET last_error=$2,settings_status='failed',settings_error=$2 WHERE id=$1`, siteID, convergenceErr.Error())
	metadata, _ := json.Marshal(map[string]string{"state": state, "error": convergenceErr.Error()})
	_, _ = w.db.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata)
SELECT u.id,s.customer_id,s.subscription_id,'hosting.convergence_failed','site',s.id,$2::jsonb
FROM sites s CROSS JOIN LATERAL (SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1) u WHERE s.id=$1`, siteID, string(metadata))
}

func (s *SQLStore) enqueueCustomerHostingStateTx(ctx context.Context, tx *sql.Tx, customerID int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT r.id,r.username,r.domain,r.php_version,
CASE WHEN c.status='active' AND sub.status='active' AND (c.reseller_id IS NULL OR (ra.status='active' AND rs.id IS NOT NULL)) THEN 'active' ELSE 'suspended' END
,r.desired_php_version,r.desired_https_redirect
FROM sites r JOIN subscriptions sub ON sub.id=r.subscription_id JOIN customers c ON c.id=sub.customer_id
LEFT JOIN reseller_accounts ra ON ra.id=c.reseller_id LEFT JOIN reseller_subscriptions rs ON rs.reseller_id=ra.id AND rs.status='active'
WHERE c.id=$1 ORDER BY r.id`, customerID)
	if err != nil {
		return err
	}
	var jobs []SetHostingStateArgs
	desiredPHPBySite := make(map[int64]string)
	desiredRedirectBySite := make(map[int64]bool)
	for rows.Next() {
		var a SetHostingStateArgs
		var desiredPHP string
		var desiredRedirect bool
		if err := rows.Scan(&a.SiteID, &a.Username, &a.Domain, &a.PHPVersion, &a.State, &desiredPHP, &desiredRedirect); err != nil {
			rows.Close()
			return err
		}
		desiredPHPBySite[a.SiteID] = desiredPHP
		desiredRedirectBySite[a.SiteID] = desiredRedirect
		jobs = append(jobs, a)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for i := range jobs {
		a := &jobs[i]
		limits, err := EffectiveSiteResourceLimitsTx(ctx, tx, a.SiteID)
		if err != nil {
			return err
		}
		a.SettingsKey = siteSettingsKey(a.State, desiredPHPBySite[a.SiteID], desiredRedirectBySite[a.SiteID], limits)
		next := a.State
		if s.river != nil {
			next = map[string]string{"active": "activating", "suspended": "suspending"}[a.State]
		}
		if _, err := tx.ExecContext(ctx, `UPDATE sites SET status=$2,last_error='',updated_at=now() WHERE id=$1`, a.SiteID, next); err != nil {
			return err
		}
		if s.river != nil {
			if _, err := s.river.InsertTx(ctx, tx, *a, nil); err != nil {
				return fmt.Errorf("enqueue hosting state: %w", err)
			}
		}
	}
	return nil
}

func (s *SQLStore) enqueueSubscriptionHostingStateTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) error {
	var customerID int64
	if err := tx.QueryRowContext(ctx, `SELECT customer_id FROM subscriptions WHERE id=$1`, subscriptionID).Scan(&customerID); err != nil {
		return err
	}
	return s.enqueueCustomerHostingStateTx(ctx, tx, customerID)
}

func (s *SQLStore) enqueueResellerHostingStateTx(ctx context.Context, tx *sql.Tx, resellerID int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM customers WHERE reseller_id=$1 ORDER BY id`, resellerID)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if err := s.enqueueCustomerHostingStateTx(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}
