package quota

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	ftpLoginRE       = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,31}$`)
	cryptSHA512RE    = regexp.MustCompile(`^\$6\$`)
	gitBranchRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	gitWebhookHashRE = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func (s *SQLStore) UpsertFTPAccount(ctx context.Context, subscriptionID, actorID int64, input types.FTPAccountInput, passwordHash string) (int64, error) {
	input.Name = strings.ToLower(strings.TrimSpace(input.Name))
	if !ftpLoginRE.MatchString(input.Name) || (passwordHash != "" && !cryptSHA512RE.MatchString(passwordHash)) {
		return 0, errors.New("valid FTPS account name and password are required")
	}
	return s.upsertAccountService(ctx, subscriptionID, func(tx *sql.Tx, policy types.HostingPolicy) (int64, error) {
		if !policy.Permissions.FTPS || !policy.Access.FTPSEnabled {
			return 0, errors.New("FTPS is disabled by the subscription policy")
		}
		if err := ensureSiteBelongsTx(ctx, tx, subscriptionID, input.SiteID); err != nil {
			return 0, err
		}
		if input.ID == 0 {
			if passwordHash == "" {
				return 0, errors.New("a password is required for a new FTPS account")
			}
			if err := enforceServiceCountTx(ctx, tx, `ftp_accounts`, subscriptionID, policy.Resources.MaxFTPAccounts); err != nil {
				return 0, err
			}
		}
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO ftp_accounts(id,subscription_id,site_id,name,password_hash,enabled)
VALUES(CASE WHEN $1=0 THEN nextval('ftp_accounts_id_seq') ELSE $1 END,$2,NULLIF($3,0),$4,$5,$6)
ON CONFLICT(id) DO UPDATE SET site_id=EXCLUDED.site_id,name=EXCLUDED.name,
password_hash=CASE WHEN EXCLUDED.password_hash='' THEN ftp_accounts.password_hash ELSE EXCLUDED.password_hash END,
enabled=EXCLUDED.enabled,convergence_status='pending',last_error='',updated_at=now()
WHERE ftp_accounts.subscription_id=EXCLUDED.subscription_id RETURNING id`,
			input.ID, subscriptionID, input.SiteID, input.Name, passwordHash, input.Enabled).Scan(&id)
		return id, err
	})
}

func (s *SQLStore) DeleteFTPAccount(ctx context.Context, subscriptionID, id int64) error {
	return s.deleteAccountService(ctx, subscriptionID, `DELETE FROM ftp_accounts WHERE id=$1 AND subscription_id=$2`, id)
}

func (s *SQLStore) UpsertGitRepository(ctx context.Context, subscriptionID, actorID, siteID int64, input types.GitRepositoryInput) (int64, error) {
	input.Mode = strings.ToLower(strings.TrimSpace(input.Mode))
	input.Branch = strings.TrimSpace(input.Branch)
	target := filepath.Clean(strings.TrimSpace(input.DeployTarget))
	if target == "" {
		target = "."
	}
	if (input.Mode != "remote" && input.Mode != "hosted") || !gitBranchRE.MatchString(input.Branch) ||
		filepath.IsAbs(target) || target == ".." || strings.HasPrefix(target, ".."+string(filepath.Separator)) ||
		strings.ContainsAny(input.RemoteURL, "\x00\r\n") {
		return 0, errors.New("invalid Git repository settings")
	}
	if input.Mode == "remote" && strings.TrimSpace(input.RemoteURL) == "" {
		return 0, errors.New("a remote URL is required")
	}
	if input.Mode == "remote" {
		parsed, err := url.Parse(input.RemoteURL)
		if err != nil || parsed.User != nil || (parsed.Scheme != "ssh" && parsed.Scheme != "https") || parsed.Hostname() == "" {
			return 0, errors.New("remote URL must be credential-free ssh or https")
		}
		if parsed.Scheme == "ssh" {
			fields := strings.Fields(input.KnownHostKey)
			if len(fields) < 3 || strings.ContainsAny(input.KnownHostKey, "\r\n") || fields[0] != parsed.Hostname() {
				return 0, errors.New("SSH repositories require a verified host key for the remote hostname")
			}
		}
	}
	return s.upsertAccountService(ctx, subscriptionID, func(tx *sql.Tx, policy types.HostingPolicy) (int64, error) {
		if !policy.Permissions.Git {
			return 0, errors.New("Git is disabled by the subscription policy")
		}
		if err := ensureSiteBelongsTx(ctx, tx, subscriptionID, siteID); err != nil {
			return 0, err
		}
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO git_repositories(site_id,mode,remote_url,branch,deploy_target,automatic,known_host_key)
VALUES($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT(site_id) DO UPDATE SET mode=EXCLUDED.mode,remote_url=EXCLUDED.remote_url,branch=EXCLUDED.branch,
deploy_target=EXCLUDED.deploy_target,automatic=EXCLUDED.automatic,known_host_key=EXCLUDED.known_host_key,
convergence_status='pending',last_error='',updated_at=now()
RETURNING id`, siteID, input.Mode, strings.TrimSpace(input.RemoteURL), input.Branch, target, input.Automatic, strings.TrimSpace(input.KnownHostKey)).Scan(&id)
		return id, err
	})
}

func (s *SQLStore) QueueGitDeployment(ctx context.Context, subscriptionID, siteID int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err = lockActiveSubscriptionTx(ctx, tx, subscriptionID); err != nil {
		return 0, err
	}
	if err = requireGitPermissionTx(ctx, tx, subscriptionID); err != nil {
		return 0, err
	}
	var repositoryID int64
	if err = tx.QueryRowContext(ctx, `SELECT repository.id FROM git_repositories repository
JOIN sites site ON site.id=repository.site_id
WHERE repository.site_id=$1 AND site.subscription_id=$2 FOR UPDATE`, siteID, subscriptionID).Scan(&repositoryID); err != nil {
		return 0, err
	}
	var deploymentID int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO git_deployments(repository_id,revision,status)
VALUES($1,'','pending') RETURNING id`, repositoryID).Scan(&deploymentID); err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE git_repositories SET convergence_status='pending',last_error='',updated_at=now() WHERE id=$1`, repositoryID); err != nil {
		return 0, err
	}
	if err = s.markSubscriptionPendingTx(ctx, tx, subscriptionID); err != nil {
		return 0, err
	}
	return deploymentID, tx.Commit()
}

func (s *SQLStore) SetGitWebhook(ctx context.Context, subscriptionID, siteID int64, tokenHash string) error {
	if tokenHash != "" && !gitWebhookHashRE.MatchString(tokenHash) {
		return errors.New("invalid webhook credential hash")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockActiveSubscriptionTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	if err = requireGitPermissionTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE git_repositories repository SET webhook_secret_hash=$3,updated_at=now()
FROM sites site WHERE repository.site_id=$1 AND site.id=repository.site_id AND site.subscription_id=$2`, siteID, subscriptionID, tokenHash)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

func (s *SQLStore) TriggerGitWebhook(ctx context.Context, siteID int64, tokenHash string) error {
	if siteID <= 0 || !gitWebhookHashRE.MatchString(tokenHash) {
		return sql.ErrNoRows
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var subscriptionID int64
	var repositoryID int64
	var storedHash string
	var automatic bool
	if err = tx.QueryRowContext(ctx, `SELECT site.subscription_id,repository.id,repository.webhook_secret_hash,repository.automatic
FROM git_repositories repository JOIN sites site ON site.id=repository.site_id
WHERE repository.site_id=$1`, siteID).Scan(&subscriptionID, &repositoryID, &storedHash, &automatic); err != nil {
		return err
	}
	if err = LockSubscriptionMutationTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	var lockedSubscriptionID int64
	if err = tx.QueryRowContext(ctx, `SELECT site.subscription_id,repository.id,repository.webhook_secret_hash,repository.automatic
FROM git_repositories repository JOIN sites site ON site.id=repository.site_id
WHERE repository.site_id=$1 FOR UPDATE`, siteID).Scan(&lockedSubscriptionID, &repositoryID, &storedHash, &automatic); err != nil {
		return err
	}
	if lockedSubscriptionID != subscriptionID {
		return errors.New("repository ownership changed while acquiring its mutation lock")
	}
	if err = lockActiveSubscriptionTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	if err = requireGitPermissionTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	if storedHash == "" || subtle.ConstantTimeCompare([]byte(storedHash), []byte(tokenHash)) != 1 || !automatic {
		return sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO git_deployments(repository_id,revision,status) VALUES($1,'','pending')`, repositoryID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE git_repositories SET convergence_status='pending',last_error='',updated_at=now() WHERE id=$1`, repositoryID); err != nil {
		return err
	}
	if err = s.markSubscriptionPendingTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_label,subscription_id,action,target_type,target_id,metadata)
VALUES('git-webhook',$2,'git.webhook_triggered','git_repository',$1,'{}'::jsonb)`, repositoryID, subscriptionID); err != nil {
		return err
	}
	return tx.Commit()
}

func requireGitPermissionTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) error {
	base, patch, err := effectiveSubscriptionPolicyTx(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	effective, err := controlpolicy.Resolve(base, patch, nil)
	if err != nil {
		return err
	}
	return requireGitPermission(effective)
}

func requireGitPermission(policy types.HostingPolicy) error {
	if policy.Permissions.Git {
		return nil
	}
	return errors.New("Git is disabled by the subscription policy")
}

func (s *SQLStore) UpsertValkey(ctx context.Context, subscriptionID, actorID int64, input types.ValkeyInput, aclHash string) error {
	input.DesiredState = strings.ToLower(strings.TrimSpace(input.DesiredState))
	if input.DesiredState != "enabled" && input.DesiredState != "disabled" {
		return errors.New("Valkey state must be enabled or disabled")
	}
	if input.MemoryMB < 16 || input.MaxClients < 1 || input.IdleTimeoutSeconds < 0 || input.CPUPercent < 1 || input.ProcessLimit < 8 {
		return errors.New("invalid Valkey limits")
	}
	returnedID, err := s.upsertAccountService(ctx, subscriptionID, func(tx *sql.Tx, policy types.HostingPolicy) (int64, error) {
		if !policy.Permissions.Valkey || !policy.Valkey.Enabled {
			return 0, errors.New("Valkey is disabled by the subscription policy")
		}
		if exceedsFiniteLimit(input.MemoryMB, policy.Resources.ValkeyMemoryMB) {
			return 0, fmt.Errorf("%w: Valkey memory exceeds the subscription limit", ErrExceeded)
		}
		if exceedsFiniteLimit(input.MemoryMB, policy.Valkey.MemoryMB) {
			return 0, fmt.Errorf("%w: Valkey memory exceeds the policy limit", ErrExceeded)
		}
		for _, limit := range []struct {
			name           string
			value, ceiling int
		}{
			{"maximum clients", input.MaxClients, policy.Valkey.MaxClients},
			{"idle timeout", input.IdleTimeoutSeconds, policy.Valkey.IdleTimeoutSeconds},
			{"CPU quota", input.CPUPercent, policy.Valkey.CPUPercent},
			{"process limit", input.ProcessLimit, policy.Valkey.ProcessLimit},
		} {
			if exceedsFiniteLimit(limit.value, limit.ceiling) {
				return 0, fmt.Errorf("%w: Valkey %s exceeds the policy limit", ErrExceeded, limit.name)
			}
		}
		var capacity, committed int
		if err := tx.QueryRowContext(ctx, `SELECT valkey_capacity_mb FROM settings WHERE id FOR UPDATE`).Scan(&capacity); err != nil {
			return 0, err
		}
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(memory_mb),0) FROM valkey_instances WHERE desired_state='enabled' AND subscription_id<>$1`, subscriptionID).Scan(&committed); err != nil {
			return 0, err
		}
		if capacity > 0 && input.DesiredState == "enabled" && committed+input.MemoryMB > capacity {
			return 0, fmt.Errorf("%w: server cache capacity is exhausted", ErrExceeded)
		}
		if aclHash == "" {
			if err := tx.QueryRowContext(ctx, `SELECT acl_hash FROM valkey_instances WHERE subscription_id=$1`, subscriptionID).Scan(&aclHash); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return 0, errors.New("a credential is required for a new Valkey instance")
				}
				return 0, err
			}
		}
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO valkey_instances(subscription_id,desired_state,memory_mb,max_clients,idle_timeout_seconds,cpu_percent,process_limit,acl_hash,flush_requested)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT(subscription_id) DO UPDATE SET desired_state=EXCLUDED.desired_state,memory_mb=EXCLUDED.memory_mb,
max_clients=EXCLUDED.max_clients,idle_timeout_seconds=EXCLUDED.idle_timeout_seconds,cpu_percent=EXCLUDED.cpu_percent,
process_limit=EXCLUDED.process_limit,acl_hash=EXCLUDED.acl_hash,
flush_requested=valkey_instances.flush_requested OR EXCLUDED.flush_requested,
convergence_status='pending',last_error='',updated_at=now()
RETURNING id`, subscriptionID, input.DesiredState, input.MemoryMB, input.MaxClients, input.IdleTimeoutSeconds, input.CPUPercent, input.ProcessLimit, aclHash, input.Flush).Scan(&id)
		return id, err
	})
	_ = returnedID
	return err
}

func exceedsFiniteLimit(value, limit int) bool {
	return limit != -1 && value > limit
}

func (s *SQLStore) ScheduledTaskRunRequest(ctx context.Context, subscriptionID, taskID int64) (types.RunScheduledTaskReq, error) {
	var req types.RunScheduledTaskReq
	err := s.db.QueryRowContext(ctx, `SELECT task.id,task.subscription_id,COALESCE(task.site_id,0),account.username,
COALESCE(site.domain,''),COALESCE(site.php_version,''),task.kind,task.command,task.url,task.script_path,task.timeout_seconds,task.working_directory
FROM scheduled_tasks task
JOIN subscription_system_accounts account ON account.subscription_id=task.subscription_id
JOIN subscriptions subscription ON subscription.id=task.subscription_id
JOIN customers customer ON customer.id=subscription.customer_id
LEFT JOIN sites site ON site.id=task.site_id
WHERE task.id=$1 AND task.subscription_id=$2 AND task.enabled
  AND subscription.status='active' AND customer.status='active'
  AND (customer.reseller_id IS NULL OR EXISTS (
      SELECT 1 FROM reseller_accounts reseller
      JOIN reseller_subscriptions allocation ON allocation.reseller_id=reseller.id AND allocation.status='active'
      WHERE reseller.id=customer.reseller_id AND reseller.status='active'
  ))`, taskID, subscriptionID).Scan(
		&req.TaskID, &req.SubscriptionID, &req.SiteID, &req.Username, &req.Domain, &req.PHPVersion, &req.Kind,
		&req.Command, &req.URL, &req.Script, &req.TimeoutSeconds, &req.WorkingDirectory,
	)
	if err != nil {
		return req, err
	}
	policy, err := s.EffectiveSubscriptionPolicy(ctx, subscriptionID)
	if err != nil {
		return req, err
	}
	if !scheduledTasksAllowed(policy) {
		return types.RunScheduledTaskReq{}, fmt.Errorf("%w: scheduled tasks are disabled", ErrExceeded)
	}
	return req, err
}

func (s *SQLStore) CreateScheduledTaskRun(ctx context.Context, taskID int64) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO scheduled_task_runs(task_id,status,started_at) VALUES($1,'running',now()) RETURNING id`, taskID).Scan(&id)
	return id, err
}

func (s *SQLStore) FinishScheduledTaskRun(ctx context.Context, runID int64, result types.RunScheduledTaskResult) error {
	var exitCode any
	if result.Status == "succeeded" || result.Status == "failed" {
		exitCode = result.ExitCode
	}
	_, err := s.db.ExecContext(ctx, `UPDATE scheduled_task_runs SET status=$2,exit_code=$3,output=$4,finished_at=now() WHERE id=$1`,
		runID, result.Status, exitCode, result.Output)
	return err
}
