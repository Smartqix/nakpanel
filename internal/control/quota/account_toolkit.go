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
	"github.com/nakroteck/nakpanel/internal/gitremote"
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
	if input.Mode == "" {
		input.Mode = "remote"
	}
	if input.DeploymentMode == "" {
		input.DeploymentMode = "manual"
		if input.Automatic {
			input.DeploymentMode = "automatic"
		}
	}
	if input.DeploymentMode != "manual" && input.DeploymentMode != "automatic" && input.DeploymentMode != "disabled" {
		return 0, errors.New("invalid deployment mode")
	}
	input.Automatic = input.DeploymentMode == "automatic"
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
		var normalizeErr error
		input.RemoteURL, normalizeErr = gitremote.Normalize(input.RemoteURL)
		if normalizeErr != nil {
			return 0, normalizeErr
		}
		parsed, err := url.Parse(input.RemoteURL)
		if err != nil || (parsed.Scheme != "ssh" && parsed.Scheme != "https") || parsed.Hostname() == "" {
			return 0, errors.New("remote URL must be credential-free ssh or https")
		}
		if input.Connect {
			if pinned := gitremote.TrustedHostKey(input.RemoteURL); pinned != "" {
				input.KnownHostKey = pinned
			}
			if parsed.Scheme == "ssh" && input.KnownHostKey == "" {
				return 0, errors.New("verify the SSH server key before connecting")
			}
		}
		if parsed.Scheme == "ssh" && input.KnownHostKey != "" {
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
		var currentRevision int64
		var existingRemote, existingTarget, existingMode, existingConnection, existingDeployed string
		revisionErr := tx.QueryRowContext(ctx, `SELECT operation_revision,remote_url,deploy_target,mode,connection_status,deployed_revision FROM git_repositories WHERE site_id=$1 FOR UPDATE`, siteID).Scan(&currentRevision, &existingRemote, &existingTarget, &existingMode, &existingConnection, &existingDeployed)
		if revisionErr != nil && !errors.Is(revisionErr, sql.ErrNoRows) {
			return 0, revisionErr
		}
		if currentRevision != input.ExpectedRevision {
			return 0, errors.New("Git workspace changed; refresh before saving")
		}
		if existingDeployed != "" && existingConnection != "disconnected" && (existingRemote != input.RemoteURL || existingTarget != target || existingMode != input.Mode) {
			return 0, errors.New("disconnect the published repository before changing its source or deployment target")
		}
		var active bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM git_deployments d JOIN git_repositories r ON r.id=d.repository_id WHERE r.site_id=$1 AND d.status IN ('pending','running'))`, siteID).Scan(&active); err != nil {
			return 0, err
		}
		if active {
			return 0, errors.New("a Git workspace operation is already pending")
		}
		if input.Mode == "hosted" {
			var existing bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM git_repositories WHERE site_id=$1 AND mode='hosted')`, siteID).Scan(&existing); err != nil {
				return 0, err
			}
			if !existing {
				return 0, errors.New("new repositories must use a remote repository")
			}
		}
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO git_repositories(site_id,mode,remote_url,branch,deploy_target,automatic,known_host_key,deployment_mode)
VALUES($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT(site_id) DO UPDATE SET mode=EXCLUDED.mode,remote_url=EXCLUDED.remote_url,branch=EXCLUDED.branch,
deploy_target=EXCLUDED.deploy_target,automatic=EXCLUDED.automatic,known_host_key=EXCLUDED.known_host_key,
deployment_mode=EXCLUDED.deployment_mode,operation_revision=git_repositories.operation_revision+1,
connection_status='not_connected',
deployed_revision=CASE WHEN git_repositories.remote_url<>EXCLUDED.remote_url OR git_repositories.deploy_target<>EXCLUDED.deploy_target OR git_repositories.mode<>EXCLUDED.mode THEN '' ELSE git_repositories.deployed_revision END,
last_revision=CASE WHEN git_repositories.remote_url<>EXCLUDED.remote_url OR git_repositories.deploy_target<>EXCLUDED.deploy_target OR git_repositories.mode<>EXCLUDED.mode THEN '' ELSE git_repositories.last_revision END,
previous_revision=CASE WHEN git_repositories.connection_status='disconnected' THEN '' ELSE git_repositories.previous_revision END,
webhook_secret_hash=CASE WHEN EXCLUDED.deployment_mode='disabled' OR git_repositories.remote_url<>EXCLUDED.remote_url THEN '' ELSE git_repositories.webhook_secret_hash END,
fetched_revision='',branches='[]',commits='[]',conflicts='[]',
convergence_status='pending',last_error='',updated_at=now()
RETURNING id`, siteID, input.Mode, strings.TrimSpace(input.RemoteURL), input.Branch, target, input.Automatic, strings.TrimSpace(input.KnownHostKey), input.DeploymentMode).Scan(&id)
		if err != nil {
			return 0, err
		}
		action := "prepare"
		if input.Connect {
			action = "test"
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO git_deployments(repository_id,revision,status,action,operation_revision) SELECT id,'','pending',$2,operation_revision FROM git_repositories WHERE id=$1`, id, action)
		return id, err
	})
}

// GitKeyRequest loads identity and permission without creating repository intent.
func (s *SQLStore) GitKeyRequest(ctx context.Context, subscriptionID, siteID int64) (types.EnsureGitRepositoryReq, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.EnsureGitRepositoryReq{}, err
	}
	defer tx.Rollback()
	if err = lockActiveSubscriptionTx(ctx, tx, subscriptionID); err != nil {
		return types.EnsureGitRepositoryReq{}, err
	}
	if err = ensureSiteBelongsTx(ctx, tx, subscriptionID, siteID); err != nil {
		return types.EnsureGitRepositoryReq{}, err
	}
	policy, err := EffectiveSitePolicyTx(ctx, tx, siteID)
	if err != nil {
		return types.EnsureGitRepositoryReq{}, err
	}
	if !policy.Permissions.Git {
		return types.EnsureGitRepositoryReq{}, errors.New("Git is disabled by the subscription policy")
	}
	req := types.EnsureGitRepositoryReq{SiteID: siteID, Action: "key", Mode: "remote", Branch: "main", DeployTarget: "."}
	err = tx.QueryRowContext(ctx, `SELECT username,domain,status FROM sites WHERE id=$1`, siteID).Scan(&req.Username, &req.Domain, &req.State)
	if err != nil {
		return req, err
	}
	if req.State != "active" {
		return req, errors.New("key preparation requires an active site")
	}
	return req, tx.Commit()
}

func (s *SQLStore) QueueGitDeployment(ctx context.Context, subscriptionID, siteID int64) (int64, error) {
	return 0, errors.New("select an immutable fetched commit and confirm deployment")
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
	return errors.New("webhook delivery ID and branch ref are required")
}

func (s *SQLStore) TriggerGitWorkspaceWebhook(ctx context.Context, siteID int64, tokenHash, deliveryID, ref string) error {
	if siteID <= 0 || !gitWebhookHashRE.MatchString(tokenHash) || deliveryID == "" || len(deliveryID) > 128 || strings.ContainsAny(deliveryID, "\x00\r\n") {
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
	var branch, mode, state string
	if err = tx.QueryRowContext(ctx, `SELECT r.branch,r.deployment_mode,s.desired_status FROM git_repositories r JOIN sites s ON s.id=r.site_id WHERE r.id=$1`, repositoryID).Scan(&branch, &mode, &state); err != nil {
		return err
	}
	if mode != "automatic" || state != "active" || ref != "refs/heads/"+branch {
		return sql.ErrNoRows
	}
	inserted, err := tx.ExecContext(ctx, `INSERT INTO git_webhook_deliveries(repository_id,delivery_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, repositoryID, deliveryID)
	if err != nil {
		return err
	}
	if n, _ := inserted.RowsAffected(); n == 0 {
		return tx.Commit()
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM git_deployments WHERE repository_id=$1 AND status IN ('pending','running'))`, repositoryID).Scan(&active); err != nil {
		return err
	}
	if active {
		return errors.New("Git workspace busy; retry webhook delivery")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO git_deployments(repository_id,revision,status,action,operation_revision,idempotency_key) SELECT id,'','pending','fetch',operation_revision+1,$2 FROM git_repositories WHERE id=$1`, repositoryID, "webhook:"+deliveryID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE git_repositories SET operation_revision=operation_revision+1,convergence_status='pending',last_error='',updated_at=now() WHERE id=$1`, repositoryID); err != nil {
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
