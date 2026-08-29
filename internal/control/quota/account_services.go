package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/robfig/cron/v3"
)

type AccountServiceStore interface {
	SetSubscriptionPolicy(context.Context, int64, int64, json.RawMessage, bool) error
	SetSitePolicy(context.Context, int64, int64, json.RawMessage) error
	ResetSitePolicy(context.Context, int64, int64, string) error
	UpsertSFTPIdentity(context.Context, int64, int64, types.SFTPIdentityInput) (int64, error)
	DeleteSFTPIdentity(context.Context, int64, int64) error
	UpsertScheduledTask(context.Context, int64, int64, types.ScheduledTaskInput) (int64, error)
	DeleteScheduledTask(context.Context, int64, int64) error
	UpsertMailDomain(context.Context, int64, int64, types.MailDomainInput) (int64, error)
	DeleteMailDomain(context.Context, int64, int64) error
	UpsertMailbox(context.Context, int64, int64, types.MailboxInput) (int64, error)
	DeleteMailbox(context.Context, int64, int64) error
	UpsertMailAlias(context.Context, int64, int64, types.MailAliasInput) (int64, error)
	DeleteMailAlias(context.Context, int64, int64) error
	UpsertApplication(context.Context, int64, int64, types.ApplicationInput) (int64, error)
	UpsertApplicationPreset(context.Context, int64, string, types.ApplicationPresetInput) (int64, error)
	UpsertProtectedDirectory(context.Context, int64, int64, types.ProtectedDirectoryInput, string) (int64, error)
	DeleteProtectedDirectory(context.Context, int64, int64) error
	DeleteApplication(context.Context, int64, int64) error
	UpsertFTPAccount(context.Context, int64, int64, types.FTPAccountInput, string) (int64, error)
	DeleteFTPAccount(context.Context, int64, int64) error
	UpsertGitRepository(context.Context, int64, int64, int64, types.GitRepositoryInput) (int64, error)
	UpsertValkey(context.Context, int64, int64, types.ValkeyInput, string) error
	ScheduledTaskRunRequest(context.Context, int64, int64) (types.RunScheduledTaskReq, error)
	CreateScheduledTaskRun(context.Context, int64) (int64, error)
	FinishScheduledTaskRun(context.Context, int64, types.RunScheduledTaskResult) error
}

// EffectiveSubscriptionPolicy returns the immutable entitlement snapshot plus
// the provider-controlled subscription override. Site-specific values are
// applied separately after a site exists.
func (s *SQLStore) EffectiveSubscriptionPolicy(ctx context.Context, subscriptionID int64) (types.HostingPolicy, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return types.HostingPolicy{}, err
	}
	defer tx.Rollback()
	base, patch, err := effectiveSubscriptionPolicyTx(ctx, tx, subscriptionID)
	if err != nil {
		return types.HostingPolicy{}, err
	}
	return controlpolicy.Resolve(base, patch, nil)
}

func (s *SQLStore) EffectiveSitePolicy(ctx context.Context, siteID int64) (types.HostingPolicy, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return types.HostingPolicy{}, err
	}
	defer tx.Rollback()
	return EffectiveSitePolicyTx(ctx, tx, siteID)
}

var (
	applicationServiceNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)
	applicationEnvKeyRE      = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	applicationPresetSlugRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)
	applicationVolumeNameRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	pinnedApplicationImageRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}$`)
	protectedUsernameRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$`)
	bcryptHashRE             = regexp.MustCompile(`^\$2[aby]\$`)
)

func (s *SQLStore) SetSubscriptionPolicy(ctx context.Context, subscriptionID, actorID int64, patch json.RawMessage, unrestricted bool) error {
	if len(patch) == 0 {
		patch = json.RawMessage(`{}`)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockActiveSubscriptionTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	base, _, err := effectiveSubscriptionPolicyTx(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	effective, err := controlpolicy.Resolve(base, patch, nil)
	if err != nil {
		return err
	}
	if !unrestricted {
		ceiling, ok, err := resellerPolicyCeilingTx(ctx, tx, subscriptionID)
		if err != nil {
			return err
		}
		if ok {
			if err := controlpolicy.ValidateWithin(effective, ceiling); err != nil {
				return err
			}
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO subscription_policy_overrides(subscription_id,policy_patch,updated_by)
VALUES($1,$2,$3) ON CONFLICT(subscription_id) DO UPDATE SET policy_patch=EXCLUDED.policy_patch,updated_by=EXCLUDED.updated_by,updated_at=now()`, subscriptionID, []byte(patch), nullableInt64(actorID)); err != nil {
		return err
	}
	if err = s.markSubscriptionPendingTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	if err = s.enqueueSubscriptionHostingStateTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) SetSitePolicy(ctx context.Context, siteID, actorID int64, patch json.RawMessage) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var subscriptionID int64
	if err = tx.QueryRowContext(ctx, `SELECT subscription_id FROM sites WHERE id=$1`, siteID).Scan(&subscriptionID); err != nil {
		return err
	}
	if err = LockSubscriptionMutationTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	var lockedSubscriptionID int64
	if err = tx.QueryRowContext(ctx, `SELECT subscription_id FROM sites WHERE id=$1 FOR UPDATE`, siteID).Scan(&lockedSubscriptionID); err != nil {
		return err
	}
	if lockedSubscriptionID != subscriptionID {
		return errors.New("domain ownership changed while acquiring its mutation lock")
	}
	if err = lockActiveSubscriptionTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	base, subscriptionPatch, err := effectiveSubscriptionPolicyTx(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	subscriptionPolicy, err := controlpolicy.Resolve(base, subscriptionPatch, nil)
	if err != nil {
		return err
	}
	existingPatch, err := sitePolicyPatchTx(ctx, tx, siteID)
	if err != nil {
		return err
	}
	patch, err = mergeSitePolicyPatch(existingPatch, patch)
	if err != nil {
		return err
	}
	effective, err := controlpolicy.Resolve(base, subscriptionPatch, patch)
	if err != nil {
		return err
	}
	if err = controlpolicy.ValidateSiteWithin(effective, subscriptionPolicy); err != nil {
		return fmt.Errorf("site policy exceeds subscription: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO site_policy_overrides(site_id,policy_patch,updated_by)
VALUES($1,$2,$3) ON CONFLICT(site_id) DO UPDATE SET policy_patch=EXCLUDED.policy_patch,updated_by=EXCLUDED.updated_by,updated_at=now()`, siteID, []byte(patch), nullableInt64(actorID)); err != nil {
		return err
	}
	if err = s.markSubscriptionPendingTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE sites SET settings_status='pending',settings_error='',updated_at=now() WHERE id=$1`, siteID); err != nil {
		return err
	}
	if err = s.enqueueSubscriptionHostingStateTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) ResetSitePolicy(ctx context.Context, siteID, actorID int64, scope string) error {
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope != "web" && scope != "php" && scope != "all" {
		return errors.New("reset scope must be web, php, or all")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var subscriptionID int64
	if err = tx.QueryRowContext(ctx, `SELECT subscription_id FROM sites WHERE id=$1`, siteID).Scan(&subscriptionID); err != nil {
		return err
	}
	if err = LockSubscriptionMutationTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	if err = tx.QueryRowContext(ctx, `SELECT subscription_id FROM sites WHERE id=$1 FOR UPDATE`, siteID).Scan(&subscriptionID); err != nil {
		return err
	}
	if err = lockActiveSubscriptionTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	patch, err := sitePolicyPatchTx(ctx, tx, siteID)
	if err != nil {
		return err
	}
	if scope == "all" {
		patch = json.RawMessage(`{}`)
	} else {
		patch, err = removeSitePolicyScope(patch, scope)
		if err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO site_policy_overrides(site_id,policy_patch,updated_by)
VALUES($1,$2,$3) ON CONFLICT(site_id) DO UPDATE SET policy_patch=EXCLUDED.policy_patch,updated_by=EXCLUDED.updated_by,updated_at=now()`, siteID, []byte(patch), nullableInt64(actorID)); err != nil {
		return err
	}
	if err = s.markSubscriptionPendingTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE sites SET settings_status='pending',settings_error='',updated_at=now() WHERE id=$1`, siteID); err != nil {
		return err
	}
	if err = s.enqueueSubscriptionHostingStateTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	return tx.Commit()
}

func sitePolicyPatchTx(ctx context.Context, tx *sql.Tx, siteID int64) (json.RawMessage, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(policy_patch,'{}'::jsonb) FROM site_policy_overrides WHERE site_id=$1`, siteID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return json.RawMessage(`{}`), nil
	}
	return json.RawMessage(raw), err
}

func mergeSitePolicyPatch(existing, incoming json.RawMessage) (json.RawMessage, error) {
	var current, update map[string]json.RawMessage
	if len(existing) == 0 {
		existing = json.RawMessage(`{}`)
	}
	if len(incoming) == 0 {
		incoming = json.RawMessage(`{}`)
	}
	if err := json.Unmarshal(existing, &current); err != nil {
		return nil, fmt.Errorf("decode current site policy: %w", err)
	}
	if err := json.Unmarshal(incoming, &update); err != nil {
		return nil, fmt.Errorf("decode site policy update: %w", err)
	}
	if current == nil {
		current = make(map[string]json.RawMessage)
	}
	for key, value := range update {
		current[key] = value
	}
	encoded, err := json.Marshal(current)
	return json.RawMessage(encoded), err
}

func removeSitePolicyScope(existing json.RawMessage, scope string) (json.RawMessage, error) {
	var patch map[string]json.RawMessage
	if len(existing) == 0 {
		existing = json.RawMessage(`{}`)
	}
	if err := json.Unmarshal(existing, &patch); err != nil {
		return nil, fmt.Errorf("decode current site policy: %w", err)
	}
	delete(patch, scope)
	encoded, err := json.Marshal(patch)
	return json.RawMessage(encoded), err
}

func effectiveSubscriptionPolicyTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) (types.HostingPolicy, json.RawMessage, error) {
	entitlements, err := readSubscriptionEntitlementsTx(ctx, tx, subscriptionID)
	if err != nil {
		return types.HostingPolicy{}, nil, err
	}
	base := controlpolicy.DefaultFromEntitlements(entitlements)
	var stored, patch []byte
	if err = tx.QueryRowContext(ctx, `SELECT e.hosting_policy,COALESCE(o.policy_patch,'{}'::jsonb)
FROM subscription_entitlements e LEFT JOIN subscription_policy_overrides o ON o.subscription_id=e.subscription_id
WHERE e.subscription_id=$1`, subscriptionID).Scan(&stored, &patch); err != nil {
		return types.HostingPolicy{}, nil, err
	}
	if hasConfiguredPolicy(stored) {
		if err := json.Unmarshal(stored, &base); err != nil {
			return types.HostingPolicy{}, nil, err
		}
	}
	return base, patch, nil
}

// EffectiveSitePolicyTx resolves the immutable entitlement snapshot,
// subscription override, and domain override in the caller's transaction.
func EffectiveSitePolicyTx(ctx context.Context, tx *sql.Tx, siteID int64) (types.HostingPolicy, error) {
	var subscriptionID int64
	var sitePatch []byte
	if err := tx.QueryRowContext(ctx, `SELECT site.subscription_id,COALESCE(override.policy_patch,'{}'::jsonb)
FROM sites site LEFT JOIN site_policy_overrides override ON override.site_id=site.id
WHERE site.id=$1`, siteID).Scan(&subscriptionID, &sitePatch); err != nil {
		return types.HostingPolicy{}, err
	}
	base, subscriptionPatch, err := effectiveSubscriptionPolicyTx(ctx, tx, subscriptionID)
	if err != nil {
		return types.HostingPolicy{}, err
	}
	effective, err := controlpolicy.Resolve(base, subscriptionPatch, sitePatch)
	if err != nil {
		return types.HostingPolicy{}, err
	}
	return effective, nil
}

func EffectiveSiteResourceLimitsTx(ctx context.Context, tx *sql.Tx, siteID int64) (types.SiteResourceLimits, error) {
	effective, err := EffectiveSitePolicyTx(ctx, tx, siteID)
	if err != nil {
		return types.SiteResourceLimits{}, err
	}
	return siteResourceLimitsFromPolicy(effective), nil
}

func IsSharedSiteDocumentRoot(username, domain, documentRoot string) bool {
	want := filepath.Join("/home", username, "domains", domain, "public_html")
	return filepath.Clean(documentRoot) == want
}

func siteResourceLimitsFromPolicy(value types.HostingPolicy) types.SiteResourceLimits {
	return types.SiteResourceLimits{
		DiskQuotaMB: value.Resources.DiskMB, PHPFPMMaxChildren: value.PHP.FPMMaxChildren,
		PHPMemoryMB: value.PHP.MemoryLimitMB, PHPFPMMaxRequests: value.PHP.FPMMaxRequests,
		PHPMaxExecutionSeconds: value.PHP.MaxExecutionSeconds, PHPMaxInputSeconds: value.PHP.MaxInputSeconds,
		PHPPostMaxMB: value.PHP.PostMaxMB, PHPUploadMaxMB: value.PHP.UploadMaxMB,
		PHPDisplayErrors: value.PHP.DisplayErrors, PHPLogErrors: value.PHP.LogErrors,
		PHPAllowURLFOpen: value.PHP.AllowURLFOpen, PHPExecEnabled: value.PHP.ExecEnabled,
		RequestRatePerSecond: value.Web.RequestRatePerSecond, RequestBurst: value.Web.RequestBurst,
		MaxConnections: value.Web.MaxConnections, StaticCache: value.Web.StaticCache,
		FastCGIMicrocache: value.Web.FastCGIMicrocache, RequestBodyLimitMB: value.Web.RequestBodyLimitMB,
		Compression: value.Web.Compression, CacheTTLSeconds: value.Web.CacheTTLSeconds,
		ConnectTimeoutSeconds: value.Web.ConnectTimeoutSecs, ReadTimeoutSeconds: value.Web.ReadTimeoutSecs,
		SecurityHeaderPreset: value.Web.SecurityHeaderPreset, IndexFiles: value.Web.IndexFiles,
		PreferredDomain: value.Web.PreferredDomain, AllowedCIDRs: strings.Join(value.Web.AllowedCIDRs, ","),
		ErrorDocument404: value.Web.ErrorDocument404, ErrorDocument50X: value.Web.ErrorDocument50X,
		PHPFPMMode: value.PHP.FPMMode, PHPFPMIdleTimeoutSecs: value.PHP.FPMIdleTimeoutSecs,
		PHPRequestTerminateSecs: value.PHP.RequestTerminateSecs,
		PHPOPcacheEnabled:       value.PHP.OPcacheEnabled, PHPOPcacheMemoryMB: value.PHP.OPcacheMemoryMB,
	}
}

func resellerPolicyCeilingTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) (types.HostingPolicy, bool, error) {
	var raw []byte
	var legacy types.ResellerPlan
	err := tx.QueryRowContext(ctx, `SELECT rp.hosting_policy FROM subscriptions sub
JOIN customers customer ON customer.id=sub.customer_id
JOIN reseller_subscriptions rs ON rs.reseller_id=customer.reseller_id AND rs.status='active'
JOIN reseller_plans rp ON rp.id=rs.reseller_plan_id
WHERE sub.id=$1`, subscriptionID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return types.HostingPolicy{}, false, nil
	}
	if err != nil {
		return types.HostingPolicy{}, false, err
	}
	var ceiling types.HostingPolicy
	if hasConfiguredPolicy(raw) {
		if err := json.Unmarshal(raw, &ceiling); err != nil {
			return types.HostingPolicy{}, false, err
		}
	} else if err := tx.QueryRowContext(ctx, `SELECT rp.disk_mb,rp.max_sites,rp.max_subdomains,rp.max_domain_aliases,
rp.max_databases,rp.bandwidth_mb,rp.max_mailboxes,rp.max_ftp_accounts,rp.max_backups,rp.backup_storage_mb,
rp.allow_ssh,rp.allow_dns,rp.allow_tls,rp.allow_backups,rp.allow_php_settings
FROM subscriptions sub
JOIN customers customer ON customer.id=sub.customer_id
JOIN reseller_subscriptions allocation ON allocation.reseller_id=customer.reseller_id AND allocation.status='active'
JOIN reseller_plans rp ON rp.id=allocation.reseller_plan_id
WHERE sub.id=$1`, subscriptionID).Scan(
		&legacy.DiskMB, &legacy.MaxSites, &legacy.MaxSubdomains, &legacy.MaxDomainAliases,
		&legacy.MaxDatabases, &legacy.BandwidthMB, &legacy.MaxMailboxes, &legacy.MaxFTPAccounts,
		&legacy.MaxBackups, &legacy.BackupStorageMB, &legacy.AllowSSH, &legacy.AllowDNS,
		&legacy.AllowTLS, &legacy.AllowBackups, &legacy.AllowPHPSettings,
	); err != nil {
		return types.HostingPolicy{}, false, err
	} else {
		ceiling = resellerHostingPolicyFromLegacy(legacy)
	}
	return ceiling, true, controlpolicy.Validate(ceiling)
}

func (s *SQLStore) markSubscriptionPendingTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) error {
	_, err := EnqueueSubscriptionConvergenceTx(ctx, tx, s.river, subscriptionID)
	return err
}

func (s *SQLStore) UpsertSFTPIdentity(ctx context.Context, subscriptionID, actorID int64, input types.SFTPIdentityInput) (int64, error) {
	name := strings.TrimSpace(input.Name)
	key := strings.TrimSpace(input.PublicKey)
	root := filepath.Clean(strings.TrimSpace(input.RelativeRoot))
	if root == "" {
		root = "."
	}
	if name == "" || strings.ContainsAny(name+key, "\r\n") || !(strings.HasPrefix(key, "ssh-ed25519 ") || strings.HasPrefix(key, "ssh-rsa ") || strings.HasPrefix(key, "ecdsa-sha2-")) {
		return 0, errors.New("valid SFTP name and public key are required")
	}
	if err := site.ValidateSFTPRelativeRoot(root); err != nil {
		return 0, err
	}
	return s.upsertAccountService(ctx, subscriptionID, func(tx *sql.Tx, policy types.HostingPolicy) (int64, error) {
		if !policy.Permissions.SFTP {
			return 0, errors.New("SFTP is disabled by the subscription policy")
		}
		if input.ID == 0 {
			if err := enforceServiceCountTx(ctx, tx, `sftp_access_identities`, subscriptionID, policy.Resources.MaxSFTPIdentities); err != nil {
				return 0, err
			}
		}
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO sftp_access_identities(id,subscription_id,name,public_key,relative_root,enabled)
VALUES(CASE WHEN $1=0 THEN nextval('sftp_access_identities_id_seq') ELSE $1 END,$2,$3,$4,$5,$6)
ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,public_key=EXCLUDED.public_key,relative_root=EXCLUDED.relative_root,enabled=EXCLUDED.enabled,updated_at=now()
WHERE sftp_access_identities.subscription_id=EXCLUDED.subscription_id RETURNING id`, input.ID, subscriptionID, name, key, root, input.Enabled).Scan(&id)
		return id, err
	})
}

func (s *SQLStore) UpsertScheduledTask(ctx context.Context, subscriptionID, actorID int64, input types.ScheduledTaskInput) (int64, error) {
	if input.SiteID <= 0 {
		return 0, errors.New("a hosted domain is required for a scheduled task")
	}
	if _, err := cron.ParseStandard(strings.TrimSpace(input.Schedule)); err != nil {
		return 0, fmt.Errorf("invalid schedule: %w", err)
	}
	cronParts := strings.Fields(input.Schedule)
	if len(cronParts) != 5 || strings.ContainsAny(input.Schedule, "/?") || (cronParts[2] != "*" && cronParts[4] != "*") {
		return 0, errors.New("schedule must use fixed/list/range fields and cannot restrict both day-of-month and weekday")
	}
	if input.TimeoutSeconds == 0 {
		input.TimeoutSeconds = 300
	}
	if input.Kind == "" {
		input.Kind = "command"
	}
	if input.Timezone == "" {
		input.Timezone = "UTC"
	}
	if input.Kind != "command" && input.Kind != "url" && input.Kind != "php" {
		return 0, errors.New("invalid scheduled task kind")
	}
	if input.Kind == "command" && strings.TrimSpace(input.Command) == "" {
		return 0, errors.New("a command is required")
	}
	if input.Kind == "url" {
		parsed, parseErr := url.ParseRequestURI(input.URL)
		if parseErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return 0, errors.New("a valid HTTP or HTTPS URL is required")
		}
	}
	script := filepath.Clean(strings.TrimSpace(input.Script))
	if input.Kind == "php" && (script == "." || filepath.IsAbs(script) || script == ".." || strings.HasPrefix(script, ".."+string(filepath.Separator))) {
		return 0, errors.New("a site-relative PHP script is required")
	}
	if strings.TrimSpace(input.Name) == "" || strings.ContainsAny(input.Name+input.Command+input.URL+input.Script+input.WorkingDirectory+input.Timezone, "\x00\r\n") || input.TimeoutSeconds < 1 || input.TimeoutSeconds > 86400 {
		return 0, errors.New("invalid scheduled task")
	}
	return s.upsertAccountService(ctx, subscriptionID, func(tx *sql.Tx, policy types.HostingPolicy) (int64, error) {
		if !policy.Permissions.ScheduledTasks {
			return 0, errors.New("scheduled tasks are disabled by the subscription policy")
		}
		if err := ensureSiteBelongsTx(ctx, tx, subscriptionID, input.SiteID); err != nil {
			return 0, err
		}
		if input.ID == 0 {
			if err := enforceServiceCountTx(ctx, tx, `scheduled_tasks`, subscriptionID, policy.Resources.MaxScheduledTasks); err != nil {
				return 0, err
			}
		}
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO scheduled_tasks(id,subscription_id,site_id,name,schedule,command,working_directory,timeout_seconds,enabled,kind,url,script_path,timezone)
VALUES(CASE WHEN $1=0 THEN nextval('scheduled_tasks_id_seq') ELSE $1 END,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT(id) DO UPDATE SET site_id=EXCLUDED.site_id,name=EXCLUDED.name,schedule=EXCLUDED.schedule,command=EXCLUDED.command,working_directory=EXCLUDED.working_directory,timeout_seconds=EXCLUDED.timeout_seconds,enabled=EXCLUDED.enabled,kind=EXCLUDED.kind,url=EXCLUDED.url,script_path=EXCLUDED.script_path,timezone=EXCLUDED.timezone,convergence_status='pending',last_error='',updated_at=now()
WHERE scheduled_tasks.subscription_id=EXCLUDED.subscription_id RETURNING id`, input.ID, subscriptionID, input.SiteID, strings.TrimSpace(input.Name), strings.TrimSpace(input.Schedule), input.Command, strings.TrimSpace(input.WorkingDirectory), input.TimeoutSeconds, input.Enabled, input.Kind, strings.TrimSpace(input.URL), script, input.Timezone).Scan(&id)
		return id, err
	})
}

func (s *SQLStore) UpsertMailDomain(ctx context.Context, subscriptionID, actorID int64, input types.MailDomainInput) (int64, error) {
	input.Domain = site.NormalizeDomain(input.Domain)
	if (input.SiteID == 0 && site.ValidateDomain(input.Domain) != nil) || (input.DMARCPolicy != "none" && input.DMARCPolicy != "quarantine" && input.DMARCPolicy != "reject") {
		return 0, errors.New("invalid mail domain settings")
	}
	return s.upsertAccountService(ctx, subscriptionID, func(tx *sql.Tx, policy types.HostingPolicy) (int64, error) {
		if !policy.Permissions.Mail || !policy.Mail.Enabled {
			return 0, errors.New("mail is disabled by the subscription policy")
		}
		if input.SiteID > 0 {
			if err := tx.QueryRowContext(ctx, `SELECT domain FROM sites WHERE id=$1 AND subscription_id=$2 AND status='active'`, input.SiteID, subscriptionID).Scan(&input.Domain); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return 0, errors.New("active domain does not belong to the subscription")
				}
				return 0, err
			}
		} else if err := ensureSiteBelongsTx(ctx, tx, subscriptionID, input.SiteID); err != nil {
			return 0, err
		}
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO mail_domains(id,subscription_id,site_id,domain,enabled,dkim_enabled,dmarc_policy,catch_all)
VALUES(CASE WHEN $1=0 THEN nextval('mail_domains_id_seq') ELSE $1 END,$2,NULLIF($3,0),$4,$5,$6,$7,$8)
ON CONFLICT(id) DO UPDATE SET site_id=EXCLUDED.site_id,domain=EXCLUDED.domain,enabled=EXCLUDED.enabled,dkim_enabled=EXCLUDED.dkim_enabled,dmarc_policy=EXCLUDED.dmarc_policy,catch_all=EXCLUDED.catch_all,delete_requested=false,convergence_status='pending',last_error='',updated_at=now()
WHERE mail_domains.subscription_id=EXCLUDED.subscription_id RETURNING id`, input.ID, subscriptionID, input.SiteID, input.Domain, input.Enabled, input.DKIM, input.DMARCPolicy, strings.TrimSpace(input.CatchAll)).Scan(&id)
		return id, err
	})
}

func (s *SQLStore) UpsertApplication(ctx context.Context, subscriptionID, actorID int64, input types.ApplicationInput) (int64, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.ImageRef = strings.TrimSpace(input.ImageRef)
	input.CatalogSlug = strings.ToLower(strings.TrimSpace(input.CatalogSlug))
	input.Runtime = strings.ToLower(strings.TrimSpace(input.Runtime))
	input.RouteMode = strings.ToLower(strings.TrimSpace(input.RouteMode))
	input.RoutePrefix = strings.TrimSpace(input.RoutePrefix)
	input.HealthKind = strings.ToLower(strings.TrimSpace(input.HealthKind))
	input.HealthPath = strings.TrimSpace(input.HealthPath)
	if !applicationServiceNameRE.MatchString(input.Name) {
		return 0, errors.New("invalid application name")
	}
	for key, value := range input.Environment {
		if !applicationEnvKeyRE.MatchString(key) || strings.ContainsRune(value, '\x00') || len(value) > 8192 {
			return 0, fmt.Errorf("invalid application environment entry %q", key)
		}
	}
	for key, value := range input.Secrets {
		if !applicationEnvKeyRE.MatchString(key) || strings.ContainsRune(value, '\x00') || len(value) > 65536 {
			return 0, fmt.Errorf("invalid application secret %q", key)
		}
	}
	if input.Runtime != "oci" {
		return 0, errors.New("only the OCI container runtime is available; managed PHP, Node.js, and Python adapters are not installed")
	}
	if input.DesiredState == "" {
		input.DesiredState = "running"
	}
	if input.DesiredState != "running" && input.DesiredState != "stopped" {
		return 0, errors.New("invalid application state")
	}
	if input.RouteMode == "" {
		input.RouteMode = types.ApplicationRoutePrefix
	}
	if input.RoutePrefix == "" {
		input.RoutePrefix = "/apps/" + input.Name + "/"
	}
	if input.RouteMode == types.ApplicationRouteDomain {
		input.RoutePrefix = "/"
	}
	if input.ContainerPort == 0 {
		input.ContainerPort = 8080
	}
	if input.HealthKind == "" {
		input.HealthKind = types.ApplicationHealthHTTP
	}
	if input.HealthPath == "" {
		input.HealthPath = "/healthz"
	}
	if input.HealthTimeoutSeconds == 0 {
		input.HealthTimeoutSeconds = 30
	}
	endpoint := types.ApplicationEndpointSpec{
		RouteMode: input.RouteMode, RoutePrefix: input.RoutePrefix, ContainerPort: input.ContainerPort,
	}
	health := types.ApplicationHealthSpec{
		Kind: input.HealthKind, Path: input.HealthPath, TimeoutSeconds: input.HealthTimeoutSeconds,
	}
	if err := validateApplicationNetworkSettings(endpoint, health); err != nil {
		return 0, err
	}
	environment, err := json.Marshal(input.Environment)
	if err != nil {
		return 0, err
	}
	var inputManifest types.ApplicationManifestRevision
	var inputCatalogRevision int64
	return s.upsertApplicationService(ctx, subscriptionID, func(tx *sql.Tx, policy types.HostingPolicy) (int64, error) {
		if !policy.Permissions.Applications {
			return 0, errors.New("applications are disabled by the subscription policy")
		}
		if err := ensureSiteBelongsTx(ctx, tx, subscriptionID, input.SiteID); err != nil {
			return 0, err
		}
		var providerID sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT customer.reseller_id
FROM subscriptions subscription JOIN customers customer ON customer.id=subscription.customer_id
WHERE subscription.id=$1`, subscriptionID).Scan(&providerID); err != nil {
			return 0, err
		}
		if input.CatalogSlug != "" {
			if !policy.Applications.CatalogEnabled || !stringInPolicyList(policy.Applications.AllowedCatalogSlugs, input.CatalogSlug) {
				return 0, errors.New("application preset is not allowed by the subscription policy")
			}
			var manifestRaw []byte
			var catalogRevision int64
			err := tx.QueryRowContext(ctx, `SELECT runtime,image_ref,manifest_revision,manifest FROM application_presets
WHERE slug=$1 AND reseller_id IS NOT DISTINCT FROM $2 AND active`,
				input.CatalogSlug, providerID,
			).Scan(&input.Runtime, &input.ImageRef, &catalogRevision, &manifestRaw)
			if err != nil {
				return 0, err
			}
			if input.Runtime != "oci" {
				return 0, errors.New("this catalog recipe requires a runtime adapter that is not available")
			}
			var manifest types.ApplicationManifestRevision
			if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
				return 0, errors.New("provider catalog manifest is invalid")
			}
			manifest.Revision = catalogRevision
			if manifest.Endpoint.ContainerPort > 0 {
				input.ContainerPort = manifest.Endpoint.ContainerPort
			}
			if manifest.Health.Kind != "" {
				input.HealthKind = manifest.Health.Kind
				input.HealthPath = manifest.Health.Path
				input.HealthTimeoutSeconds = manifest.Health.TimeoutSeconds
			}
			inputManifest = manifest
			inputCatalogRevision = catalogRevision
		} else {
			if !policy.Permissions.CustomOCIImages || input.Runtime != "oci" {
				return 0, errors.New("custom OCI images are disabled by the subscription policy")
			}
			if !pinnedApplicationImageRE.MatchString(input.ImageRef) || !applicationRegistryAllowed(policy.Applications.AllowedRegistries, input.ImageRef) {
				return 0, errors.New("custom image must use an allowed registry and immutable digest")
			}
			inputManifest = types.ApplicationManifestRevision{
				Runtime: input.Runtime, ImageRef: input.ImageRef, ReadOnlyRoot: true,
				Endpoint: types.ApplicationEndpointSpec{ContainerPort: input.ContainerPort},
				Health: types.ApplicationHealthSpec{
					Kind: input.HealthKind, Path: input.HealthPath, TimeoutSeconds: input.HealthTimeoutSeconds,
				},
				Volumes: input.Volumes,
			}
		}
		if err := validateApplicationNetworkSettings(types.ApplicationEndpointSpec{
			RouteMode: input.RouteMode, RoutePrefix: input.RoutePrefix, ContainerPort: input.ContainerPort,
		}, types.ApplicationHealthSpec{
			Kind: input.HealthKind, Path: input.HealthPath, TimeoutSeconds: input.HealthTimeoutSeconds,
		}); err != nil {
			return 0, err
		}
		if !stringInPolicyList(policy.Applications.AllowedRuntimes, input.Runtime) {
			return 0, errors.New("application runtime is disabled by the subscription policy")
		}
		if input.ID == 0 {
			if err := enforceServiceCountTx(ctx, tx, `application_instances`, subscriptionID, policy.Resources.MaxApplications); err != nil {
				return 0, err
			}
		} else if err := ensureApplicationIdentityTx(ctx, tx, subscriptionID, input); err != nil {
			return 0, err
		}
		if err := validateApplicationVolumes(inputManifest.Volumes); err != nil {
			return 0, err
		}
		if err := enforceContainerStorageDeclarationTx(ctx, tx, subscriptionID, input.ID,
			inputManifest.Volumes, policy.Resources.ContainerStorageMB); err != nil {
			return 0, err
		}
		manifestJSON, err := json.Marshal(inputManifest)
		if err != nil {
			return 0, err
		}
		endpointPort, err := allocateApplicationEndpointTx(ctx, tx, input.ID)
		if err != nil {
			return 0, err
		}
		var id int64
		err = tx.QueryRowContext(ctx, `INSERT INTO application_instances(
id,subscription_id,site_id,name,runtime,catalog_slug,image_ref,desired_state,environment,kind,catalog_revision,manifest,
route_mode,route_prefix,container_port,endpoint_port,health_kind,health_path,health_timeout_seconds,observed_state)
VALUES(CASE WHEN $1=0 THEN nextval('application_instances_id_seq') ELSE $1 END,$2,NULLIF($3,0),$4,$5,$6,$7,$8,$9,
'container',$10,$11,$12,$13,$14,$15,$16,$17,$18,'unknown')
ON CONFLICT(id) DO UPDATE SET site_id=EXCLUDED.site_id,name=EXCLUDED.name,runtime=EXCLUDED.runtime,
catalog_slug=EXCLUDED.catalog_slug,image_ref=EXCLUDED.image_ref,desired_state=EXCLUDED.desired_state,
environment=EXCLUDED.environment,kind='container',catalog_revision=EXCLUDED.catalog_revision,manifest=EXCLUDED.manifest,
route_mode=EXCLUDED.route_mode,route_prefix=EXCLUDED.route_prefix,
container_port=EXCLUDED.container_port,health_kind=EXCLUDED.health_kind,health_path=EXCLUDED.health_path,
health_timeout_seconds=EXCLUDED.health_timeout_seconds,delete_requested=false,convergence_status='pending',
observed_state='unknown',observed_message='',last_error='',updated_at=now()
WHERE application_instances.subscription_id=EXCLUDED.subscription_id RETURNING id`,
			input.ID, subscriptionID, input.SiteID, input.Name, input.Runtime, input.CatalogSlug, input.ImageRef,
			input.DesiredState, environment, inputCatalogRevision, manifestJSON, input.RouteMode, input.RoutePrefix,
			input.ContainerPort, endpointPort, input.HealthKind, input.HealthPath, input.HealthTimeoutSeconds).Scan(&id)
		if err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM application_volumes WHERE application_id=$1`, id); err != nil {
			return 0, err
		}
		for _, volume := range inputManifest.Volumes {
			if _, err = tx.ExecContext(ctx, `INSERT INTO application_volumes(application_id,name,container_path,size_mb,read_only)
VALUES($1,$2,$3,$4,$5)`, id, volume.Name, volume.Target, volume.SizeMB, volume.ReadOnly); err != nil {
				return 0, err
			}
		}
		if len(input.Secrets) > 0 {
			if s.secrets == nil {
				return 0, errors.New("application secret encryption is not configured")
			}
			for name, plaintext := range input.Secrets {
				secretName := "env-" + strings.ToLower(strings.ReplaceAll(name, "_", "-"))
				reference, secretErr := s.secrets.PutSecretTx(ctx, tx, serveradmin.PutSecretParams{
					Scope:       "application",
					Name:        "app-" + strconv.FormatInt(id, 10) + "-" + secretName,
					Plaintext:   []byte(plaintext),
					Metadata:    json.RawMessage(`{"kind":"application_environment"}`),
					ActorUserID: actorID,
				})
				if secretErr != nil {
					return 0, secretErr
				}
				if _, secretErr = tx.ExecContext(ctx, `INSERT INTO application_secret_bindings(application_id,name,secret_id)
VALUES($1,$2,$3) ON CONFLICT(application_id,name) DO UPDATE
SET secret_id=EXCLUDED.secret_id,updated_at=now()`, id, name, reference.ID); secretErr != nil {
					return 0, secretErr
				}
			}
		}
		var revision int64
		if err = tx.QueryRowContext(ctx, `SELECT desired_revision FROM application_instances
WHERE id=$1 FOR UPDATE`, id).Scan(&revision); err != nil {
			return 0, err
		}
		if err = s.enqueueApplicationConvergenceTx(ctx, tx, id, revision); err != nil {
			return 0, err
		}
		return id, nil
	})
}

func validateApplicationVolumes(volumes []types.ApplicationVolumeSpec) error {
	if len(volumes) > 16 {
		return errors.New("an application manifest may declare at most 16 volume slots")
	}
	seen := make(map[string]bool, len(volumes))
	for _, volume := range volumes {
		target := path.Clean(strings.TrimSpace(volume.Target))
		if !applicationVolumeNameRE.MatchString(volume.Name) || seen[volume.Name] ||
			!strings.HasPrefix(target, "/") || target == "/" || strings.HasPrefix(target, "/run/secrets") ||
			strings.ContainsAny(target, "\x00\r\n") || volume.SizeMB <= 0 {
			return errors.New("application volume slots require unique safe names, absolute targets, and positive sizes")
		}
		seen[volume.Name] = true
	}
	return nil
}

func enforceContainerStorageDeclarationTx(
	ctx context.Context,
	tx *sql.Tx,
	subscriptionID, applicationID int64,
	volumes []types.ApplicationVolumeSpec,
	limitMB int,
) error {
	if limitMB == -1 {
		return nil
	}
	var allocated int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(volume.size_mb),0)::integer
FROM application_volumes volume JOIN application_instances application ON application.id=volume.application_id
WHERE application.subscription_id=$1 AND application.id<>$2 AND NOT application.delete_requested`,
		subscriptionID, applicationID).Scan(&allocated); err != nil {
		return err
	}
	for _, volume := range volumes {
		allocated += volume.SizeMB
	}
	if allocated > limitMB {
		return ErrExceeded
	}
	return nil
}

func validateApplicationNetworkSettings(endpoint types.ApplicationEndpointSpec, health types.ApplicationHealthSpec) error {
	if endpoint.RouteMode != types.ApplicationRouteDomain && endpoint.RouteMode != types.ApplicationRoutePrefix {
		return errors.New("application route must use the whole domain or a URL prefix")
	}
	if endpoint.RouteMode == types.ApplicationRouteDomain {
		endpoint.RoutePrefix = "/"
	}
	if endpoint.ContainerPort < 1 || endpoint.ContainerPort > 65535 {
		return errors.New("application container port must be between 1 and 65535")
	}
	if endpoint.RoutePrefix == "" || !strings.HasPrefix(endpoint.RoutePrefix, "/") ||
		strings.Contains(endpoint.RoutePrefix, "..") || strings.ContainsAny(endpoint.RoutePrefix, "\x00\r\n?#") {
		return errors.New("application route prefix is invalid")
	}
	if health.Kind != types.ApplicationHealthHTTP && health.Kind != types.ApplicationHealthTCP {
		return errors.New("application health check must use HTTP or TCP")
	}
	if health.Kind == types.ApplicationHealthHTTP &&
		(health.Path == "" || !strings.HasPrefix(health.Path, "/") || strings.Contains(health.Path, "..") ||
			strings.ContainsAny(health.Path, "\x00\r\n?#")) {
		return errors.New("application health path is invalid")
	}
	if health.TimeoutSeconds < 1 || health.TimeoutSeconds > 300 {
		return errors.New("application health timeout must be between 1 and 300 seconds")
	}
	return nil
}

func allocateApplicationEndpointTx(ctx context.Context, tx *sql.Tx, applicationID int64) (int, error) {
	if applicationID > 0 {
		var port int
		if err := tx.QueryRowContext(ctx, `SELECT endpoint_port FROM application_instances
WHERE id=$1 FOR UPDATE`, applicationID).Scan(&port); err != nil {
			return 0, err
		}
		return port, nil
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(2810001)`); err != nil {
		return 0, err
	}
	var port int
	err := tx.QueryRowContext(ctx, `SELECT candidate FROM generate_series(20000,24999) AS candidate
WHERE NOT EXISTS (
    SELECT 1 FROM application_instances application
    WHERE application.endpoint_port IN (candidate,candidate+5000) AND NOT application.delete_requested
)
ORDER BY candidate LIMIT 1`).Scan(&port)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errors.New("no application loopback endpoints are available")
	}
	return port, err
}

func ensureApplicationIdentityTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, input types.ApplicationInput) error {
	var currentSiteID sql.NullInt64
	var currentName string
	err := tx.QueryRowContext(ctx, `SELECT site_id,name FROM application_instances
WHERE id=$1 AND subscription_id=$2 FOR UPDATE`, input.ID, subscriptionID).Scan(&currentSiteID, &currentName)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("application does not belong to the subscription")
	}
	if err != nil {
		return err
	}
	if !currentSiteID.Valid || currentSiteID.Int64 != input.SiteID || currentName != input.Name {
		return errors.New("application site and name cannot be changed; create a new application")
	}
	return nil
}

func (s *SQLStore) SetApplicationAction(ctx context.Context, subscriptionID, applicationID int64, action string) error {
	action = strings.ToLower(strings.TrimSpace(action))
	if applicationID <= 0 {
		return errors.New("application is required")
	}
	switch action {
	case "start", "stop", "restart", "redeploy", "rollback", "reconcile":
	default:
		return errors.New("unsupported application action")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockActiveSubscriptionTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	var currentImage string
	if err = tx.QueryRowContext(ctx, `SELECT image_ref FROM application_instances
WHERE id=$1 AND subscription_id=$2 AND runtime='oci' AND NOT delete_requested FOR UPDATE`,
		applicationID, subscriptionID).Scan(&currentImage); errors.Is(err, sql.ErrNoRows) {
		return errors.New("container does not belong to the subscription")
	} else if err != nil {
		return err
	}
	switch action {
	case "start":
		_, err = tx.ExecContext(ctx, `UPDATE application_instances
SET desired_state='running',desired_revision=desired_revision+1,convergence_status='pending',
observed_state='unknown',observed_message='',last_error='',updated_at=now() WHERE id=$1`, applicationID)
	case "stop":
		_, err = tx.ExecContext(ctx, `UPDATE application_instances
SET desired_state='stopped',desired_revision=desired_revision+1,convergence_status='pending',
observed_state='unknown',observed_message='',last_error='',updated_at=now() WHERE id=$1`, applicationID)
	case "rollback":
		var previousImage string
		err = tx.QueryRowContext(ctx, `SELECT image_ref FROM application_generations
WHERE application_id=$1 AND image_ref<>$2 AND status IN ('healthy','retired','rolled_back')
ORDER BY desired_revision DESC LIMIT 1`, applicationID, currentImage).Scan(&previousImage)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("no previous healthy container generation is available")
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE application_instances
SET image_ref=$2,desired_state='running',convergence_status='pending',
observed_state='unknown',observed_message='',last_error='',updated_at=now() WHERE id=$1`, applicationID, previousImage)
		}
	default:
		_, err = tx.ExecContext(ctx, `UPDATE application_instances
SET desired_revision=desired_revision+1,convergence_status='pending',
observed_state='unknown',observed_message='',last_error='',updated_at=now() WHERE id=$1`, applicationID)
	}
	if err != nil {
		return err
	}
	var revision int64
	if err = tx.QueryRowContext(ctx, `SELECT desired_revision FROM application_instances
WHERE id=$1 FOR UPDATE`, applicationID).Scan(&revision); err != nil {
		return err
	}
	if err = s.enqueueApplicationConvergenceTx(ctx, tx, applicationID, revision); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) UpsertApplicationPreset(ctx context.Context, actorID int64, actorRole string, input types.ApplicationPresetInput) (int64, error) {
	input.Slug = strings.ToLower(strings.TrimSpace(input.Slug))
	input.Name = strings.TrimSpace(input.Name)
	input.Runtime = strings.ToLower(strings.TrimSpace(input.Runtime))
	input.ImageRef = strings.TrimSpace(input.ImageRef)
	if actorID <= 0 || !applicationPresetSlugRE.MatchString(input.Slug) || input.Name == "" ||
		input.Runtime != "oci" ||
		!pinnedApplicationImageRE.MatchString(input.ImageRef) {
		return 0, errors.New("valid OCI preset name and digest-pinned image are required")
	}
	input.Manifest.Runtime = input.Runtime
	input.Manifest.ImageRef = input.ImageRef
	input.Manifest.ReadOnlyRoot = true
	if input.Manifest.Endpoint.ContainerPort == 0 {
		input.Manifest.Endpoint.ContainerPort = 8080
	}
	if input.Manifest.Health.Kind == "" {
		input.Manifest.Health.Kind = types.ApplicationHealthHTTP
	}
	if input.Manifest.Health.Path == "" {
		input.Manifest.Health.Path = "/healthz"
	}
	if input.Manifest.Health.TimeoutSeconds == 0 {
		input.Manifest.Health.TimeoutSeconds = 30
	}
	if err := validateApplicationNetworkSettings(types.ApplicationEndpointSpec{
		RouteMode: types.ApplicationRoutePrefix, RoutePrefix: "/", ContainerPort: input.Manifest.Endpoint.ContainerPort,
	}, input.Manifest.Health); err != nil {
		return 0, err
	}
	if err := validateApplicationVolumes(input.Manifest.Volumes); err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var resellerID any
	switch actorRole {
	case "admin":
		resellerID = nil
	case "reseller":
		var id int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM reseller_accounts WHERE login_user_id=$1 AND status='active'`, actorID).Scan(&id); err != nil {
			return 0, err
		}
		resellerID = id
	default:
		return 0, errors.New("application preset management is forbidden")
	}
	var id, revision int64
	err = tx.QueryRowContext(ctx, `INSERT INTO application_presets(id,reseller_id,slug,name,runtime,image_ref,active)
VALUES(CASE WHEN $1=0 THEN nextval('application_presets_id_seq') ELSE $1 END,$2,$3,$4,$5,$6,$7)
ON CONFLICT(id) DO UPDATE SET slug=EXCLUDED.slug,name=EXCLUDED.name,runtime=EXCLUDED.runtime,
image_ref=EXCLUDED.image_ref,active=EXCLUDED.active,manifest_revision=application_presets.manifest_revision+1,updated_at=now()
WHERE application_presets.reseller_id IS NOT DISTINCT FROM EXCLUDED.reseller_id
RETURNING id,manifest_revision`, input.ID, resellerID, input.Slug, input.Name, input.Runtime, input.ImageRef, input.Active).Scan(&id, &revision)
	if err != nil {
		return 0, err
	}
	input.Manifest.PresetID, input.Manifest.Revision = id, revision
	manifestJSON, err := json.Marshal(input.Manifest)
	if err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE application_presets SET manifest=$2 WHERE id=$1`, id, manifestJSON); err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO application_manifest_revisions(
preset_id,revision,manifest,image_ref,created_by_user_id) VALUES($1,$2,$3,$4,$5)`,
		id, revision, manifestJSON, input.ImageRef, actorID); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func (s *SQLStore) UpsertProtectedDirectory(ctx context.Context, subscriptionID, actorID int64, input types.ProtectedDirectoryInput, passwordHash string) (int64, error) {
	relativePath := path.Clean(strings.TrimSpace(strings.TrimPrefix(input.Path, "/")))
	input.Realm = strings.TrimSpace(input.Realm)
	input.Username = strings.TrimSpace(input.Username)
	if relativePath == "." || relativePath == ".." || strings.HasPrefix(relativePath, "../") ||
		strings.ContainsAny(relativePath+input.Realm+input.Username, "\x00\r\n") ||
		input.Realm == "" || len(input.Realm) > 128 || !protectedUsernameRE.MatchString(input.Username) ||
		(passwordHash != "" && !bcryptHashRE.MatchString(passwordHash)) {
		return 0, errors.New("valid protected path, realm, username, and password are required")
	}
	return s.upsertAccountService(ctx, subscriptionID, func(tx *sql.Tx, policy types.HostingPolicy) (int64, error) {
		if !policy.Permissions.Hosting {
			return 0, errors.New("hosting is disabled by the subscription policy")
		}
		if err := ensureSiteBelongsTx(ctx, tx, subscriptionID, input.SiteID); err != nil {
			return 0, err
		}
		if input.ID == 0 && passwordHash == "" {
			return 0, errors.New("a password is required for a new protected directory")
		}
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO protected_directories(id,site_id,relative_path,realm,username,password_hash,enabled)
VALUES(CASE WHEN $1=0 THEN nextval('protected_directories_id_seq') ELSE $1 END,$2,$3,$4,$5,$6,$7)
ON CONFLICT(id) DO UPDATE SET relative_path=EXCLUDED.relative_path,realm=EXCLUDED.realm,username=EXCLUDED.username,
password_hash=CASE WHEN EXCLUDED.password_hash='' THEN protected_directories.password_hash ELSE EXCLUDED.password_hash END,
enabled=EXCLUDED.enabled,updated_at=now()
WHERE protected_directories.site_id=EXCLUDED.site_id
RETURNING id`, input.ID, input.SiteID, relativePath, input.Realm, input.Username, passwordHash, input.Enabled).Scan(&id)
		return id, err
	})
}

func (s *SQLStore) DeleteProtectedDirectory(ctx context.Context, subscriptionID, id int64) error {
	return s.deleteAccountService(ctx, subscriptionID, `DELETE FROM protected_directories item
USING sites site WHERE item.id=$1 AND item.site_id=site.id AND site.subscription_id=$2`, id)
}

func stringInPolicyList(items []string, candidate string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), candidate) {
			return true
		}
	}
	return false
}

func applicationRegistryAllowed(allowed []string, image string) bool {
	repository := strings.SplitN(image, "@", 2)[0]
	first := strings.SplitN(repository, "/", 2)[0]
	registry := "docker.io"
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		registry = first
	}
	return stringInPolicyList(allowed, registry)
}

func ensureSiteBelongsTx(ctx context.Context, tx *sql.Tx, subscriptionID, siteID int64) error {
	if siteID == 0 {
		return nil
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sites WHERE id=$1 AND subscription_id=$2)`, siteID, subscriptionID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errors.New("domain does not belong to the subscription")
	}
	return nil
}

func (s *SQLStore) upsertAccountService(ctx context.Context, subscriptionID int64, fn func(*sql.Tx, types.HostingPolicy) (int64, error)) (int64, error) {
	return s.upsertAccountServiceWithSubscriptionConvergence(ctx, subscriptionID, true, fn)
}

// Application instances have their own desired revisions and River worker.
// Queueing the generic subscription convergence here as well can deploy the
// same immutable application revision twice and tear down the generation that
// the first job just made active.
func (s *SQLStore) upsertApplicationService(ctx context.Context, subscriptionID int64, fn func(*sql.Tx, types.HostingPolicy) (int64, error)) (int64, error) {
	return s.upsertAccountServiceWithSubscriptionConvergence(ctx, subscriptionID, false, fn)
}

func (s *SQLStore) upsertAccountServiceWithSubscriptionConvergence(
	ctx context.Context,
	subscriptionID int64,
	convergeSubscription bool,
	fn func(*sql.Tx, types.HostingPolicy) (int64, error),
) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := lockActiveSubscriptionTx(ctx, tx, subscriptionID); err != nil {
		return 0, err
	}
	base, patch, err := effectiveSubscriptionPolicyTx(ctx, tx, subscriptionID)
	if err != nil {
		return 0, err
	}
	effective, err := controlpolicy.Resolve(base, patch, nil)
	if err != nil {
		return 0, err
	}
	id, err := fn(tx, effective)
	if err != nil {
		return 0, err
	}
	if convergeSubscription {
		if err := s.markSubscriptionPendingTx(ctx, tx, subscriptionID); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

func enforceServiceCountTx(ctx context.Context, tx *sql.Tx, table string, subscriptionID int64, limit int) error {
	if limit == -1 {
		return nil
	}
	if limit == 0 {
		return ErrExceeded
	}
	allowed := map[string]bool{"ftp_accounts": true, "sftp_access_identities": true, "scheduled_tasks": true, "application_instances": true}
	if !allowed[table] {
		return errors.New("unsupported service count")
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE subscription_id=$1`, subscriptionID).Scan(&count); err != nil {
		return err
	}
	if count >= limit {
		return ErrExceeded
	}
	return nil
}

func (s *SQLStore) DeleteSFTPIdentity(ctx context.Context, subscriptionID, id int64) error {
	return s.deleteAccountService(ctx, subscriptionID, `DELETE FROM sftp_access_identities WHERE id=$1 AND subscription_id=$2`, id)
}
func (s *SQLStore) DeleteScheduledTask(ctx context.Context, subscriptionID, id int64) error {
	return s.deleteAccountService(ctx, subscriptionID, `DELETE FROM scheduled_tasks WHERE id=$1 AND subscription_id=$2`, id)
}
func (s *SQLStore) DeleteMailDomain(ctx context.Context, subscriptionID, id int64) error {
	return s.deleteAccountService(ctx, subscriptionID, `UPDATE mail_domains SET enabled=false,delete_requested=true,convergence_status='pending',updated_at=now() WHERE id=$1 AND subscription_id=$2`, id)
}
func (s *SQLStore) DeleteApplication(ctx context.Context, subscriptionID, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockActiveSubscriptionTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	var revision int64
	err = tx.QueryRowContext(ctx, `UPDATE application_instances
SET delete_requested=true,
    desired_revision=CASE WHEN delete_requested THEN desired_revision+1 ELSE desired_revision END,
    convergence_status='pending',last_error='',updated_at=now()
WHERE id=$1 AND subscription_id=$2
RETURNING desired_revision`, id, subscriptionID).Scan(&revision)
	if err != nil {
		return err
	}
	// Container teardown must not be held behind an unrelated subscription
	// account convergence failure (for example, a temporarily unavailable
	// filesystem quota backend). Queue the fenced application revision too.
	if err = s.enqueueApplicationConvergenceTx(ctx, tx, id, revision); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) enqueueApplicationConvergenceTx(ctx context.Context, tx *sql.Tx, applicationID, revision int64) error {
	if s.river == nil {
		return nil
	}
	_, err := s.river.InsertTx(ctx, tx, ConvergeApplicationArgs{
		ApplicationID: applicationID,
		Revision:      revision,
	}, nil)
	return err
}

func (s *SQLStore) deleteAccountService(ctx context.Context, subscriptionID int64, query string, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockActiveSubscriptionTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, query, id, subscriptionID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	if err := s.markSubscriptionPendingTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	return tx.Commit()
}

func lockActiveSubscriptionTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) error {
	if err := LockSubscriptionMutationTx(ctx, tx, subscriptionID); err != nil {
		return err
	}
	var subscriptionStatus, customerStatus string
	var resellerID sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT subscription.status,customer.status,customer.reseller_id
FROM subscriptions subscription
JOIN customers customer ON customer.id=subscription.customer_id
JOIN subscription_entitlements entitlement ON entitlement.subscription_id=subscription.id
WHERE subscription.id=$1
FOR UPDATE OF subscription,customer,entitlement`, subscriptionID).Scan(
		&subscriptionStatus, &customerStatus, &resellerID,
	); err != nil {
		return err
	}
	if subscriptionStatus != "active" || customerStatus != "active" {
		return errors.New("the customer or subscription is suspended")
	}
	if !resellerID.Valid {
		return nil
	}
	var resellerStatus string
	if err := tx.QueryRowContext(ctx, `SELECT reseller.status
FROM reseller_accounts reseller
JOIN reseller_subscriptions allocation ON allocation.reseller_id=reseller.id AND allocation.status='active'
WHERE reseller.id=$1
FOR UPDATE OF reseller,allocation`, resellerID.Int64).Scan(&resellerStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("the owning reseller is suspended or has no active allocation")
		}
		return err
	}
	if resellerStatus != "active" {
		return errors.New("the owning reseller is suspended")
	}
	return nil
}
