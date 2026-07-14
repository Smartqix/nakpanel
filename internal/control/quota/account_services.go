package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/robfig/cron/v3"
)

type AccountServiceStore interface {
	SetSubscriptionPolicy(context.Context, int64, int64, json.RawMessage, bool) error
	SetSitePolicy(context.Context, int64, int64, json.RawMessage) error
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
	DeleteApplication(context.Context, int64, int64) error
}

var (
	applicationServiceNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)
	applicationImageRE       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{1,511}$`)
	applicationEnvKeyRE      = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
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
	return tx.Commit()
}

func (s *SQLStore) SetSitePolicy(ctx context.Context, siteID, actorID int64, patch json.RawMessage) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var subscriptionID int64
	if err = tx.QueryRowContext(ctx, `SELECT subscription_id FROM sites WHERE id=$1 FOR UPDATE`, siteID).Scan(&subscriptionID); err != nil {
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
	return tx.Commit()
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
	}
}

func resellerPolicyCeilingTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) (types.HostingPolicy, bool, error) {
	var raw []byte
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
	if !hasConfiguredPolicy(raw) {
		return types.HostingPolicy{}, false, nil
	}
	var ceiling types.HostingPolicy
	if err := json.Unmarshal(raw, &ceiling); err != nil {
		return types.HostingPolicy{}, false, err
	}
	return ceiling, true, controlpolicy.Validate(ceiling)
}

func (s *SQLStore) markSubscriptionPendingTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE subscription_system_accounts SET convergence_status='pending',last_error='',updated_at=now() WHERE subscription_id=$1`, subscriptionID); err != nil {
		return err
	}
	if s.river != nil {
		if _, err := s.river.InsertTx(ctx, tx, ConvergeSubscriptionArgs{SubscriptionID: subscriptionID}, nil); err != nil {
			return err
		}
		return wakeSubscriptionConvergenceTx(ctx, tx, subscriptionID)
	}
	return nil
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
	if filepath.IsAbs(root) || root == ".." || strings.HasPrefix(root, ".."+string(filepath.Separator)) {
		return 0, errors.New("SFTP root escapes the subscription home")
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
	if strings.TrimSpace(input.Name) == "" || strings.TrimSpace(input.Command) == "" || strings.ContainsAny(input.Name+input.Command+input.WorkingDirectory, "\x00\r\n") || input.TimeoutSeconds < 1 || input.TimeoutSeconds > 86400 {
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
		err := tx.QueryRowContext(ctx, `INSERT INTO scheduled_tasks(id,subscription_id,site_id,name,schedule,command,working_directory,timeout_seconds,enabled)
VALUES(CASE WHEN $1=0 THEN nextval('scheduled_tasks_id_seq') ELSE $1 END,$2,NULLIF($3,0),$4,$5,$6,$7,$8,$9)
ON CONFLICT(id) DO UPDATE SET site_id=EXCLUDED.site_id,name=EXCLUDED.name,schedule=EXCLUDED.schedule,command=EXCLUDED.command,working_directory=EXCLUDED.working_directory,timeout_seconds=EXCLUDED.timeout_seconds,enabled=EXCLUDED.enabled,convergence_status='pending',last_error='',updated_at=now()
WHERE scheduled_tasks.subscription_id=EXCLUDED.subscription_id RETURNING id`, input.ID, subscriptionID, input.SiteID, strings.TrimSpace(input.Name), strings.TrimSpace(input.Schedule), input.Command, strings.TrimSpace(input.WorkingDirectory), input.TimeoutSeconds, input.Enabled).Scan(&id)
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
	if !applicationServiceNameRE.MatchString(input.Name) || !applicationImageRE.MatchString(input.ImageRef) {
		return 0, errors.New("invalid application name or image reference")
	}
	for key, value := range input.Environment {
		if !applicationEnvKeyRE.MatchString(key) || strings.ContainsRune(value, '\x00') || len(value) > 8192 {
			return 0, fmt.Errorf("invalid application environment entry %q", key)
		}
	}
	if input.Runtime != "php" && input.Runtime != "python" && input.Runtime != "node" && input.Runtime != "oci" {
		return 0, errors.New("invalid application runtime")
	}
	if input.DesiredState == "" {
		input.DesiredState = "running"
	}
	if input.DesiredState != "running" && input.DesiredState != "stopped" {
		return 0, errors.New("invalid application state")
	}
	environment, err := json.Marshal(input.Environment)
	if err != nil {
		return 0, err
	}
	return s.upsertAccountService(ctx, subscriptionID, func(tx *sql.Tx, policy types.HostingPolicy) (int64, error) {
		if !policy.Permissions.Applications {
			return 0, errors.New("applications are disabled by the subscription policy")
		}
		if err := ensureSiteBelongsTx(ctx, tx, subscriptionID, input.SiteID); err != nil {
			return 0, err
		}
		if input.ID == 0 {
			if err := enforceServiceCountTx(ctx, tx, `application_instances`, subscriptionID, policy.Resources.MaxApplications); err != nil {
				return 0, err
			}
		}
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO application_instances(id,subscription_id,site_id,name,runtime,catalog_slug,image_ref,desired_state,environment)
VALUES(CASE WHEN $1=0 THEN nextval('application_instances_id_seq') ELSE $1 END,$2,NULLIF($3,0),$4,$5,$6,$7,$8,$9)
ON CONFLICT(id) DO UPDATE SET site_id=EXCLUDED.site_id,name=EXCLUDED.name,runtime=EXCLUDED.runtime,catalog_slug=EXCLUDED.catalog_slug,image_ref=EXCLUDED.image_ref,desired_state=EXCLUDED.desired_state,environment=EXCLUDED.environment,delete_requested=false,convergence_status='pending',last_error='',updated_at=now()
WHERE application_instances.subscription_id=EXCLUDED.subscription_id RETURNING id`, input.ID, subscriptionID, input.SiteID, strings.TrimSpace(input.Name), input.Runtime, strings.TrimSpace(input.CatalogSlug), strings.TrimSpace(input.ImageRef), input.DesiredState, environment).Scan(&id)
		return id, err
	})
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
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
	if err := s.markSubscriptionPendingTx(ctx, tx, subscriptionID); err != nil {
		return 0, err
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
	allowed := map[string]bool{"sftp_access_identities": true, "scheduled_tasks": true, "application_instances": true}
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
	return s.deleteAccountService(ctx, subscriptionID, `UPDATE application_instances SET delete_requested=true,convergence_status='pending',updated_at=now() WHERE id=$1 AND subscription_id=$2`, id)
}

func (s *SQLStore) deleteAccountService(ctx context.Context, subscriptionID int64, query string, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
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
