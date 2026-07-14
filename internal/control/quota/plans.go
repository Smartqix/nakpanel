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
)

const (
	OversellPolicyWarn = "warn"
	OversellPolicyCap  = "cap"
)

var ErrOversellCap = errors.New("oversell cap exceeded")

type Plan struct {
	ID                    int64
	Name                  string
	Description           string
	PriceCents            sql.NullInt64
	DiskMB                int
	MaxSites              int
	MaxDatabases          int
	BandwidthMB           int
	MaxMailboxes          int
	AllowSSH              bool
	AllowDNS              bool
	BackupRetentionDays   int
	PHPAllowlist          string
	PHPFPMMaxChildren     int
	PHPMemoryMB           int
	SiteDiskQuotaMB       int
	MaxBackups            int
	BackupStorageMB       int
	IsActive              bool
	CreatedAt             time.Time
	UpdatedAt             time.Time
	ResellerID            int64
	Revision              int
	OverusePolicy         types.PlanOverusePolicy
	DiskWarningPercent    int
	TrafficWarningPercent int
	MaxSubdomains         int
	MaxDomainAliases      int
	MaxFTPAccounts        int
	ValidityDays          int
	HostingEnabled        bool
	DefaultPHPVersion     string
	AllowTLS              bool
	AllowBackups          bool
	AllowPHPSettings      bool
	Presets               types.PlanServicePresets
	HostingPolicy         types.HostingPolicy
}

type Settings struct {
	OversellPolicy       string
	ServerDiskCapacityMB int
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type SubscriptionAssignment struct {
	SubscriptionID int64
	CustomerUserID int64
	PlanID         int64
	Warning        string
}

const maxPlanLimit = 1<<31 - 1

func ValidatePlan(plan Plan) error {
	plan = normalizePlanDefaults(plan)
	if strings.TrimSpace(plan.Name) == "" {
		return errors.New("plan name is required")
	}
	if plan.PriceCents.Valid && plan.PriceCents.Int64 < 0 {
		return errors.New("price_cents cannot be negative")
	}
	for name, value := range map[string]int{
		"disk_mb":               plan.DiskMB,
		"max_sites":             plan.MaxSites,
		"max_databases":         plan.MaxDatabases,
		"bandwidth_mb":          plan.BandwidthMB,
		"max_mailboxes":         plan.MaxMailboxes,
		"backup_retention_days": plan.BackupRetentionDays,
		"php_max_children":      plan.PHPFPMMaxChildren,
		"php_memory_mb":         plan.PHPMemoryMB,
		"site_disk_quota_mb":    plan.SiteDiskQuotaMB,
		"max_backups":           plan.MaxBackups,
		"backup_storage_mb":     plan.BackupStorageMB,
		"max_subdomains":        plan.MaxSubdomains,
		"max_domain_aliases":    plan.MaxDomainAliases,
		"max_ftp_accounts":      plan.MaxFTPAccounts,
		"validity_days":         plan.ValidityDays,
	} {
		if value < -1 {
			return fmt.Errorf("%s cannot be less than -1", name)
		}
		if value > maxPlanLimit {
			return fmt.Errorf("%s exceeds the maximum supported value", name)
		}
	}
	switch plan.OverusePolicy {
	case types.PlanOveruseBlock, types.PlanOveruseNormal, types.PlanOveruseNotify,
		types.PlanOveruseNotSuspend, types.PlanOveruseNotSuspendNotify:
	default:
		return fmt.Errorf("unsupported overuse policy %q", plan.OverusePolicy)
	}
	if plan.DiskWarningPercent < 1 || plan.DiskWarningPercent > 100 {
		return errors.New("disk warning percent must be between 1 and 100")
	}
	if plan.TrafficWarningPercent < 1 || plan.TrafficWarningPercent > 100 {
		return errors.New("traffic warning percent must be between 1 and 100")
	}
	if plan.HostingEnabled {
		if strings.TrimSpace(plan.DefaultPHPVersion) == "" {
			return errors.New("default PHP version is required when hosting is enabled")
		}
		if !csvContains(plan.PHPAllowlist, plan.DefaultPHPVersion) {
			return errors.New("default PHP version must be included in the PHP allowlist")
		}
	}
	return nil
}

const planCoreColumns = `p.id, p.name, p.description, p.price_cents, p.disk_mb, p.max_sites, p.max_databases, p.bandwidth_mb,
       p.max_mailboxes, p.allow_ssh, p.allow_dns, p.backup_retention_days, p.php_allowlist,
       p.php_fpm_max_children, p.php_memory_mb, p.site_disk_quota_mb, p.max_backups,
       p.backup_storage_mb, p.is_active, p.created_at, p.updated_at, COALESCE(p.reseller_id, 0), p.revision,
       p.overuse_policy, p.disk_warning_percent, p.traffic_warning_percent, p.max_subdomains,
       p.max_domain_aliases, p.max_ftp_accounts, p.validity_days, p.hosting_enabled,
	       p.default_php_version, p.allow_tls, p.allow_backups, p.allow_php_settings, p.hosting_policy`

const planPresetJSON = `jsonb_build_object(
       'schema_version', COALESCE(ps.schema_version, 1),
       'hosting', COALESCE(ps.hosting, '{}'::jsonb), 'php', COALESCE(ps.php, '{}'::jsonb),
       'mail', COALESCE(ps.mail, '{}'::jsonb), 'dns', COALESCE(ps.dns, '{}'::jsonb),
       'performance', COALESCE(ps.performance, '{}'::jsonb), 'logs', COALESCE(ps.logs, '{}'::jsonb),
       'applications', COALESCE(ps.applications, '{}'::jsonb))`

func ValidateSettings(settings Settings) error {
	switch settings.OversellPolicy {
	case OversellPolicyWarn, OversellPolicyCap:
	default:
		return fmt.Errorf("unsupported oversell policy %q", settings.OversellPolicy)
	}
	if settings.ServerDiskCapacityMB < 0 {
		return errors.New("server disk capacity cannot be negative")
	}
	return nil
}

func (s *SQLStore) ListPlans(ctx context.Context) ([]Plan, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("quota database is not configured")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+planCoreColumns+`, `+planPresetJSON+`
FROM plans p LEFT JOIN plan_service_presets ps ON ps.plan_id=p.id
ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var plans []Plan
	for rows.Next() {
		plan, err := scanPlanWithPresets(rows)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	return plans, rows.Err()
}

func (s *SQLStore) ListPlansForUser(ctx context.Context, userID int64) ([]Plan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+planCoreColumns+`, `+planPresetJSON+` FROM plans p LEFT JOIN plan_service_presets ps ON ps.plan_id=p.id WHERE p.reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$1) ORDER BY p.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Plan
	for rows.Next() {
		p, err := scanPlanWithPresets(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertPlan(ctx context.Context, plan Plan) (Plan, error) {
	if s == nil || s.db == nil {
		return Plan{}, errors.New("quota database is not configured")
	}
	plan = normalizePlanDefaults(plan)
	if err := ValidatePlan(plan); err != nil {
		return Plan{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Plan{}, err
	}
	defer tx.Rollback()
	var saved Plan
	if plan.ID > 0 {
		saved, err = updatePlanTx(ctx, tx, plan)
	} else {
		saved, err = insertPlanTx(ctx, tx, plan)
	}
	if err != nil {
		return Plan{}, err
	}
	if err := upsertPlanPresetsTx(ctx, tx, saved.ID, normalizedPlanPresets(plan)); err != nil {
		return Plan{}, err
	}
	saved.Presets = normalizedPlanPresets(plan)
	if plan.HostingPolicy.SchemaVersion == 0 {
		plan.HostingPolicy = hostingPolicyFromPlan(plan)
	}
	if err := controlpolicy.Validate(plan.HostingPolicy); err != nil {
		return Plan{}, fmt.Errorf("hosting policy: %w", err)
	}
	policyJSON, err := json.Marshal(plan.HostingPolicy)
	if err != nil {
		return Plan{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE plans SET hosting_policy=$2 WHERE id=$1`, saved.ID, policyJSON); err != nil {
		return Plan{}, err
	}
	saved.HostingPolicy = plan.HostingPolicy
	if err := validatePlanWithinResellerTx(ctx, tx, saved); err != nil {
		return Plan{}, err
	}
	if err := enforceProjectedResellerPlanTx(ctx, tx, saved); err != nil {
		return Plan{}, err
	}
	if err := enforceCommittedAllocationCapTx(ctx, tx); err != nil {
		return Plan{}, err
	}
	if saved.ID > 0 && plan.ID > 0 {
		if err := enforceProjectedPlanCapTx(ctx, tx, saved); err != nil {
			return Plan{}, err
		}
		if s.river != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE subscriptions SET sync_status='pending',sync_error='',updated_at=now() WHERE plan_id=$1 AND sync_mode='synced'`, saved.ID); err != nil {
				return Plan{}, err
			}
			if _, err := s.river.InsertTx(ctx, tx, SyncPlanArgs{PlanID: saved.ID}, nil); err != nil {
				return Plan{}, fmt.Errorf("enqueue plan synchronization: %w", err)
			}
		} else {
			if err := syncPlanSubscriptionsTx(ctx, tx, saved.ID); err != nil {
				return Plan{}, err
			}
			if err := enforceCommittedAllocationCapTx(ctx, tx); err != nil {
				return Plan{}, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return Plan{}, err
	}
	return saved, nil
}

func (s *SQLStore) SetPlanActive(ctx context.Context, planID int64, active bool) error {
	if s == nil || s.db == nil {
		return errors.New("quota database is not configured")
	}
	if planID <= 0 {
		return errors.New("plan id is required")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE plans SET is_active = $2, updated_at = now() WHERE id = $1`, planID, active)
	return err
}

func (s *SQLStore) PreviewPlan(ctx context.Context, plan Plan) (types.PlanPreview, error) {
	if s == nil || s.db == nil {
		return types.PlanPreview{}, errors.New("quota database is not configured")
	}
	plan = normalizePlanDefaults(plan)
	if err := ValidatePlan(plan); err != nil {
		return types.PlanPreview{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.PlanPreview{}, err
	}
	defer tx.Rollback()
	if err := validatePlanWithinResellerTx(ctx, tx, plan); err != nil {
		return types.PlanPreview{}, err
	}
	preview := types.PlanPreview{Allowed: true}
	if plan.ID > 0 {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FILTER (WHERE sync_mode='synced')::int,
COUNT(*) FILTER (WHERE sync_mode='locked')::int,COUNT(*) FILTER (WHERE sync_mode='custom')::int
FROM subscriptions WHERE plan_id=$1`, plan.ID).Scan(&preview.SyncedSubscriptions, &preview.LockedSubscriptions, &preview.CustomSubscriptions); err != nil {
			return types.PlanPreview{}, err
		}
	}
	settings, err := getSettingsTx(ctx, tx)
	if err != nil {
		return types.PlanPreview{}, err
	}
	preview.ServerCapacityMB = settings.ServerDiskCapacityMB
	committed, unlimited, err := projectedCommittedAllocationTx(ctx, tx, plan.ID, plan.DiskMB)
	if err != nil {
		return types.PlanPreview{}, err
	}
	preview.CommittedDiskMB = committed
	if unlimited {
		preview.CommittedDiskMB = -1
	}
	if settings.OversellPolicy == OversellPolicyCap && (unlimited || (settings.ServerDiskCapacityMB > 0 && committed > settings.ServerDiskCapacityMB)) {
		preview.Allowed = false
		preview.Warning = "Current committed disk exceeds the configured server capacity."
	} else if settings.ServerDiskCapacityMB > 0 && (unlimited || committed > settings.ServerDiskCapacityMB) {
		preview.Warning = "Committed disk exceeds the configured server capacity."
	}
	if plan.ResellerID > 0 {
		resellerCommitted, resellerCapacity, resellerUnlimited, err := projectedResellerDiskAllocationTx(ctx, tx, plan.ResellerID, plan.ID, plan.DiskMB)
		if err != nil {
			return types.PlanPreview{}, err
		}
		preview.ResellerCommittedMB = resellerCommitted
		preview.ResellerCapacityMB = resellerCapacity
		preview.HasResellerCapacity = true
		if resellerUnlimited {
			preview.ResellerCommittedMB = -1
		}
		if resellerCapacity >= 0 && (resellerUnlimited || resellerCommitted > resellerCapacity) {
			preview.Allowed = false
			preview.Warning = fmt.Sprintf("Synchronized subscriptions would exceed the reseller disk allocation of %d MB.", resellerCapacity)
		}
	}
	return preview, nil
}

func projectedResellerDiskAllocationTx(ctx context.Context, q queryRower, resellerID, planID int64, diskMB int) (int, int, bool, error) {
	var capacity int
	if err := q.QueryRowContext(ctx, `SELECT p.disk_mb FROM reseller_subscriptions rs JOIN reseller_plans p ON p.id=rs.reseller_plan_id WHERE rs.reseller_id=$1 AND rs.status='active'`, resellerID).Scan(&capacity); err != nil {
		return 0, 0, false, err
	}
	var committed int64
	var unlimited bool
	if err := q.QueryRowContext(ctx, `WITH affected AS (
    SELECT s.id,
           CASE WHEN $3::bigint < 0 OR COALESCE(BOOL_OR(a.disk_mb < 0), false)
                THEN -1::bigint
                ELSE $3::bigint + COALESCE(SUM(a.disk_mb) FILTER (WHERE a.disk_mb >= 0), 0)::bigint
           END AS disk_mb
    FROM subscriptions s
    JOIN customers c ON c.id=s.customer_id
    LEFT JOIN subscription_addons sa ON sa.subscription_id=s.id
    LEFT JOIN addon_plans a ON a.id=sa.addon_plan_id
    WHERE c.reseller_id=$1 AND s.status='active' AND s.plan_id=$2 AND s.sync_mode='synced'
    GROUP BY s.id
), projected AS (
    SELECT e.disk_mb::bigint AS disk_mb
    FROM subscriptions s
    JOIN customers c ON c.id=s.customer_id
    JOIN subscription_entitlements e ON e.subscription_id=s.id
    WHERE c.reseller_id=$1 AND s.status='active'
      AND NOT (COALESCE(s.plan_id,0)=$2 AND s.sync_mode='synced')
    UNION ALL
    SELECT disk_mb FROM affected
)
SELECT COALESCE(SUM(CASE WHEN disk_mb>=0 THEN disk_mb ELSE 0 END),0)::bigint,
       COALESCE(BOOL_OR(disk_mb<0),false)
FROM projected`, resellerID, planID, diskMB).Scan(&committed, &unlimited); err != nil {
		return 0, 0, false, err
	}
	return int(committed), capacity, unlimited, nil
}

func enforceProjectedResellerPlanTx(ctx context.Context, tx *sql.Tx, plan Plan) error {
	if plan.ResellerID <= 0 || plan.ID <= 0 {
		return nil
	}
	committed, capacity, unlimited, err := projectedResellerDiskAllocationTx(ctx, tx, plan.ResellerID, plan.ID, plan.DiskMB)
	if err != nil {
		return err
	}
	if capacity >= 0 && (unlimited || committed > capacity) {
		return fmt.Errorf("%w: synchronized subscriptions would exceed reseller disk allocation %d MB", ErrResellerCapacity, capacity)
	}
	return nil
}

func projectedCommittedAllocationTx(ctx context.Context, q queryRower, planID int64, diskMB int) (int, bool, error) {
	var committed int64
	var unlimited bool
	err := q.QueryRowContext(ctx, `WITH affected AS (
    SELECT s.id,
           CASE WHEN $2::bigint < 0 OR COALESCE(BOOL_OR(a.disk_mb < 0), false)
                THEN -1::bigint
                ELSE $2::bigint + COALESCE(SUM(a.disk_mb) FILTER (WHERE a.disk_mb >= 0), 0)::bigint
           END AS disk_mb
    FROM subscriptions s
    LEFT JOIN subscription_addons sa ON sa.subscription_id=s.id
    LEFT JOIN addon_plans a ON a.id=sa.addon_plan_id
    WHERE s.status='active' AND s.plan_id=$1 AND s.sync_mode='synced'
    GROUP BY s.id
), projected AS (
    SELECT e.disk_mb::bigint AS disk_mb
    FROM subscriptions s
    JOIN subscription_entitlements e ON e.subscription_id=s.id
    WHERE s.status='active'
      AND NOT (COALESCE(s.plan_id,0)=$1 AND s.sync_mode='synced')
    UNION ALL
    SELECT disk_mb FROM affected
)
SELECT COALESCE(SUM(CASE WHEN disk_mb>=0 THEN disk_mb ELSE 0 END),0)::bigint,
       COALESCE(BOOL_OR(disk_mb<0),false)
FROM projected`, planID, diskMB).Scan(&committed, &unlimited)
	if err != nil {
		return 0, false, err
	}
	return int(committed), unlimited, nil
}

func enforceProjectedPlanCapTx(ctx context.Context, tx *sql.Tx, plan Plan) error {
	settings, err := getSettingsForUpdateTx(ctx, tx)
	if err != nil || settings.OversellPolicy != OversellPolicyCap {
		return err
	}
	committed, unlimited, err := projectedCommittedAllocationTx(ctx, tx, plan.ID, plan.DiskMB)
	if err != nil {
		return err
	}
	if unlimited {
		return fmt.Errorf("%w: synchronized subscriptions would include unlimited disk", ErrOversellCap)
	}
	if settings.ServerDiskCapacityMB > 0 && committed > settings.ServerDiskCapacityMB {
		return fmt.Errorf("%w: synchronized committed disk %d MB exceeds capacity %d MB", ErrOversellCap, committed, settings.ServerDiskCapacityMB)
	}
	return nil
}

func (s *SQLStore) AssignSubscription(ctx context.Context, customerUserID int64, planID int64) (SubscriptionAssignment, error) {
	if s == nil || s.db == nil {
		return SubscriptionAssignment{}, errors.New("quota database is not configured")
	}
	if customerUserID <= 0 {
		return SubscriptionAssignment{}, errors.New("customer user id is required")
	}
	if planID <= 0 {
		return SubscriptionAssignment{}, errors.New("plan id is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SubscriptionAssignment{}, err
	}
	defer tx.Rollback()
	plan, err := selectPlanForUpdateTx(ctx, tx, planID)
	if err != nil {
		return SubscriptionAssignment{}, err
	}
	if !plan.IsActive {
		return SubscriptionAssignment{}, fmt.Errorf("plan %q is inactive", plan.Name)
	}
	warning, err := subscriptionOversellWarningTx(ctx, tx, customerUserID, plan)
	if err != nil {
		return SubscriptionAssignment{}, err
	}
	subscriptionID, err := assignSubscriptionTx(ctx, tx, customerUserID, planID)
	if err != nil {
		return SubscriptionAssignment{}, err
	}
	if err := relinkResourcesTx(ctx, tx, customerUserID, subscriptionID); err != nil {
		return SubscriptionAssignment{}, err
	}
	if err := tx.Commit(); err != nil {
		return SubscriptionAssignment{}, err
	}
	return SubscriptionAssignment{
		SubscriptionID: subscriptionID,
		CustomerUserID: customerUserID,
		PlanID:         planID,
		Warning:        warning,
	}, nil
}

func (s *SQLStore) GetSettings(ctx context.Context) (Settings, error) {
	if s == nil || s.db == nil {
		return Settings{}, errors.New("quota database is not configured")
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO settings (id, oversell_policy, server_disk_capacity_mb)
VALUES (true, 'warn', 0)
ON CONFLICT (id) DO NOTHING`); err != nil {
		return Settings{}, err
	}
	return getSettingsTx(ctx, s.db)
}

func (s *SQLStore) UpdateSettings(ctx context.Context, settings Settings) error {
	if s == nil || s.db == nil {
		return errors.New("quota database is not configured")
	}
	if err := ValidateSettings(settings); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings (id, oversell_policy, server_disk_capacity_mb)
VALUES (true, $1, $2)
ON CONFLICT (id) DO UPDATE SET
    oversell_policy = EXCLUDED.oversell_policy,
    server_disk_capacity_mb = EXCLUDED.server_disk_capacity_mb,
    updated_at = now()`, settings.OversellPolicy, settings.ServerDiskCapacityMB); err != nil {
		return err
	}
	if err := enforceCommittedAllocationCapTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) CommittedAllocationMB(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("quota database is not configured")
	}
	committed, unlimited, err := committedAllocationTx(ctx, s.db, 0)
	if err != nil {
		return 0, err
	}
	if unlimited {
		return -1, nil
	}
	return committed, nil
}

func insertPlanTx(ctx context.Context, tx *sql.Tx, plan Plan) (Plan, error) {
	row := tx.QueryRowContext(ctx, `INSERT INTO plans (
    name, description, price_cents, disk_mb, max_sites, max_databases, bandwidth_mb,
    max_mailboxes, allow_ssh, allow_dns, backup_retention_days, php_allowlist,
    php_fpm_max_children, php_memory_mb, site_disk_quota_mb, max_backups,
	    backup_storage_mb, is_active, reseller_id, overuse_policy, disk_warning_percent,
	    traffic_warning_percent, max_subdomains, max_domain_aliases, max_ftp_accounts,
	    validity_days, hosting_enabled, default_php_version, allow_tls, allow_backups, allow_php_settings
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
	          $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31)
RETURNING id, name, description, price_cents, disk_mb, max_sites, max_databases, bandwidth_mb,
       max_mailboxes, allow_ssh, allow_dns, backup_retention_days, php_allowlist,
       php_fpm_max_children, php_memory_mb, site_disk_quota_mb, max_backups,
       backup_storage_mb, is_active, created_at, updated_at, COALESCE(reseller_id, 0), revision,
       overuse_policy, disk_warning_percent, traffic_warning_percent, max_subdomains,
       max_domain_aliases, max_ftp_accounts, validity_days, hosting_enabled, default_php_version,
       allow_tls, allow_backups, allow_php_settings`,
		strings.TrimSpace(plan.Name),
		strings.TrimSpace(plan.Description),
		nullInt64Value(plan.PriceCents),
		plan.DiskMB,
		plan.MaxSites,
		plan.MaxDatabases,
		plan.BandwidthMB,
		plan.MaxMailboxes,
		plan.AllowSSH,
		plan.AllowDNS,
		plan.BackupRetentionDays,
		strings.TrimSpace(plan.PHPAllowlist),
		plan.PHPFPMMaxChildren,
		plan.PHPMemoryMB,
		plan.SiteDiskQuotaMB,
		plan.MaxBackups,
		plan.BackupStorageMB,
		plan.IsActive,
		nullableInt64(plan.ResellerID),
		plan.OverusePolicy,
		plan.DiskWarningPercent,
		plan.TrafficWarningPercent,
		plan.MaxSubdomains,
		plan.MaxDomainAliases,
		plan.MaxFTPAccounts,
		plan.ValidityDays,
		plan.HostingEnabled,
		strings.TrimSpace(plan.DefaultPHPVersion),
		plan.AllowTLS,
		plan.AllowBackups,
		plan.AllowPHPSettings,
	)
	return scanPlan(row)
}

func updatePlanTx(ctx context.Context, tx *sql.Tx, plan Plan) (Plan, error) {
	row := tx.QueryRowContext(ctx, `UPDATE plans
SET
    name = $2,
    description = $3,
    price_cents = $4,
    disk_mb = $5,
    max_sites = $6,
    max_databases = $7,
    bandwidth_mb = $8,
    max_mailboxes = $9,
    allow_ssh = $10,
    allow_dns = $11,
    backup_retention_days = $12,
    php_allowlist = $13,
    php_fpm_max_children = $14,
    php_memory_mb = $15,
    site_disk_quota_mb = $16,
	    max_backups = $17,
	    backup_storage_mb = $18,
		    is_active = $19,
		    overuse_policy = $20,
		    disk_warning_percent = $21,
		    traffic_warning_percent = $22,
		    max_subdomains = $23,
		    max_domain_aliases = $24,
		    max_ftp_accounts = $25,
		    validity_days = $26,
		    hosting_enabled = $27,
		    default_php_version = $28,
		    allow_tls = $29,
		    allow_backups = $30,
		    allow_php_settings = $31,
		 revision = revision + 1,
    updated_at = now()
WHERE id = $1
RETURNING id, name, description, price_cents, disk_mb, max_sites, max_databases, bandwidth_mb,
       max_mailboxes, allow_ssh, allow_dns, backup_retention_days, php_allowlist,
       php_fpm_max_children, php_memory_mb, site_disk_quota_mb, max_backups,
	       backup_storage_mb, is_active, created_at, updated_at, COALESCE(reseller_id, 0), revision,
	       overuse_policy, disk_warning_percent, traffic_warning_percent, max_subdomains,
	       max_domain_aliases, max_ftp_accounts, validity_days, hosting_enabled, default_php_version,
	       allow_tls, allow_backups, allow_php_settings`,
		plan.ID,
		strings.TrimSpace(plan.Name),
		strings.TrimSpace(plan.Description),
		nullInt64Value(plan.PriceCents),
		plan.DiskMB,
		plan.MaxSites,
		plan.MaxDatabases,
		plan.BandwidthMB,
		plan.MaxMailboxes,
		plan.AllowSSH,
		plan.AllowDNS,
		plan.BackupRetentionDays,
		strings.TrimSpace(plan.PHPAllowlist),
		plan.PHPFPMMaxChildren,
		plan.PHPMemoryMB,
		plan.SiteDiskQuotaMB,
		plan.MaxBackups,
		plan.BackupStorageMB,
		plan.IsActive,
		plan.OverusePolicy,
		plan.DiskWarningPercent,
		plan.TrafficWarningPercent,
		plan.MaxSubdomains,
		plan.MaxDomainAliases,
		plan.MaxFTPAccounts,
		plan.ValidityDays,
		plan.HostingEnabled,
		strings.TrimSpace(plan.DefaultPHPVersion),
		plan.AllowTLS,
		plan.AllowBackups,
		plan.AllowPHPSettings,
	)
	return scanPlan(row)
}

func selectPlanForUpdateTx(ctx context.Context, tx *sql.Tx, planID int64) (Plan, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+planCoreColumns+`, `+planPresetJSON+`
FROM plans p LEFT JOIN plan_service_presets ps ON ps.plan_id=p.id
WHERE p.id = $1 FOR UPDATE OF p`, planID)
	return scanPlanWithPresets(row)
}

func upsertLegacyQuotaPlanTx(ctx context.Context, tx *sql.Tx, limits Limits) (int64, error) {
	var planID int64
	name := fmt.Sprintf("Custom quota user %d", limits.UserID)
	description := fmt.Sprintf("Compatibility plan generated from /quotas for user %d.", limits.UserID)
	err := tx.QueryRowContext(ctx, `INSERT INTO plans (
    name, description, disk_mb, max_sites, max_databases, bandwidth_mb, max_mailboxes,
    allow_ssh, allow_dns, backup_retention_days, php_allowlist, php_fpm_max_children,
    php_memory_mb, site_disk_quota_mb, max_backups, backup_storage_mb, is_active
) VALUES ($1, $2, $3, $4, $5, -1, 0, false, true, 0, '8.3', $6, $7, $8, $9, $10, false)
ON CONFLICT DO NOTHING
RETURNING id`,
		name,
		description,
		limits.StorageMB,
		limits.MaxSites,
		limits.MaxDatabases,
		limits.PHPFPMMaxChildren,
		limits.PHPMemoryMB,
		limits.SiteDiskQuotaMB,
		limits.MaxBackups,
		limits.BackupStorageMB,
	).Scan(&planID)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, `UPDATE plans SET description=$2,disk_mb=$3,max_sites=$4,max_databases=$5,
php_fpm_max_children=$6,php_memory_mb=$7,site_disk_quota_mb=$8,max_backups=$9,
backup_storage_mb=$10,updated_at=now()
WHERE reseller_id IS NULL AND lower(name)=lower($1)
RETURNING id`, name, description, limits.StorageMB, limits.MaxSites, limits.MaxDatabases,
			limits.PHPFPMMaxChildren, limits.PHPMemoryMB, limits.SiteDiskQuotaMB,
			limits.MaxBackups, limits.BackupStorageMB).Scan(&planID)
	}
	if err != nil {
		return 0, err
	}
	plan := normalizePlanDefaults(Plan{
		ID: planID, Name: name, Description: description, DiskMB: limits.StorageMB,
		MaxSites: limits.MaxSites, MaxDatabases: limits.MaxDatabases, BandwidthMB: -1,
		AllowDNS: true, PHPAllowlist: "8.3", PHPFPMMaxChildren: limits.PHPFPMMaxChildren,
		PHPMemoryMB: limits.PHPMemoryMB, SiteDiskQuotaMB: limits.SiteDiskQuotaMB,
		MaxBackups: limits.MaxBackups, BackupStorageMB: limits.BackupStorageMB,
		ValidityDays: -1, HostingEnabled: true, AllowTLS: true, AllowBackups: true,
	})
	policyJSON, err := json.Marshal(hostingPolicyFromPlan(plan))
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE plans SET hosting_policy=$2 WHERE id=$1`, planID, policyJSON); err != nil {
		return 0, err
	}
	return planID, nil
}

func assignSubscriptionTx(ctx context.Context, tx *sql.Tx, customerUserID int64, planID int64) (int64, error) {
	customerID, err := ensureCustomerForUserTx(ctx, tx, customerUserID)
	if err != nil {
		return 0, err
	}
	plan, err := selectPlanForUpdateTx(ctx, tx, planID)
	if err != nil {
		return 0, err
	}
	var subscriptionID int64
	err = tx.QueryRowContext(ctx, `SELECT id
FROM subscriptions
WHERE customer_user_id=$1 AND status IN ('active','suspended')
ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END,id
LIMIT 1
FOR UPDATE`, customerUserID).Scan(&subscriptionID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		err = tx.QueryRowContext(ctx, `INSERT INTO subscriptions
(customer_id,customer_user_id,plan_id,name,status,sync_mode,sync_status,plan_revision,sync_error)
VALUES($1,$2,$3,$4,'active','synced','in_sync',$5,'')
RETURNING id`, customerID, customerUserID, planID, plan.Name+" subscription", maxInt(plan.Revision, 1)).Scan(&subscriptionID)
	case err == nil:
		_, err = tx.ExecContext(ctx, `UPDATE subscriptions
SET customer_id=$2,customer_user_id=$3,plan_id=$4,name=$5,status='active',
    sync_mode='synced',sync_status='in_sync',plan_revision=$6,sync_error='',updated_at=now()
WHERE id=$1`, subscriptionID, customerID, customerUserID, planID, plan.Name+" subscription", maxInt(plan.Revision, 1))
	}
	if err != nil {
		return 0, err
	}
	if err := writePlanEntitlementsTx(ctx, tx, subscriptionID, plan); err != nil {
		return 0, err
	}
	var accountID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM subscription_system_accounts WHERE subscription_id=$1 FOR UPDATE`, subscriptionID).Scan(&accountID)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = createSubscriptionSystemAccountTx(ctx, tx, subscriptionID, "", "active")
	} else if err == nil {
		_, err = tx.ExecContext(ctx, `UPDATE subscription_system_accounts
SET desired_state='active',convergence_status='pending',last_error='',updated_at=now()
WHERE id=$1`, accountID)
	}
	if err != nil {
		return 0, err
	}
	return subscriptionID, nil
}

func relinkResourcesTx(ctx context.Context, tx *sql.Tx, customerUserID int64, subscriptionID int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE sites
SET subscription_id = $2,
    customer_id = (SELECT customer_id FROM subscriptions WHERE id = $2)
WHERE owner_user_id = $1`, customerUserID, subscriptionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE databases
SET subscription_id = $2,
    customer_id = (SELECT customer_id FROM subscriptions WHERE id = $2)
WHERE owner_user_id = $1`, customerUserID, subscriptionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE backups
SET subscription_id = $2,
    customer_id = (SELECT customer_id FROM subscriptions WHERE id = $2)
WHERE owner_user_id = $1`, customerUserID, subscriptionID); err != nil {
		return err
	}
	return nil
}

func ensureCustomerForUserTx(ctx context.Context, tx *sql.Tx, userID int64) (int64, error) {
	var customerID int64
	err := tx.QueryRowContext(ctx, `SELECT id FROM customers WHERE login_user_id = $1`, userID).Scan(&customerID)
	if err == nil {
		return customerID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO customers (login_user_id, email, display_name, status)
SELECT id, email, email, 'active'
FROM users
WHERE id = $1
RETURNING id`, userID).Scan(&customerID)
	return customerID, err
}

func subscriptionOversellWarningTx(ctx context.Context, tx *sql.Tx, customerUserID int64, plan Plan) (string, error) {
	settings, err := getSettingsForUpdateTx(ctx, tx)
	if err != nil {
		return "", err
	}
	committed, unlimited, err := committedAllocationTx(ctx, tx, customerUserID)
	if err != nil {
		return "", err
	}
	if settings.OversellPolicy == OversellPolicyCap {
		if plan.DiskMB < 0 {
			return "", fmt.Errorf("%w: plan %q has unlimited disk", ErrOversellCap, plan.Name)
		}
		if unlimited {
			return "", fmt.Errorf("%w: existing active subscriptions include unlimited disk", ErrOversellCap)
		}
		if settings.ServerDiskCapacityMB > 0 && committed+plan.DiskMB > settings.ServerDiskCapacityMB {
			return "", fmt.Errorf("%w: committed disk %d MB + plan %d MB exceeds capacity %d MB", ErrOversellCap, committed, plan.DiskMB, settings.ServerDiskCapacityMB)
		}
		return "", nil
	}
	if plan.DiskMB < 0 || unlimited {
		return "Warning: committed allocation includes unlimited disk.", nil
	}
	if settings.ServerDiskCapacityMB > 0 && committed+plan.DiskMB > settings.ServerDiskCapacityMB {
		return fmt.Sprintf("Warning: committed disk %d MB exceeds capacity %d MB.", committed+plan.DiskMB, settings.ServerDiskCapacityMB), nil
	}
	return "", nil
}

func enforceCommittedAllocationCapTx(ctx context.Context, tx *sql.Tx) error {
	settings, err := getSettingsForUpdateTx(ctx, tx)
	if err != nil {
		return err
	}
	if settings.OversellPolicy != OversellPolicyCap {
		return nil
	}
	committed, unlimited, err := committedAllocationTx(ctx, tx, 0)
	if err != nil {
		return err
	}
	if unlimited {
		return fmt.Errorf("%w: active subscriptions include unlimited disk", ErrOversellCap)
	}
	if settings.ServerDiskCapacityMB > 0 && committed > settings.ServerDiskCapacityMB {
		return fmt.Errorf("%w: committed disk %d MB exceeds capacity %d MB", ErrOversellCap, committed, settings.ServerDiskCapacityMB)
	}
	return nil
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func getSettingsTx(ctx context.Context, q queryRower) (Settings, error) {
	var settings Settings
	err := q.QueryRowContext(ctx, `SELECT oversell_policy, server_disk_capacity_mb, created_at, updated_at
FROM settings
WHERE id = true`).Scan(&settings.OversellPolicy, &settings.ServerDiskCapacityMB, &settings.CreatedAt, &settings.UpdatedAt)
	return settings, err
}

func getSettingsForUpdateTx(ctx context.Context, tx *sql.Tx) (Settings, error) {
	var settings Settings
	err := tx.QueryRowContext(ctx, `SELECT oversell_policy, server_disk_capacity_mb, created_at, updated_at
FROM settings
WHERE id = true
FOR UPDATE`).Scan(&settings.OversellPolicy, &settings.ServerDiskCapacityMB, &settings.CreatedAt, &settings.UpdatedAt)
	return settings, err
}

func committedAllocationTx(ctx context.Context, q queryRower, excludeCustomerUserID int64) (int, bool, error) {
	var committed sql.NullInt64
	var unlimited sql.NullBool
	err := q.QueryRowContext(ctx, `SELECT
    COALESCE(SUM(CASE WHEN e.disk_mb >= 0 THEN e.disk_mb ELSE 0 END), 0)::bigint,
    COALESCE(BOOL_OR(e.disk_mb < 0), false)
FROM subscriptions s
JOIN subscription_entitlements e ON e.subscription_id = s.id
WHERE s.status = 'active'
  AND ($1::bigint = 0 OR s.customer_user_id <> $1)`, excludeCustomerUserID).Scan(&committed, &unlimited)
	if err != nil {
		return 0, false, err
	}
	return int(committed.Int64), unlimited.Valid && unlimited.Bool, nil
}

type planScanner interface {
	Scan(dest ...any) error
}

func scanPlan(row planScanner) (Plan, error) {
	var plan Plan
	if err := row.Scan(
		&plan.ID,
		&plan.Name,
		&plan.Description,
		&plan.PriceCents,
		&plan.DiskMB,
		&plan.MaxSites,
		&plan.MaxDatabases,
		&plan.BandwidthMB,
		&plan.MaxMailboxes,
		&plan.AllowSSH,
		&plan.AllowDNS,
		&plan.BackupRetentionDays,
		&plan.PHPAllowlist,
		&plan.PHPFPMMaxChildren,
		&plan.PHPMemoryMB,
		&plan.SiteDiskQuotaMB,
		&plan.MaxBackups,
		&plan.BackupStorageMB,
		&plan.IsActive,
		&plan.CreatedAt,
		&plan.UpdatedAt,
		&plan.ResellerID,
		&plan.Revision,
		&plan.OverusePolicy,
		&plan.DiskWarningPercent,
		&plan.TrafficWarningPercent,
		&plan.MaxSubdomains,
		&plan.MaxDomainAliases,
		&plan.MaxFTPAccounts,
		&plan.ValidityDays,
		&plan.HostingEnabled,
		&plan.DefaultPHPVersion,
		&plan.AllowTLS,
		&plan.AllowBackups,
		&plan.AllowPHPSettings,
	); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func scanPlanWithPresets(row planScanner) (Plan, error) {
	var plan Plan
	var policyRaw, presetsRaw []byte
	if err := row.Scan(
		&plan.ID, &plan.Name, &plan.Description, &plan.PriceCents, &plan.DiskMB,
		&plan.MaxSites, &plan.MaxDatabases, &plan.BandwidthMB, &plan.MaxMailboxes,
		&plan.AllowSSH, &plan.AllowDNS, &plan.BackupRetentionDays, &plan.PHPAllowlist,
		&plan.PHPFPMMaxChildren, &plan.PHPMemoryMB, &plan.SiteDiskQuotaMB,
		&plan.MaxBackups, &plan.BackupStorageMB, &plan.IsActive, &plan.CreatedAt,
		&plan.UpdatedAt, &plan.ResellerID, &plan.Revision, &plan.OverusePolicy,
		&plan.DiskWarningPercent, &plan.TrafficWarningPercent, &plan.MaxSubdomains,
		&plan.MaxDomainAliases, &plan.MaxFTPAccounts, &plan.ValidityDays,
		&plan.HostingEnabled, &plan.DefaultPHPVersion, &plan.AllowTLS,
		&plan.AllowBackups, &plan.AllowPHPSettings, &policyRaw, &presetsRaw,
	); err != nil {
		return Plan{}, err
	}
	if err := json.Unmarshal(presetsRaw, &plan.Presets); err != nil {
		return Plan{}, fmt.Errorf("decode plan service presets: %w", err)
	}
	if err := json.Unmarshal(policyRaw, &plan.HostingPolicy); err != nil {
		return Plan{}, fmt.Errorf("decode plan hosting policy: %w", err)
	}
	return plan, nil
}

func hostingPolicyFromPlan(plan Plan) types.HostingPolicy {
	e := entitlementsFromPlan(plan)
	return controlpolicy.DefaultFromEntitlements(e)
}

func normalizedPlanPresets(plan Plan) types.PlanServicePresets {
	presets := plan.Presets
	if presets.SchemaVersion <= 0 {
		presets.SchemaVersion = 1
	}
	if presets.Hosting.WebServer == "" {
		presets.Hosting.WebServer = "nginx"
	}
	if presets.Hosting.PreferredDomain == "" {
		presets.Hosting.PreferredDomain = "none"
	}
	if presets.Hosting.DefaultPHPVersion == "" {
		presets.Hosting.DefaultPHPVersion = plan.DefaultPHPVersion
	}
	if len(presets.Hosting.AllowedPHPVersions) == 0 {
		for _, version := range strings.Split(plan.PHPAllowlist, ",") {
			if version = strings.TrimSpace(version); version != "" {
				presets.Hosting.AllowedPHPVersions = append(presets.Hosting.AllowedPHPVersions, version)
			}
		}
	}
	return presets
}

func normalizePlanDefaults(plan Plan) Plan {
	if plan.OverusePolicy == "" {
		plan.OverusePolicy = types.PlanOveruseBlock
	}
	if plan.DiskWarningPercent == 0 {
		plan.DiskWarningPercent = 80
	}
	if plan.TrafficWarningPercent == 0 {
		plan.TrafficWarningPercent = 80
	}
	if plan.DefaultPHPVersion == "" && strings.TrimSpace(plan.PHPAllowlist) != "" {
		plan.DefaultPHPVersion = strings.TrimSpace(strings.Split(plan.PHPAllowlist, ",")[0])
	}
	plan.Presets = normalizedPlanPresets(plan)
	return plan
}

func upsertPlanPresetsTx(ctx context.Context, tx *sql.Tx, planID int64, presets types.PlanServicePresets) error {
	plan := Plan{Presets: presets}
	presets = normalizedPlanPresets(plan)
	values := []any{planID, presets.SchemaVersion}
	for _, value := range []any{presets.Hosting, presets.PHP, presets.Mail, presets.DNS, presets.Performance, presets.Logs, presets.Applications} {
		raw, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("encode plan service preset: %w", err)
		}
		values = append(values, raw)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO plan_service_presets (plan_id,schema_version,hosting,php,mail,dns,performance,logs,applications)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (plan_id) DO UPDATE SET schema_version=EXCLUDED.schema_version,hosting=EXCLUDED.hosting,
php=EXCLUDED.php,mail=EXCLUDED.mail,dns=EXCLUDED.dns,performance=EXCLUDED.performance,
logs=EXCLUDED.logs,applications=EXCLUDED.applications,updated_at=now()`, values...)
	return err
}

func csvContains(csv, wanted string) bool {
	wanted = strings.TrimSpace(wanted)
	for _, item := range strings.Split(csv, ",") {
		if strings.TrimSpace(item) == wanted {
			return true
		}
	}
	return false
}

func nullInt64Value(value sql.NullInt64) any {
	if value.Valid {
		return value.Int64
	}
	return nil
}
