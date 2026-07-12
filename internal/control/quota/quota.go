package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

var (
	ErrExceeded             = errors.New("quota exceeded")
	ErrNoActiveSubscription = errors.New("no active subscription")
)

type Limits struct {
	UserID            int64
	CustomerID        int64
	SubscriptionID    int64
	PlanID            int64
	PlanName          string
	MaxSites          int
	MaxDatabases      int
	StorageMB         int
	MaxBackups        int
	BackupStorageMB   int
	SiteDiskQuotaMB   int
	PHPFPMMaxChildren int
	PHPMemoryMB       int
	BandwidthMB       int
	OverusePolicy     types.PlanOverusePolicy
	PHPAllowlist      string
	DefaultPHPVersion string
	HostingEnabled    bool
	AllowBackups      bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type Usage struct {
	UserID             int64
	CustomerID         int64
	SubscriptionID     int64
	Sites              int
	Databases          int
	Backups            int
	BackupStorageBytes int64
}

type Summary struct {
	UserID         int64
	Email          string
	Role           string
	HasQuota       bool
	PlanID         int64
	PlanName       string
	SubscriptionID int64
	Limits         Limits
	Usage          Usage
}

type Store interface {
	GetLimits(ctx context.Context, userID int64) (Limits, bool, error)
	GetUsage(ctx context.Context, userID int64) (Usage, error)
	GetLimitsForSubscription(ctx context.Context, subscriptionID int64) (Limits, bool, error)
	GetUsageForSubscription(ctx context.Context, subscriptionID int64) (Usage, error)
	UpsertLimits(ctx context.Context, limits Limits) error
	ListAccountQuotas(ctx context.Context) ([]Summary, error)
	GetAccountQuotaSummary(ctx context.Context, userID int64) (Summary, error)
}

type AdminStore interface {
	Store
	ListPlans(ctx context.Context) ([]Plan, error)
	UpsertPlan(ctx context.Context, plan Plan) (Plan, error)
	SetPlanActive(ctx context.Context, planID int64, active bool) error
	AssignSubscription(ctx context.Context, customerUserID int64, planID int64) (SubscriptionAssignment, error)
	CreateCustomer(ctx context.Context, req types.CreateCustomerReq) (types.Customer, error)
	EnableCustomerLogin(ctx context.Context, customerID int64, email string, password string) (types.Customer, error)
	SetCustomerStatus(ctx context.Context, customerID int64, status string) error
	SetSubscriptionStatus(ctx context.Context, subscriptionID int64, status string) error
	CreateSubscription(ctx context.Context, req types.CreateSubscriptionReq) (types.SubscriptionSummary, error)
	ListCustomers(ctx context.Context) ([]types.Customer, error)
	ListSubscriptionSummaries(ctx context.Context) ([]types.SubscriptionSummary, error)
	ListSubscriptionSummariesForUser(ctx context.Context, userID int64) ([]types.SubscriptionSummary, error)
	GetSettings(ctx context.Context) (Settings, error)
	UpdateSettings(ctx context.Context, settings Settings) error
	CommittedAllocationMB(ctx context.Context) (int, error)
	ProviderScopeForUser(ctx context.Context, user auth.SessionUser) (types.ProviderScope, error)
	ListResellers(ctx context.Context) ([]types.Reseller, error)
	ListResellerPlans(ctx context.Context) ([]types.ResellerPlan, error)
	UpsertResellerPlan(ctx context.Context, plan types.ResellerPlan) (types.ResellerPlan, error)
	CreateReseller(ctx context.Context, req types.CreateCustomerReq, resellerPlanID int64) (types.Reseller, error)
	SetResellerStatus(ctx context.Context, resellerID int64, status string) error
	TransferCustomer(ctx context.Context, customerID, resellerID int64) error
	ListAddonPlans(ctx context.Context) ([]types.AddonPlan, error)
	UpsertAddonPlan(ctx context.Context, addon types.AddonPlan) (types.AddonPlan, error)
	SetSubscriptionAddons(ctx context.Context, subscriptionID int64, addonIDs []int64) error
	SyncSubscription(ctx context.Context, subscriptionID int64) error
	SetSubscriptionMode(ctx context.Context, subscriptionID int64, mode string, custom types.SubscriptionEntitlements) error
}

// BulkStatusStore applies a lifecycle change atomically across all selected
// objects. Keeping this separate preserves compatibility with focused test
// stores that only implement the single-object AdminStore contract.
type BulkStatusStore interface {
	SetCustomerStatuses(ctx context.Context, customerIDs []int64, status string) error
	SetSubscriptionStatuses(ctx context.Context, subscriptionIDs []int64, status string) error
	SetResellerStatuses(ctx context.Context, resellerIDs []int64, status string) error
}

type PlanBulkStatusStore interface {
	SetPlanStatuses(ctx context.Context, planIDs []int64, resellerID int64, unrestricted bool, active bool) error
	SetAddonPlanStatuses(ctx context.Context, addonIDs []int64, resellerID int64, unrestricted bool, active bool) error
	SetResellerPlanStatuses(ctx context.Context, planIDs []int64, active bool) error
}

type DomainSettingsStore interface {
	SiteDomain(ctx context.Context, siteID int64) (string, error)
	UpdateSiteSettings(ctx context.Context, req types.UpdateSiteSettingsReq) error
}

type SubscriptionChangeStore interface {
	ChangeSubscriptionPlans(ctx context.Context, subscriptionIDs []int64, planID int64) error
	ChangeSubscriptionSubscriber(ctx context.Context, subscriptionIDs []int64, customerID int64) error
}

func SiteLimits(ctx context.Context, store Store, userID int64) (types.SiteResourceLimits, error) {
	if store == nil {
		return types.SiteResourceLimits{}, nil
	}
	limits, hasLimits, err := store.GetLimits(ctx, userID)
	if err != nil {
		return types.SiteResourceLimits{}, err
	}
	if !hasLimits {
		return types.SiteResourceLimits{}, ErrNoActiveSubscription
	}
	usage, err := store.GetUsage(ctx, userID)
	if err != nil {
		return types.SiteResourceLimits{}, err
	}
	if countLimitReached(usage.Sites, limits.MaxSites, limits.OverusePolicy) {
		return types.SiteResourceLimits{}, fmt.Errorf("%w: sites %d / %d", ErrExceeded, usage.Sites, limits.MaxSites)
	}
	if limits.SiteDiskQuotaMB == 0 {
		return types.SiteResourceLimits{}, fmt.Errorf("%w: site disk quota is 0 MB", ErrExceeded)
	}
	if limits.PHPFPMMaxChildren == 0 {
		return types.SiteResourceLimits{}, fmt.Errorf("%w: php max children is 0", ErrExceeded)
	}
	if limits.PHPMemoryMB == 0 {
		return types.SiteResourceLimits{}, fmt.Errorf("%w: php memory is 0 MB", ErrExceeded)
	}
	return types.SiteResourceLimits{
		DiskQuotaMB:       positiveLimit(limits.SiteDiskQuotaMB),
		PHPFPMMaxChildren: positiveLimit(limits.PHPFPMMaxChildren),
		PHPMemoryMB:       positiveLimit(limits.PHPMemoryMB),
	}, nil
}

func SiteLimitsForSubscription(ctx context.Context, store Store, subscriptionID int64) (types.SiteResourceLimits, Limits, error) {
	if store == nil {
		return types.SiteResourceLimits{}, Limits{}, nil
	}
	limits, hasLimits, err := store.GetLimitsForSubscription(ctx, subscriptionID)
	if err != nil {
		return types.SiteResourceLimits{}, Limits{}, err
	}
	if !hasLimits {
		return types.SiteResourceLimits{}, Limits{}, ErrNoActiveSubscription
	}
	usage, err := store.GetUsageForSubscription(ctx, subscriptionID)
	if err != nil {
		return types.SiteResourceLimits{}, Limits{}, err
	}
	if !limits.HostingEnabled && limits.OverusePolicy != "" {
		return types.SiteResourceLimits{}, Limits{}, fmt.Errorf("%w: hosting is disabled by the subscription", ErrExceeded)
	}
	if countLimitReached(usage.Sites, limits.MaxSites, limits.OverusePolicy) {
		return types.SiteResourceLimits{}, Limits{}, fmt.Errorf("%w: sites %d / %d", ErrExceeded, usage.Sites, limits.MaxSites)
	}
	if limits.SiteDiskQuotaMB == 0 {
		return types.SiteResourceLimits{}, Limits{}, fmt.Errorf("%w: site disk quota is 0 MB", ErrExceeded)
	}
	if limits.PHPFPMMaxChildren == 0 {
		return types.SiteResourceLimits{}, Limits{}, fmt.Errorf("%w: php max children is 0", ErrExceeded)
	}
	if limits.PHPMemoryMB == 0 {
		return types.SiteResourceLimits{}, Limits{}, fmt.Errorf("%w: php memory is 0 MB", ErrExceeded)
	}
	return types.SiteResourceLimits{
		DiskQuotaMB:       positiveLimit(limits.SiteDiskQuotaMB),
		PHPFPMMaxChildren: positiveLimit(limits.PHPFPMMaxChildren),
		PHPMemoryMB:       positiveLimit(limits.PHPMemoryMB),
	}, limits, nil
}

func CheckDatabase(ctx context.Context, store Store, userID int64) error {
	if store == nil {
		return nil
	}
	limits, hasLimits, err := store.GetLimits(ctx, userID)
	if err != nil {
		return err
	}
	if !hasLimits {
		return ErrNoActiveSubscription
	}
	usage, err := store.GetUsage(ctx, userID)
	if err != nil {
		return err
	}
	if countLimitReached(usage.Databases, limits.MaxDatabases, limits.OverusePolicy) {
		return fmt.Errorf("%w: databases %d / %d", ErrExceeded, usage.Databases, limits.MaxDatabases)
	}
	return nil
}

func CheckDatabaseForSubscription(ctx context.Context, store Store, subscriptionID int64) (Limits, error) {
	if store == nil {
		return Limits{}, nil
	}
	limits, hasLimits, err := store.GetLimitsForSubscription(ctx, subscriptionID)
	if err != nil {
		return Limits{}, err
	}
	if !hasLimits {
		return Limits{}, ErrNoActiveSubscription
	}
	usage, err := store.GetUsageForSubscription(ctx, subscriptionID)
	if err != nil {
		return Limits{}, err
	}
	if countLimitReached(usage.Databases, limits.MaxDatabases, limits.OverusePolicy) {
		return Limits{}, fmt.Errorf("%w: databases %d / %d", ErrExceeded, usage.Databases, limits.MaxDatabases)
	}
	return limits, nil
}

func CheckBackup(ctx context.Context, store Store, userID int64) error {
	if store == nil {
		return nil
	}
	limits, hasLimits, err := store.GetLimits(ctx, userID)
	if err != nil {
		return err
	}
	if !hasLimits {
		return ErrNoActiveSubscription
	}
	usage, err := store.GetUsage(ctx, userID)
	if err != nil {
		return err
	}
	if !limits.AllowBackups && limits.OverusePolicy != "" {
		return fmt.Errorf("%w: backups are disabled by the subscription", ErrExceeded)
	}
	if countLimitReached(usage.Backups, limits.MaxBackups, limits.OverusePolicy) {
		return fmt.Errorf("%w: backups %d / %d", ErrExceeded, usage.Backups, limits.MaxBackups)
	}
	if limits.BackupStorageMB >= 0 {
		maxBytes := int64(limits.BackupStorageMB) * 1024 * 1024
		if usage.BackupStorageBytes >= maxBytes {
			return fmt.Errorf("%w: backup storage %d / %d bytes", ErrExceeded, usage.BackupStorageBytes, maxBytes)
		}
	}
	return nil
}

func CheckBackupForSubscription(ctx context.Context, store Store, subscriptionID int64) (Limits, error) {
	if store == nil {
		return Limits{}, nil
	}
	limits, hasLimits, err := store.GetLimitsForSubscription(ctx, subscriptionID)
	if err != nil {
		return Limits{}, err
	}
	if !hasLimits {
		return Limits{}, ErrNoActiveSubscription
	}
	usage, err := store.GetUsageForSubscription(ctx, subscriptionID)
	if err != nil {
		return Limits{}, err
	}
	if !limits.AllowBackups && limits.OverusePolicy != "" {
		return Limits{}, fmt.Errorf("%w: backups are disabled by the subscription", ErrExceeded)
	}
	if countLimitReached(usage.Backups, limits.MaxBackups, limits.OverusePolicy) {
		return Limits{}, fmt.Errorf("%w: backups %d / %d", ErrExceeded, usage.Backups, limits.MaxBackups)
	}
	if limits.BackupStorageMB >= 0 {
		maxBytes := int64(limits.BackupStorageMB) * 1024 * 1024
		if usage.BackupStorageBytes >= maxBytes {
			return Limits{}, fmt.Errorf("%w: backup storage %d / %d bytes", ErrExceeded, usage.BackupStorageBytes, maxBytes)
		}
	}
	return limits, nil
}

func limitReached(used int, allowed int) bool {
	return allowed >= 0 && used >= allowed
}

func countLimitReached(used, allowed int, policy types.PlanOverusePolicy) bool {
	if policy == types.PlanOveruseNormal || policy == types.PlanOveruseNotify {
		return false
	}
	return limitReached(used, allowed)
}

func ResolvePHPVersion(limits Limits, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if strings.TrimSpace(limits.PHPAllowlist) == "" && limits.OverusePolicy == "" {
		return requested, nil
	}
	if requested == "" {
		requested = strings.TrimSpace(limits.DefaultPHPVersion)
	}
	if requested == "" {
		return "", errors.New("subscription has no default PHP version")
	}
	for _, version := range strings.Split(limits.PHPAllowlist, ",") {
		if strings.TrimSpace(version) == requested {
			return requested, nil
		}
	}
	return "", fmt.Errorf("PHP %s is not allowed by the subscription", requested)
}

func positiveLimit(value int) int {
	if value > 0 {
		return value
	}
	return 0
}

func ValidateLimits(limits Limits) error {
	if limits.UserID <= 0 {
		return errors.New("quota user id is required")
	}
	for name, value := range map[string]int{
		"max_sites":          limits.MaxSites,
		"max_databases":      limits.MaxDatabases,
		"storage_mb":         limits.StorageMB,
		"max_backups":        limits.MaxBackups,
		"backup_storage_mb":  limits.BackupStorageMB,
		"site_disk_quota_mb": limits.SiteDiskQuotaMB,
		"php_max_children":   limits.PHPFPMMaxChildren,
		"php_memory_mb":      limits.PHPMemoryMB,
	} {
		if value < -1 {
			return fmt.Errorf("%s cannot be less than -1", name)
		}
	}
	return nil
}

type SQLStore struct {
	db    *sql.DB
	river *river.Client[*sql.Tx]
}

func NewSQLStore(db *sql.DB, clients ...*river.Client[*sql.Tx]) *SQLStore {
	store := &SQLStore{db: db}
	if len(clients) > 0 {
		store.river = clients[0]
	}
	return store
}

func (s *SQLStore) GetLimits(ctx context.Context, userID int64) (Limits, bool, error) {
	if s == nil || s.db == nil {
		return Limits{}, false, errors.New("quota database is not configured")
	}
	var limits Limits
	err := s.db.QueryRowContext(ctx, `SELECT s.customer_user_id, s.id, COALESCE(s.plan_id, 0), e.plan_name,
	       e.max_sites, e.max_databases, e.disk_mb, e.max_backups, e.backup_storage_mb,
	       e.site_disk_quota_mb, e.php_fpm_max_children, e.php_memory_mb, e.bandwidth_mb,
	       e.overuse_policy, e.php_allowlist, e.default_php_version, e.hosting_enabled,
	       e.allow_backups, e.updated_at, e.updated_at
FROM subscriptions s
JOIN subscription_entitlements e ON e.subscription_id = s.id
LEFT JOIN customers c ON c.id = s.customer_id
LEFT JOIN reseller_accounts r ON r.id = c.reseller_id
LEFT JOIN reseller_subscriptions rs ON rs.reseller_id = r.id AND rs.status = 'active'
WHERE s.customer_user_id = $1
  AND s.status = 'active'
  AND COALESCE(c.status, 'active') = 'active'
  AND (c.reseller_id IS NULL OR (r.status = 'active' AND rs.id IS NOT NULL))
ORDER BY s.id LIMIT 1`, userID).Scan(
		&limits.UserID,
		&limits.SubscriptionID,
		&limits.PlanID,
		&limits.PlanName,
		&limits.MaxSites,
		&limits.MaxDatabases,
		&limits.StorageMB,
		&limits.MaxBackups,
		&limits.BackupStorageMB,
		&limits.SiteDiskQuotaMB,
		&limits.PHPFPMMaxChildren,
		&limits.PHPMemoryMB,
		&limits.BandwidthMB,
		&limits.OverusePolicy,
		&limits.PHPAllowlist,
		&limits.DefaultPHPVersion,
		&limits.HostingEnabled,
		&limits.AllowBackups,
		&limits.CreatedAt,
		&limits.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Limits{}, false, nil
	}
	if err != nil {
		return Limits{}, false, err
	}
	return limits, true, nil
}

func (s *SQLStore) GetLimitsForSubscription(ctx context.Context, subscriptionID int64) (Limits, bool, error) {
	if s == nil || s.db == nil {
		return Limits{}, false, errors.New("quota database is not configured")
	}
	var limits Limits
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(s.customer_id, 0), s.id, COALESCE(s.plan_id, 0), e.plan_name,
	       e.max_sites, e.max_databases, e.disk_mb, e.max_backups, e.backup_storage_mb,
	       e.site_disk_quota_mb, e.php_fpm_max_children, e.php_memory_mb, e.bandwidth_mb,
	       e.overuse_policy, e.php_allowlist, e.default_php_version, e.hosting_enabled,
	       e.allow_backups, e.updated_at, e.updated_at
FROM subscriptions s
JOIN subscription_entitlements e ON e.subscription_id = s.id
JOIN customers c ON c.id = s.customer_id
LEFT JOIN reseller_accounts r ON r.id = c.reseller_id
LEFT JOIN reseller_subscriptions rs ON rs.reseller_id = r.id AND rs.status = 'active'
WHERE s.id = $1
  AND s.status = 'active'
  AND c.status = 'active'
  AND (c.reseller_id IS NULL OR (r.status = 'active' AND rs.id IS NOT NULL))`, subscriptionID).Scan(
		&limits.CustomerID,
		&limits.SubscriptionID,
		&limits.PlanID,
		&limits.PlanName,
		&limits.MaxSites,
		&limits.MaxDatabases,
		&limits.StorageMB,
		&limits.MaxBackups,
		&limits.BackupStorageMB,
		&limits.SiteDiskQuotaMB,
		&limits.PHPFPMMaxChildren,
		&limits.PHPMemoryMB,
		&limits.BandwidthMB,
		&limits.OverusePolicy,
		&limits.PHPAllowlist,
		&limits.DefaultPHPVersion,
		&limits.HostingEnabled,
		&limits.AllowBackups,
		&limits.CreatedAt,
		&limits.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Limits{}, false, nil
	}
	if err != nil {
		return Limits{}, false, err
	}
	return limits, true, nil
}

func (s *SQLStore) GetUsage(ctx context.Context, userID int64) (Usage, error) {
	if s == nil || s.db == nil {
		return Usage{}, errors.New("quota database is not configured")
	}
	var usage Usage
	err := s.db.QueryRowContext(ctx, `SELECT $1::bigint AS user_id,
    COALESCE((SELECT COUNT(*) FROM sites WHERE owner_user_id = $1 AND status <> 'failed'), 0)::int AS sites,
    COALESCE((SELECT COUNT(*) FROM databases WHERE owner_user_id = $1 AND status <> 'failed'), 0)::int AS databases,
    COALESCE((SELECT COUNT(*) FROM backups WHERE owner_user_id = $1 AND status <> 'failed'), 0)::int AS backups,
    COALESCE((SELECT SUM(size_bytes) FROM backups WHERE owner_user_id = $1 AND status = 'active'), 0)::bigint AS backup_storage_bytes`, userID).Scan(
		&usage.UserID,
		&usage.Sites,
		&usage.Databases,
		&usage.Backups,
		&usage.BackupStorageBytes,
	)
	return usage, err
}

func (s *SQLStore) GetUsageForSubscription(ctx context.Context, subscriptionID int64) (Usage, error) {
	if s == nil || s.db == nil {
		return Usage{}, errors.New("quota database is not configured")
	}
	var usage Usage
	err := s.db.QueryRowContext(ctx, `SELECT $1::bigint AS subscription_id,
    COALESCE((SELECT COUNT(*) FROM sites WHERE subscription_id = $1 AND status <> 'failed'), 0)::int AS sites,
    COALESCE((SELECT COUNT(*) FROM databases WHERE subscription_id = $1 AND status <> 'failed'), 0)::int AS databases,
    COALESCE((SELECT COUNT(*) FROM backups WHERE subscription_id = $1 AND status <> 'failed'), 0)::int AS backups,
    COALESCE((SELECT SUM(size_bytes) FROM backups WHERE subscription_id = $1 AND status = 'active'), 0)::bigint AS backup_storage_bytes`, subscriptionID).Scan(
		&usage.SubscriptionID,
		&usage.Sites,
		&usage.Databases,
		&usage.Backups,
		&usage.BackupStorageBytes,
	)
	return usage, err
}

func (s *SQLStore) UpsertLimits(ctx context.Context, limits Limits) error {
	if s == nil || s.db == nil {
		return errors.New("quota database is not configured")
	}
	if err := ValidateLimits(limits); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	planID, err := upsertLegacyQuotaPlanTx(ctx, tx, limits)
	if err != nil {
		return err
	}
	if _, err := subscriptionOversellWarningTx(ctx, tx, limits.UserID, Plan{
		ID:     planID,
		Name:   fmt.Sprintf("Custom quota user %d", limits.UserID),
		DiskMB: limits.StorageMB,
	}); err != nil {
		return err
	}
	subscriptionID, err := assignSubscriptionTx(ctx, tx, limits.UserID, planID)
	if err != nil {
		return err
	}
	if err := relinkResourcesTx(ctx, tx, limits.UserID, subscriptionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO account_quotas (
    user_id, max_sites, max_databases, storage_mb, max_backups, backup_storage_mb,
    site_disk_quota_mb, php_fpm_max_children, php_memory_mb
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (user_id) DO UPDATE SET
    max_sites = EXCLUDED.max_sites,
    max_databases = EXCLUDED.max_databases,
    storage_mb = EXCLUDED.storage_mb,
    max_backups = EXCLUDED.max_backups,
    backup_storage_mb = EXCLUDED.backup_storage_mb,
    site_disk_quota_mb = EXCLUDED.site_disk_quota_mb,
    php_fpm_max_children = EXCLUDED.php_fpm_max_children,
    php_memory_mb = EXCLUDED.php_memory_mb,
    updated_at = now()`,
		limits.UserID,
		limits.MaxSites,
		limits.MaxDatabases,
		limits.StorageMB,
		limits.MaxBackups,
		limits.BackupStorageMB,
		limits.SiteDiskQuotaMB,
		limits.PHPFPMMaxChildren,
		limits.PHPMemoryMB,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) ListAccountQuotas(ctx context.Context) ([]Summary, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("quota database is not configured")
	}
	rows, err := s.db.QueryContext(ctx, accountQuotaSummarySQL+` ORDER BY u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var summaries []Summary
	for rows.Next() {
		summary, err := scanSummary(rows)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, summary)
	}
	return summaries, rows.Err()
}

func (s *SQLStore) GetAccountQuotaSummary(ctx context.Context, userID int64) (Summary, error) {
	if s == nil || s.db == nil {
		return Summary{}, errors.New("quota database is not configured")
	}
	row := s.db.QueryRowContext(ctx, accountQuotaSummarySQL+` WHERE u.id = $1`, userID)
	return scanSummary(row)
}

const accountQuotaSummarySQL = `SELECT u.id, u.email, u.role,
    s.id IS NOT NULL AS has_quota,
    COALESCE(s.id, 0), COALESCE(s.plan_id, 0), COALESCE(e.plan_name, ''),
    COALESCE(e.max_sites, 0), COALESCE(e.max_databases, 0), COALESCE(e.disk_mb, 0),
    COALESCE(e.max_backups, 0), COALESCE(e.backup_storage_mb, 0),
    COALESCE(e.site_disk_quota_mb, 0), COALESCE(e.php_fpm_max_children, 0), COALESCE(e.php_memory_mb, 0),
    COALESCE((SELECT COUNT(*) FROM sites WHERE owner_user_id = u.id AND status <> 'failed'), 0)::int AS sites,
    COALESCE((SELECT COUNT(*) FROM databases WHERE owner_user_id = u.id AND status <> 'failed'), 0)::int AS databases,
    COALESCE((SELECT COUNT(*) FROM backups WHERE owner_user_id = u.id AND status <> 'failed'), 0)::int AS backups,
    COALESCE((SELECT SUM(size_bytes) FROM backups WHERE owner_user_id = u.id AND status = 'active'), 0)::bigint AS backup_storage_bytes
FROM users u
LEFT JOIN subscriptions s ON s.customer_user_id = u.id AND s.status = 'active'
LEFT JOIN subscription_entitlements e ON e.subscription_id = s.id`

type summaryScanner interface {
	Scan(dest ...any) error
}

func scanSummary(row summaryScanner) (Summary, error) {
	var summary Summary
	if err := row.Scan(
		&summary.UserID,
		&summary.Email,
		&summary.Role,
		&summary.HasQuota,
		&summary.SubscriptionID,
		&summary.PlanID,
		&summary.PlanName,
		&summary.Limits.MaxSites,
		&summary.Limits.MaxDatabases,
		&summary.Limits.StorageMB,
		&summary.Limits.MaxBackups,
		&summary.Limits.BackupStorageMB,
		&summary.Limits.SiteDiskQuotaMB,
		&summary.Limits.PHPFPMMaxChildren,
		&summary.Limits.PHPMemoryMB,
		&summary.Usage.Sites,
		&summary.Usage.Databases,
		&summary.Usage.Backups,
		&summary.Usage.BackupStorageBytes,
	); err != nil {
		return Summary{}, err
	}
	summary.Limits.UserID = summary.UserID
	summary.Limits.SubscriptionID = summary.SubscriptionID
	summary.Limits.PlanID = summary.PlanID
	summary.Limits.PlanName = summary.PlanName
	summary.Usage.UserID = summary.UserID
	return summary, nil
}
