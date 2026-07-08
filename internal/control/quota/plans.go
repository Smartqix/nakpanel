package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	OversellPolicyWarn = "warn"
	OversellPolicyCap  = "cap"
)

var ErrOversellCap = errors.New("oversell cap exceeded")

type Plan struct {
	ID                  int64
	Name                string
	Description         string
	PriceCents          sql.NullInt64
	DiskMB              int
	MaxSites            int
	MaxDatabases        int
	BandwidthMB         int
	MaxMailboxes        int
	AllowSSH            bool
	AllowDNS            bool
	BackupRetentionDays int
	PHPAllowlist        string
	PHPFPMMaxChildren   int
	PHPMemoryMB         int
	SiteDiskQuotaMB     int
	MaxBackups          int
	BackupStorageMB     int
	IsActive            bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
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

func ValidatePlan(plan Plan) error {
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
	} {
		if value < -1 {
			return fmt.Errorf("%s cannot be less than -1", name)
		}
	}
	return nil
}

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
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, description, price_cents, disk_mb, max_sites, max_databases, bandwidth_mb,
       max_mailboxes, allow_ssh, allow_dns, backup_retention_days, php_allowlist,
       php_fpm_max_children, php_memory_mb, site_disk_quota_mb, max_backups,
       backup_storage_mb, is_active, created_at, updated_at
FROM plans
ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var plans []Plan
	for rows.Next() {
		plan, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	return plans, rows.Err()
}

func (s *SQLStore) UpsertPlan(ctx context.Context, plan Plan) (Plan, error) {
	if s == nil || s.db == nil {
		return Plan{}, errors.New("quota database is not configured")
	}
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
	if err := enforceCommittedAllocationCapTx(ctx, tx); err != nil {
		return Plan{}, err
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
    backup_storage_mb, is_active
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
RETURNING id, name, description, price_cents, disk_mb, max_sites, max_databases, bandwidth_mb,
       max_mailboxes, allow_ssh, allow_dns, backup_retention_days, php_allowlist,
       php_fpm_max_children, php_memory_mb, site_disk_quota_mb, max_backups,
       backup_storage_mb, is_active, created_at, updated_at`,
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
    updated_at = now()
WHERE id = $1
RETURNING id, name, description, price_cents, disk_mb, max_sites, max_databases, bandwidth_mb,
       max_mailboxes, allow_ssh, allow_dns, backup_retention_days, php_allowlist,
       php_fpm_max_children, php_memory_mb, site_disk_quota_mb, max_backups,
       backup_storage_mb, is_active, created_at, updated_at`,
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
	)
	return scanPlan(row)
}

func selectPlanForUpdateTx(ctx context.Context, tx *sql.Tx, planID int64) (Plan, error) {
	row := tx.QueryRowContext(ctx, `SELECT id, name, description, price_cents, disk_mb, max_sites, max_databases, bandwidth_mb,
       max_mailboxes, allow_ssh, allow_dns, backup_retention_days, php_allowlist,
       php_fpm_max_children, php_memory_mb, site_disk_quota_mb, max_backups,
       backup_storage_mb, is_active, created_at, updated_at
FROM plans
WHERE id = $1
FOR UPDATE`, planID)
	return scanPlan(row)
}

func upsertLegacyQuotaPlanTx(ctx context.Context, tx *sql.Tx, limits Limits) (int64, error) {
	var planID int64
	err := tx.QueryRowContext(ctx, `INSERT INTO plans (
    name, description, disk_mb, max_sites, max_databases, bandwidth_mb, max_mailboxes,
    allow_ssh, allow_dns, backup_retention_days, php_allowlist, php_fpm_max_children,
    php_memory_mb, site_disk_quota_mb, max_backups, backup_storage_mb, is_active
) VALUES ($1, $2, $3, $4, $5, -1, 0, false, true, 0, '8.3,8.2', $6, $7, $8, $9, $10, false)
ON CONFLICT (name) DO UPDATE SET
    description = EXCLUDED.description,
    disk_mb = EXCLUDED.disk_mb,
    max_sites = EXCLUDED.max_sites,
    max_databases = EXCLUDED.max_databases,
    php_fpm_max_children = EXCLUDED.php_fpm_max_children,
    php_memory_mb = EXCLUDED.php_memory_mb,
    site_disk_quota_mb = EXCLUDED.site_disk_quota_mb,
    max_backups = EXCLUDED.max_backups,
    backup_storage_mb = EXCLUDED.backup_storage_mb,
    updated_at = now()
RETURNING id`,
		fmt.Sprintf("Custom quota user %d", limits.UserID),
		fmt.Sprintf("Compatibility plan generated from /quotas for user %d.", limits.UserID),
		limits.StorageMB,
		limits.MaxSites,
		limits.MaxDatabases,
		limits.PHPFPMMaxChildren,
		limits.PHPMemoryMB,
		limits.SiteDiskQuotaMB,
		limits.MaxBackups,
		limits.BackupStorageMB,
	).Scan(&planID)
	return planID, err
}

func assignSubscriptionTx(ctx context.Context, tx *sql.Tx, customerUserID int64, planID int64) (int64, error) {
	customerID, err := ensureCustomerForUserTx(ctx, tx, customerUserID)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE subscriptions
SET status = 'cancelled', updated_at = now()
WHERE customer_user_id = $1
  AND status = 'active'`, customerUserID); err != nil {
		return 0, err
	}
	var subscriptionID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO subscriptions (customer_id, customer_user_id, plan_id, name, status)
VALUES ($1, $2, $3, (SELECT name || ' subscription' FROM plans WHERE id = $3), 'active')
RETURNING id`, customerID, customerUserID, planID).Scan(&subscriptionID); err != nil {
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
	settings, err := getSettingsTx(ctx, tx)
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
	settings, err := getSettingsTx(ctx, tx)
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

func committedAllocationTx(ctx context.Context, q queryRower, excludeCustomerUserID int64) (int, bool, error) {
	var committed sql.NullInt64
	var unlimited sql.NullBool
	err := q.QueryRowContext(ctx, `SELECT
    COALESCE(SUM(CASE WHEN p.disk_mb >= 0 THEN p.disk_mb ELSE 0 END), 0)::bigint,
    COALESCE(BOOL_OR(p.disk_mb < 0), false)
FROM subscriptions s
JOIN plans p ON p.id = s.plan_id
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
	); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func nullInt64Value(value sql.NullInt64) any {
	if value.Valid {
		return value.Int64
	}
	return nil
}
