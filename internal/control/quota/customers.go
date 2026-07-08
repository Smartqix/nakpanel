package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (s *SQLStore) CreateCustomer(ctx context.Context, req types.CreateCustomerReq) (types.Customer, error) {
	if s == nil || s.db == nil {
		return types.Customer{}, errors.New("quota database is not configured")
	}
	email := normalizeEmail(req.Email)
	if email == "" {
		return types.Customer{}, errors.New("customer email is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.Customer{}, err
	}
	defer tx.Rollback()

	var loginUserID sql.NullInt64
	if req.EnableLogin {
		if strings.TrimSpace(req.Password) == "" {
			return types.Customer{}, errors.New("customer login password is required")
		}
		userID, err := upsertClientUserTx(ctx, tx, email, req.Password)
		if err != nil {
			return types.Customer{}, err
		}
		loginUserID = sql.NullInt64{Int64: userID, Valid: true}
	}

	customer, err := insertCustomerTx(ctx, tx, loginUserID, types.CreateCustomerReq{
		Email:       email,
		DisplayName: strings.TrimSpace(req.DisplayName),
		Company:     strings.TrimSpace(req.Company),
		Notes:       strings.TrimSpace(req.Notes),
	})
	if err != nil {
		return types.Customer{}, err
	}
	if err := tx.Commit(); err != nil {
		return types.Customer{}, err
	}
	return customer, nil
}

func (s *SQLStore) EnableCustomerLogin(ctx context.Context, customerID int64, email string, password string) (types.Customer, error) {
	if s == nil || s.db == nil {
		return types.Customer{}, errors.New("quota database is not configured")
	}
	if customerID <= 0 {
		return types.Customer{}, errors.New("customer id is required")
	}
	email = normalizeEmail(email)
	if email == "" {
		return types.Customer{}, errors.New("customer email is required")
	}
	if strings.TrimSpace(password) == "" {
		return types.Customer{}, errors.New("customer login password is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.Customer{}, err
	}
	defer tx.Rollback()
	userID, err := upsertClientUserTx(ctx, tx, email, password)
	if err != nil {
		return types.Customer{}, err
	}
	row := tx.QueryRowContext(ctx, `UPDATE customers
SET login_user_id = $2, email = $3, updated_at = now()
WHERE id = $1
RETURNING id, login_user_id, email, display_name, company, status, notes, created_at, updated_at`, customerID, userID, email)
	customer, err := scanCustomer(row)
	if err != nil {
		return types.Customer{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE subscriptions
SET customer_user_id = $2, updated_at = now()
WHERE customer_id = $1`, customerID, userID); err != nil {
		return types.Customer{}, err
	}
	if err := tx.Commit(); err != nil {
		return types.Customer{}, err
	}
	return customer, nil
}

func (s *SQLStore) SetCustomerStatus(ctx context.Context, customerID int64, status string) error {
	if s == nil || s.db == nil {
		return errors.New("quota database is not configured")
	}
	if customerID <= 0 {
		return errors.New("customer id is required")
	}
	switch strings.TrimSpace(status) {
	case "active", "suspended":
	default:
		return fmt.Errorf("unsupported customer status %q", status)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE customers SET status = $2, updated_at = now() WHERE id = $1`, customerID, strings.TrimSpace(status))
	return err
}

func (s *SQLStore) CreateSubscription(ctx context.Context, req types.CreateSubscriptionReq) (types.SubscriptionSummary, error) {
	if s == nil || s.db == nil {
		return types.SubscriptionSummary{}, errors.New("quota database is not configured")
	}
	if req.CustomerID <= 0 {
		return types.SubscriptionSummary{}, errors.New("customer id is required")
	}
	if req.PlanID <= 0 {
		return types.SubscriptionSummary{}, errors.New("plan id is required")
	}
	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = "active"
	}
	switch status {
	case "active", "suspended", "cancelled":
	default:
		return types.SubscriptionSummary{}, fmt.Errorf("unsupported subscription status %q", status)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.SubscriptionSummary{}, err
	}
	defer tx.Rollback()

	customer, err := selectCustomerTx(ctx, tx, req.CustomerID)
	if err != nil {
		return types.SubscriptionSummary{}, err
	}
	if customer.Status != "active" && status == "active" {
		return types.SubscriptionSummary{}, fmt.Errorf("customer %d is %s", customer.ID, customer.Status)
	}
	plan, err := selectPlanForUpdateTx(ctx, tx, req.PlanID)
	if err != nil {
		return types.SubscriptionSummary{}, err
	}
	if !plan.IsActive && req.ID == 0 {
		return types.SubscriptionSummary{}, fmt.Errorf("plan %q is inactive", plan.Name)
	}
	warning, err := subscriptionOversellWarningForSubscriptionTx(ctx, tx, req.ID, plan, status)
	if err != nil {
		return types.SubscriptionSummary{}, err
	}
	name := strings.TrimSpace(req.SubscriptionName)
	if name == "" {
		name = plan.Name + " subscription"
	}
	var subscriptionID int64
	if req.ID > 0 {
		err = tx.QueryRowContext(ctx, `UPDATE subscriptions
SET customer_id = $2,
    customer_user_id = $3,
    plan_id = $4,
    name = $5,
    status = $6,
    updated_at = now()
WHERE id = $1
RETURNING id`, req.ID, customer.ID, nullableInt64(customer.LoginUserID), plan.ID, name, status).Scan(&subscriptionID)
	} else {
		err = tx.QueryRowContext(ctx, `INSERT INTO subscriptions (customer_id, customer_user_id, plan_id, name, status)
VALUES ($1, $2, $3, $4, $5)
RETURNING id`, customer.ID, nullableInt64(customer.LoginUserID), plan.ID, name, status).Scan(&subscriptionID)
	}
	if err != nil {
		return types.SubscriptionSummary{}, err
	}
	if err := relinkSubscriptionResourcesToCustomerTx(ctx, tx, subscriptionID, customer.ID); err != nil {
		return types.SubscriptionSummary{}, err
	}
	summary, err := getSubscriptionSummaryTx(ctx, tx, subscriptionID)
	if err != nil {
		return types.SubscriptionSummary{}, err
	}
	summary.Warning = warning
	if err := tx.Commit(); err != nil {
		return types.SubscriptionSummary{}, err
	}
	return summary, nil
}

func (s *SQLStore) ListCustomers(ctx context.Context) ([]types.Customer, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("quota database is not configured")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, login_user_id, email, display_name, company, status, notes, created_at, updated_at
FROM customers
ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var customers []types.Customer
	for rows.Next() {
		customer, err := scanCustomer(rows)
		if err != nil {
			return nil, err
		}
		customers = append(customers, customer)
	}
	return customers, rows.Err()
}

func (s *SQLStore) ListSubscriptionSummaries(ctx context.Context) ([]types.SubscriptionSummary, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("quota database is not configured")
	}
	rows, err := s.db.QueryContext(ctx, subscriptionSummarySQL+` ORDER BY s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSubscriptionSummaries(rows)
}

func (s *SQLStore) ListSubscriptionSummariesForUser(ctx context.Context, userID int64) ([]types.SubscriptionSummary, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("quota database is not configured")
	}
	rows, err := s.db.QueryContext(ctx, subscriptionSummarySQL+` WHERE c.login_user_id = $1 ORDER BY s.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSubscriptionSummaries(rows)
}

func upsertClientUserTx(ctx context.Context, tx *sql.Tx, email string, password string) (int64, error) {
	hash, err := auth.HashPassword(password, auth.DefaultPasswordParams)
	if err != nil {
		return 0, err
	}
	var existingRole string
	var existingID int64
	err = tx.QueryRowContext(ctx, `SELECT id, role FROM users WHERE lower(email) = lower($1)`, email).Scan(&existingID, &existingRole)
	if err == nil && existingRole != string(auth.RoleClient) {
		return 0, fmt.Errorf("user %q already exists with role %q", email, existingRole)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	var userID int64
	err = tx.QueryRowContext(ctx, `INSERT INTO users (email, password_hash, role)
VALUES ($1, $2, 'client')
ON CONFLICT (email) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    role = 'client',
    updated_at = now()
RETURNING id`, email, hash).Scan(&userID)
	return userID, err
}

func insertCustomerTx(ctx context.Context, tx *sql.Tx, loginUserID sql.NullInt64, req types.CreateCustomerReq) (types.Customer, error) {
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = req.Email
	}
	row := tx.QueryRowContext(ctx, `INSERT INTO customers (login_user_id, email, display_name, company, notes, status)
VALUES ($1, $2, $3, $4, $5, 'active')
RETURNING id, login_user_id, email, display_name, company, status, notes, created_at, updated_at`,
		nullInt64(loginUserID),
		req.Email,
		displayName,
		strings.TrimSpace(req.Company),
		strings.TrimSpace(req.Notes),
	)
	return scanCustomer(row)
}

func selectCustomerTx(ctx context.Context, tx *sql.Tx, customerID int64) (types.Customer, error) {
	row := tx.QueryRowContext(ctx, `SELECT id, login_user_id, email, display_name, company, status, notes, created_at, updated_at
FROM customers
WHERE id = $1
FOR UPDATE`, customerID)
	return scanCustomer(row)
}

func getSubscriptionSummaryTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) (types.SubscriptionSummary, error) {
	row := tx.QueryRowContext(ctx, subscriptionSummarySQL+` WHERE s.id = $1`, subscriptionID)
	return scanSubscriptionSummary(row)
}

func relinkSubscriptionResourcesToCustomerTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, customerID int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE sites SET customer_id = $2 WHERE subscription_id = $1`, subscriptionID, customerID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE databases SET customer_id = $2 WHERE subscription_id = $1`, subscriptionID, customerID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE backups SET customer_id = $2 WHERE subscription_id = $1`, subscriptionID, customerID); err != nil {
		return err
	}
	return nil
}

func subscriptionOversellWarningForSubscriptionTx(ctx context.Context, tx *sql.Tx, excludeSubscriptionID int64, plan Plan, status string) (string, error) {
	if status != "active" {
		return "", nil
	}
	settings, err := getSettingsTx(ctx, tx)
	if err != nil {
		return "", err
	}
	committed, unlimited, err := committedAllocationForSubscriptionTx(ctx, tx, excludeSubscriptionID)
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

func committedAllocationForSubscriptionTx(ctx context.Context, q queryRower, excludeSubscriptionID int64) (int, bool, error) {
	var committed sql.NullInt64
	var unlimited sql.NullBool
	err := q.QueryRowContext(ctx, `SELECT
    COALESCE(SUM(CASE WHEN p.disk_mb >= 0 THEN p.disk_mb ELSE 0 END), 0)::bigint,
    COALESCE(BOOL_OR(p.disk_mb < 0), false)
FROM subscriptions s
JOIN plans p ON p.id = s.plan_id
WHERE s.status = 'active'
  AND ($1::bigint = 0 OR s.id <> $1)`, excludeSubscriptionID).Scan(&committed, &unlimited)
	if err != nil {
		return 0, false, err
	}
	return int(committed.Int64), unlimited.Valid && unlimited.Bool, nil
}

const subscriptionSummarySQL = `SELECT
    s.id,
    s.customer_id,
    COALESCE(s.customer_user_id, 0),
    c.email,
    c.display_name,
    c.company,
    p.id,
    p.name,
    s.name,
    s.status,
    p.max_sites,
    p.max_databases,
    p.disk_mb,
    p.max_backups,
    p.backup_storage_mb,
    COALESCE((SELECT COUNT(*) FROM sites WHERE subscription_id = s.id AND status <> 'failed'), 0)::int,
    COALESCE((SELECT COUNT(*) FROM databases WHERE subscription_id = s.id AND status <> 'failed'), 0)::int,
    COALESCE((SELECT COUNT(*) FROM backups WHERE subscription_id = s.id AND status <> 'failed'), 0)::int,
    COALESCE((SELECT SUM(size_bytes) FROM backups WHERE subscription_id = s.id AND status = 'active'), 0)::bigint,
    s.created_at,
    s.updated_at
FROM subscriptions s
JOIN customers c ON c.id = s.customer_id
JOIN plans p ON p.id = s.plan_id`

type customerScanner interface {
	Scan(dest ...any) error
}

func scanCustomer(row customerScanner) (types.Customer, error) {
	var customer types.Customer
	var loginUserID sql.NullInt64
	if err := row.Scan(
		&customer.ID,
		&loginUserID,
		&customer.Email,
		&customer.DisplayName,
		&customer.Company,
		&customer.Status,
		&customer.Notes,
		&customer.CreatedAt,
		&customer.UpdatedAt,
	); err != nil {
		return types.Customer{}, err
	}
	if loginUserID.Valid {
		customer.LoginUserID = loginUserID.Int64
	}
	return customer, nil
}

type subscriptionSummaryScanner interface {
	Scan(dest ...any) error
}

func scanSubscriptionSummary(row subscriptionSummaryScanner) (types.SubscriptionSummary, error) {
	var summary types.SubscriptionSummary
	if err := row.Scan(
		&summary.ID,
		&summary.CustomerID,
		&summary.CustomerUserID,
		&summary.CustomerEmail,
		&summary.CustomerName,
		&summary.CustomerCompany,
		&summary.PlanID,
		&summary.PlanName,
		&summary.SubscriptionName,
		&summary.Status,
		&summary.MaxSites,
		&summary.MaxDatabases,
		&summary.DiskMB,
		&summary.MaxBackups,
		&summary.BackupStorageMB,
		&summary.SitesUsed,
		&summary.DatabasesUsed,
		&summary.BackupsUsed,
		&summary.BackupBytesUsed,
		&summary.CreatedAt,
		&summary.UpdatedAt,
	); err != nil {
		return types.SubscriptionSummary{}, err
	}
	return summary, nil
}

func scanSubscriptionSummaries(rows *sql.Rows) ([]types.SubscriptionSummary, error) {
	var summaries []types.SubscriptionSummary
	for rows.Next() {
		summary, err := scanSubscriptionSummary(rows)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, summary)
	}
	return summaries, rows.Err()
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func nullableInt64(value int64) any {
	if value <= 0 {
		return nil
	}
	return value
}

func nullInt64(value sql.NullInt64) any {
	if value.Valid {
		return value.Int64
	}
	return nil
}
