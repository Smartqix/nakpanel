package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
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
	if req.ResellerID > 0 {
		if err := validateNewResellerCustomerTx(ctx, tx, req.ResellerID); err != nil {
			return types.Customer{}, err
		}
	}

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
		ResellerID:  req.ResellerID,
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
RETURNING id, login_user_id, email, display_name, company, status, notes, created_at, updated_at, COALESCE(reseller_id, 0)`, customerID, userID, email)
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
	return s.SetCustomerStatuses(ctx, []int64{customerID}, status)
}

func (s *SQLStore) SetCustomerStatuses(ctx context.Context, customerIDs []int64, status string) error {
	if s == nil || s.db == nil {
		return errors.New("quota database is not configured")
	}
	if len(customerIDs) == 0 {
		return errors.New("at least one customer id is required")
	}
	status = strings.TrimSpace(status)
	switch status {
	case "active", "suspended":
	default:
		return fmt.Errorf("unsupported customer status %q", status)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, customerID := range customerIDs {
		if customerID <= 0 {
			return errors.New("customer id is required")
		}
		res, execErr := tx.ExecContext(ctx, `UPDATE customers SET status=$2,updated_at=now() WHERE id=$1`, customerID, status)
		if execErr != nil {
			return execErr
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		if err = s.enqueueCustomerHostingStateTx(ctx, tx, customerID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) SetSubscriptionStatus(ctx context.Context, subscriptionID int64, status string) error {
	return s.SetSubscriptionStatuses(ctx, []int64{subscriptionID}, status)
}

func (s *SQLStore) SetSubscriptionStatuses(ctx context.Context, subscriptionIDs []int64, status string) error {
	if s == nil || s.db == nil {
		return errors.New("quota database is not configured")
	}
	if len(subscriptionIDs) == 0 {
		return errors.New("at least one subscription id is required")
	}
	status = strings.TrimSpace(status)
	switch status {
	case "active", "suspended", "cancelled":
	default:
		return fmt.Errorf("unsupported subscription status %q", status)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, subscriptionID := range subscriptionIDs {
		if subscriptionID <= 0 {
			return errors.New("subscription id is required")
		}
		var resellerID int64
		var suspensionReason string
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(c.reseller_id,0),s.suspension_reason FROM subscriptions s JOIN customers c ON c.id=s.customer_id WHERE s.id=$1 FOR UPDATE OF s,c`, subscriptionID).Scan(&resellerID, &suspensionReason); err != nil {
			return err
		}
		if status == "active" {
			if resellerID > 0 {
				if err = ensureResellerActiveTx(ctx, tx, resellerID); err != nil {
					return err
				}
			}
			entitlements, loadErr := readSubscriptionEntitlementsTx(ctx, tx, subscriptionID)
			if loadErr != nil {
				return loadErr
			}
			if resellerID > 0 {
				if err = validateEntitlementsWithinResellerTx(ctx, tx, resellerID, entitlements); err != nil {
					return err
				}
				if err = validateResellerCapacityTx(ctx, tx, resellerID, subscriptionID, entitlements); err != nil {
					return err
				}
			}
			if suspensionReason == "resource_overuse" {
				if err = validateOveruseReactivationTx(ctx, tx, subscriptionID, entitlements); err != nil {
					return err
				}
			}
			if _, err = subscriptionOversellWarningForSubscriptionTx(ctx, tx, subscriptionID, planFromEntitlements(entitlements), status); err != nil {
				return err
			}
		}
		res, execErr := tx.ExecContext(ctx, `UPDATE subscriptions SET status=$2,
suspension_reason=CASE WHEN $2='active' THEN '' WHEN suspension_reason='' THEN 'manual' ELSE suspension_reason END,
updated_at=now() WHERE id=$1`, subscriptionID, status)
		if execErr != nil {
			return execErr
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		if status == "active" {
			if _, err = tx.ExecContext(ctx, `UPDATE notifications SET resolved_at=now(),updated_at=now() WHERE subscription_id=$1 AND kind='suspended' AND resolved_at IS NULL`, subscriptionID); err != nil {
				return err
			}
		}
		if err = s.enqueueSubscriptionHostingStateTx(ctx, tx, subscriptionID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) CreateSubscription(ctx context.Context, req types.CreateSubscriptionReq) (types.SubscriptionSummary, error) {
	if s == nil || s.db == nil {
		return types.SubscriptionSummary{}, errors.New("quota database is not configured")
	}
	if req.CustomerID <= 0 {
		return types.SubscriptionSummary{}, errors.New("customer id is required")
	}
	requestedUsername := strings.ToLower(strings.TrimSpace(req.SystemUsername))
	if requestedUsername != "" && !regexp.MustCompile(`^[a-z][a-z0-9]{2,31}$`).MatchString(requestedUsername) {
		return types.SubscriptionSummary{}, errors.New("system username must start with a letter and contain 3-32 lowercase letters or digits")
	}
	syncMode := strings.TrimSpace(req.SyncMode)
	if syncMode == "" {
		if req.PlanID > 0 {
			syncMode = "synced"
		} else {
			syncMode = "custom"
		}
	}
	switch syncMode {
	case "synced", "locked":
		if req.PlanID <= 0 {
			return types.SubscriptionSummary{}, errors.New("plan id is required for synced or locked subscriptions")
		}
	case "custom":
		if req.PlanID > 0 {
			return types.SubscriptionSummary{}, errors.New("custom subscriptions cannot reference a base plan")
		}
		if err := ValidateEntitlements(req.Entitlements); err != nil {
			return types.SubscriptionSummary{}, err
		}
	default:
		return types.SubscriptionSummary{}, fmt.Errorf("unsupported sync mode %q", syncMode)
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
	var currentPlanID int64
	var currentSyncMode string
	var currentPlanRevision int
	if req.ID > 0 {
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(plan_id,0),sync_mode,plan_revision FROM subscriptions WHERE id=$1 FOR UPDATE`, req.ID).Scan(&currentPlanID, &currentSyncMode, &currentPlanRevision); err != nil {
			return types.SubscriptionSummary{}, err
		}
	}

	customer, err := selectCustomerTx(ctx, tx, req.CustomerID)
	if err != nil {
		return types.SubscriptionSummary{}, err
	}
	if customer.Status != "active" && status == "active" {
		return types.SubscriptionSummary{}, fmt.Errorf("customer %d is %s", customer.ID, customer.Status)
	}
	if customer.ResellerID > 0 && status == "active" {
		if err := ensureResellerActiveTx(ctx, tx, customer.ResellerID); err != nil {
			return types.SubscriptionSummary{}, err
		}
	}
	var plan Plan
	if req.PlanID > 0 {
		plan, err = selectPlanForUpdateTx(ctx, tx, req.PlanID)
		if err != nil {
			return types.SubscriptionSummary{}, err
		}
		if !plan.IsActive && req.ID == 0 {
			return types.SubscriptionSummary{}, fmt.Errorf("plan %q is inactive", plan.Name)
		}
		if plan.ResellerID != customer.ResellerID {
			return types.SubscriptionSummary{}, errors.New("plan and customer must belong to the same provider")
		}
	} else {
		plan = planFromEntitlements(req.Entitlements)
	}
	candidate := entitlementsFromPlan(plan)
	preserveLockedSnapshot := shouldPreserveLockedSnapshot(req.ID, req.PlanID, syncMode, currentPlanID, currentSyncMode)
	if preserveLockedSnapshot {
		candidate, err = readSubscriptionEntitlementsTx(ctx, tx, req.ID)
		if err != nil {
			return types.SubscriptionSummary{}, err
		}
	}
	if req.PlanID == 0 {
		candidate = req.Entitlements
		if strings.TrimSpace(candidate.PlanName) == "" {
			candidate.PlanName = "Custom"
		}
	} else if req.ID > 0 && !preserveLockedSnapshot {
		addons, loadErr := loadSubscriptionAddonsTx(ctx, tx, req.ID)
		if loadErr != nil {
			return types.SubscriptionSummary{}, loadErr
		}
		matching := make([]types.AddonPlan, 0, len(addons))
		for _, addon := range addons {
			if addon.ResellerID == customer.ResellerID {
				matching = append(matching, addon)
			}
		}
		candidate, err = ComposeEntitlements(candidate, matching)
		if err != nil {
			return types.SubscriptionSummary{}, err
		}
	}
	if customer.ResellerID > 0 {
		if syncMode == "custom" {
			if err := validateCustomWithinResellerTx(ctx, tx, customer.ResellerID, candidate); err != nil {
				return types.SubscriptionSummary{}, err
			}
		}
		if status == "active" {
			if err := validateResellerCapacityTx(ctx, tx, customer.ResellerID, req.ID, candidate); err != nil {
				return types.SubscriptionSummary{}, err
			}
		}
	}
	if req.ID > 0 && status == "active" {
		if err := validateOveruseReactivationTx(ctx, tx, req.ID, candidate); err != nil {
			return types.SubscriptionSummary{}, err
		}
	}
	capacityPlan := planFromEntitlements(candidate)
	capacityPlan.Name = candidate.PlanName
	warning, err := subscriptionOversellWarningForSubscriptionTx(ctx, tx, req.ID, capacityPlan, status)
	if err != nil {
		return types.SubscriptionSummary{}, err
	}
	name := strings.TrimSpace(req.SubscriptionName)
	if name == "" {
		name = plan.Name + " subscription"
	}
	var subscriptionID int64
	targetRevision := maxInt(plan.Revision, 1)
	if preserveLockedSnapshot {
		targetRevision = maxInt(currentPlanRevision, 1)
	}
	if req.ID > 0 {
		err = tx.QueryRowContext(ctx, `UPDATE subscriptions
SET customer_id = $2,
    customer_user_id = $3,
    plan_id = $4,
    name = $5,
		status = $6,
		 suspension_reason = CASE WHEN $6='active' THEN '' WHEN suspension_reason='' THEN 'manual' ELSE suspension_reason END,
	 sync_mode = $7,
	 sync_status = 'in_sync',
	 plan_revision = $8,
	 sync_error = '',
    updated_at = now()
WHERE id = $1
	RETURNING id`, req.ID, customer.ID, nullableInt64(customer.LoginUserID), nullableInt64(plan.ID), name, status, syncMode, targetRevision).Scan(&subscriptionID)
	} else {
		err = tx.QueryRowContext(ctx, `INSERT INTO subscriptions (customer_id, customer_user_id, plan_id, name, status, sync_mode, sync_status, plan_revision, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'in_sync', $7, CASE WHEN $8 < 0 THEN NULL ELSE now() + ($8 * interval '1 day') END)
		RETURNING id`, customer.ID, nullableInt64(customer.LoginUserID), nullableInt64(plan.ID), name, status, syncMode, maxInt(plan.Revision, 1), candidate.ValidityDays).Scan(&subscriptionID)
	}
	if err != nil {
		return types.SubscriptionSummary{}, err
	}
	if req.ID == 0 {
		if _, err = createSubscriptionSystemAccountTx(ctx, tx, subscriptionID, requestedUsername, status); err != nil {
			return types.SubscriptionSummary{}, err
		}
	} else {
		desiredState := "active"
		if status != "active" {
			desiredState = "suspended"
		}
		if _, err = tx.ExecContext(ctx, `UPDATE subscription_system_accounts SET desired_state=$2,convergence_status='pending',last_error='',updated_at=now() WHERE subscription_id=$1`, subscriptionID, desiredState); err != nil {
			return types.SubscriptionSummary{}, err
		}
	}
	if req.ID > 0 {
		if syncMode == "custom" {
			if _, err = tx.ExecContext(ctx, `DELETE FROM subscription_addons WHERE subscription_id=$1`, subscriptionID); err != nil {
				return types.SubscriptionSummary{}, err
			}
		} else if !preserveLockedSnapshot {
			if _, err = tx.ExecContext(ctx, `DELETE FROM subscription_addons sa USING addon_plans a
WHERE sa.subscription_id=$1 AND a.id=sa.addon_plan_id AND COALESCE(a.reseller_id,0)<>$2`, subscriptionID, customer.ResellerID); err != nil {
				return types.SubscriptionSummary{}, err
			}
		}
	}
	if preserveLockedSnapshot {
		err = nil
	} else {
		candidate.SubscriptionID = subscriptionID
		err = writeSubscriptionEntitlementsTx(ctx, tx, candidate)
	}
	if err != nil {
		return types.SubscriptionSummary{}, err
	}
	if err := relinkSubscriptionResourcesToCustomerTx(ctx, tx, subscriptionID, customer.ID); err != nil {
		return types.SubscriptionSummary{}, err
	}
	if s.river != nil {
		if _, err = s.river.InsertTx(ctx, tx, ConvergeSubscriptionArgs{SubscriptionID: subscriptionID}, nil); err != nil {
			return types.SubscriptionSummary{}, fmt.Errorf("enqueue subscription convergence: %w", err)
		}
		if err = wakeSubscriptionConvergenceTx(ctx, tx, subscriptionID); err != nil {
			return types.SubscriptionSummary{}, fmt.Errorf("wake subscription convergence: %w", err)
		}
	}
	if req.ID > 0 {
		if status == "active" {
			if _, err := tx.ExecContext(ctx, `UPDATE notifications SET resolved_at=now(),updated_at=now() WHERE subscription_id=$1 AND kind='suspended' AND resolved_at IS NULL`, subscriptionID); err != nil {
				return types.SubscriptionSummary{}, err
			}
		}
		if err := s.enqueueSubscriptionHostingStateTx(ctx, tx, subscriptionID); err != nil {
			return types.SubscriptionSummary{}, err
		}
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

func availableSystemUsernameTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) (string, error) {
	for attempt := 0; attempt < 100; attempt++ {
		candidate := fmt.Sprintf("nps%d", subscriptionID)
		if attempt > 0 {
			candidate = fmt.Sprintf("np%d%s", subscriptionID, strconv.FormatInt(int64(attempt), 36))
		}
		if len(candidate) > 32 {
			candidate = candidate[:32]
		}
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM subscription_system_accounts WHERE username=$1)`, candidate).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}
	return "", errors.New("could not allocate a unique system username")
}

func createSubscriptionSystemAccountTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, requestedUsername, subscriptionStatus string) (string, error) {
	username := strings.ToLower(strings.TrimSpace(requestedUsername))
	if username == "" {
		var err error
		username, err = availableSystemUsernameTx(ctx, tx, subscriptionID)
		if err != nil {
			return "", err
		}
	}
	desiredState := "active"
	if subscriptionStatus != "active" {
		desiredState = "suspended"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO subscription_system_accounts
(subscription_id,username,home_path,shell_mode,desired_state,applied_state,convergence_status,migration_status)
VALUES($1,$2,'/home/'||$2,'disabled',$3,'pending','pending','pending')`, subscriptionID, username, desiredState); err != nil {
		return "", fmt.Errorf("create subscription system account: %w", err)
	}
	return username, nil
}

func shouldPreserveLockedSnapshot(subscriptionID, requestedPlanID int64, requestedMode string, currentPlanID int64, currentMode string) bool {
	return subscriptionID > 0 && requestedMode == "locked" && currentMode == "locked" && requestedPlanID == currentPlanID
}

func (s *SQLStore) ListCustomers(ctx context.Context) ([]types.Customer, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("quota database is not configured")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, login_user_id, email, display_name, company, status, notes, created_at, updated_at, COALESCE(reseller_id, 0)
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
	rows, err := s.db.QueryContext(ctx, subscriptionSummarySQL+` WHERE c.login_user_id = $1 OR c.reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$1) ORDER BY s.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSubscriptionSummaries(rows)
}

func (s *SQLStore) ListCustomersForUser(ctx context.Context, userID int64) ([]types.Customer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,login_user_id,email,display_name,company,status,notes,created_at,updated_at,COALESCE(reseller_id,0) FROM customers WHERE login_user_id=$1 OR reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$1) ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Customer
	for rows.Next() {
		item, err := scanCustomer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
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
	if err == nil {
		if err := tx.QueryRowContext(ctx, `UPDATE users
SET email=$2,password_hash=$3,updated_at=now()
WHERE id=$1
RETURNING id`, existingID, email, hash).Scan(&existingID); err != nil {
			return 0, err
		}
		return existingID, nil
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
	row := tx.QueryRowContext(ctx, `INSERT INTO customers (login_user_id, email, display_name, company, notes, status, reseller_id)
VALUES ($1, $2, $3, $4, $5, 'active', $6)
RETURNING id, login_user_id, email, display_name, company, status, notes, created_at, updated_at, COALESCE(reseller_id, 0)`,
		nullInt64(loginUserID),
		req.Email,
		displayName,
		strings.TrimSpace(req.Company),
		strings.TrimSpace(req.Notes),
		nullableInt64(req.ResellerID),
	)
	return scanCustomer(row)
}

func selectCustomerTx(ctx context.Context, tx *sql.Tx, customerID int64) (types.Customer, error) {
	row := tx.QueryRowContext(ctx, `SELECT id, login_user_id, email, display_name, company, status, notes, created_at, updated_at, COALESCE(reseller_id, 0)
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
	settings, err := getSettingsForUpdateTx(ctx, tx)
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
    COALESCE(SUM(CASE WHEN e.disk_mb >= 0 THEN e.disk_mb ELSE 0 END), 0)::bigint,
    COALESCE(BOOL_OR(e.disk_mb < 0), false)
FROM subscriptions s
JOIN subscription_entitlements e ON e.subscription_id = s.id
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
    COALESCE(s.plan_id, 0),
    e.plan_name,
    s.name,
    s.status,
    e.max_sites,
    e.max_databases,
    e.disk_mb,
    e.max_backups,
    e.backup_storage_mb,
    COALESCE((SELECT COUNT(*) FROM sites WHERE subscription_id = s.id AND status <> 'failed'), 0)::int,
    COALESCE((SELECT COUNT(*) FROM databases WHERE subscription_id = s.id AND status <> 'failed'), 0)::int,
    COALESCE((SELECT COUNT(*) FROM backups WHERE subscription_id = s.id AND status <> 'failed'), 0)::int,
    COALESCE((SELECT SUM(size_bytes) FROM backups WHERE subscription_id = s.id AND status = 'active'), 0)::bigint,
    s.created_at,
    s.updated_at,
    COALESCE(c.reseller_id, 0),
    s.sync_mode,
    s.sync_status,
    s.plan_revision,
    s.sync_error,
    e.allow_dns,
    e.allow_ssh,
    e.php_allowlist,
    e.php_fpm_max_children,
    e.php_memory_mb,
    e.site_disk_quota_mb,
    e.bandwidth_mb,
    e.max_mailboxes,
    e.backup_retention_days,
    e.max_subdomains,
    e.max_domain_aliases,
    e.max_ftp_accounts,
    e.validity_days,
    e.hosting_enabled,
    e.default_php_version,
    e.allow_tls,
    e.allow_backups,
    e.allow_php_settings,
    e.overuse_policy,
    e.disk_warning_percent,
    e.traffic_warning_percent,
    e.service_presets
FROM subscriptions s
JOIN customers c ON c.id = s.customer_id
JOIN subscription_entitlements e ON e.subscription_id = s.id`

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
		&customer.ResellerID,
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
	var servicePresets []byte
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
		&summary.ResellerID,
		&summary.SyncMode,
		&summary.SyncStatus,
		&summary.PlanRevision,
		&summary.SyncError,
		&summary.AllowDNS,
		&summary.AllowSSH,
		&summary.PHPAllowlist,
		&summary.PHPFPMMaxChildren,
		&summary.PHPMemoryMB,
		&summary.SiteDiskQuotaMB,
		&summary.BandwidthMB,
		&summary.MaxMailboxes,
		&summary.BackupRetentionDays,
		&summary.MaxSubdomains,
		&summary.MaxDomainAliases,
		&summary.MaxFTPAccounts,
		&summary.ValidityDays,
		&summary.HostingEnabled,
		&summary.DefaultPHPVersion,
		&summary.AllowTLS,
		&summary.AllowBackups,
		&summary.AllowPHPSettings,
		&summary.OverusePolicy,
		&summary.DiskWarningPercent,
		&summary.TrafficWarningPercent,
		&servicePresets,
	); err != nil {
		return types.SubscriptionSummary{}, err
	}
	if err := json.Unmarshal(servicePresets, &summary.ServicePresets); err != nil {
		return types.SubscriptionSummary{}, fmt.Errorf("decode subscription service presets: %w", err)
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
