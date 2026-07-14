package provisioningapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

var externalRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type AccountService struct {
	DB        *sql.DB
	River     *river.Client[*sql.Tx]
	PublicURL string
	Quota     *controlquota.SQLStore
}

type createAccountRequest struct {
	ExternalRef string `json:"external_ref"`
	Provider    string `json:"provider"`
	Plan        string `json:"plan,omitempty"`
	PlanID      int64  `json:"plan_id,omitempty"`
	Email       string `json:"email"`
	Name        string `json:"name,omitempty"`
	Company     string `json:"company,omitempty"`
	Domain      string `json:"domain"`
	Username    string `json:"username,omitempty"`
}

type changePlanRequest struct {
	Plan   string `json:"plan,omitempty"`
	PlanID int64  `json:"plan_id,omitempty"`
	Force  bool   `json:"force,omitempty"`
}

type accountView struct {
	ID            string         `json:"id"`
	ExternalRef   string         `json:"external_ref"`
	Provider      string         `json:"provider"`
	Lifecycle     string         `json:"lifecycle"`
	Provisioning  string         `json:"provisioning"`
	Status        string         `json:"status"`
	Plan          map[string]any `json:"plan"`
	PrimaryDomain string         `json:"primary_domain"`
	OverLimit     bool           `json:"over_limit"`
	LastError     string         `json:"last_error,omitempty"`
	Usage         map[string]any `json:"usage"`
	Limits        map[string]any `json:"limits"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

func (h *Handler) accountService() *AccountService {
	if h.opts.Accounts != nil {
		return h.opts.Accounts
	}
	return &AccountService{DB: h.opts.DB, PublicURL: h.opts.PublicURL}
}

func (h *Handler) handleProviders(w http.ResponseWriter, r *http.Request, requestID string) {
	rows, err := h.opts.DB.QueryContext(r.Context(), `SELECT id,display_name,company FROM reseller_accounts WHERE status='active' ORDER BY id`)
	if err != nil {
		writeAPIError(w, 500, "internal_error", "could not list providers", requestID, nil)
		return
	}
	defer rows.Close()
	providers := []map[string]any{{"ref": "admin", "type": "admin", "name": "Nakpanel administrator", "active": true}}
	for rows.Next() {
		var id int64
		var name, company string
		if rows.Scan(&id, &name, &company) != nil {
			continue
		}
		if strings.TrimSpace(name) == "" {
			name = company
		}
		providers = append(providers, map[string]any{"ref": fmt.Sprintf("reseller:%d", id), "type": "reseller", "name": name, "active": true})
	}
	writeJSON(w, 200, map[string]any{"providers": providers})
}

func (h *Handler) handlePlans(w http.ResponseWriter, r *http.Request, requestID string) {
	providerID, err := resolveProvider(r.Context(), h.opts.DB, r.URL.Query().Get("provider"))
	if err != nil {
		writeAPIError(w, 400, "invalid_provider", err.Error(), requestID, nil)
		return
	}
	rows, err := h.opts.DB.QueryContext(r.Context(), `SELECT id,api_slug,name,revision,is_active,disk_mb,bandwidth_mb,max_sites,max_databases,max_mailboxes,max_backups,backup_storage_mb,hosting_policy FROM plans WHERE reseller_id IS NOT DISTINCT FROM $1 ORDER BY id`, nullableProvider(providerID))
	if err != nil {
		writeAPIError(w, 500, "internal_error", "could not list plans", requestID, nil)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int64
		var slug, name string
		var rev int
		var active bool
		var disk, traffic, sitesN, dbs, mailboxes, backups, backupStorage int
		var policy json.RawMessage
		if err = rows.Scan(&id, &slug, &name, &rev, &active, &disk, &traffic, &sitesN, &dbs, &mailboxes, &backups, &backupStorage, &policy); err != nil {
			writeAPIError(w, 500, "internal_error", "could not read plans", requestID, nil)
			return
		}
		items = append(items, map[string]any{"id": id, "slug": slug, "name": name, "revision": rev, "active": active, "limits": map[string]any{"disk_mb": disk, "bandwidth_mb": traffic, "sites": sitesN, "databases": dbs, "mailboxes": mailboxes, "backups": backups, "backup_storage_mb": backupStorage}, "hosting_policy": policy})
	}
	writeJSON(w, 200, map[string]any{"provider": providerRef(providerID), "plans": items})
}

func (h *Handler) handleCreateAccount(w *apiRecorder, r *http.Request, requestID string) {
	var req createAccountRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		writeAPIError(w, 400, "invalid_json", "request body is invalid or contains unknown fields", requestID, nil)
		return
	}
	key := r.Context().Value(apiKeyContext).(APIKey)
	view, created, err := h.accountService().Create(r.Context(), key.ID, req)
	if err != nil {
		writeAccountError(w, requestID, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusAccepted
	}
	writeJSON(w, status, view)
}

func (h *Handler) handleAccount(w *apiRecorder, r *http.Request, suffix, requestID string) {
	parts := strings.Split(suffix, "/")
	ref := parts[0]
	if ref == "" {
		writeAPIError(w, 404, "not_found", "account not found", requestID, nil)
		return
	}
	svc := h.accountService()
	if len(parts) == 1 && r.Method == http.MethodGet {
		view, err := svc.Get(r.Context(), ref)
		if err != nil {
			writeAccountError(w, requestID, err)
			return
		}
		writeJSON(w, 200, view)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		view, err := svc.Cancel(r.Context(), ref, r.URL.Query().Get("purge") == "true")
		if err != nil {
			writeAccountError(w, requestID, err)
			return
		}
		writeJSON(w, http.StatusAccepted, view)
		return
	}
	if len(parts) != 2 || r.Method != http.MethodPost {
		writeAPIError(w, 404, "not_found", "resource not found", requestID, nil)
		return
	}
	switch parts[1] {
	case "suspend", "unsuspend":
		view, err := svc.SetLifecycle(r.Context(), ref, parts[1] == "suspend")
		if err != nil {
			writeAccountError(w, requestID, err)
			return
		}
		writeJSON(w, http.StatusAccepted, view)
	case "change-plan":
		var req changePlanRequest
		if err := decodeStrictJSON(r.Body, &req); err != nil {
			writeAPIError(w, 400, "invalid_json", "request body is invalid or contains unknown fields", requestID, nil)
			return
		}
		view, err := svc.ChangePlan(r.Context(), ref, req)
		if err != nil {
			writeAccountError(w, requestID, err)
			return
		}
		writeJSON(w, http.StatusAccepted, view)
	case "login-link":
		link, err := svc.LoginLink(r.Context(), ref)
		if err != nil {
			writeAccountError(w, requestID, err)
			return
		}
		writeJSON(w, 200, map[string]any{"url": link, "expires_in": 300})
	default:
		writeAPIError(w, 404, "not_found", "resource not found", requestID, nil)
	}
}

type accountError struct {
	status        int
	code, message string
	details       any
}

func (e *accountError) Error() string { return e.message }
func writeAccountError(w http.ResponseWriter, requestID string, err error) {
	var apiErr *accountError
	if errors.As(err, &apiErr) {
		writeAPIError(w, apiErr.status, apiErr.code, apiErr.message, requestID, apiErr.details)
		return
	}
	log.Printf("provisioning API request %s failed: %v", requestID, err)
	writeAPIError(w, 500, "internal_error", "internal provisioning error", requestID, nil)
}

func (s *AccountService) Create(ctx context.Context, keyID int64, req createAccountRequest) (accountView, bool, error) {
	if s == nil || s.DB == nil {
		return accountView{}, false, errors.New("database unavailable")
	}
	req.ExternalRef = strings.TrimSpace(req.ExternalRef)
	if !externalRefPattern.MatchString(req.ExternalRef) {
		return accountView{}, false, &accountError{400, "invalid_external_ref", "external_ref must contain 1-128 safe identifier characters", nil}
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	address, err := mail.ParseAddress(req.Email)
	if err != nil || !strings.EqualFold(address.Address, req.Email) {
		return accountView{}, false, &accountError{400, "invalid_email", "a valid customer email is required", nil}
	}
	req.Domain = site.NormalizeDomain(req.Domain)
	if err = site.ValidateDomain(req.Domain); err != nil {
		return accountView{}, false, &accountError{400, "invalid_domain", err.Error(), nil}
	}
	providerID, err := resolveProvider(ctx, s.DB, req.Provider)
	if err != nil {
		return accountView{}, false, &accountError{400, "invalid_provider", err.Error(), nil}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return accountView{}, false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,20))`, req.ExternalRef); err != nil {
		return accountView{}, false, err
	}
	var existing string
	if err = tx.QueryRowContext(ctx, `SELECT public_id FROM billing_accounts WHERE external_ref=$1`, req.ExternalRef).Scan(&existing); err == nil {
		if err = tx.Commit(); err != nil {
			return accountView{}, false, err
		}
		view, err := s.Get(ctx, existing)
		return view, false, err
	} else if !errors.Is(err, sql.ErrNoRows) {
		return accountView{}, false, err
	}
	plan, err := selectPlanTx(ctx, tx, providerID, req.PlanID, req.Plan, true)
	if err != nil {
		return accountView{}, false, err
	}
	var customerID, userID int64
	var customerProvider sql.NullInt64
	var customerStatus string
	err = tx.QueryRowContext(ctx, `SELECT id,COALESCE(login_user_id,0),reseller_id,status FROM customers WHERE lower(email)=lower($1) FOR UPDATE`, req.Email).Scan(&customerID, &userID, &customerProvider, &customerStatus)
	if err == nil {
		if providerValue(customerProvider) != providerID {
			return accountView{}, false, &accountError{409, "customer_provider_conflict", "customer belongs to another provider", nil}
		}
		if customerStatus != "active" {
			return accountView{}, false, &accountError{409, "invalid_account_state", "customer is suspended", nil}
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return accountView{}, false, err
	} else {
		password := make([]byte, 32)
		_, _ = rand.Read(password)
		hash, hashErr := auth.HashPassword(base64.RawURLEncoding.EncodeToString(password), auth.DefaultPasswordParams)
		if hashErr != nil {
			return accountView{}, false, hashErr
		}
		if err = tx.QueryRowContext(ctx, `INSERT INTO users(email,password_hash,role) VALUES($1,$2,'client') RETURNING id`, req.Email, hash).Scan(&userID); err != nil {
			return accountView{}, false, &accountError{409, "customer_provider_conflict", "email is already attached to another panel identity", nil}
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = req.Email
		}
		if err = tx.QueryRowContext(ctx, `INSERT INTO customers(login_user_id,email,display_name,company,status,reseller_id) VALUES($1,$2,$3,$4,'active',$5) RETURNING id`, userID, req.Email, name, strings.TrimSpace(req.Company), nullableProvider(providerID)).Scan(&customerID); err != nil {
			return accountView{}, false, err
		}
	}
	if userID == 0 {
		password := make([]byte, 32)
		_, _ = rand.Read(password)
		hash, hashErr := auth.HashPassword(base64.RawURLEncoding.EncodeToString(password), auth.DefaultPasswordParams)
		if hashErr != nil {
			return accountView{}, false, hashErr
		}
		if err = tx.QueryRowContext(ctx, `INSERT INTO users(email,password_hash,role) VALUES($1,$2,'client') RETURNING id`, req.Email, hash).Scan(&userID); err != nil {
			return accountView{}, false, &accountError{409, "customer_provider_conflict", "email is already attached to another panel identity", nil}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE customers SET login_user_id=$2,updated_at=now() WHERE id=$1`, customerID, userID); err != nil {
			return accountView{}, false, err
		}
	}
	var subscriptionID int64
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = req.Domain
	}
	if err = tx.QueryRowContext(ctx, `INSERT INTO subscriptions(customer_id,customer_user_id,plan_id,name,status,sync_mode,sync_status,plan_revision) VALUES($1,$2,$3,$4,'active','synced','pending',$5) RETURNING id`, customerID, userID, plan.ID, name, plan.Revision).Scan(&subscriptionID); err != nil {
		return accountView{}, false, err
	}
	// The compatibility trigger seeds a basic snapshot for every subscription;
	// replace it inside this transaction with the complete Phase 15 policy.
	if _, err = tx.ExecContext(ctx, `DELETE FROM subscription_entitlements WHERE subscription_id=$1`, subscriptionID); err != nil {
		return accountView{}, false, err
	}
	if err = copyPlanEntitlementsTx(ctx, tx, subscriptionID, plan.ID); err != nil {
		return accountView{}, false, err
	}
	if err = controlquota.ValidateProvisioningCapacityTx(ctx, tx, providerID, subscriptionID); err != nil {
		return accountView{}, false, &accountError{409, "provider_capacity_exceeded", err.Error(), nil}
	}
	username := strings.ToLower(strings.TrimSpace(req.Username))
	if username != "" && !regexp.MustCompile(`^[a-z][a-z0-9]{2,31}$`).MatchString(username) {
		return accountView{}, false, &accountError{400, "invalid_username", "username must contain 3-32 lowercase letters or digits and start with a letter", nil}
	}
	if username == "" {
		username = allocateUsernameTx(ctx, tx, subscriptionID)
	}
	var accountID int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO subscription_system_accounts(subscription_id,username,home_path,desired_state,applied_state,convergence_status,migration_status) VALUES($1,$2,'/home/'||$2,'active','pending','pending','pending') RETURNING id`, subscriptionID, username).Scan(&accountID); err != nil {
		return accountView{}, false, &accountError{409, "username_conflict", "system username is already in use", nil}
	}
	php := plan.DefaultPHP
	if php == "" {
		php = strings.TrimSpace(strings.Split(plan.PHPAllowlist, ",")[0])
	}
	if php == "" {
		php = "8.3"
	}
	var siteID int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO sites(owner_user_id,customer_id,subscription_id,system_account_id,username,domain,document_root,php_version,desired_php_version,status,last_error) VALUES($1,$2,$3,$4,$5,$6,'/home/'||$5||'/domains/'||$6||'/public_html',$7,$7,'pending','') RETURNING id`, userID, customerID, subscriptionID, accountID, username, req.Domain, php).Scan(&siteID); err != nil {
		return accountView{}, false, &accountError{409, "domain_conflict", "primary domain is already in use", nil}
	}
	publicID, err := randomID("acc_", 24)
	if err != nil {
		return accountView{}, false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO billing_accounts(subscription_id,public_id,external_ref,provider_reseller_id,primary_site_id,created_by_api_key_id) VALUES($1,$2,$3,$4,$5,$6)`, subscriptionID, publicID, req.ExternalRef, nullableProvider(providerID), siteID, keyID); err != nil {
		return accountView{}, false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_label,customer_id,subscription_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'account.created','billing_account',$3,jsonb_build_object('external_ref',$4::text,'public_id',$5::text))`, `api-key-id:`+strconv.FormatInt(keyID, 10), customerID, subscriptionID, req.ExternalRef, publicID); err != nil {
		return accountView{}, false, err
	}
	if s.River != nil {
		limits := types.SiteResourceLimits{DiskQuotaMB: plan.SiteDiskMB, PHPFPMMaxChildren: plan.FPMChildren, PHPMemoryMB: plan.PHPMemoryMB}
		if _, err = s.River.InsertTx(ctx, tx, provision.CreateSiteArgs{SiteID: siteID, Username: username, Domain: req.Domain, PHPVersion: php, SharedAccount: true, Limits: limits}, nil); err != nil {
			return accountView{}, false, err
		}
		if _, err = s.River.InsertTx(ctx, tx, controlquota.ConvergeSubscriptionArgs{SubscriptionID: subscriptionID}, nil); err != nil {
			return accountView{}, false, err
		}
		if _, err = s.River.InsertTx(ctx, tx, FinalizeAccountArgs{BillingAccountID: 0, PublicID: publicID}, nil); err != nil {
			return accountView{}, false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return accountView{}, false, err
	}
	view, err := s.Get(ctx, publicID)
	return view, true, err
}

type selectedPlan struct {
	ID                                   int64
	Revision                             int
	DefaultPHP, PHPAllowlist             string
	SiteDiskMB, FPMChildren, PHPMemoryMB int
}

func selectPlanTx(ctx context.Context, tx *sql.Tx, providerID, planID int64, slug string, active bool) (selectedPlan, error) {
	var p selectedPlan
	query := `SELECT id,revision,default_php_version,php_allowlist,site_disk_quota_mb,php_fpm_max_children,php_memory_mb FROM plans WHERE reseller_id IS NOT DISTINCT FROM $1 AND `
	var arg any
	if planID > 0 {
		query += `id=$2`
		arg = planID
	} else {
		slug = strings.TrimSpace(slug)
		if slug == "" {
			return p, &accountError{400, "invalid_plan", "plan or plan_id is required", nil}
		}
		query += `api_slug=$2`
		arg = slug
	}
	if active {
		query += ` AND is_active=true`
	}
	if err := tx.QueryRowContext(ctx, query, nullableProvider(providerID), arg).Scan(&p.ID, &p.Revision, &p.DefaultPHP, &p.PHPAllowlist, &p.SiteDiskMB, &p.FPMChildren, &p.PHPMemoryMB); err != nil {
		return p, &accountError{404, "plan_not_found", "active plan was not found for provider", nil}
	}
	return p, nil
}

func copyPlanEntitlementsTx(ctx context.Context, tx *sql.Tx, subscriptionID, planID int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO subscription_entitlements(subscription_id,plan_name,disk_mb,max_sites,max_databases,bandwidth_mb,max_mailboxes,allow_ssh,allow_dns,backup_retention_days,php_allowlist,php_fpm_max_children,php_memory_mb,site_disk_quota_mb,max_backups,backup_storage_mb,source_revision,overuse_policy,disk_warning_percent,traffic_warning_percent,max_subdomains,max_domain_aliases,max_ftp_accounts,validity_days,hosting_enabled,default_php_version,allow_tls,allow_backups,allow_php_settings,service_presets,hosting_policy)
SELECT $1,p.name,p.disk_mb,p.max_sites,p.max_databases,p.bandwidth_mb,p.max_mailboxes,p.allow_ssh,p.allow_dns,p.backup_retention_days,p.php_allowlist,p.php_fpm_max_children,p.php_memory_mb,p.site_disk_quota_mb,p.max_backups,p.backup_storage_mb,p.revision,p.overuse_policy,p.disk_warning_percent,p.traffic_warning_percent,p.max_subdomains,p.max_domain_aliases,p.max_ftp_accounts,p.validity_days,p.hosting_enabled,p.default_php_version,p.allow_tls,p.allow_backups,p.allow_php_settings,jsonb_build_object('schema_version',COALESCE(ps.schema_version,1),'hosting',COALESCE(ps.hosting,'{}'),'php',COALESCE(ps.php,'{}'),'mail',COALESCE(ps.mail,'{}'),'dns',COALESCE(ps.dns,'{}'),'performance',COALESCE(ps.performance,'{}'),'logs',COALESCE(ps.logs,'{}'),'applications',COALESCE(ps.applications,'{}')),p.hosting_policy FROM plans p LEFT JOIN plan_service_presets ps ON ps.plan_id=p.id WHERE p.id=$2`, subscriptionID, planID)
	return err
}

func (s *AccountService) Get(ctx context.Context, ref string) (accountView, error) {
	var v accountView
	var reseller sql.NullInt64
	var planID int64
	var slug, planName, domain, lifecycle, provisioning, lastError string
	var limits [7]int
	var counts [7]int
	var siteBytes, databaseBytes, backupBytes, diskBytes, trafficBytes int64
	var complete bool
	var collected sql.NullTime
	var diskLimitMB, trafficLimitMB int
	err := s.DB.QueryRowContext(ctx, `SELECT b.public_id,b.external_ref,b.provider_reseller_id,sub.status,b.provisioning_state,b.over_limit,b.last_error,p.id,p.api_slug,p.name,COALESCE(site.domain,''),e.max_sites,e.max_databases,e.max_mailboxes,e.max_backups,e.max_ftp_accounts,COALESCE((e.hosting_policy#>>'{resources,max_scheduled_tasks}')::int,0),COALESCE((e.hosting_policy#>>'{resources,max_applications}')::int,0),e.disk_mb,e.bandwidth_mb,(SELECT count(*) FROM sites WHERE subscription_id=sub.id),(SELECT count(*) FROM databases WHERE subscription_id=sub.id),(SELECT count(*) FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE md.subscription_id=sub.id),(SELECT count(*) FROM backups WHERE subscription_id=sub.id),(SELECT count(*) FROM sftp_access_identities WHERE subscription_id=sub.id),(SELECT count(*) FROM scheduled_tasks WHERE subscription_id=sub.id),(SELECT count(*) FROM application_instances WHERE subscription_id=sub.id),COALESCE(u.site_bytes,0),COALESCE(u.database_bytes,0),COALESCE(u.backup_bytes,0),COALESCE(u.disk_bytes,0),COALESCE(u.traffic_bytes,0),COALESCE(u.is_complete,false),u.collected_at,b.created_at,b.updated_at FROM billing_accounts b JOIN subscriptions sub ON sub.id=b.subscription_id JOIN plans p ON p.id=sub.plan_id JOIN subscription_entitlements e ON e.subscription_id=sub.id LEFT JOIN sites site ON site.id=b.primary_site_id LEFT JOIN subscription_usage_current u ON u.subscription_id=sub.id WHERE b.public_id=$1 OR b.external_ref=$1`, ref).Scan(&v.ID, &v.ExternalRef, &reseller, &lifecycle, &provisioning, &v.OverLimit, &lastError, &planID, &slug, &planName, &domain, &limits[0], &limits[1], &limits[2], &limits[3], &limits[4], &limits[5], &limits[6], &diskLimitMB, &trafficLimitMB, &counts[0], &counts[1], &counts[2], &counts[3], &counts[4], &counts[5], &counts[6], &siteBytes, &databaseBytes, &backupBytes, &diskBytes, &trafficBytes, &complete, &collected, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return v, &accountError{404, "account_not_found", "account was not found", nil}
	}
	if err != nil {
		return v, err
	}
	v.Provider = providerRef(providerValue(reseller))
	v.Lifecycle = lifecycle
	v.Provisioning = provisioning
	v.Status = combinedStatus(lifecycle, provisioning)
	v.LastError = lastError
	v.PrimaryDomain = domain
	v.Plan = map[string]any{"id": planID, "slug": slug, "name": planName}
	fresh := collected.Valid && complete && time.Since(collected.Time) <= 30*time.Minute
	v.Usage = map[string]any{"sites": counts[0], "databases": counts[1], "mailboxes": counts[2], "backups": counts[3], "sftp_identities": counts[4], "tasks": counts[5], "applications": counts[6], "site_bytes": siteBytes, "database_bytes": databaseBytes, "backup_bytes": backupBytes, "disk_bytes": diskBytes, "bandwidth_bytes": trafficBytes, "collected_at": collected.Time, "fresh": fresh}
	v.Limits = map[string]any{"sites": limits[0], "databases": limits[1], "mailboxes": limits[2], "backups": limits[3], "sftp_identities": limits[4], "tasks": limits[5], "applications": limits[6], "disk_mb": diskLimitMB, "bandwidth_mb": trafficLimitMB}
	return v, nil
}

func (s *AccountService) SetLifecycle(ctx context.Context, ref string, suspend bool) (accountView, error) {
	var id, subscriptionID int64
	var state, lifecycle string
	if err := s.DB.QueryRowContext(ctx, `SELECT id,subscription_id,provisioning_state,(SELECT status FROM subscriptions WHERE id=subscription_id) FROM billing_accounts WHERE public_id=$1 OR external_ref=$1`, ref).Scan(&id, &subscriptionID, &state, &lifecycle); err != nil {
		return accountView{}, &accountError{404, "account_not_found", "account was not found", nil}
	}
	if state == "terminating" || state == "terminated" {
		return accountView{}, &accountError{409, "invalid_account_state", "account teardown has started", nil}
	}
	target := "active"
	event := "account.unsuspended"
	if suspend {
		target = "suspended"
		event = "account.suspended"
	}
	if lifecycle != target {
		if s.Quota != nil {
			if err := s.Quota.SetSubscriptionStatus(ctx, subscriptionID, target); err != nil {
				return accountView{}, err
			}
		} else {
			_, err := s.DB.ExecContext(ctx, `UPDATE subscriptions SET status=$2,updated_at=now() WHERE id=$1`, subscriptionID, target)
			if err != nil {
				return accountView{}, err
			}
		}
	}
	_, _ = s.DB.ExecContext(ctx, `UPDATE billing_accounts SET cancelled_at=NULL,purge_eligible_at=NULL,updated_at=now() WHERE id=$1 AND $2='active'`, id, target)
	_ = s.enqueueWebhook(ctx, id, event, event+":"+strconv.FormatInt(id, 10)+":"+target)
	return s.Get(ctx, ref)
}

func (s *AccountService) Cancel(ctx context.Context, ref string, purge bool) (accountView, error) {
	var id, subscriptionID int64
	var state string
	if err := s.DB.QueryRowContext(ctx, `SELECT id,subscription_id,provisioning_state FROM billing_accounts WHERE public_id=$1 OR external_ref=$1`, ref).Scan(&id, &subscriptionID, &state); err != nil {
		return accountView{}, &accountError{404, "account_not_found", "account was not found", nil}
	}
	if state == "terminated" {
		return s.Get(ctx, ref)
	}
	if purge {
		if state != "terminating" {
			_, err := s.DB.ExecContext(ctx, `UPDATE billing_accounts SET provisioning_state='terminating',purge_requested_at=now(),updated_at=now() WHERE id=$1`, id)
			if err != nil {
				return accountView{}, err
			}
			if s.River != nil {
				_, err = s.River.Insert(ctx, TeardownAccountArgs{BillingAccountID: id}, &river.InsertOpts{Queue: "heavy", MaxAttempts: 10})
				if err != nil {
					return accountView{}, err
				}
			}
		}
		return s.Get(ctx, ref)
	}
	if s.Quota != nil {
		_ = s.Quota.SetSubscriptionStatus(ctx, subscriptionID, "cancelled")
	} else {
		_, _ = s.DB.ExecContext(ctx, `UPDATE subscriptions SET status='cancelled',updated_at=now() WHERE id=$1`, subscriptionID)
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE billing_accounts SET cancelled_at=COALESCE(cancelled_at,now()),purge_eligible_at=COALESCE(purge_eligible_at,now()+interval '7 days'),updated_at=now() WHERE id=$1`, id)
	if err != nil {
		return accountView{}, err
	}
	_ = s.enqueueWebhook(ctx, id, "account.terminated", "account.terminated:"+strconv.FormatInt(id, 10))
	return s.Get(ctx, ref)
}

func (s *AccountService) ChangePlan(ctx context.Context, ref string, req changePlanRequest) (accountView, error) {
	view, err := s.Get(ctx, ref)
	if err != nil {
		return view, err
	}
	if view.Provisioning == "terminating" || view.Provisioning == "terminated" {
		return view, &accountError{409, "invalid_account_state", "account teardown has started", nil}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return view, err
	}
	defer tx.Rollback()
	var subscriptionID, providerID int64
	if err = tx.QueryRowContext(ctx, `SELECT subscription_id,COALESCE(provider_reseller_id,0) FROM billing_accounts WHERE public_id=$1 OR external_ref=$1 FOR UPDATE`, ref).Scan(&subscriptionID, &providerID); err != nil {
		return view, err
	}
	plan, err := selectPlanTx(ctx, tx, providerID, req.PlanID, req.Plan, true)
	if err != nil {
		return view, err
	}
	if currentPlanID := asInt64(view.Plan["id"]); currentPlanID == plan.ID {
		if err = tx.Commit(); err != nil {
			return view, err
		}
		return s.Get(ctx, ref)
	}
	var maxSites, maxDB, maxMail, maxBackups, diskMB, trafficMB int
	if err = tx.QueryRowContext(ctx, `SELECT max_sites,max_databases,max_mailboxes,max_backups,disk_mb,bandwidth_mb FROM plans WHERE id=$1`, plan.ID).Scan(&maxSites, &maxDB, &maxMail, &maxBackups, &diskMB, &trafficMB); err != nil {
		return view, err
	}
	offending := []map[string]any{}
	checks := []struct {
		name        string
		used, limit int
	}{{"sites", asInt(view.Usage["sites"]), maxSites}, {"databases", asInt(view.Usage["databases"]), maxDB}, {"mailboxes", asInt(view.Usage["mailboxes"]), maxMail}, {"backups", asInt(view.Usage["backups"]), maxBackups}}
	for _, c := range checks {
		if c.limit >= 0 && c.used > c.limit {
			offending = append(offending, map[string]any{"resource": c.name, "used": c.used, "limit": c.limit})
		}
	}
	fresh, _ := view.Usage["fresh"].(bool)
	currentDisk := asInt64(view.Usage["disk_bytes"])
	currentTraffic := asInt64(view.Usage["bandwidth_bytes"])
	currentDiskLimit := asInt(view.Limits["disk_mb"])
	diskStricter := diskMB >= 0 && (currentDiskLimit < 0 || diskMB < currentDiskLimit)
	if diskMB >= 0 && (currentDisk > int64(diskMB)*1048576 || (diskStricter && !fresh)) {
		offending = append(offending, map[string]any{"resource": "disk_bytes", "used": currentDisk, "limit": int64(diskMB) * 1048576, "fresh": fresh})
	}
	currentTrafficLimit := asInt(view.Limits["bandwidth_mb"])
	trafficStricter := trafficMB >= 0 && (currentTrafficLimit < 0 || trafficMB < currentTrafficLimit)
	if trafficMB >= 0 && (currentTraffic > int64(trafficMB)*1048576 || (trafficStricter && !fresh)) {
		offending = append(offending, map[string]any{"resource": "bandwidth_bytes", "used": currentTraffic, "limit": int64(trafficMB) * 1048576, "fresh": fresh})
	}
	if len(offending) > 0 && !req.Force {
		return view, &accountError{409, "plan_downgrade_conflict", "current usage exceeds the requested plan", map[string]any{"resources": offending}}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE subscriptions SET plan_id=$2,plan_revision=$3,sync_status='pending',updated_at=now() WHERE id=$1`, subscriptionID, plan.ID, plan.Revision); err != nil {
		return view, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM subscription_entitlements WHERE subscription_id=$1`, subscriptionID); err != nil {
		return view, err
	}
	if err = copyPlanEntitlementsTx(ctx, tx, subscriptionID, plan.ID); err != nil {
		return view, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE billing_accounts SET over_limit=$2,updated_at=now() WHERE subscription_id=$1`, subscriptionID, len(offending) > 0)
	if err != nil {
		return view, err
	}
	if s.River != nil {
		if _, err = s.River.InsertTx(ctx, tx, controlquota.ConvergeSubscriptionArgs{SubscriptionID: subscriptionID}, nil); err != nil {
			return view, err
		}
	}
	if err = tx.Commit(); err != nil {
		return view, err
	}
	return s.Get(ctx, ref)
}

func (s *AccountService) LoginLink(ctx context.Context, ref string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(s.PublicURL))
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil {
		return "", &accountError{503, "login_link_unavailable", "NAKPANEL_PUBLIC_URL is not safely configured", nil}
	}
	var accountID, userID int64
	var lifecycle, state string
	if err = s.DB.QueryRowContext(ctx, `SELECT b.id,COALESCE(c.login_user_id,0),sub.status,b.provisioning_state FROM billing_accounts b JOIN subscriptions sub ON sub.id=b.subscription_id JOIN customers c ON c.id=sub.customer_id WHERE b.public_id=$1 OR b.external_ref=$1`, ref).Scan(&accountID, &userID, &lifecycle, &state); err != nil {
		return "", &accountError{404, "account_not_found", "account was not found", nil}
	}
	if userID == 0 || lifecycle == "cancelled" || state == "terminating" || state == "terminated" {
		return "", &accountError{409, "invalid_account_state", "account cannot create a login link", nil}
	}
	raw, err := randomID("sso_", 32)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(raw))
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	_, _ = tx.ExecContext(ctx, `UPDATE customer_login_tokens SET used_at=now() WHERE billing_account_id=$1 AND used_at IS NULL`, accountID)
	if _, err = tx.ExecContext(ctx, `INSERT INTO customer_login_tokens(billing_account_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, accountID, userID, digest[:]); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	base.Path = "/sso/customer/" + raw
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}

func (s *AccountService) enqueueWebhook(ctx context.Context, accountID int64, event, dedupe string) error {
	var publicID, externalRef string
	if err := s.DB.QueryRowContext(ctx, `SELECT public_id,external_ref FROM billing_accounts WHERE id=$1`, accountID).Scan(&publicID, &externalRef); err != nil {
		return err
	}
	delivery, _ := randomID("whd_", 18)
	payload, _ := json.Marshal(map[string]any{"event": event, "account_id": publicID, "external_ref": externalRef, "occurred_at": time.Now().UTC()})
	_, err := s.DB.ExecContext(ctx, `INSERT INTO billing_webhook_outbox(delivery_id,billing_account_id,event_type,dedupe_key,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT(dedupe_key) DO NOTHING`, delivery, accountID, event, dedupe, payload)
	return err
}

func resolveProvider(ctx context.Context, db *sql.DB, ref string) (int64, error) {
	ref = strings.TrimSpace(ref)
	if ref == "admin" {
		return 0, nil
	}
	if !strings.HasPrefix(ref, "reseller:") {
		return 0, errors.New("provider must be admin or reseller:{id}")
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(ref, "reseller:"), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid reseller provider")
	}
	var active bool
	if err = db.QueryRowContext(ctx, `SELECT status='active' FROM reseller_accounts WHERE id=$1`, id).Scan(&active); err != nil || !active {
		return 0, errors.New("reseller provider is not active")
	}
	return id, nil
}
func nullableProvider(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}
func providerValue(v sql.NullInt64) int64 {
	if v.Valid {
		return v.Int64
	}
	return 0
}
func providerRef(id int64) string {
	if id == 0 {
		return "admin"
	}
	return fmt.Sprintf("reseller:%d", id)
}
func allocateUsernameTx(ctx context.Context, tx *sql.Tx, subID int64) string {
	for n := 0; n < 100; n++ {
		candidate := "nps" + strconv.FormatInt(subID, 10)
		if n > 0 {
			candidate += "x" + strconv.FormatInt(int64(n), 36)
		}
		if len(candidate) > 32 {
			candidate = candidate[:32]
		}
		var exists bool
		if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM subscription_system_accounts WHERE username=$1)`, candidate).Scan(&exists) == nil && !exists {
			return candidate
		}
	}
	return "nps" + strconv.FormatInt(subID, 10) + "x"
}
func randomID(prefix string, n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}
func combinedStatus(lifecycle, provisioning string) string {
	if provisioning == "terminated" {
		return "terminated"
	}
	if provisioning == "terminating" {
		return "terminating"
	}
	if lifecycle == "cancelled" {
		return "cancelled"
	}
	if lifecycle == "suspended" {
		return "suspended"
	}
	return provisioning
}
func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}
func asInt64(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	}
	return 0
}
