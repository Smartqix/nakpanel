package operator

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/certificates"
	"github.com/nakroteck/nakpanel/internal/control/agentclient"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/store"
	"github.com/nakroteck/nakpanel/internal/control/workspace"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
)

type Service struct {
	db         *sql.DB
	river      *river.Client[*sql.Tx]
	manager    *provision.Manager
	quota      *controlquota.SQLStore
	agent      *agentclient.Client
	actorLabel string
	stagingDir string
	closeDB    bool
}

type Options struct {
	DatabaseURL string
	AgentSocket string
	ActorLabel  string
	StagingDir  string
}

type User struct {
	ID            int64
	Email         string
	Role          string
	LoginDisabled bool
	Status        string
}

type Session struct {
	ID        int64
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Site struct {
	ID             int64
	Domain         string
	Username       string
	PHPVersion     string
	Status         string
	SubscriptionID int64
	TLSIssuer      string
	TLSStatus      string
	TLSExpiresAt   sql.NullTime
}

type Backup struct {
	ID             int64
	Domain         string
	Status         string
	SizeBytes      int64
	SubscriptionID int64
	CreatedAt      time.Time
}

type Plan struct {
	ID       int64
	Name     string
	Provider string
	Active   bool
	Revision int
}

type Subscription struct {
	ID       int64
	Name     string
	Customer string
	Plan     string
	Status   string
	Mode     string
}

func Open(ctx context.Context, opts Options) (*Service, error) {
	db, err := sql.Open("pgx", strings.TrimSpace(opts.DatabaseURL))
	if err != nil {
		return nil, err
	}
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	service, err := New(db, opts)
	if err != nil {
		db.Close()
		return nil, err
	}
	service.closeDB = true
	return service, nil
}

func New(db *sql.DB, opts Options) (*Service, error) {
	if db == nil {
		return nil, errors.New("operator database is required")
	}
	actor := strings.TrimSpace(opts.ActorLabel)
	if actor == "" {
		return nil, errors.New("operator audit actor is required")
	}
	riverClient, err := river.NewClient(riverdatabasesql.New(db), &river.Config{})
	if err != nil {
		return nil, fmt.Errorf("create insert-only River client: %w", err)
	}
	queries := store.New(db)
	siteRepo := provision.NewSQLSiteRepository(db, queries, riverClient)
	phase6Repo := provision.NewSQLPhase6Repository(db, riverClient)
	quotaStore := controlquota.NewSQLStore(db, riverClient)
	policy := workspace.NewStore(db)
	stagingDir := strings.TrimSpace(opts.StagingDir)
	if stagingDir == "" {
		stagingDir = provision.DefaultCustomTLSStagingDir
	}
	manager := provision.NewManager(siteRepo,
		provision.WithCertificateRepository(siteRepo),
		provision.WithCustomCertificateRepository(siteRepo),
		provision.WithCustomCertificateStager(&provision.FileCustomCertificateStager{Dir: stagingDir}),
		provision.WithPhase6Repository(phase6Repo),
		provision.WithQuotaStore(quotaStore),
		provision.WithAccessPolicy(policy),
	)
	return &Service{
		db: db, river: riverClient, manager: manager, quota: quotaStore, actorLabel: actor, stagingDir: stagingDir,
		agent: agentclient.New(strings.TrimSpace(opts.AgentSocket)),
	}, nil
}

func (s *Service) Close() error {
	if s != nil && s.closeDB {
		return s.db.Close()
	}
	return nil
}

func (s *Service) CreateAdmin(ctx context.Context, email, password string) (int64, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	address, err := mail.ParseAddress(email)
	if err != nil || !strings.EqualFold(address.Address, email) {
		return 0, errors.New("a valid admin email is required")
	}
	if len(password) < 12 {
		return 0, errors.New("admin password must contain at least 12 characters")
	}
	hash, err := auth.HashPassword(password, auth.DefaultPasswordParams)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var id int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO users(email,password_hash,role,login_disabled) VALUES($1,$2,'admin',false) RETURNING id`, email, hash).Scan(&id); err != nil {
		return 0, fmt.Errorf("create administrator: %w", err)
	}
	if err = s.auditTx(ctx, tx, "admin.created", "user", id, map[string]any{"email": email}); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT u.id,u.email,u.role,u.login_disabled,
		CASE WHEN u.role='client' THEN COALESCE((SELECT status FROM customers WHERE login_user_id=u.id),'unlinked')
		WHEN u.role='reseller' THEN COALESCE((SELECT status FROM reseller_accounts WHERE login_user_id=u.id),'unlinked')
		ELSE CASE WHEN u.login_disabled THEN 'disabled' ELSE 'active' END END
		FROM users u ORDER BY u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []User
	for rows.Next() {
		var item User
		if err := rows.Scan(&item.ID, &item.Email, &item.Role, &item.LoginDisabled, &item.Status); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) SetUserSuspended(ctx context.Context, email string, suspended bool) error {
	var userID, businessID int64
	var role string
	var loginDisabled bool
	if err := s.db.QueryRowContext(ctx, `SELECT id,role,login_disabled FROM users WHERE lower(email)=lower($1)`, strings.TrimSpace(email)).Scan(&userID, &role, &loginDisabled); err != nil {
		return err
	}
	if role == string(auth.RoleAdmin) || loginDisabled {
		return errors.New("administrator and internal scheduler accounts cannot be suspended with panelctl")
	}
	actor, err := s.systemActor(ctx)
	if err != nil {
		return err
	}
	status := "active"
	if suspended {
		status = "suspended"
	}
	switch auth.Role(role) {
	case auth.RoleClient:
		if err = s.db.QueryRowContext(ctx, `SELECT id FROM customers WHERE login_user_id=$1`, userID).Scan(&businessID); err == nil {
			err = s.manager.SetCustomerStatus(ctx, actor, businessID, status)
		}
	case auth.RoleReseller:
		if err = s.db.QueryRowContext(ctx, `SELECT id FROM reseller_accounts WHERE login_user_id=$1`, userID).Scan(&businessID); err == nil {
			err = s.manager.SetResellerStatus(ctx, actor, businessID, status)
		}
	default:
		err = fmt.Errorf("unsupported user role %q", role)
	}
	if err != nil {
		return err
	}
	action := "user.unsuspended"
	if suspended {
		action = "user.suspended"
	}
	return s.audit(ctx, action, role, businessID, map[string]any{"email": strings.ToLower(strings.TrimSpace(email))})
}

func (s *Service) ListSessions(ctx context.Context, email string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sess.id,u.email,sess.created_at,sess.expires_at FROM sessions sess JOIN users u ON u.id=sess.user_id
		WHERE ($1='' OR lower(u.email)=lower($1)) ORDER BY sess.id`, strings.TrimSpace(email))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Session
	for rows.Next() {
		var item Session
		if err := rows.Scan(&item.ID, &item.Email, &item.CreatedAt, &item.ExpiresAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) RevokeSession(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var email string
	if err = tx.QueryRowContext(ctx, `DELETE FROM sessions sess USING users u WHERE sess.id=$1 AND u.id=sess.user_id RETURNING u.email`, id).Scan(&email); err != nil {
		return err
	}
	if err = s.auditTx(ctx, tx, "session.revoked", "session", id, map[string]any{"user": email}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) RevokeUserSessions(ctx context.Context, email string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var userID int64
	if err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE lower(email)=lower($1)`, strings.TrimSpace(email)).Scan(&userID); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err = s.auditTx(ctx, tx, "session.user_revoked", "user", userID, map[string]any{"email": strings.ToLower(strings.TrimSpace(email)), "count": count}); err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

func (s *Service) ListSites(ctx context.Context, domain string) ([]Site, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,domain,username,php_version,status,subscription_id,tls_issuer,tls_status,tls_expires_at
		FROM sites WHERE ($1='' OR lower(domain)=lower($1)) ORDER BY domain`, site.NormalizeDomain(domain))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Site
	for rows.Next() {
		var item Site
		if err := rows.Scan(&item.ID, &item.Domain, &item.Username, &item.PHPVersion, &item.Status, &item.SubscriptionID, &item.TLSIssuer, &item.TLSStatus, &item.TLSExpiresAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) ReconcileSite(ctx context.Context, domain string) (int64, error) {
	actor, err := s.systemActor(ctx)
	if err != nil {
		return 0, err
	}
	runID, err := s.manager.ReconcileSite(ctx, actor, domain)
	if err != nil {
		return 0, err
	}
	return runID, s.audit(ctx, "site.reconcile_queued", "reconciliation", runID, map[string]any{"domain": site.NormalizeDomain(domain)})
}

func (s *Service) RenewSSL(ctx context.Context, domain string, replaceCustom bool) (int64, error) {
	var siteID int64
	var issuer string
	if err := s.db.QueryRowContext(ctx, `SELECT id,tls_issuer FROM sites WHERE lower(domain)=lower($1)`, site.NormalizeDomain(domain)).Scan(&siteID, &issuer); err != nil {
		return 0, err
	}
	if issuer == string(types.CertIssuerCustom) && !replaceCustom {
		return 0, errors.New("site uses a custom certificate; replacement confirmation is required")
	}
	actor, err := s.systemActor(ctx)
	if err != nil {
		return 0, err
	}
	_, err = s.manager.IssueCertificate(ctx, actor, domain, types.CertIssuerACME)
	if err != nil {
		return 0, err
	}
	return siteID, s.audit(ctx, "certificate.renew_queued", "site", siteID, map[string]any{"domain": site.NormalizeDomain(domain), "issuer": "acme"})
}

func (s *Service) SetCustomSSL(ctx context.Context, domain string, bundle certificates.Bundle) (int64, error) {
	var siteID int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM sites WHERE lower(domain)=lower($1)`, site.NormalizeDomain(domain)).Scan(&siteID); err != nil {
		return 0, err
	}
	actor, err := s.systemActor(ctx)
	if err != nil {
		return 0, err
	}
	jobID, err := s.manager.InstallCustomCertificate(ctx, actor, siteID, bundle)
	if err != nil {
		return 0, err
	}
	return jobID, s.audit(ctx, "certificate.custom_queued", "site", siteID, map[string]any{"domain": site.NormalizeDomain(domain), "job_id": jobID})
}

func (s *Service) CreateBackup(ctx context.Context, domain string) (int64, error) {
	var subscriptionID int64
	if err := s.db.QueryRowContext(ctx, `SELECT subscription_id FROM sites WHERE lower(domain)=lower($1)`, site.NormalizeDomain(domain)).Scan(&subscriptionID); err != nil {
		return 0, err
	}
	actor, err := s.systemActor(ctx)
	if err != nil {
		return 0, err
	}
	backupID, err := s.manager.CreateBackupForSubscription(ctx, actor, subscriptionID, types.CreateBackupReq{SubscriptionID: subscriptionID, Domain: domain})
	if err != nil {
		return 0, err
	}
	return backupID, s.audit(ctx, "backup.queued", "backup", backupID, map[string]any{"domain": site.NormalizeDomain(domain), "subscription_id": subscriptionID})
}

func (s *Service) ListBackups(ctx context.Context, domain string) ([]Backup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,target_name,status,size_bytes,subscription_id,created_at FROM backups
		WHERE ($1='' OR lower(target_name)=lower($1)) ORDER BY id DESC`, site.NormalizeDomain(domain))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Backup
	for rows.Next() {
		var item Backup
		if err := rows.Scan(&item.ID, &item.Domain, &item.Status, &item.SizeBytes, &item.SubscriptionID, &item.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) RestoreBackup(ctx context.Context, backupID int64) (int64, error) {
	actor, err := s.systemActor(ctx)
	if err != nil {
		return 0, err
	}
	restoreID, err := s.manager.RestoreBackup(ctx, actor, backupID)
	if err != nil {
		return 0, err
	}
	return restoreID, s.audit(ctx, "backup.restore_queued", "restore", restoreID, map[string]any{"backup_id": backupID})
}

func (s *Service) ListPlans(ctx context.Context) ([]Plan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.id,p.name,COALESCE(r.display_name,'Administrator'),p.is_active,p.revision
		FROM plans p LEFT JOIN reseller_accounts r ON r.id=p.reseller_id ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Plan
	for rows.Next() {
		var item Plan
		if err := rows.Scan(&item.ID, &item.Name, &item.Provider, &item.Active, &item.Revision); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) ListSubscriptions(ctx context.Context, customerEmail string) ([]Subscription, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sub.id,sub.name,c.email,COALESCE(p.name,'Custom'),sub.status,sub.sync_mode
		FROM subscriptions sub JOIN customers c ON c.id=sub.customer_id LEFT JOIN plans p ON p.id=sub.plan_id
		WHERE ($1='' OR lower(c.email)=lower($1)) ORDER BY sub.id`, strings.TrimSpace(customerEmail))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Subscription
	for rows.Next() {
		var item Subscription
		if err := rows.Scan(&item.ID, &item.Name, &item.Customer, &item.Plan, &item.Status, &item.Mode); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Service) ReconcileSystem(ctx context.Context) (int64, error) {
	actor, err := s.systemActor(ctx)
	if err != nil {
		return 0, err
	}
	runID, err := s.manager.ReconcileSystem(ctx, actor)
	if err != nil {
		return 0, err
	}
	return runID, s.audit(ctx, "system.reconcile_queued", "reconciliation", runID, nil)
}

func (s *Service) AgentPing(ctx context.Context) error {
	response, err := s.agent.Ping(ctx)
	if err != nil {
		return err
	}
	if !response.OK {
		return errors.New(response.Error)
	}
	return nil
}

func (s *Service) systemActor(ctx context.Context) (auth.SessionUser, error) {
	var actor auth.SessionUser
	var role string
	err := s.db.QueryRowContext(ctx, `SELECT id,email,role FROM users WHERE email='scheduler@nakpanel.internal' AND login_disabled=true`).Scan(&actor.ID, &actor.Email, &role)
	if err != nil {
		return auth.SessionUser{}, fmt.Errorf("find scheduler account: %w", err)
	}
	actor.Role = auth.Role(role)
	return actor, nil
}

func (s *Service) audit(ctx context.Context, action, targetType string, targetID int64, metadata map[string]any) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO audit_events(actor_label,action,target_type,target_id,metadata) VALUES($1,$2,$3,NULLIF($4,0),$5)`, s.actorLabel, action, targetType, targetID, data)
	if err != nil {
		return fmt.Errorf("write operator audit event: %w", err)
	}
	return nil
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, action, targetType string, targetID int64, metadata map[string]any) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_label,action,target_type,target_id,metadata) VALUES($1,$2,$3,NULLIF($4,0),$5)`, s.actorLabel, action, targetType, targetID, data)
	if err != nil {
		return fmt.Errorf("write operator audit event: %w", err)
	}
	return nil
}

func ReadBundle(certPath, keyPath, chainPath string) (certificates.Bundle, error) {
	read := func(path string, required bool) ([]byte, error) {
		if strings.TrimSpace(path) == "" && !required {
			return nil, nil
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s must be a regular file no larger than 256 KiB", path)
		}
		data, err := io.ReadAll(io.LimitReader(file, certificates.MaxPEMBytes+1))
		if err != nil {
			return nil, err
		}
		if len(data) > certificates.MaxPEMBytes {
			return nil, fmt.Errorf("%s must be a regular file no larger than 256 KiB", path)
		}
		return data, nil
	}
	certPEM, err := read(certPath, true)
	if err != nil {
		return certificates.Bundle{}, fmt.Errorf("read certificate: %w", err)
	}
	keyPEM, err := read(keyPath, true)
	if err != nil {
		return certificates.Bundle{}, fmt.Errorf("read private key: %w", err)
	}
	chainPEM, err := read(chainPath, false)
	if err != nil {
		return certificates.Bundle{}, fmt.Errorf("read certificate chain: %w", err)
	}
	return certificates.Bundle{CertificatePEM: certPEM, PrivateKeyPEM: keyPEM, ChainPEM: chainPEM}, nil
}
