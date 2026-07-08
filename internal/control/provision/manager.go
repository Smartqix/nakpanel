package provision

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	dbvalidation "github.com/nakroteck/nakpanel/internal/database"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

var ErrForbidden = errors.New("forbidden")

type SiteRepository interface {
	CreateSite(ctx context.Context, ownerID int64, req types.CreateSiteReq) (int64, error)
}

type DatabaseRepository interface {
	CreateDatabase(ctx context.Context, ownerID int64, req types.CreateDatabaseReq) (int64, error)
}

type CertificateRepository interface {
	IssueCertificate(ctx context.Context, ownerID int64, domain string, issuer types.CertIssuer) (int64, error)
}

type Phase6Repository interface {
	CreateBackup(ctx context.Context, ownerID int64, req types.CreateBackupReq) (int64, error)
	ConfigureWebmail(ctx context.Context, ownerID int64, domain string) (int64, error)
	ConfigureDNS(ctx context.Context, ownerID int64, domain string, address string) (int64, error)
	ReconcileSystem(ctx context.Context, ownerID int64) (int64, error)
	CreateAdminerToken(ctx context.Context, ownerID int64) (types.AdminerSSO, error)
	RestoreBackup(ctx context.Context, ownerID int64, backupID int64) (int64, error)
}

type PasswordGenerator func() (string, error)

type Manager struct {
	siteRepo          SiteRepository
	databaseRepo      DatabaseRepository
	certificateRepo   CertificateRepository
	phase6Repo        Phase6Repository
	quotaStore        controlquota.Store
	quotaAdmin        controlquota.AdminStore
	passwordGenerator PasswordGenerator
}

type ManagerOption func(*Manager)

func NewManager(repo SiteRepository, options ...ManagerOption) *Manager {
	manager := &Manager{
		siteRepo:          repo,
		passwordGenerator: GenerateDatabasePassword,
	}
	for _, option := range options {
		option(manager)
	}
	return manager
}

func WithDatabaseRepository(repo DatabaseRepository) ManagerOption {
	return func(m *Manager) {
		m.databaseRepo = repo
	}
}

func WithPasswordGenerator(generator PasswordGenerator) ManagerOption {
	return func(m *Manager) {
		m.passwordGenerator = generator
	}
}

func WithCertificateRepository(repo CertificateRepository) ManagerOption {
	return func(m *Manager) {
		m.certificateRepo = repo
	}
}

func WithPhase6Repository(repo Phase6Repository) ManagerOption {
	return func(m *Manager) {
		m.phase6Repo = repo
	}
}

func WithQuotaStore(store controlquota.Store) ManagerOption {
	return func(m *Manager) {
		m.quotaStore = store
		if adminStore, ok := store.(controlquota.AdminStore); ok {
			m.quotaAdmin = adminStore
		}
	}
}

func (m *Manager) CreateSite(ctx context.Context, owner auth.SessionUser, req types.CreateSiteReq) (int64, error) {
	return m.CreateSiteFor(ctx, owner, owner.ID, req)
}

func (m *Manager) CreateSiteFor(ctx context.Context, actor auth.SessionUser, resourceOwnerID int64, req types.CreateSiteReq) (int64, error) {
	if req.SubscriptionID > 0 {
		return m.CreateSiteForSubscription(ctx, actor, req.SubscriptionID, req)
	}
	if actor.Role != auth.RoleAdmin {
		return 0, ErrForbidden
	}
	if resourceOwnerID <= 0 {
		return 0, errors.New("resource owner id is required")
	}
	if m.siteRepo == nil {
		return 0, errors.New("site repository is not configured")
	}

	normalized := site.NormalizeCreateSiteRequest(req)
	if err := site.ValidateCreateSiteRequest(normalized); err != nil {
		return 0, err
	}
	limits, err := controlquota.SiteLimits(ctx, m.quotaStore, resourceOwnerID)
	if err != nil {
		return 0, err
	}
	if m.quotaStore != nil {
		entitlement, hasEntitlement, err := m.quotaStore.GetLimits(ctx, resourceOwnerID)
		if err != nil {
			return 0, err
		}
		if hasEntitlement {
			normalized.SubscriptionID = entitlement.SubscriptionID
		}
	}
	normalized.Limits = limits
	return m.siteRepo.CreateSite(ctx, resourceOwnerID, normalized)
}

func (m *Manager) CreateSiteForSubscription(ctx context.Context, actor auth.SessionUser, subscriptionID int64, req types.CreateSiteReq) (int64, error) {
	if actor.Role != auth.RoleAdmin {
		return 0, ErrForbidden
	}
	if subscriptionID <= 0 {
		return 0, errors.New("subscription id is required")
	}
	if m.siteRepo == nil {
		return 0, errors.New("site repository is not configured")
	}

	normalized := site.NormalizeCreateSiteRequest(req)
	if err := site.ValidateCreateSiteRequest(normalized); err != nil {
		return 0, err
	}
	limits, entitlement, err := controlquota.SiteLimitsForSubscription(ctx, m.quotaStore, subscriptionID)
	if err != nil {
		return 0, err
	}
	normalized.SubscriptionID = subscriptionID
	normalized.Limits = limits
	ownerID := entitlement.UserID
	if ownerID <= 0 {
		ownerID = actor.ID
	}
	return m.siteRepo.CreateSite(ctx, ownerID, normalized)
}

func (m *Manager) CreateDatabase(ctx context.Context, owner auth.SessionUser, req types.CreateDatabaseReq) (int64, error) {
	return m.CreateDatabaseFor(ctx, owner, owner.ID, req)
}

func (m *Manager) CreateDatabaseFor(ctx context.Context, actor auth.SessionUser, resourceOwnerID int64, req types.CreateDatabaseReq) (int64, error) {
	if req.SubscriptionID > 0 {
		return m.CreateDatabaseForSubscription(ctx, actor, req.SubscriptionID, req)
	}
	if actor.Role != auth.RoleAdmin {
		return 0, ErrForbidden
	}
	if resourceOwnerID <= 0 {
		return 0, errors.New("resource owner id is required")
	}
	if m.databaseRepo == nil {
		return 0, errors.New("database repository is not configured")
	}
	if m.passwordGenerator == nil {
		return 0, errors.New("database password generator is not configured")
	}

	normalized := dbvalidation.NormalizeCreateDatabaseRequest(req)
	if normalized.Engine == "" {
		normalized.Engine = types.EngineMariaDB
	}
	password, err := m.passwordGenerator()
	if err != nil {
		return 0, fmt.Errorf("generate database password: %w", err)
	}
	normalized.Password = password
	if err := dbvalidation.ValidateCreateDatabaseRequest(normalized); err != nil {
		return 0, err
	}
	if err := controlquota.CheckDatabase(ctx, m.quotaStore, resourceOwnerID); err != nil {
		return 0, err
	}
	if m.quotaStore != nil {
		entitlement, hasEntitlement, err := m.quotaStore.GetLimits(ctx, resourceOwnerID)
		if err != nil {
			return 0, err
		}
		if hasEntitlement {
			normalized.SubscriptionID = entitlement.SubscriptionID
		}
	}
	return m.databaseRepo.CreateDatabase(ctx, resourceOwnerID, normalized)
}

func (m *Manager) CreateDatabaseForSubscription(ctx context.Context, actor auth.SessionUser, subscriptionID int64, req types.CreateDatabaseReq) (int64, error) {
	if actor.Role != auth.RoleAdmin {
		return 0, ErrForbidden
	}
	if subscriptionID <= 0 {
		return 0, errors.New("subscription id is required")
	}
	if m.databaseRepo == nil {
		return 0, errors.New("database repository is not configured")
	}
	if m.passwordGenerator == nil {
		return 0, errors.New("database password generator is not configured")
	}

	normalized := dbvalidation.NormalizeCreateDatabaseRequest(req)
	if normalized.Engine == "" {
		normalized.Engine = types.EngineMariaDB
	}
	password, err := m.passwordGenerator()
	if err != nil {
		return 0, fmt.Errorf("generate database password: %w", err)
	}
	normalized.Password = password
	if err := dbvalidation.ValidateCreateDatabaseRequest(normalized); err != nil {
		return 0, err
	}
	entitlement, err := controlquota.CheckDatabaseForSubscription(ctx, m.quotaStore, subscriptionID)
	if err != nil {
		return 0, err
	}
	normalized.SubscriptionID = subscriptionID
	ownerID := entitlement.UserID
	if ownerID <= 0 {
		ownerID = actor.ID
	}
	return m.databaseRepo.CreateDatabase(ctx, ownerID, normalized)
}

func (m *Manager) IssueCertificate(ctx context.Context, owner auth.SessionUser, domain string, issuer types.CertIssuer) (int64, error) {
	if owner.Role != auth.RoleAdmin {
		return 0, ErrForbidden
	}
	if m.certificateRepo == nil {
		return 0, errors.New("certificate repository is not configured")
	}
	normalized := site.NormalizeDomain(domain)
	if err := site.ValidateDomain(normalized); err != nil {
		return 0, err
	}
	if issuer == "" {
		issuer = types.CertIssuerLocalSelfSigned
	}
	switch issuer {
	case types.CertIssuerLocalSelfSigned, types.CertIssuerACME:
	default:
		return 0, fmt.Errorf("unsupported certificate issuer %q", issuer)
	}
	return m.certificateRepo.IssueCertificate(ctx, owner.ID, normalized, issuer)
}

func (m *Manager) CreateBackup(ctx context.Context, owner auth.SessionUser, req types.CreateBackupReq) (int64, error) {
	return m.CreateBackupFor(ctx, owner, owner.ID, req)
}

func (m *Manager) CreateBackupFor(ctx context.Context, actor auth.SessionUser, resourceOwnerID int64, req types.CreateBackupReq) (int64, error) {
	if req.SubscriptionID > 0 {
		return m.CreateBackupForSubscription(ctx, actor, req.SubscriptionID, req)
	}
	if actor.Role != auth.RoleAdmin {
		return 0, ErrForbidden
	}
	if resourceOwnerID <= 0 {
		return 0, errors.New("resource owner id is required")
	}
	if m.phase6Repo == nil {
		return 0, errors.New("phase6 repository is not configured")
	}
	req.Domain = site.NormalizeDomain(req.Domain)
	if err := site.ValidateDomain(req.Domain); err != nil {
		return 0, err
	}
	if err := controlquota.CheckBackup(ctx, m.quotaStore, resourceOwnerID); err != nil {
		return 0, err
	}
	if m.quotaStore != nil {
		entitlement, hasEntitlement, err := m.quotaStore.GetLimits(ctx, resourceOwnerID)
		if err != nil {
			return 0, err
		}
		if hasEntitlement {
			req.SubscriptionID = entitlement.SubscriptionID
		}
	}
	return m.phase6Repo.CreateBackup(ctx, resourceOwnerID, req)
}

func (m *Manager) CreateBackupForSubscription(ctx context.Context, actor auth.SessionUser, subscriptionID int64, req types.CreateBackupReq) (int64, error) {
	if actor.Role != auth.RoleAdmin {
		return 0, ErrForbidden
	}
	if subscriptionID <= 0 {
		return 0, errors.New("subscription id is required")
	}
	if m.phase6Repo == nil {
		return 0, errors.New("phase6 repository is not configured")
	}
	req.Domain = site.NormalizeDomain(req.Domain)
	if err := site.ValidateDomain(req.Domain); err != nil {
		return 0, err
	}
	entitlement, err := controlquota.CheckBackupForSubscription(ctx, m.quotaStore, subscriptionID)
	if err != nil {
		return 0, err
	}
	req.SubscriptionID = subscriptionID
	ownerID := entitlement.UserID
	if ownerID <= 0 {
		ownerID = actor.ID
	}
	return m.phase6Repo.CreateBackup(ctx, ownerID, req)
}

func (m *Manager) ConfigureWebmail(ctx context.Context, owner auth.SessionUser, domain string) (int64, error) {
	if owner.Role != auth.RoleAdmin {
		return 0, ErrForbidden
	}
	if m.phase6Repo == nil {
		return 0, errors.New("phase6 repository is not configured")
	}
	normalized := site.NormalizeDomain(domain)
	if err := site.ValidateDomain(normalized); err != nil {
		return 0, err
	}
	return m.phase6Repo.ConfigureWebmail(ctx, owner.ID, normalized)
}

func (m *Manager) ConfigureDNS(ctx context.Context, owner auth.SessionUser, domain string, address string) (int64, error) {
	if owner.Role != auth.RoleAdmin {
		return 0, ErrForbidden
	}
	if m.phase6Repo == nil {
		return 0, errors.New("phase6 repository is not configured")
	}
	normalized := site.NormalizeDomain(domain)
	if err := site.ValidateDomain(normalized); err != nil {
		return 0, err
	}
	return m.phase6Repo.ConfigureDNS(ctx, owner.ID, normalized, address)
}

func (m *Manager) ReconcileSystem(ctx context.Context, owner auth.SessionUser) (int64, error) {
	if owner.Role != auth.RoleAdmin {
		return 0, ErrForbidden
	}
	if m.phase6Repo == nil {
		return 0, errors.New("phase6 repository is not configured")
	}
	return m.phase6Repo.ReconcileSystem(ctx, owner.ID)
}

func (m *Manager) CreateAdminerToken(ctx context.Context, owner auth.SessionUser) (types.AdminerSSO, error) {
	if owner.Role != auth.RoleAdmin {
		return types.AdminerSSO{}, ErrForbidden
	}
	if m.phase6Repo == nil {
		return types.AdminerSSO{}, errors.New("phase6 repository is not configured")
	}
	return m.phase6Repo.CreateAdminerToken(ctx, owner.ID)
}

func (m *Manager) RestoreBackup(ctx context.Context, owner auth.SessionUser, backupID int64) (int64, error) {
	if owner.Role != auth.RoleAdmin {
		return 0, ErrForbidden
	}
	if backupID <= 0 {
		return 0, errors.New("backup id is required")
	}
	if m.phase6Repo == nil {
		return 0, errors.New("phase6 repository is not configured")
	}
	return m.phase6Repo.RestoreBackup(ctx, owner.ID, backupID)
}

func (m *Manager) UpsertAccountQuota(ctx context.Context, owner auth.SessionUser, limits controlquota.Limits) error {
	if owner.Role != auth.RoleAdmin {
		return ErrForbidden
	}
	if m.quotaStore == nil {
		return errors.New("quota store is not configured")
	}
	return m.quotaStore.UpsertLimits(ctx, limits)
}

func (m *Manager) UpsertPlan(ctx context.Context, owner auth.SessionUser, plan controlquota.Plan) (controlquota.Plan, error) {
	if owner.Role != auth.RoleAdmin {
		return controlquota.Plan{}, ErrForbidden
	}
	if m.quotaAdmin == nil {
		return controlquota.Plan{}, errors.New("plan store is not configured")
	}
	return m.quotaAdmin.UpsertPlan(ctx, plan)
}

func (m *Manager) SetPlanActive(ctx context.Context, owner auth.SessionUser, planID int64, active bool) error {
	if owner.Role != auth.RoleAdmin {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("plan store is not configured")
	}
	return m.quotaAdmin.SetPlanActive(ctx, planID, active)
}

func (m *Manager) AssignSubscription(ctx context.Context, owner auth.SessionUser, customerUserID int64, planID int64) (controlquota.SubscriptionAssignment, error) {
	if owner.Role != auth.RoleAdmin {
		return controlquota.SubscriptionAssignment{}, ErrForbidden
	}
	if m.quotaAdmin == nil {
		return controlquota.SubscriptionAssignment{}, errors.New("plan store is not configured")
	}
	return m.quotaAdmin.AssignSubscription(ctx, customerUserID, planID)
}

func (m *Manager) CreateCustomer(ctx context.Context, owner auth.SessionUser, req types.CreateCustomerReq) (types.Customer, error) {
	if owner.Role != auth.RoleAdmin {
		return types.Customer{}, ErrForbidden
	}
	if m.quotaAdmin == nil {
		return types.Customer{}, errors.New("customer store is not configured")
	}
	return m.quotaAdmin.CreateCustomer(ctx, req)
}

func (m *Manager) EnableCustomerLogin(ctx context.Context, owner auth.SessionUser, customerID int64, email string, password string) (types.Customer, error) {
	if owner.Role != auth.RoleAdmin {
		return types.Customer{}, ErrForbidden
	}
	if m.quotaAdmin == nil {
		return types.Customer{}, errors.New("customer store is not configured")
	}
	return m.quotaAdmin.EnableCustomerLogin(ctx, customerID, email, password)
}

func (m *Manager) SetCustomerStatus(ctx context.Context, owner auth.SessionUser, customerID int64, status string) error {
	if owner.Role != auth.RoleAdmin {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("customer store is not configured")
	}
	return m.quotaAdmin.SetCustomerStatus(ctx, customerID, status)
}

func (m *Manager) CreateSubscription(ctx context.Context, owner auth.SessionUser, req types.CreateSubscriptionReq) (types.SubscriptionSummary, error) {
	if owner.Role != auth.RoleAdmin {
		return types.SubscriptionSummary{}, ErrForbidden
	}
	if m.quotaAdmin == nil {
		return types.SubscriptionSummary{}, errors.New("subscription store is not configured")
	}
	return m.quotaAdmin.CreateSubscription(ctx, req)
}

func (m *Manager) UpdateSettings(ctx context.Context, owner auth.SessionUser, settings controlquota.Settings) error {
	if owner.Role != auth.RoleAdmin {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("plan store is not configured")
	}
	return m.quotaAdmin.UpdateSettings(ctx, settings)
}

func GenerateDatabasePassword() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
