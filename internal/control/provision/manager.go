package provision

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

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

type DNSRecordUpserter interface {
	UpsertDNSRecord(ctx context.Context, siteID int64, record types.DNSRecord) error
}

type DNSRecordDeleter interface {
	DeleteDNSRecord(ctx context.Context, siteID, recordID int64) error
}

func (m *Manager) UpsertDNSRecord(ctx context.Context, owner auth.SessionUser, siteID int64, record types.DNSRecord) error {
	store, ok := m.quotaStore.(controlquota.DomainSettingsStore)
	upserter, canUpsert := m.phase6Repo.(DNSRecordUpserter)
	if !ok || !canUpsert {
		return errors.New("DNS record management is not configured")
	}
	domain, err := store.SiteDomain(ctx, siteID)
	if err != nil {
		return err
	}
	if err := m.canManageDNS(ctx, owner, domain); err != nil {
		return err
	}
	return upserter.UpsertDNSRecord(ctx, siteID, record)
}

func (m *Manager) DeleteDNSRecord(ctx context.Context, owner auth.SessionUser, siteID, recordID int64) error {
	store, ok := m.quotaStore.(controlquota.DomainSettingsStore)
	deleter, canDelete := m.phase6Repo.(DNSRecordDeleter)
	if !ok || !canDelete {
		return errors.New("DNS record management is not configured")
	}
	domain, err := store.SiteDomain(ctx, siteID)
	if err != nil {
		return err
	}
	if err := m.canManageDNS(ctx, owner, domain); err != nil {
		return err
	}
	return deleter.DeleteDNSRecord(ctx, siteID, recordID)
}

type PasswordGenerator func() (string, error)

type AccessPolicy interface {
	CanManageSubscription(ctx context.Context, actor auth.SessionUser, subscriptionID int64) (bool, error)
	CanManageDomain(ctx context.Context, actor auth.SessionUser, domain string) (bool, error)
	CanManageDNS(ctx context.Context, actor auth.SessionUser, domain string) (bool, error)
	CanManagePHP(ctx context.Context, actor auth.SessionUser, domain string) (bool, error)
	CanManageTLS(ctx context.Context, actor auth.SessionUser, domain string) (bool, error)
	CanManageBackup(ctx context.Context, actor auth.SessionUser, backupID int64) (bool, error)
	CanManageCustomer(ctx context.Context, actor auth.SessionUser, customerID int64) (bool, error)
	CanManagePlan(ctx context.Context, actor auth.SessionUser, planID int64) (bool, error)
}

type RuntimeCapabilityReader interface {
	RuntimeCapabilities(context.Context) (types.RuntimeCapabilities, error)
}

type Manager struct {
	siteRepo                SiteRepository
	databaseRepo            DatabaseRepository
	certificateRepo         CertificateRepository
	phase6Repo              Phase6Repository
	quotaStore              controlquota.Store
	quotaAdmin              controlquota.AdminStore
	passwordGenerator       PasswordGenerator
	accessPolicy            AccessPolicy
	capabilities            RuntimeCapabilityReader
	customCertificateRepo   CustomCertificateRepository
	customCertificateStager CustomCertificateStager
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

func WithCustomCertificateRepository(repo CustomCertificateRepository) ManagerOption {
	return func(m *Manager) { m.customCertificateRepo = repo }
}

func WithCustomCertificateStager(stager CustomCertificateStager) ManagerOption {
	return func(m *Manager) { m.customCertificateStager = stager }
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

func WithRuntimeCapabilities(reader RuntimeCapabilityReader) ManagerOption {
	return func(m *Manager) {
		m.capabilities = reader
	}
}

func (m *Manager) validateInstalledPHP(ctx context.Context, version string) error {
	if m.capabilities == nil {
		return nil
	}
	capabilities, err := m.capabilities.RuntimeCapabilities(ctx)
	if err != nil {
		return fmt.Errorf("load agent PHP capabilities: %w", err)
	}
	for _, installed := range capabilities.PHPVersions {
		if strings.TrimSpace(installed) == strings.TrimSpace(version) {
			return nil
		}
	}
	return fmt.Errorf("PHP %s is not installed on the server", version)
}

func (m *Manager) validatePlanPHP(ctx context.Context, allowlist, defaultVersion string, hostingEnabled bool) error {
	if m.capabilities == nil {
		return nil
	}
	if !hostingEnabled && strings.TrimSpace(allowlist) == "" {
		return nil
	}
	capabilities, err := m.capabilities.RuntimeCapabilities(ctx)
	if err != nil {
		return fmt.Errorf("load agent PHP capabilities: %w", err)
	}
	installed := make(map[string]bool, len(capabilities.PHPVersions))
	for _, version := range capabilities.PHPVersions {
		if version = strings.TrimSpace(version); version != "" {
			installed[version] = true
		}
	}
	for _, version := range strings.Split(allowlist, ",") {
		if version = strings.TrimSpace(version); version != "" && !installed[version] {
			return fmt.Errorf("PHP %s is not installed on the server", version)
		}
	}
	defaultVersion = strings.TrimSpace(defaultVersion)
	if defaultVersion == "" && strings.TrimSpace(allowlist) != "" {
		defaultVersion = strings.TrimSpace(strings.Split(allowlist, ",")[0])
	}
	if hostingEnabled && !installed[defaultVersion] {
		return fmt.Errorf("default PHP %s is not installed on the server", defaultVersion)
	}
	return nil
}

func WithAccessPolicy(policy AccessPolicy) ManagerOption {
	return func(m *Manager) { m.accessPolicy = policy }
}

func (m *Manager) canManageSubscription(ctx context.Context, actor auth.SessionUser, subscriptionID int64) error {
	if actor.Role == auth.RoleAdmin {
		return nil
	}
	if m.accessPolicy == nil {
		return ErrForbidden
	}
	ok, err := m.accessPolicy.CanManageSubscription(ctx, actor, subscriptionID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

func (m *Manager) canManageDomain(ctx context.Context, actor auth.SessionUser, domain string) error {
	if actor.Role == auth.RoleAdmin {
		return nil
	}
	if m.accessPolicy == nil {
		return ErrForbidden
	}
	ok, err := m.accessPolicy.CanManageDomain(ctx, actor, domain)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

func (m *Manager) canManageDNS(ctx context.Context, actor auth.SessionUser, domain string) error {
	if actor.Role == auth.RoleAdmin {
		return nil
	}
	if m.accessPolicy == nil {
		return ErrForbidden
	}
	ok, err := m.accessPolicy.CanManageDNS(ctx, actor, domain)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

func (m *Manager) canManagePHP(ctx context.Context, actor auth.SessionUser, domain string) error {
	if actor.Role == auth.RoleAdmin {
		return nil
	}
	if m.accessPolicy == nil {
		return ErrForbidden
	}
	ok, err := m.accessPolicy.CanManagePHP(ctx, actor, domain)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

func (m *Manager) canManageTLS(ctx context.Context, actor auth.SessionUser, domain string) error {
	if actor.Role == auth.RoleAdmin {
		return nil
	}
	if m.accessPolicy == nil {
		return ErrForbidden
	}
	ok, err := m.accessPolicy.CanManageTLS(ctx, actor, domain)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

func (m *Manager) canManageBackup(ctx context.Context, actor auth.SessionUser, backupID int64) error {
	if actor.Role == auth.RoleAdmin {
		return nil
	}
	if m.accessPolicy == nil {
		return ErrForbidden
	}
	ok, err := m.accessPolicy.CanManageBackup(ctx, actor, backupID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

func (m *Manager) canManageCustomer(ctx context.Context, actor auth.SessionUser, customerID int64) error {
	if actor.Role == auth.RoleAdmin {
		return nil
	}
	if m.accessPolicy == nil {
		return ErrForbidden
	}
	ok, err := m.accessPolicy.CanManageCustomer(ctx, actor, customerID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

func (m *Manager) canManagePlan(ctx context.Context, actor auth.SessionUser, planID int64) error {
	if actor.Role == auth.RoleAdmin {
		return nil
	}
	if m.accessPolicy == nil {
		return ErrForbidden
	}
	ok, err := m.accessPolicy.CanManagePlan(ctx, actor, planID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
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
			normalized.PHPVersion, err = controlquota.ResolvePHPVersion(entitlement, normalized.PHPVersion)
			if err != nil {
				return 0, err
			}
		}
	}
	if err := site.ValidateCreateSiteRequest(normalized); err != nil {
		return 0, err
	}
	if err := m.validateInstalledPHP(ctx, normalized.PHPVersion); err != nil {
		return 0, err
	}
	normalized.Limits = limits
	return m.siteRepo.CreateSite(ctx, resourceOwnerID, normalized)
}

func (m *Manager) CreateSiteForSubscription(ctx context.Context, actor auth.SessionUser, subscriptionID int64, req types.CreateSiteReq) (int64, error) {
	if subscriptionID <= 0 {
		return 0, errors.New("subscription id is required")
	}
	if err := m.canManageSubscription(ctx, actor, subscriptionID); err != nil {
		return 0, err
	}
	if m.siteRepo == nil {
		return 0, errors.New("site repository is not configured")
	}

	normalized := site.NormalizeCreateSiteRequest(req)
	limits, entitlement, err := controlquota.SiteLimitsForSubscription(ctx, m.quotaStore, subscriptionID)
	if err != nil {
		return 0, err
	}
	normalized.PHPVersion, err = controlquota.ResolvePHPVersion(entitlement, normalized.PHPVersion)
	if err != nil {
		return 0, err
	}
	if err := site.ValidateCreateSiteRequest(normalized); err != nil {
		return 0, err
	}
	if err := m.validateInstalledPHP(ctx, normalized.PHPVersion); err != nil {
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
	if subscriptionID <= 0 {
		return 0, errors.New("subscription id is required")
	}
	if err := m.canManageSubscription(ctx, actor, subscriptionID); err != nil {
		return 0, err
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
	if m.certificateRepo == nil {
		return 0, errors.New("certificate repository is not configured")
	}
	normalized := site.NormalizeDomain(domain)
	if err := site.ValidateDomain(normalized); err != nil {
		return 0, err
	}
	if err := m.canManageTLS(ctx, owner, normalized); err != nil {
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
	if subscriptionID <= 0 {
		return 0, errors.New("subscription id is required")
	}
	if err := m.canManageSubscription(ctx, actor, subscriptionID); err != nil {
		return 0, err
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
	if m.phase6Repo == nil {
		return 0, errors.New("phase6 repository is not configured")
	}
	normalized := site.NormalizeDomain(domain)
	if err := site.ValidateDomain(normalized); err != nil {
		return 0, err
	}
	if err := m.canManageDNS(ctx, owner, normalized); err != nil {
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

func (m *Manager) ReconcileSite(ctx context.Context, owner auth.SessionUser, domain string) (int64, error) {
	normalized := site.NormalizeDomain(domain)
	if err := site.ValidateDomain(normalized); err != nil {
		return 0, err
	}
	if err := m.canManageDomain(ctx, owner, normalized); err != nil {
		return 0, err
	}
	repository, ok := m.phase6Repo.(interface {
		ReconcileSite(context.Context, int64, string) (int64, error)
	})
	if !ok {
		return 0, errors.New("site reconciliation is not configured")
	}
	return repository.ReconcileSite(ctx, owner.ID, normalized)
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
	if backupID <= 0 {
		return 0, errors.New("backup id is required")
	}
	if m.phase6Repo == nil {
		return 0, errors.New("phase6 repository is not configured")
	}
	if err := m.canManageBackup(ctx, owner, backupID); err != nil {
		return 0, err
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
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return controlquota.Plan{}, ErrForbidden
	}
	if m.quotaAdmin == nil {
		return controlquota.Plan{}, errors.New("plan store is not configured")
	}
	if err := m.validatePlanPHP(ctx, plan.PHPAllowlist, plan.DefaultPHPVersion, plan.HostingEnabled); err != nil {
		return controlquota.Plan{}, err
	}
	if owner.Role == auth.RoleReseller {
		scope, err := m.quotaAdmin.ProviderScopeForUser(ctx, owner)
		if err != nil {
			return controlquota.Plan{}, err
		}
		if plan.ID > 0 {
			if err := m.canManagePlan(ctx, owner, plan.ID); err != nil {
				return controlquota.Plan{}, err
			}
		}
		plan.ResellerID = scope.ResellerID
	}
	return m.quotaAdmin.UpsertPlan(ctx, plan)
}

func (m *Manager) PreviewPlan(ctx context.Context, owner auth.SessionUser, plan controlquota.Plan) (types.PlanPreview, error) {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return types.PlanPreview{}, ErrForbidden
	}
	previewer, ok := m.quotaAdmin.(interface {
		PreviewPlan(context.Context, controlquota.Plan) (types.PlanPreview, error)
	})
	if !ok {
		return types.PlanPreview{}, errors.New("plan preview is not configured")
	}
	if err := m.validatePlanPHP(ctx, plan.PHPAllowlist, plan.DefaultPHPVersion, plan.HostingEnabled); err != nil {
		return types.PlanPreview{}, err
	}
	if owner.Role == auth.RoleReseller {
		scope, err := m.quotaAdmin.ProviderScopeForUser(ctx, owner)
		if err != nil {
			return types.PlanPreview{}, err
		}
		if plan.ID > 0 {
			if err := m.canManagePlan(ctx, owner, plan.ID); err != nil {
				return types.PlanPreview{}, err
			}
		}
		plan.ResellerID = scope.ResellerID
	}
	return previewer.PreviewPlan(ctx, plan)
}

func (m *Manager) SetPlanActive(ctx context.Context, owner auth.SessionUser, planID int64, active bool) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("plan store is not configured")
	}
	if owner.Role == auth.RoleReseller {
		if err := m.canManagePlan(ctx, owner, planID); err != nil {
			return err
		}
	}
	return m.quotaAdmin.SetPlanActive(ctx, planID, active)
}

func (m *Manager) SetPlanStatuses(ctx context.Context, owner auth.SessionUser, planIDs []int64, active bool) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	bulk, ok := m.quotaAdmin.(controlquota.PlanBulkStatusStore)
	if !ok {
		return errors.New("atomic plan status updates are not configured")
	}
	resellerID, unrestricted := int64(0), owner.Role == auth.RoleAdmin
	if owner.Role == auth.RoleReseller {
		scope, err := m.quotaAdmin.ProviderScopeForUser(ctx, owner)
		if err != nil {
			return err
		}
		resellerID = scope.ResellerID
	}
	if err := bulk.SetPlanStatuses(ctx, planIDs, resellerID, unrestricted, active); err != nil {
		if errors.Is(err, controlquota.ErrProviderScope) {
			return ErrForbidden
		}
		return err
	}
	return nil
}

func (m *Manager) AssignSubscription(ctx context.Context, owner auth.SessionUser, customerUserID int64, planID int64) (controlquota.SubscriptionAssignment, error) {
	// This is the Phase 9 user-based compatibility path. Provider-scoped
	// callers must use CreateSubscription, which checks customer ownership.
	if owner.Role != auth.RoleAdmin {
		return controlquota.SubscriptionAssignment{}, ErrForbidden
	}
	if m.quotaAdmin == nil {
		return controlquota.SubscriptionAssignment{}, errors.New("plan store is not configured")
	}
	return m.quotaAdmin.AssignSubscription(ctx, customerUserID, planID)
}

func (m *Manager) CreateCustomer(ctx context.Context, owner auth.SessionUser, req types.CreateCustomerReq) (types.Customer, error) {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return types.Customer{}, ErrForbidden
	}
	if m.quotaAdmin == nil {
		return types.Customer{}, errors.New("customer store is not configured")
	}
	if owner.Role == auth.RoleReseller {
		scope, err := m.quotaAdmin.ProviderScopeForUser(ctx, owner)
		if err != nil {
			return types.Customer{}, err
		}
		req.ResellerID = scope.ResellerID
	}
	return m.quotaAdmin.CreateCustomer(ctx, req)
}

func (m *Manager) EnableCustomerLogin(ctx context.Context, owner auth.SessionUser, customerID int64, email string, password string) (types.Customer, error) {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return types.Customer{}, ErrForbidden
	}
	if m.quotaAdmin == nil {
		return types.Customer{}, errors.New("customer store is not configured")
	}
	if owner.Role == auth.RoleReseller {
		if err := m.canManageCustomer(ctx, owner, customerID); err != nil {
			return types.Customer{}, err
		}
	}
	return m.quotaAdmin.EnableCustomerLogin(ctx, customerID, email, password)
}

func (m *Manager) SetCustomerStatus(ctx context.Context, owner auth.SessionUser, customerID int64, status string) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("customer store is not configured")
	}
	if owner.Role == auth.RoleReseller {
		if err := m.canManageCustomer(ctx, owner, customerID); err != nil {
			return err
		}
	}
	return m.quotaAdmin.SetCustomerStatus(ctx, customerID, status)
}

func (m *Manager) SetCustomerStatuses(ctx context.Context, owner auth.SessionUser, customerIDs []int64, status string) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("customer store is not configured")
	}
	if owner.Role == auth.RoleReseller {
		for _, customerID := range customerIDs {
			if err := m.canManageCustomer(ctx, owner, customerID); err != nil {
				return err
			}
		}
	}
	bulk, ok := m.quotaAdmin.(controlquota.BulkStatusStore)
	if !ok {
		return errors.New("atomic customer lifecycle updates are not configured")
	}
	return bulk.SetCustomerStatuses(ctx, customerIDs, status)
}

func (m *Manager) SetSubscriptionStatus(ctx context.Context, owner auth.SessionUser, subscriptionID int64, status string) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("subscription store is not configured")
	}
	if err := m.canManageSubscription(ctx, owner, subscriptionID); err != nil {
		return err
	}
	return m.quotaAdmin.SetSubscriptionStatus(ctx, subscriptionID, status)
}

func (m *Manager) SetSubscriptionStatuses(ctx context.Context, owner auth.SessionUser, subscriptionIDs []int64, status string) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("subscription store is not configured")
	}
	for _, subscriptionID := range subscriptionIDs {
		if err := m.canManageSubscription(ctx, owner, subscriptionID); err != nil {
			return err
		}
	}
	bulk, ok := m.quotaAdmin.(controlquota.BulkStatusStore)
	if !ok {
		return errors.New("atomic subscription lifecycle updates are not configured")
	}
	return bulk.SetSubscriptionStatuses(ctx, subscriptionIDs, status)
}

func (m *Manager) ChangeSubscriptionPlans(ctx context.Context, owner auth.SessionUser, subscriptionIDs []int64, planID int64) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	for _, id := range subscriptionIDs {
		if err := m.canManageSubscription(ctx, owner, id); err != nil {
			return err
		}
	}
	if owner.Role == auth.RoleReseller {
		if err := m.canManagePlan(ctx, owner, planID); err != nil {
			return err
		}
	}
	store, ok := m.quotaAdmin.(controlquota.SubscriptionChangeStore)
	if !ok {
		return errors.New("subscription plan changes are not configured")
	}
	return store.ChangeSubscriptionPlans(ctx, subscriptionIDs, planID)
}

func (m *Manager) ChangeSubscriptionSubscriber(ctx context.Context, owner auth.SessionUser, subscriptionIDs []int64, customerID int64) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	for _, id := range subscriptionIDs {
		if err := m.canManageSubscription(ctx, owner, id); err != nil {
			return err
		}
	}
	if owner.Role == auth.RoleReseller {
		if err := m.canManageCustomer(ctx, owner, customerID); err != nil {
			return err
		}
	}
	store, ok := m.quotaAdmin.(controlquota.SubscriptionChangeStore)
	if !ok {
		return errors.New("subscription subscriber changes are not configured")
	}
	return store.ChangeSubscriptionSubscriber(ctx, subscriptionIDs, customerID)
}

func (m *Manager) UpdateSiteSettings(ctx context.Context, owner auth.SessionUser, req types.UpdateSiteSettingsReq) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleClient && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	store, ok := m.quotaStore.(controlquota.DomainSettingsStore)
	if !ok {
		return errors.New("domain settings are not configured")
	}
	domain, err := store.SiteDomain(ctx, req.SiteID)
	if err != nil {
		return err
	}
	if err := m.canManageDomain(ctx, owner, domain); err != nil {
		return err
	}
	if owner.Role != auth.RoleAdmin {
		switch req.Section {
		case "php":
			if err := m.canManagePHP(ctx, owner, domain); err != nil {
				return err
			}
		case "hosting":
			if req.DesiredHTTPSRedirect {
				if err := m.canManageTLS(ctx, owner, domain); err != nil {
					return err
				}
			}
		}
	}
	return store.UpdateSiteSettings(ctx, req)
}

func (m *Manager) SetTLSAutoRenew(ctx context.Context, owner auth.SessionUser, siteID int64, enabled bool) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleClient && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	store, ok := m.quotaStore.(controlquota.DomainSettingsStore)
	if !ok {
		return errors.New("domain settings are not configured")
	}
	domain, err := store.SiteDomain(ctx, siteID)
	if err != nil {
		return err
	}
	if err = m.canManageDomain(ctx, owner, domain); err != nil {
		return err
	}
	if err = m.canManageTLS(ctx, owner, domain); err != nil {
		return err
	}
	return store.SetTLSAutoRenew(ctx, siteID, enabled)
}

func (m *Manager) CreateSubscription(ctx context.Context, owner auth.SessionUser, req types.CreateSubscriptionReq) (types.SubscriptionSummary, error) {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return types.SubscriptionSummary{}, ErrForbidden
	}
	if m.quotaAdmin == nil {
		return types.SubscriptionSummary{}, errors.New("subscription store is not configured")
	}
	if owner.Role == auth.RoleReseller {
		if req.ID > 0 {
			if err := m.canManageSubscription(ctx, owner, req.ID); err != nil {
				return types.SubscriptionSummary{}, err
			}
		}
		if err := m.canManageCustomer(ctx, owner, req.CustomerID); err != nil {
			return types.SubscriptionSummary{}, err
		}
		if req.PlanID > 0 {
			if err := m.canManagePlan(ctx, owner, req.PlanID); err != nil {
				return types.SubscriptionSummary{}, err
			}
		}
	}
	return m.quotaAdmin.CreateSubscription(ctx, req)
}

func (m *Manager) CreateReseller(ctx context.Context, owner auth.SessionUser, req types.CreateCustomerReq, planID int64) (types.Reseller, error) {
	if owner.Role != auth.RoleAdmin {
		return types.Reseller{}, ErrForbidden
	}
	if m.quotaAdmin == nil {
		return types.Reseller{}, errors.New("provider store is not configured")
	}
	return m.quotaAdmin.CreateReseller(ctx, req, planID)
}
func (m *Manager) SetResellerStatus(ctx context.Context, owner auth.SessionUser, id int64, status string) error {
	if owner.Role != auth.RoleAdmin {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("provider store is not configured")
	}
	return m.quotaAdmin.SetResellerStatus(ctx, id, status)
}
func (m *Manager) SetResellerStatuses(ctx context.Context, owner auth.SessionUser, ids []int64, status string) error {
	if owner.Role != auth.RoleAdmin {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("provider store is not configured")
	}
	bulk, ok := m.quotaAdmin.(controlquota.BulkStatusStore)
	if !ok {
		return errors.New("atomic reseller lifecycle updates are not configured")
	}
	return bulk.SetResellerStatuses(ctx, ids, status)
}
func (m *Manager) UpsertResellerPlan(ctx context.Context, owner auth.SessionUser, p types.ResellerPlan) (types.ResellerPlan, error) {
	if owner.Role != auth.RoleAdmin {
		return types.ResellerPlan{}, ErrForbidden
	}
	if m.quotaAdmin == nil {
		return types.ResellerPlan{}, errors.New("provider store is not configured")
	}
	return m.quotaAdmin.UpsertResellerPlan(ctx, p)
}
func (m *Manager) SetResellerPlanStatuses(ctx context.Context, owner auth.SessionUser, ids []int64, active bool) error {
	if owner.Role != auth.RoleAdmin {
		return ErrForbidden
	}
	bulk, ok := m.quotaAdmin.(controlquota.PlanBulkStatusStore)
	if !ok {
		return errors.New("atomic reseller plan status updates are not configured")
	}
	return bulk.SetResellerPlanStatuses(ctx, ids, active)
}
func (m *Manager) TransferCustomer(ctx context.Context, owner auth.SessionUser, customerID, resellerID int64) error {
	if owner.Role != auth.RoleAdmin {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("provider store is not configured")
	}
	return m.quotaAdmin.TransferCustomer(ctx, customerID, resellerID)
}
func (m *Manager) UpsertAddonPlan(ctx context.Context, owner auth.SessionUser, a types.AddonPlan) (types.AddonPlan, error) {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return types.AddonPlan{}, ErrForbidden
	}
	if m.quotaAdmin == nil {
		return types.AddonPlan{}, errors.New("provider store is not configured")
	}
	if err := m.validatePlanPHP(ctx, a.Entitlements.PHPAllowlist, a.Entitlements.DefaultPHPVersion, false); err != nil {
		return types.AddonPlan{}, err
	}
	if owner.Role == auth.RoleReseller {
		scope, err := m.quotaAdmin.ProviderScopeForUser(ctx, owner)
		if err != nil {
			return types.AddonPlan{}, err
		}
		a.ResellerID = scope.ResellerID
	}
	return m.quotaAdmin.UpsertAddonPlan(ctx, a)
}
func (m *Manager) SetAddonPlanStatuses(ctx context.Context, owner auth.SessionUser, ids []int64, active bool) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	bulk, ok := m.quotaAdmin.(controlquota.PlanBulkStatusStore)
	if !ok {
		return errors.New("atomic add-on status updates are not configured")
	}
	resellerID, unrestricted := int64(0), owner.Role == auth.RoleAdmin
	if owner.Role == auth.RoleReseller {
		scope, err := m.quotaAdmin.ProviderScopeForUser(ctx, owner)
		if err != nil {
			return err
		}
		resellerID = scope.ResellerID
	}
	if err := bulk.SetAddonPlanStatuses(ctx, ids, resellerID, unrestricted, active); err != nil {
		if errors.Is(err, controlquota.ErrProviderScope) {
			return ErrForbidden
		}
		return err
	}
	return nil
}
func (m *Manager) SetSubscriptionAddons(ctx context.Context, owner auth.SessionUser, id int64, addonIDs []int64) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("provider store is not configured")
	}
	if err := m.canManageSubscription(ctx, owner, id); err != nil {
		return err
	}
	return m.quotaAdmin.SetSubscriptionAddons(ctx, id, addonIDs)
}
func (m *Manager) SyncSubscription(ctx context.Context, owner auth.SessionUser, id int64) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("provider store is not configured")
	}
	if err := m.canManageSubscription(ctx, owner, id); err != nil {
		return err
	}
	return m.quotaAdmin.SyncSubscription(ctx, id)
}
func (m *Manager) SetSubscriptionMode(ctx context.Context, owner auth.SessionUser, id int64, mode string, e types.SubscriptionEntitlements) error {
	if owner.Role != auth.RoleAdmin && owner.Role != auth.RoleReseller {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("provider store is not configured")
	}
	if err := m.canManageSubscription(ctx, owner, id); err != nil {
		return err
	}
	return m.quotaAdmin.SetSubscriptionMode(ctx, id, mode, e)
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
