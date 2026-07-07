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
	}
}

func (m *Manager) CreateSite(ctx context.Context, owner auth.SessionUser, req types.CreateSiteReq) (int64, error) {
	if owner.Role != auth.RoleAdmin {
		return 0, ErrForbidden
	}
	if m.siteRepo == nil {
		return 0, errors.New("site repository is not configured")
	}

	normalized := site.NormalizeCreateSiteRequest(req)
	if err := site.ValidateCreateSiteRequest(normalized); err != nil {
		return 0, err
	}
	limits, err := controlquota.SiteLimits(ctx, m.quotaStore, owner.ID)
	if err != nil {
		return 0, err
	}
	normalized.Limits = limits
	return m.siteRepo.CreateSite(ctx, owner.ID, normalized)
}

func (m *Manager) CreateDatabase(ctx context.Context, owner auth.SessionUser, req types.CreateDatabaseReq) (int64, error) {
	if owner.Role != auth.RoleAdmin {
		return 0, ErrForbidden
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
	if err := controlquota.CheckDatabase(ctx, m.quotaStore, owner.ID); err != nil {
		return 0, err
	}
	return m.databaseRepo.CreateDatabase(ctx, owner.ID, normalized)
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
	if owner.Role != auth.RoleAdmin {
		return 0, ErrForbidden
	}
	if m.phase6Repo == nil {
		return 0, errors.New("phase6 repository is not configured")
	}
	req.Domain = site.NormalizeDomain(req.Domain)
	if err := site.ValidateDomain(req.Domain); err != nil {
		return 0, err
	}
	if err := controlquota.CheckBackup(ctx, m.quotaStore, owner.ID); err != nil {
		return 0, err
	}
	return m.phase6Repo.CreateBackup(ctx, owner.ID, req)
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

func GenerateDatabasePassword() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
