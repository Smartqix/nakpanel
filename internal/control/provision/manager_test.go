package provision

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeSiteRepository struct {
	ownerID int64
	req     types.CreateSiteReq
	err     error
}

func (r *fakeSiteRepository) CreateSite(ctx context.Context, ownerID int64, req types.CreateSiteReq) (int64, error) {
	r.ownerID = ownerID
	r.req = req
	if r.err != nil {
		return 0, r.err
	}
	return 7, nil
}

type fakeDatabaseRepository struct {
	ownerID int64
	req     types.CreateDatabaseReq
	err     error
}

func (r *fakeDatabaseRepository) CreateDatabase(ctx context.Context, ownerID int64, req types.CreateDatabaseReq) (int64, error) {
	r.ownerID = ownerID
	r.req = req
	if r.err != nil {
		return 0, r.err
	}
	return 11, nil
}

type fakeCertificateRepository struct {
	ownerID int64
	domain  string
	issuer  types.CertIssuer
	err     error
}

func (r *fakeCertificateRepository) IssueCertificate(ctx context.Context, ownerID int64, domain string, issuer types.CertIssuer) (int64, error) {
	r.ownerID = ownerID
	r.domain = domain
	r.issuer = issuer
	if r.err != nil {
		return 0, r.err
	}
	return 7, nil
}

func TestManagerRejectsNonAdminSiteCreation(t *testing.T) {
	repo := &fakeSiteRepository{}
	manager := NewManager(repo)

	_, err := manager.CreateSite(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, types.CreateSiteReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
	})

	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("CreateSite error = %v, want ErrForbidden", err)
	}
	if repo.req != (types.CreateSiteReq{}) {
		t.Fatalf("repository was called for non-admin: %#v", repo.req)
	}
}

func TestManagerNormalizesSiteIntent(t *testing.T) {
	repo := &fakeSiteRepository{}
	manager := NewManager(repo)

	siteID, err := manager.CreateSite(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, types.CreateSiteReq{
		Username:   "  NpDemo  ",
		Domain:     "  EXAMPLE.TEST. ",
		PHPVersion: " 8.3 ",
	})
	if err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}
	if siteID != 7 {
		t.Fatalf("siteID = %d, want 7", siteID)
	}
	if repo.ownerID != 1 {
		t.Fatalf("ownerID = %d, want 1", repo.ownerID)
	}
	want := types.CreateSiteReq{Username: "npdemo", Domain: "example.test", PHPVersion: "8.3"}
	if repo.req != want {
		t.Fatalf("repository request = %#v, want %#v", repo.req, want)
	}
}

func TestManagerRejectsInvalidSiteIntent(t *testing.T) {
	repo := &fakeSiteRepository{}
	manager := NewManager(repo)

	_, err := manager.CreateSite(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, types.CreateSiteReq{
		Username:   "../root",
		Domain:     "example.test",
		PHPVersion: "8.3",
	})
	if err == nil {
		t.Fatal("CreateSite returned nil error")
	}
	if repo.req != (types.CreateSiteReq{}) {
		t.Fatalf("repository was called for invalid intent: %#v", repo.req)
	}
}

func TestManagerRejectsNonAdminDatabaseCreation(t *testing.T) {
	repo := &fakeDatabaseRepository{}
	manager := NewManager(nil, WithDatabaseRepository(repo), WithPasswordGenerator(func() (string, error) {
		return "generated-password", nil
	}))

	_, err := manager.CreateDatabase(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, types.CreateDatabaseReq{
		Engine: types.EngineMariaDB,
		DBName: "np_demo",
		DBUser: "np_demo_user",
	})

	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("CreateDatabase error = %v, want ErrForbidden", err)
	}
	if repo.req != (types.CreateDatabaseReq{}) {
		t.Fatalf("repository was called for non-admin: %#v", repo.req)
	}
}

func TestManagerNormalizesDatabaseIntentAndGeneratesPassword(t *testing.T) {
	repo := &fakeDatabaseRepository{}
	manager := NewManager(nil, WithDatabaseRepository(repo), WithPasswordGenerator(func() (string, error) {
		return "generated-password", nil
	}))

	databaseID, err := manager.CreateDatabase(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, types.CreateDatabaseReq{
		Engine: " MariaDB ",
		DBName: "  Np_Demo  ",
		DBUser: "  Np_Demo_User  ",
	})
	if err != nil {
		t.Fatalf("CreateDatabase returned error: %v", err)
	}
	if databaseID != 11 {
		t.Fatalf("databaseID = %d, want 11", databaseID)
	}
	if repo.ownerID != 1 {
		t.Fatalf("ownerID = %d, want 1", repo.ownerID)
	}
	want := types.CreateDatabaseReq{
		Engine:   types.EngineMariaDB,
		DBName:   "np_demo",
		DBUser:   "np_demo_user",
		Password: "generated-password",
	}
	if repo.req != want {
		t.Fatalf("repository request = %#v, want %#v", repo.req, want)
	}
}

func TestManagerRejectsInvalidDatabaseIntent(t *testing.T) {
	repo := &fakeDatabaseRepository{}
	manager := NewManager(nil, WithDatabaseRepository(repo), WithPasswordGenerator(func() (string, error) {
		return "generated-password", nil
	}))

	_, err := manager.CreateDatabase(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, types.CreateDatabaseReq{
		Engine: types.EngineMariaDB,
		DBName: "np-demo",
		DBUser: "np_demo_user",
	})
	if err == nil {
		t.Fatal("CreateDatabase returned nil error")
	}
	if repo.req != (types.CreateDatabaseReq{}) {
		t.Fatalf("repository was called for invalid intent: %#v", repo.req)
	}
}

func TestManagerRejectsNonAdminCertificateIssue(t *testing.T) {
	repo := &fakeCertificateRepository{}
	manager := NewManager(nil, WithCertificateRepository(repo))

	_, err := manager.IssueCertificate(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, "example.test", types.CertIssuerLocalSelfSigned)

	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("IssueCertificate error = %v, want ErrForbidden", err)
	}
	if repo.domain != "" {
		t.Fatalf("repository was called for non-admin: %#v", repo)
	}
}

func TestManagerNormalizesCertificateIntent(t *testing.T) {
	repo := &fakeCertificateRepository{}
	manager := NewManager(nil, WithCertificateRepository(repo))

	siteID, err := manager.IssueCertificate(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, " EXAMPLE.TEST. ", "")
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	if siteID != 7 {
		t.Fatalf("siteID = %d, want 7", siteID)
	}
	if repo.ownerID != 1 {
		t.Fatalf("ownerID = %d, want 1", repo.ownerID)
	}
	if repo.domain != "example.test" {
		t.Fatalf("domain = %q, want example.test", repo.domain)
	}
	if repo.issuer != types.CertIssuerLocalSelfSigned {
		t.Fatalf("issuer = %q, want local self-signed", repo.issuer)
	}
}

func TestManagerRejectsInvalidCertificateIntent(t *testing.T) {
	repo := &fakeCertificateRepository{}
	manager := NewManager(nil, WithCertificateRepository(repo))

	_, err := manager.IssueCertificate(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, "example.test;reboot", types.CertIssuerLocalSelfSigned)
	if err == nil {
		t.Fatal("IssueCertificate returned nil error")
	}
	if repo.domain != "" {
		t.Fatalf("repository was called for invalid intent: %#v", repo)
	}
}

func TestManagerAcceptsACMECertificateIntent(t *testing.T) {
	repo := &fakeCertificateRepository{}
	manager := NewManager(nil, WithCertificateRepository(repo))

	siteID, err := manager.IssueCertificate(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, "example.test", types.CertIssuerACME)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	if siteID != 7 {
		t.Fatalf("siteID = %d, want 7", siteID)
	}
	if repo.domain != "example.test" || repo.issuer != types.CertIssuerACME {
		t.Fatalf("repository request = %#v, want ACME example.test", repo)
	}
}
