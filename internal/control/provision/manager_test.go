package provision

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeSiteRepository struct {
	ownerID int64
	req     types.CreateSiteReq
	err     error
}

type fakeRuntimeCapabilities struct {
	result types.RuntimeCapabilities
	err    error
}

type fakeDomainSettingsStore struct {
	controlquota.Store
	domain string
	req    types.UpdateSiteSettingsReq
}

func (s *fakeDomainSettingsStore) SiteDomain(context.Context, int64) (string, error) {
	return s.domain, nil
}

func (s *fakeDomainSettingsStore) UpdateSiteSettings(_ context.Context, req types.UpdateSiteSettingsReq) error {
	s.req = req
	return nil
}

type capabilityAccessPolicy struct {
	fakeAccessPolicy
	php bool
	tls bool
}

func (p capabilityAccessPolicy) CanManagePHP(context.Context, auth.SessionUser, string) (bool, error) {
	return p.php, nil
}

func (p capabilityAccessPolicy) CanManageTLS(context.Context, auth.SessionUser, string) (bool, error) {
	return p.tls, nil
}

func (f fakeRuntimeCapabilities) RuntimeCapabilities(context.Context) (types.RuntimeCapabilities, error) {
	return f.result, f.err
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

type fakeAccessPolicy struct {
	allow bool
}

type selectiveBulkAccessPolicy struct {
	fakeAccessPolicy
	deniedCustomerID     int64
	deniedSubscriptionID int64
}

func (p selectiveBulkAccessPolicy) CanManageCustomer(_ context.Context, _ auth.SessionUser, id int64) (bool, error) {
	return id != p.deniedCustomerID, nil
}

func (p selectiveBulkAccessPolicy) CanManageSubscription(_ context.Context, _ auth.SessionUser, id int64) (bool, error) {
	return id != p.deniedSubscriptionID, nil
}

type fakeBulkAdminStore struct {
	controlquota.AdminStore
	customerIDs     []int64
	subscriptionIDs []int64
	resellerIDs     []int64
}

func (s *fakeBulkAdminStore) SetCustomerStatuses(_ context.Context, ids []int64, _ string) error {
	s.customerIDs = append([]int64(nil), ids...)
	return nil
}

func (s *fakeBulkAdminStore) SetSubscriptionStatuses(_ context.Context, ids []int64, _ string) error {
	s.subscriptionIDs = append([]int64(nil), ids...)
	return nil
}

func (s *fakeBulkAdminStore) SetResellerStatuses(_ context.Context, ids []int64, _ string) error {
	s.resellerIDs = append([]int64(nil), ids...)
	return nil
}

func (p fakeAccessPolicy) CanManageSubscription(context.Context, auth.SessionUser, int64) (bool, error) {
	return p.allow, nil
}
func (p fakeAccessPolicy) CanManageDomain(context.Context, auth.SessionUser, string) (bool, error) {
	return p.allow, nil
}
func (p fakeAccessPolicy) CanManageDNS(context.Context, auth.SessionUser, string) (bool, error) {
	return p.allow, nil
}
func (p fakeAccessPolicy) CanManagePHP(context.Context, auth.SessionUser, string) (bool, error) {
	return p.allow, nil
}
func (p fakeAccessPolicy) CanManageTLS(context.Context, auth.SessionUser, string) (bool, error) {
	return p.allow, nil
}
func (p fakeAccessPolicy) CanManageBackup(context.Context, auth.SessionUser, int64) (bool, error) {
	return p.allow, nil
}
func (p fakeAccessPolicy) CanManageCustomer(context.Context, auth.SessionUser, int64) (bool, error) {
	return p.allow, nil
}
func (p fakeAccessPolicy) CanManagePlan(context.Context, auth.SessionUser, int64) (bool, error) {
	return p.allow, nil
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

func TestBulkLifecyclePreauthorizesEveryProviderObject(t *testing.T) {
	store := &fakeBulkAdminStore{}
	manager := NewManager(nil,
		WithQuotaStore(store),
		WithAccessPolicy(selectiveBulkAccessPolicy{
			fakeAccessPolicy:     fakeAccessPolicy{allow: true},
			deniedCustomerID:     8,
			deniedSubscriptionID: 18,
		}),
	)
	reseller := auth.SessionUser{ID: 3, Role: auth.RoleReseller}

	if err := manager.SetCustomerStatuses(context.Background(), reseller, []int64{7, 8}, "suspended"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("SetCustomerStatuses error = %v, want ErrForbidden", err)
	}
	if len(store.customerIDs) != 0 {
		t.Fatalf("customer bulk store called before full authorization: %v", store.customerIDs)
	}

	if err := manager.SetSubscriptionStatuses(context.Background(), reseller, []int64{17, 18}, "suspended"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("SetSubscriptionStatuses error = %v, want ErrForbidden", err)
	}
	if len(store.subscriptionIDs) != 0 {
		t.Fatalf("subscription bulk store called before full authorization: %v", store.subscriptionIDs)
	}

	if _, err := manager.CreateSubscription(context.Background(), reseller, types.CreateSubscriptionReq{ID: 18, CustomerID: 7, PlanID: 10}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("CreateSubscription foreign update error = %v, want ErrForbidden", err)
	}
	if _, err := manager.AssignSubscription(context.Background(), reseller, 42, 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("legacy AssignSubscription as reseller error = %v, want ErrForbidden", err)
	}
}

func TestClientCannotMutateSubscriptionEntitlements(t *testing.T) {
	manager := NewManager(nil,
		WithQuotaStore(&fakeBulkAdminStore{}),
		WithAccessPolicy(fakeAccessPolicy{allow: true}),
	)
	client := auth.SessionUser{ID: 9, Role: auth.RoleClient}

	checks := []error{
		manager.SetSubscriptionAddons(context.Background(), client, 11, []int64{1}),
		manager.SyncSubscription(context.Background(), client, 11),
		manager.SetSubscriptionMode(context.Background(), client, 11, "custom", types.SubscriptionEntitlements{}),
	}
	for _, err := range checks {
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("subscription entitlement mutation error = %v, want ErrForbidden", err)
		}
	}
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

func TestManagerAllowsClientSiteCreationOnlyForOwnedSubscription(t *testing.T) {
	client := auth.SessionUser{ID: 22, Role: auth.RoleClient}
	request := types.CreateSiteReq{Username: "clientsite", Domain: "client.test", PHPVersion: "8.3", SubscriptionID: 44}

	deniedRepo := &fakeSiteRepository{}
	denied := NewManager(deniedRepo, WithQuotaStore(&fakeQuotaStore{hasLimits: true, limits: controlquota.Limits{MaxSites: -1, SiteDiskQuotaMB: 512, PHPFPMMaxChildren: 2, PHPMemoryMB: 128}}), WithAccessPolicy(fakeAccessPolicy{allow: false}))
	if _, err := denied.CreateSiteForSubscription(context.Background(), client, 44, request); !errors.Is(err, ErrForbidden) {
		t.Fatalf("denied CreateSiteForSubscription error = %v, want ErrForbidden", err)
	}
	if deniedRepo.req != (types.CreateSiteReq{}) {
		t.Fatalf("denied request reached repository: %#v", deniedRepo.req)
	}

	allowedRepo := &fakeSiteRepository{}
	allowed := NewManager(allowedRepo, WithQuotaStore(&fakeQuotaStore{hasLimits: true, limits: controlquota.Limits{UserID: 22, MaxSites: -1, SiteDiskQuotaMB: 512, PHPFPMMaxChildren: 2, PHPMemoryMB: 128}}), WithAccessPolicy(fakeAccessPolicy{allow: true}))
	if _, err := allowed.CreateSiteForSubscription(context.Background(), client, 44, request); err != nil {
		t.Fatalf("allowed CreateSiteForSubscription: %v", err)
	}
	if allowedRepo.req.SubscriptionID != 44 {
		t.Fatalf("repository subscription = %d, want 44", allowedRepo.req.SubscriptionID)
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

func TestManagerEnforcesDomainSettingCapabilities(t *testing.T) {
	client := auth.SessionUser{ID: 2, Role: auth.RoleClient}
	store := &fakeDomainSettingsStore{domain: "owned.test"}
	manager := NewManager(nil,
		WithQuotaStore(store),
		WithAccessPolicy(capabilityAccessPolicy{fakeAccessPolicy: fakeAccessPolicy{allow: true}}),
	)

	err := manager.UpdateSiteSettings(context.Background(), client, types.UpdateSiteSettingsReq{SiteID: 7, Section: "php", DesiredStatus: "active", DesiredPHPVersion: "8.3"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("PHP settings error = %v, want ErrForbidden", err)
	}
	err = manager.UpdateSiteSettings(context.Background(), client, types.UpdateSiteSettingsReq{SiteID: 7, Section: "hosting", DesiredStatus: "active", DesiredPHPVersion: "8.3", DesiredHTTPSRedirect: true})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("HTTPS redirect error = %v, want ErrForbidden", err)
	}
	err = manager.UpdateSiteSettings(context.Background(), client, types.UpdateSiteSettingsReq{SiteID: 7, Section: "hosting", DesiredStatus: "suspended", DesiredPHPVersion: "8.3"})
	if err != nil {
		t.Fatalf("hosting status update error = %v", err)
	}
	if store.req.DesiredStatus != "suspended" {
		t.Fatalf("stored request = %#v", store.req)
	}
}

func TestManagerEnforcesTLSCapabilityForCertificateIssue(t *testing.T) {
	repo := &fakeCertificateRepository{}
	manager := NewManager(nil,
		WithCertificateRepository(repo),
		WithAccessPolicy(capabilityAccessPolicy{fakeAccessPolicy: fakeAccessPolicy{allow: true}}),
	)

	_, err := manager.IssueCertificate(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, "owned.test", types.CertIssuerLocalSelfSigned)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("IssueCertificate error = %v, want ErrForbidden", err)
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

func TestManagerValidatesPlanPHPAgainstAgentCapabilities(t *testing.T) {
	manager := NewManager(nil, WithRuntimeCapabilities(fakeRuntimeCapabilities{result: types.RuntimeCapabilities{PHPVersions: []string{"8.3"}}}))
	if err := manager.validatePlanPHP(context.Background(), "8.3", "8.3", true); err != nil {
		t.Fatalf("installed PHP rejected: %v", err)
	}
	if err := manager.validatePlanPHP(context.Background(), "8.3,8.2", "8.3", true); err == nil {
		t.Fatal("uninstalled PHP version was accepted")
	}
}

func TestManagerFailsClosedWhenAgentCapabilitiesAreUnavailable(t *testing.T) {
	manager := NewManager(nil, WithRuntimeCapabilities(fakeRuntimeCapabilities{err: errors.New("agent offline")}))
	if err := manager.validateInstalledPHP(context.Background(), "8.3"); err == nil {
		t.Fatal("site PHP validation succeeded while the agent was unavailable")
	}
}
