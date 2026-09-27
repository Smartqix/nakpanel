package wordpress

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeAccess struct{ allowed bool }

func (a fakeAccess) CanManageDomain(context.Context, auth.SessionUser, string) (bool, error) {
	return a.allowed, nil
}

func (a fakeAccess) CanManageSubscription(context.Context, auth.SessionUser, int64) (bool, error) {
	return a.allowed, nil
}

type fakeStore struct {
	site                  SiteIdentity
	workspace             Workspace
	preflightErr          error
	preflightCalls        int
	reserveErr            error
	operationErr          error
	reserveCalls          int
	operationCalls        int
	completeCalls         int
	failCalls             int
	backupAttachedCalls   int
	detachCalls           int
	reserveUninstallCalls int
	failUninstallCalls    int
	uninstallInstance     Instance
	uninstallOperation    Operation
}

func (s *fakeStore) PreflightNewSite(context.Context, int64) error {
	s.preflightCalls++
	return s.preflightErr
}

func TestPreflightNewSiteChecksOwnershipBeforeEntitlement(t *testing.T) {
	store := &fakeStore{}
	manager := NewManager(store, fakeAccess{allowed: false}, nil)
	if err := manager.PreflightNewSite(context.Background(), auth.SessionUser{ID: 7}, 21); !errors.Is(err, ErrNotFound) {
		t.Fatalf("PreflightNewSite = %v, want not found", err)
	}
	if store.preflightCalls != 0 {
		t.Fatalf("entitlement checked for another customer's subscription")
	}

	store.preflightErr = ErrLimitReached
	manager = NewManager(store, fakeAccess{allowed: true}, nil)
	if err := manager.PreflightNewSite(context.Background(), auth.SessionUser{ID: 7}, 21); !errors.Is(err, ErrLimitReached) {
		t.Fatalf("PreflightNewSite = %v, want limit reached", err)
	}
}

func (s *fakeStore) SiteIdentity(context.Context, int64) (SiteIdentity, error) { return s.site, nil }
func (s *fakeStore) Workspace(context.Context, int64) (Workspace, error)       { return s.workspace, nil }
func (s *fakeStore) ReserveInstall(context.Context, int64, SiteIdentity, InstallInput) (Instance, Operation, error) {
	s.reserveCalls++
	return Instance{ID: 3, SubscriptionID: s.site.SubscriptionID, SiteID: s.site.SiteID}, Operation{ID: 4}, s.reserveErr
}
func (s *fakeStore) CompleteInstallReservation(context.Context, int64, int64, int64, string) error {
	s.completeCalls++
	return nil
}
func (s *fakeStore) FailReservation(context.Context, int64, int64, error) error {
	s.failCalls++
	return nil
}
func (s *fakeStore) ReserveOperation(context.Context, int64, SiteIdentity, OperationInput) (Instance, Operation, error) {
	s.operationCalls++
	return Instance{ID: 3, SubscriptionID: s.site.SubscriptionID, SiteID: s.site.SiteID}, Operation{ID: 5}, s.operationErr
}
func (s *fakeStore) AttachBackupAndEnqueue(context.Context, int64, int64) error {
	s.backupAttachedCalls++
	return nil
}
func (s *fakeStore) Detach(context.Context, int64, SiteIdentity) error {
	s.detachCalls++
	return nil
}
func (s *fakeStore) ReserveUninstall(context.Context, auth.SessionUser, SiteIdentity, UninstallInput) (Instance, Operation, error) {
	s.reserveUninstallCalls++
	instance := s.uninstallInstance
	if instance.ID == 0 {
		instance = Instance{ID: 3, SubscriptionID: s.site.SubscriptionID, SiteID: s.site.SiteID}
	}
	operation := s.uninstallOperation
	if operation.ID == 0 {
		operation = Operation{ID: 6, InstanceID: instance.ID, Status: "pending"}
	}
	return instance, operation, s.operationErr
}
func (s *fakeStore) FailUninstallReservation(context.Context, int64, int64, error) error {
	s.failUninstallCalls++
	return nil
}

type fakeProvisioner struct {
	databases, backups int
	backupErr          error
}

func (p *fakeProvisioner) CreateDatabaseForSubscription(context.Context, auth.SessionUser, int64, types.CreateDatabaseReq) (int64, error) {
	p.databases++
	return 9, nil
}
func (p *fakeProvisioner) CreateBackupForSubscription(context.Context, auth.SessionUser, int64, types.CreateBackupReq) (int64, error) {
	p.backups++
	return 10, p.backupErr
}

func TestInstallRejectsCrossTenantBeforeMutation(t *testing.T) {
	store := &fakeStore{site: SiteIdentity{SiteID: 1, SubscriptionID: 2, Domain: "example.test", HostingMode: types.PHPHostingModeClassic}}
	provisioner := &fakeProvisioner{}
	manager := NewManager(store, fakeAccess{allowed: false}, provisioner)
	_, _, err := manager.Install(context.Background(), auth.SessionUser{ID: 7}, 1, InstallInput{Title: "Site", AdminUser: "admin", AdminEmail: "admin@example.test", AdminPassword: "a-strong-password"})
	if !errors.Is(err, ErrNotFound) || store.reserveCalls != 0 || provisioner.databases != 0 {
		t.Fatalf("Install = %v, reserve=%d databases=%d", err, store.reserveCalls, provisioner.databases)
	}
}

func TestWordPressAuthorizationUsesDomainOwnership(t *testing.T) {
	store := &fakeStore{site: SiteIdentity{SiteID: 1, SubscriptionID: 2, Domain: "example.test", HostingMode: types.PHPHostingModeClassic}}
	manager := NewManager(store, fakeAccess{allowed: true}, &fakeProvisioner{})
	if _, err := manager.Workspace(context.Background(), auth.SessionUser{ID: 7, Role: auth.RoleClient}, 1); err != nil {
		t.Fatalf("owned WordPress workspace = %v, want access independent of PHP settings permission", err)
	}
}

func TestInstallDoesNotProvisionDatabaseWhenPolicyReservationFails(t *testing.T) {
	store := &fakeStore{site: SiteIdentity{SiteID: 1, SubscriptionID: 2, Domain: "example.test", HostingMode: types.PHPHostingModeClassic}, reserveErr: ErrDisabled}
	provisioner := &fakeProvisioner{}
	manager := NewManager(store, fakeAccess{allowed: true}, provisioner)
	_, _, err := manager.Install(context.Background(), auth.SessionUser{ID: 7}, 1, InstallInput{Title: "Site", AdminUser: "admin", AdminEmail: "admin@example.test", AdminPassword: "a-strong-password"})
	if !errors.Is(err, ErrDisabled) || provisioner.databases != 0 || store.completeCalls != 0 {
		t.Fatalf("Install = %v, databases=%d complete=%d", err, provisioner.databases, store.completeCalls)
	}
}

func TestUpdateCreatesRequiredBackupBeforeEnqueue(t *testing.T) {
	store := &fakeStore{site: SiteIdentity{SiteID: 1, SubscriptionID: 2, Domain: "example.test", Username: "npuser", HostingMode: types.PHPHostingModeClassic}}
	provisioner := &fakeProvisioner{}
	manager := NewManager(store, fakeAccess{allowed: true}, provisioner)
	_, err := manager.QueueOperation(context.Background(), auth.SessionUser{ID: 7}, 1, OperationInput{Action: types.WordPressActionUpdate, TargetType: types.WordPressTargetAll})
	if err != nil {
		t.Fatal(err)
	}
	if provisioner.backups != 1 || store.backupAttachedCalls != 1 {
		t.Fatalf("backups=%d attached=%d", provisioner.backups, store.backupAttachedCalls)
	}
}

func TestFailedDiscoveryReservationCanBeReusedForInstall(t *testing.T) {
	failedDiscovery := Instance{ID: 12, SubscriptionID: 2, SiteID: 1, DesiredState: "present", ObservedState: "failed", ConvergenceStatus: "failed"}
	if !reusableForInstall(failedDiscovery) {
		t.Fatalf("failed discovery should be reusable: %#v", failedDiscovery)
	}
	failedBeforeDatabase := failedDiscovery
	failedBeforeDatabase.AdminUser = "siteadmin"
	if !reusableForInstall(failedBeforeDatabase) {
		t.Fatalf("failed install before database assignment should be reusable: %#v", failedBeforeDatabase)
	}
	for _, installed := range []Instance{
		{ID: 12, DatabaseID: 4, InstalledVersion: "7.1"},
		{ID: 12, DatabaseID: 4, ObservedState: "failed", ConvergenceStatus: "failed"},
		{ID: 12, InstalledVersion: "7.1", ObservedState: "failed", ConvergenceStatus: "failed"},
		{ID: 12, ObservedState: "pending", ConvergenceStatus: "pending"},
	} {
		if reusableForInstall(installed) {
			t.Fatalf("configured WordPress instance was reusable: %#v", installed)
		}
	}
	removed := Instance{ID: 12, DesiredState: "absent", ObservedState: "removed", ConvergenceStatus: "in_sync"}
	if !reusableForInstall(removed) || hiddenFailedReservation(removed) {
		t.Fatalf("removed tombstone should be visible and reusable: %#v", removed)
	}
}

func TestFailedInstallWithDatabaseCanOnlyUseCredentialFreeRetry(t *testing.T) {
	failed := Instance{ID: 12, DatabaseID: 4, AdminUser: "siteadmin", ObservedState: "failed", ConvergenceStatus: "failed"}
	if !retryableInstall(failed) {
		t.Fatalf("failed provisioned install should be retryable: %#v", failed)
	}
	for _, blocked := range []Instance{
		{ID: 12, DatabaseID: 0, ObservedState: "failed", ConvergenceStatus: "failed"},
		{ID: 12, DatabaseID: 4, InstalledVersion: "7.1", ObservedState: "failed", ConvergenceStatus: "failed"},
		{ID: 12, DatabaseID: 4, ObservedState: "healthy", ConvergenceStatus: "in_sync"},
	} {
		if retryableInstall(blocked) {
			t.Fatalf("unsafe install retry accepted: %#v", blocked)
		}
	}

	input, err := normalizeOperation(OperationInput{Action: types.WordPressActionInstall})
	if err != nil || input.AdminPassword != "" {
		t.Fatalf("credential-free install retry = %#v, %v", input, err)
	}
	if _, err = normalizeOperation(OperationInput{Action: types.WordPressActionInstall, AdminPassword: "browser-secret-must-not-be-used"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("install retry accepted a browser secret: %v", err)
	}
}

func TestWordPressOperationInputRejectsInternalAndIrrelevantFields(t *testing.T) {
	invalid := []OperationInput{
		{Action: types.WordPressActionInspect},
		{Action: types.WordPressActionRefresh, AdminPassword: "must-not-be-accepted"},
		{Action: types.WordPressActionVerify, RequestedVersion: "7.1"},
		{Action: types.WordPressActionMaintenance, TargetType: types.WordPressTargetCore},
		{Action: types.WordPressActionUpdate, TargetType: types.WordPressTargetCore, TargetSlug: "akismet"},
		{Action: types.WordPressActionUpdate, TargetType: types.WordPressTargetAll, AdminPassword: "must-not-be-accepted"},
		{Action: types.WordPressActionPasswordReset, AdminPassword: "a-strong-password", TargetSlug: "admin"},
	}
	for _, input := range invalid {
		if _, err := normalizeOperation(input); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("normalizeOperation(%#v) = %v, want ErrInvalidInput", input, err)
		}
	}
	valid := []OperationInput{
		{Action: types.WordPressActionRefresh},
		{Action: types.WordPressActionMaintenance, Maintenance: true},
		{Action: types.WordPressActionUpdate, TargetType: types.WordPressTargetPlugin, TargetSlug: "akismet"},
		{Action: types.WordPressActionPasswordReset, AdminPassword: "a-strong-password"},
	}
	for _, input := range valid {
		if _, err := normalizeOperation(input); err != nil {
			t.Errorf("normalizeOperation(%#v) = %v", input, err)
		}
	}
}

func TestDetachAuthorizesBeforeRemovingTracking(t *testing.T) {
	store := &fakeStore{site: SiteIdentity{SiteID: 1, SubscriptionID: 2, Domain: "example.test", HostingMode: types.PHPHostingModeClassic}}
	manager := NewManager(store, fakeAccess{allowed: false}, &fakeProvisioner{})
	if err := manager.Detach(context.Background(), auth.SessionUser{ID: 7}, 1); !errors.Is(err, ErrNotFound) || store.detachCalls != 0 {
		t.Fatalf("cross-tenant detach = %v, calls=%d", err, store.detachCalls)
	}
	manager = NewManager(store, fakeAccess{allowed: true}, &fakeProvisioner{})
	if err := manager.Detach(context.Background(), auth.SessionUser{ID: 7}, 1); err != nil || store.detachCalls != 1 {
		t.Fatalf("authorized detach = %v, calls=%d", err, store.detachCalls)
	}
}

func TestUninstallRequiresExactDomainConfirmation(t *testing.T) {
	store := &fakeStore{site: SiteIdentity{SiteID: 7, SubscriptionID: 3, Domain: "example.test"}}
	manager := NewManager(store, fakeAccess{allowed: true}, &fakeProvisioner{})
	for _, confirmation := range []string{"", "EXAMPLE.TEST", "https://example.test", "example.test/"} {
		_, err := manager.Uninstall(context.Background(), auth.SessionUser{ID: 4, Role: auth.RoleAdmin}, 7, UninstallInput{
			CreateBackup: true, ConfirmDomain: confirmation,
		})
		if !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("confirmation %q = %v, want ErrInvalidInput", confirmation, err)
		}
	}
	if store.reserveUninstallCalls != 0 {
		t.Fatalf("unsafe confirmation reserved uninstall %d times", store.reserveUninstallCalls)
	}
}

func TestUninstallRequiresBackupForManagedDatabaseRemoval(t *testing.T) {
	store := &fakeStore{site: SiteIdentity{SiteID: 7, SubscriptionID: 3, Domain: "example.test"}}
	manager := NewManager(store, fakeAccess{allowed: true}, &fakeProvisioner{})
	_, err := manager.Uninstall(context.Background(), auth.SessionUser{ID: 4, Role: auth.RoleAdmin}, 7, UninstallInput{
		DeleteDatabase: true, ConfirmDomain: "example.test",
	})
	if !errors.Is(err, ErrInvalidInput) || store.reserveUninstallCalls != 0 {
		t.Fatalf("unsafe uninstall reserved: err=%v calls=%d", err, store.reserveUninstallCalls)
	}
}

func TestUninstallRejectsCrossTenantBeforeReservation(t *testing.T) {
	store := &fakeStore{site: SiteIdentity{SiteID: 7, SubscriptionID: 3, Domain: "example.test"}}
	manager := NewManager(store, fakeAccess{allowed: false}, &fakeProvisioner{})
	_, err := manager.Uninstall(context.Background(), auth.SessionUser{ID: 4, Role: auth.RoleAdmin}, 7, UninstallInput{
		CreateBackup: true, ConfirmDomain: "example.test",
	})
	if !errors.Is(err, ErrNotFound) || store.reserveUninstallCalls != 0 {
		t.Fatalf("cross-tenant uninstall = %v, reservations=%d", err, store.reserveUninstallCalls)
	}
}

func TestUninstallCreatesBackupAndAttachesIt(t *testing.T) {
	store := &fakeStore{site: SiteIdentity{SiteID: 7, SubscriptionID: 3, Domain: "example.test", Username: "npdemo"}}
	provisioner := &fakeProvisioner{}
	manager := NewManager(store, fakeAccess{allowed: true}, provisioner)
	operation, err := manager.Uninstall(context.Background(), auth.SessionUser{ID: 4, Role: auth.RoleAdmin}, 7, UninstallInput{
		CreateBackup: true, DeleteDatabase: true, ConfirmDomain: "example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if provisioner.backups != 1 || store.backupAttachedCalls != 1 || operation.BackupID != 10 || operation.Status != "waiting_backup" {
		t.Fatalf("operation=%#v backups=%d attached=%d", operation, provisioner.backups, store.backupAttachedCalls)
	}
}

func TestUninstallBackupFailureRestoresReservation(t *testing.T) {
	store := &fakeStore{site: SiteIdentity{SiteID: 7, SubscriptionID: 3, Domain: "example.test", Username: "npdemo"}}
	provisioner := &fakeProvisioner{backupErr: errors.New("backup unavailable")}
	manager := NewManager(store, fakeAccess{allowed: true}, provisioner)
	_, err := manager.Uninstall(context.Background(), auth.SessionUser{ID: 4, Role: auth.RoleAdmin}, 7, UninstallInput{
		CreateBackup: true, ConfirmDomain: "example.test",
	})
	if err == nil || store.failUninstallCalls != 1 || store.backupAttachedCalls != 0 {
		t.Fatalf("uninstall=%v rollback=%d attached=%d", err, store.failUninstallCalls, store.backupAttachedCalls)
	}
}
