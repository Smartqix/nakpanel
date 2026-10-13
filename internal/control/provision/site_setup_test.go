package provision

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestSiteSetupReportsRealConvergence(t *testing.T) {
	for _, tc := range []struct {
		name, hosting, settings, dns, tls, job, state string
		address, applied                              bool
	}{
		{"hosting pending", "pending", "in_sync", "active", "none", "running", "pending", true, true},
		{"ready", "active", "in_sync", "active", "none", "completed", "ready", true, true},
		{"tls pending", "active", "in_sync", "active", "pending", "completed", "pending", true, true},
		{"tls failed", "active", "in_sync", "active", "failed", "completed", "failed", true, true},
		{"dns unapplied", "active", "in_sync", "active", "none", "completed", "pending", true, false},
		{"dns missing", "active", "in_sync", "active", "none", "completed", "attention", false, true},
		{"dns failed", "active", "in_sync", "failed", "none", "completed", "failed", true, true},
		{"hosting failed", "failed", "in_sync", "active", "none", "retryable", "failed", true, true},
		{"dns enqueue failed", "active", "in_sync", "active", "none", "retryable", "failed", false, true},
		{"settings pending", "active", "pending", "active", "none", "completed", "pending", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			rows := sqlmock.NewRows([]string{"id", "parent", "customer", "subscription", "domain", "hosting", "desired", "settings", "tls", "zone_mode", "dns", "address", "applied", "job", "started", "parent_domain"}).AddRow(7, 1, 88, 20, "blog.example.test", tc.hosting, "active", tc.settings, tc.tls, "primary", tc.dns, tc.address, tc.applied, tc.job, time.Now(), "example.test")
			mock.ExpectQuery("SELECT site.id").WithArgs(int64(7)).WillReturnRows(rows)
			if tc.tls != "none" {
				mock.ExpectQuery("SELECT site.desired_https_redirect").WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"desired", "applied", "integrated", "job", "started"}).AddRow(false, false, false, "completed", nil))
			}
			setup, err := (&SQLSiteRepository{db: db}).ReadSiteSetup(context.Background(), 7)
			if err != nil || setup.State != tc.state {
				t.Fatalf("setup=%#v error=%v want=%s", setup, err, tc.state)
			}
			if len(setup.Steps) != 3 {
				t.Fatalf("steps=%#v", setup.Steps)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIntegratedSSLSetupRequiresCertificateAndAppliedHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name, tls, settings, cert, mode, want string
		desired, applied                      bool
	}{
		{"certificate pending", "pending", "in_sync", "scheduled", "primary", "pending", false, false},
		{"HTTPS not applied", "active", "in_sync", "completed", "primary", "pending", true, false},
		{"HTTPS job pending", "active", "pending", "completed", "primary", "pending", true, true},
		{"fully secured", "active", "in_sync", "completed", "primary", "ready", true, true},
		{"durable after job cleanup", "active", "in_sync", "", "primary", "ready", true, true},
		{"HTTPS failure", "active", "failed", "completed", "primary", "failed", true, false},
		{"external DNS HTTPS pending", "active", "in_sync", "completed", "external", "pending", true, false},
		{"external DNS secured", "active", "in_sync", "completed", "external", "ready", true, true},
		{"certificate cancelled", "pending", "in_sync", "cancelled", "primary", "failed", false, false},
		{"HTTPS recovery cancelled", "active", "in_sync", "cancelled", "primary", "failed", true, false},
		{"HTTPS recovery discarded", "active", "pending", "discarded", "primary", "failed", true, false},
		{"secured despite terminal history", "active", "in_sync", "cancelled", "primary", "ready", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, _ := sqlmock.New()
			defer db.Close()
			mock.ExpectQuery("SELECT site.id").WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"id", "parent", "customer", "subscription", "domain", "hosting", "desired", "settings", "tls", "mode", "dns", "address", "applied", "job", "started", "parentDomain"}).AddRow(7, 0, 88, 20, "example.test", "active", "active", tc.settings, tc.tls, tc.mode, "active", true, true, "completed", time.Now(), ""))
			mock.ExpectQuery("SELECT site.desired_https_redirect").WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"desired", "applied", "integrated", "job", "started"}).AddRow(tc.desired, tc.applied, true, tc.cert, nil))
			status, err := (&SQLSiteRepository{db: db}).ReadSiteSetup(context.Background(), 7)
			if err != nil || status.State != tc.want || !status.SSLRequested || len(status.Steps) != 4 {
				t.Fatalf("status=%#v error=%v", status, err)
			}
			if tc.want == "ready" && status.CanRetrySSL {
				t.Fatal("secured website still offers SSL retry")
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIntegratedSSLRecoveryRemainsPendingWithoutAnotherRetry(t *testing.T) {
	for _, state := range []string{"available", "pending", "retryable", "running", "scheduled"} {
		t.Run(state, func(t *testing.T) {
			db, mock, _ := sqlmock.New()
			defer db.Close()
			retryStarted := time.Now()
			mock.ExpectQuery("SELECT site.id").WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"id", "parent", "customer", "subscription", "domain", "hosting", "desired", "settings", "tls", "mode", "dns", "address", "applied", "job", "started", "parentDomain"}).AddRow(7, 0, 88, 20, "example.test", "active", "active", "failed", "active", "primary", "active", true, true, "completed", retryStarted.Add(-24*time.Hour), ""))
			mock.ExpectQuery("SELECT site.desired_https_redirect").WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"desired", "applied", "integrated", "job", "started"}).AddRow(true, false, true, state, retryStarted))
			status, err := (&SQLSiteRepository{db: db}).ReadSiteSetup(context.Background(), 7)
			if err != nil || status.State != "pending" || status.CanRetrySSL {
				t.Fatalf("recovery status=%#v error=%v", status, err)
			}
			if !status.StartedAt.Equal(retryStarted) {
				t.Fatalf("retry timer=%v want=%v", status.StartedAt, retryStarted)
			}
		})
	}
}

type fakeSetupRepository struct {
	fakeSiteRepository
	setup   types.SiteSetupStatus
	readErr error
	retries int
}

func (r *fakeSetupRepository) RetryCreationSSL(context.Context, int64, string) (int64, error) {
	r.retries++
	return r.setup.SiteID, nil
}
func TestSSLOnlyRetryRequiresFailedIntegratedSetupAndOwnership(t *testing.T) {
	for _, tc := range []struct {
		name           string
		allowed, retry bool
		want           int
	}{{"allowed", true, true, 1}, {"not failed", true, false, 0}, {"cross tenant", false, true, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeSetupRepository{setup: types.SiteSetupStatus{SiteID: 7, SubscriptionID: 20, Domain: "example.test", CanRetrySSL: tc.retry}}
			m := NewManager(repo, WithAccessPolicy(fakeAccessPolicy{allow: tc.allowed}))
			_, err := m.RetryCreationSSLFor(context.Background(), auth.SessionUser{ID: 9, Role: auth.RoleClient}, 7)
			if repo.retries != tc.want || (tc.want == 1 && err != nil) || (tc.want == 0 && err == nil) {
				t.Fatalf("retries=%d error=%v", repo.retries, err)
			}
		})
	}
}

type rootSetupAccessPolicy struct{ fakeAccessPolicy }

func (rootSetupAccessPolicy) CanManageDomain(_ context.Context, _ auth.SessionUser, domain string) (bool, error) {
	return domain == "example.test", nil
}

func TestFailedChildSetupRemainsReadableWithinOwnedRoot(t *testing.T) {
	repo := &fakeSetupRepository{setup: types.SiteSetupStatus{SiteID: 7, ParentID: 1, ParentDomain: "example.test", SubscriptionID: 20, Domain: "blog.example.test", State: "failed"}}
	manager := NewManager(repo, WithAccessPolicy(rootSetupAccessPolicy{fakeAccessPolicy{allow: true}}))
	_, err := manager.SiteSetupStatus(context.Background(), auth.SessionUser{Role: auth.RoleClient, ID: 9}, 7)
	if err != nil {
		t.Fatalf("owned failed child setup denied: %v", err)
	}
}

func TestOwnedRootSetupCanBeReadEvenWhenHostingFailed(t *testing.T) {
	repo := &fakeSetupRepository{setup: types.SiteSetupStatus{SiteID: 7, SubscriptionID: 20, Domain: "example.test", State: "failed"}}
	manager := NewManager(repo, WithAccessPolicy(fakeAccessPolicy{allow: true}))
	setup, err := manager.SiteSetupStatus(context.Background(), auth.SessionUser{ID: 9, Role: auth.RoleClient}, 7)
	if err != nil || setup.SiteID != 7 {
		t.Fatalf("owned root result=%#v error=%v", setup, err)
	}
}

func (r *fakeSetupRepository) ReadSiteSetup(context.Context, int64) (types.SiteSetupStatus, error) {
	return r.setup, r.readErr
}

func TestSiteSetupManagerAppliesCentralOwnershipChecks(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReseller, auth.RoleClient} {
		for _, allowed := range []bool{false, true} {
			repo := &fakeSetupRepository{setup: types.SiteSetupStatus{SiteID: 7, ParentID: 1, ParentDomain: "example.test", SubscriptionID: 20, Domain: "blog.example.test"}}
			manager := NewManager(repo, WithAccessPolicy(fakeAccessPolicy{allow: allowed}))
			result, err := manager.SiteSetupStatus(context.Background(), auth.SessionUser{ID: 9, Role: role}, 7)
			if role == auth.RoleAdmin || allowed {
				if err != nil || result.SiteID != 7 {
					t.Fatalf("allowed=%v role=%s: %v %#v", allowed, role, err, result)
				}
			} else if !errors.Is(err, ErrForbidden) || result.SiteID != 0 {
				t.Fatalf("cross-tenant result=%#v error=%v", result, err)
			}
		}
	}
	repo := &fakeSetupRepository{readErr: sql.ErrNoRows}
	if _, err := NewManager(repo).SiteSetupStatus(context.Background(), auth.SessionUser{Role: auth.RoleAdmin}, 7); !errors.Is(err, ErrForbidden) {
		t.Fatalf("missing resource error=%v", err)
	}
}
