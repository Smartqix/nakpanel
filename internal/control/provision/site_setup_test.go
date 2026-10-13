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

type fakeSetupRepository struct {
	fakeSiteRepository
	setup   types.SiteSetupStatus
	readErr error
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
