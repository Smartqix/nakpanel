package workspace

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/control/auth"
)

func TestAccessPolicyScopesClientObjects(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	store := NewStore(db)
	client := auth.SessionUser{ID: 42, Role: auth.RoleClient}

	mock.ExpectQuery("SELECT EXISTS").WithArgs(int64(9), int64(42), "client").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	ok, err := store.CanManageSubscription(context.Background(), client, 9)
	if err != nil || !ok {
		t.Fatalf("CanManageSubscription = %v, %v; want true, nil", ok, err)
	}

	mock.ExpectQuery("SELECT EXISTS").WithArgs("owned.test", int64(42), "client").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	ok, err = store.CanManageDomain(context.Background(), client, "OWNED.TEST")
	if err != nil || ok {
		t.Fatalf("CanManageDomain = %v, %v; want false, nil", ok, err)
	}

	mock.ExpectQuery("SELECT EXISTS").WithArgs("owned.test", int64(42), "client").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	ok, err = store.CanManageDNS(context.Background(), client, "OWNED.TEST")
	if err != nil || !ok {
		t.Fatalf("CanManageDNS = %v, %v; want true, nil", ok, err)
	}

	mock.ExpectQuery("SELECT EXISTS").WithArgs("owned.test", int64(42), "client").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	ok, err = store.CanManagePHP(context.Background(), client, "OWNED.TEST")
	if err != nil || ok {
		t.Fatalf("CanManagePHP = %v, %v; want false, nil", ok, err)
	}

	mock.ExpectQuery("SELECT EXISTS").WithArgs("owned.test", int64(42), "client").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	ok, err = store.CanManageTLS(context.Background(), client, "OWNED.TEST")
	if err != nil || !ok {
		t.Fatalf("CanManageTLS = %v, %v; want true, nil", ok, err)
	}

	mock.ExpectQuery("SELECT EXISTS").WithArgs(int64(81), int64(42), "client").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	ok, err = store.CanManageBackup(context.Background(), client, 81)
	if err != nil || !ok {
		t.Fatalf("CanManageBackup = %v, %v; want true, nil", ok, err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAccessPolicyAdminBypassesOwnershipLookup(t *testing.T) {
	store := NewStore(nil)
	admin := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	checks := []func() (bool, error){
		func() (bool, error) { return store.CanManageSubscription(context.Background(), admin, 99) },
		func() (bool, error) { return store.CanManageDomain(context.Background(), admin, "other.test") },
		func() (bool, error) { return store.CanManagePHP(context.Background(), admin, "other.test") },
		func() (bool, error) { return store.CanManageTLS(context.Background(), admin, "other.test") },
		func() (bool, error) { return store.CanManageBackup(context.Background(), admin, 99) },
		func() (bool, error) { return store.CanManageCustomer(context.Background(), admin, 99) },
		func() (bool, error) { return store.CanManagePlan(context.Background(), admin, 99) },
	}
	for _, check := range checks {
		ok, err := check()
		if err != nil || !ok {
			t.Fatalf("admin check = %v, %v; want true, nil", ok, err)
		}
	}
}

func TestAccessPolicyAdminDNSStillHonorsEffectiveSuspension(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewStore(db)
	mock.ExpectQuery("SELECT EXISTS").WithArgs("suspended.test").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	ok, err := store.CanManageDNS(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, "SUSPENDED.TEST")
	if err != nil || ok {
		t.Fatalf("CanManageDNS = %v, %v; want false", ok, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAccessPolicyScopesResellerCustomersAndPlans(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	store := NewStore(db)
	reseller := auth.SessionUser{ID: 51, Role: auth.RoleReseller}

	mock.ExpectQuery("SELECT EXISTS").WithArgs(int64(77), int64(51)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	ok, err := store.CanManageCustomer(context.Background(), reseller, 77)
	if err != nil || !ok {
		t.Fatalf("CanManageCustomer = %v, %v; want true", ok, err)
	}
	mock.ExpectQuery("SELECT EXISTS").WithArgs(int64(99), int64(51)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	ok, err = store.CanManagePlan(context.Background(), reseller, 99)
	if err != nil || ok {
		t.Fatalf("CanManagePlan = %v, %v; want false", ok, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSearchUsesActorRoleAndIdentity(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	store := NewStore(db)
	client := auth.SessionUser{ID: 42, Role: auth.RoleClient}
	mock.ExpectQuery(regexp.QuoteMeta("CASE WHEN site.id IS NULL THEN '/subscriptions/' || sub.id || '?tab=mail' ELSE '/sites/' || site.id || '?tab=mail' END")).WithArgs("demo", "client", int64(42), 8).
		WillReturnRows(sqlmock.NewRows([]string{"kind", "id", "label", "detail", "url"}).
			AddRow("site", int64(7), "demo.test", "active", "/sites/7").
			AddRow("mailbox", int64(8), "hello@demo.test", "Demo hosting", "/sites/7?tab=mail"))

	results, err := store.Search(context.Background(), client, " demo ", 8)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) != 2 || results[0].URL != "/sites/7" || results[1].URL != "/sites/7?tab=mail" {
		t.Fatalf("results = %#v", results)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
