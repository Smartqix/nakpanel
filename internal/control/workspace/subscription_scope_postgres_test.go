package workspace

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nakroteck/nakpanel/internal/control/auth"
)

// Use an isolated schema, as in phpapp's PostgreSQL state tests. Only local
// databases are eligible; this test never contacts a remote database host.
func subscriptionScopePostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("NAKPANEL_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Skip("PostgreSQL test configuration unavailable")
	}
	if config.Host != "localhost" && config.Host != "127.0.0.1" && config.Host != "::1" && !strings.HasPrefix(config.Host, "/") {
		t.Skip("scope integration test requires local PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	admin := stdlib.OpenDB(*config)
	if err := admin.PingContext(ctx); err != nil {
		admin.Close()
		t.Skip("local PostgreSQL unavailable")
	}
	schema := fmt.Sprintf("navigation_services_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = schema
	config.RuntimeParams["statement_timeout"] = "750ms"
	db := stdlib.OpenDB(*config)
	t.Cleanup(func() { db.Close(); _, _ = admin.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`); admin.Close() })
	return db
}

func TestSubscriptionServicesSubscriptionAndTenantScopePostgres(t *testing.T) {
	db := subscriptionScopePostgres(t)
	// Deliberately omit unrelated inventories: the store must retain SFTP rows
	// while reporting those independent query failures, as in its SQL mock test.
	_, err := db.Exec(`
CREATE TABLE reseller_accounts(id bigint PRIMARY KEY,login_user_id bigint);
CREATE TABLE customers(id bigint PRIMARY KEY,login_user_id bigint,reseller_id bigint);
CREATE TABLE subscriptions(id bigint PRIMARY KEY,customer_id bigint);
CREATE TABLE subscription_entitlements(subscription_id bigint,hosting_policy jsonb);
CREATE TABLE subscription_policy_overrides(subscription_id bigint,policy_patch jsonb);
CREATE TABLE site_policy_overrides(site_id bigint,policy_patch jsonb);
CREATE TABLE sites(id bigint,subscription_id bigint);
CREATE TABLE subscription_system_accounts(id bigint,subscription_id bigint,username text,home_path text,linux_uid bigint,shell_mode text,desired_state text,applied_state text,convergence_status text,last_error text,migration_status text,migration_error text);
CREATE TABLE sftp_access_identities(id bigint,subscription_id bigint,name text,relative_root text,enabled boolean);
CREATE TABLE application_presets(id bigint,reseller_id bigint,slug text,name text,runtime text,image_ref text,active boolean,created_at timestamptz);
INSERT INTO reseller_accounts VALUES(1,100),(2,200);
INSERT INTO customers VALUES(10,11,1),(20,22,2);
INSERT INTO subscriptions VALUES(42,10),(43,10),(99,20);
INSERT INTO sftp_access_identities VALUES(1,42,'first','.',true),(2,43,'second','.',true),(3,99,'other tenant','.',true);
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		role     auth.Role
		user, id int64
		want     int
	}{
		{auth.RoleAdmin, 1, 42, 1}, {auth.RoleAdmin, 1, 99, 1},
		{auth.RoleReseller, 100, 42, 1}, {auth.RoleReseller, 100, 99, 0},
		{auth.RoleClient, 11, 42, 1}, {auth.RoleClient, 11, 43, 1}, {auth.RoleClient, 11, 99, 0},
	} {
		data, err := NewStore(db).ListSubscriptionServicesFor(context.Background(), auth.SessionUser{Role: tc.role, ID: tc.user}, tc.id)
		if err == nil || !strings.Contains(err.Error(), "subscription services:") {
			t.Fatalf("expected unrelated inventory errors, got %v", err)
		}
		if len(data.SFTP) != tc.want {
			t.Fatalf("%s user %d subscription %d: %#v", tc.role, tc.user, tc.id, data.SFTP)
		}
		for _, item := range data.SFTP {
			if item.SubscriptionID != tc.id {
				t.Fatalf("unscoped row: %#v", item)
			}
		}
	}
}
