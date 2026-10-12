package phpapp

import (
	"context"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestPostgresManagedSiteAcknowledgedOnlyAfterHealthyCurrentResult(t *testing.T) {
	for _, scenario := range []string{"healthy", "deployment", "pending", "site_suspended", "subscription_suspended", "customer_suspended", "provider_suspended", "provider_allocation_suspended", "ownership_changed", "application_suspended", "stale_revision"} {
		t.Run(scenario, func(t *testing.T) {
			db := phpApplicationPostgres(t)
			_, err := db.Exec(`
CREATE TABLE customers(id BIGINT PRIMARY KEY,status TEXT,reseller_id BIGINT);
CREATE TABLE subscriptions(id BIGINT PRIMARY KEY,customer_id BIGINT,status TEXT);
CREATE TABLE reseller_accounts(id BIGINT PRIMARY KEY,status TEXT);
CREATE TABLE reseller_subscriptions(reseller_id BIGINT,status TEXT);
CREATE TABLE sites(id BIGINT PRIMARY KEY,subscription_id BIGINT,desired_status TEXT,status TEXT,
 settings_status TEXT,settings_error TEXT,last_error TEXT,php_version TEXT,desired_php_version TEXT,
 https_redirect BOOLEAN,desired_https_redirect BOOLEAN,tls_status TEXT,updated_at TIMESTAMPTZ);
CREATE TABLE php_applications(id BIGINT PRIMARY KEY,site_id BIGINT,subscription_id BIGINT,
 hosting_mode TEXT,desired_state TEXT,desired_revision BIGINT,active_deployment_id BIGINT,
 observed_state TEXT,observed_message TEXT,applied_revision BIGINT,convergence_status TEXT,last_error TEXT,
 last_reconciled_at TIMESTAMPTZ,updated_at TIMESTAMPTZ,php_version TEXT);
CREATE TABLE php_workers(id BIGINT,application_id BIGINT,desired_state TEXT,observed_state TEXT,
 desired_revision BIGINT,applied_revision BIGINT,convergence_status TEXT,last_error TEXT,last_reconciled_at TIMESTAMPTZ,updated_at TIMESTAMPTZ);
CREATE TABLE notifications(dedupe_key TEXT,resolved_at TIMESTAMPTZ,updated_at TIMESTAMPTZ);
INSERT INTO customers VALUES(2,'active',NULL);
INSERT INTO subscriptions VALUES(1,2,'active');
INSERT INTO reseller_accounts VALUES(9,'active');
INSERT INTO reseller_subscriptions VALUES(9,'active');
INSERT INTO sites VALUES(3,1,'active','suspended','pending','','','8.3','8.4',false,true,'active',now());
INSERT INTO php_applications VALUES(7,3,1,'managed','active',2,11,'healthy','',1,'pending','',now(),now(),'8.4');
`)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "site_suspended":
				_, err = db.Exec(`UPDATE sites SET desired_status='suspended'`)
			case "subscription_suspended":
				_, err = db.Exec(`UPDATE subscriptions SET status='suspended'`)
			case "customer_suspended":
				_, err = db.Exec(`UPDATE customers SET status='suspended'`)
			case "provider_suspended":
				_, err = db.Exec(`UPDATE customers SET reseller_id=9; UPDATE reseller_accounts SET status='suspended'`)
			case "provider_allocation_suspended":
				_, err = db.Exec(`UPDATE customers SET reseller_id=9; UPDATE reseller_subscriptions SET status='suspended'`)
			case "ownership_changed":
				_, err = db.Exec(`UPDATE php_applications SET hosting_mode='classic'`)
			case "application_suspended":
				_, err = db.Exec(`UPDATE php_applications SET desired_state='suspended'`)
			case "stale_revision":
				_, err = db.Exec(`UPDATE php_applications SET desired_revision=3`)
			case "deployment":
				_, err = db.Exec(`ALTER TABLE php_applications ADD COLUMN previous_deployment_id BIGINT;
CREATE TABLE php_deployments(id BIGINT,application_id BIGINT,status TEXT,resolved_revision TEXT,
composer_audit JSONB,health_message TEXT,last_error TEXT,activated_at TIMESTAMPTZ,finished_at TIMESTAMPTZ);
CREATE TABLE audit_events(actor_user_id BIGINT,actor_label TEXT,customer_id BIGINT,subscription_id BIGINT,
action TEXT,target_type TEXT,target_id BIGINT,metadata JSONB);
INSERT INTO php_deployments(id,application_id,status) VALUES(11,7,'preparing');`)
			}
			if err != nil {
				t.Fatal(err)
			}
			loaded := loadedApplication{record: applicationRecord{spec: types.PHPApplicationSpec{
				ApplicationID: 7, SiteID: 3, SubscriptionID: 1, HostingMode: types.PHPHostingModeManaged, DesiredState: "active", PHPVersion: "8.4",
			}, activeDeploymentID: 11}}
			result := types.ReconcilePHPApplicationResult{ApplicationID: 7, ActiveDeploymentID: 11, ObservedState: "healthy"}
			if scenario == "pending" {
				result.ObservedState = "pending"
			}
			store := &SQLStore{db: db}
			if scenario == "deployment" {
				err = store.completeDeployment(context.Background(), DeployPHPReleaseArgs{ApplicationID: 7, DeploymentID: 11, DesiredRevision: 2}, loaded,
					types.DeployPHPReleaseResult{DeploymentID: 11, ResolvedRevision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ComposerAudit: "clean", HealthMessage: "healthy"})
			} else {
				err = store.completeReconcile(context.Background(), ReconcilePHPApplicationArgs{ApplicationID: 7, DesiredRevision: 2}, loaded, result)
			}
			if err != nil {
				t.Fatal(err)
			}
			var state, settings, version string
			if err := db.QueryRow(`SELECT status,settings_status,php_version FROM sites WHERE id=3`).Scan(&state, &settings, &version); err != nil {
				t.Fatal(err)
			}
			if scenario == "healthy" || scenario == "deployment" {
				if state != "active" || settings != "in_sync" || version != "8.4" {
					t.Fatalf("healthy owned runtime not acknowledged: %s/%s/%s", state, settings, version)
				}
			} else if state != "suspended" || settings != "pending" || version != "8.3" {
				t.Fatalf("ineligible result falsely acknowledged: %s/%s/%s", state, settings, version)
			}
		})
	}
}
