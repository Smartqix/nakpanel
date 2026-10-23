package provision

import (
	"fmt"
	"github.com/lib/pq"
	"github.com/nakroteck/nakpanel/internal/types"
	"strconv"
	"strings"
)

// Shared jobs must reload or filter current surviving intent, not be cancelled
// merely because their payload used to include a removed website.
var removalJobClassification = map[string]string{
	"dispatch_operation_events": "node",
	"create_site":               "target", "issue_cert": "target", "install_custom_cert": "target", "set_hosting_state": "target",
	"create_backup": "target", "restore_backup": "target", "configure_webmail": "target", "configure_dns_zone": "target", "create_database": "target",
	"deploy_php_release": "target", "rollback_php_release": "target", "reconcile_php_application": "target", "reconcile_php_workers": "target",
	"wordpress_operation": "target", "cleanup_wordpress_removal": "target", "converge_application": "target", "run_scheduled_task": "target", "run_staging_operation": "target",
	"generate_web_statistics": "target", "maintenance_prune_site_backups": "target", "maintenance_delete_backup": "target", "system_database_mutation": "target",
	"mail_import":      "target",
	"reconcile_system": "shared", "converge_subscription": "shared", "converge_pending_subscriptions": "shared", "configure_mail": "shared", "reconcile_applications": "shared",
	"sync_dns_template": "shared", "sync_plan_subscriptions": "shared", "sync_addon_subscriptions": "shared", "collect_subscription_usage": "shared",
	"migrate_subscription_account": "shared", "cleanup_legacy_homes": "shared", "sweep_legacy_account_cleanup": "shared", "sweep_legacy_account_migrations": "shared",
	"sweep_scheduled_tasks": "shared", "sweep_wordpress": "shared", "sweep_php_applications": "shared", "sweep_php_runtimes": "shared", "sweep_web_statistics": "shared",
	"maintenance_renew_certs": "shared", "maintenance_scheduled_backups": "shared", "maintenance_prune_backups": "shared", "maintenance_reconcile": "shared", "maintenance_mail_queue_sweep": "shared",
	"finalize_billing_account": "shared", "teardown_billing_account": "shared",
	"system_refresh_inventory": "node", "system_control_service": "node", "system_apply_fail2ban": "node", "system_stage_firewall": "node", "system_apply_updates": "node", "system_host_power": "node",
	"sweep_billing_webhooks": "node", "deliver_billing_webhook": "node", "deliver_notifications": "node", "server_backup": "node", "server_backup_prune": "node", "server_backup_sweep": "node",
	"remove_site":                 "removal",
	"sweep_site_removals":         "shared",
	"expire_mail_import_previews": "shared",
}

func TargetSiteJobScope(snapshot types.SiteRemovalSnapshot) (string, []any) {
	siteIDs := []string{}
	domains := []string{}
	resourceIDs := map[string][]string{}
	for _, site := range snapshot.Sites {
		siteIDs = append(siteIDs, strconv.FormatInt(site.SiteID, 10))
		domains = append(domains, site.Domain)
	}
	for _, item := range snapshot.Resources {
		resourceIDs[item.Kind] = append(resourceIDs[item.Kind], strconv.FormatInt(item.ID, 10))
	}
	for _, item := range snapshot.Databases {
		resourceIDs["database"] = append(resourceIDs["database"], strconv.FormatInt(item.ID, 10))
	}
	for _, item := range snapshot.Backups {
		resourceIDs["backup_proof"] = append(resourceIDs["backup_proof"], strconv.FormatInt(item.ID, 10))
		// Recovery proof can come from a surviving sibling; it is not a target.
		for _, selected := range snapshot.Sites {
			if item.SiteID == selected.SiteID {
				resourceIDs["backup"] = append(resourceIDs["backup"], strconv.FormatInt(item.ID, 10))
				break
			}
		}
	}
	args := []any{pq.Array(siteIDs), pq.Array(domains)}
	parts := []string{`(kind IN ('create_site','issue_cert','install_custom_cert','set_hosting_state','create_backup','restore_backup','generate_web_statistics','maintenance_prune_site_backups') AND args->>'site_id'=ANY($1::text[]))`,
		`(kind='mail_import' AND args->>'import_id' IN (SELECT i.id FROM mail_imports i JOIN mailboxes mb ON mb.id=i.mailbox_id JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE md.site_id::text=ANY($1::text[])))`,
		`(kind IN ('issue_cert','install_custom_cert','configure_webmail','create_backup','restore_backup','configure_dns_zone') AND args->>'domain'=ANY($2::text[]))`,
		`(kind='reconcile_system' AND CASE WHEN jsonb_typeof(args->'sites')='array' THEN jsonb_array_length(args->'sites')=1 AND args->'sites'->0->>'site_id'=ANY($1::text[]) ELSE false END)`}
	for _, rule := range []struct{ kind, field, resource string }{
		{"deploy_php_release','rollback_php_release','reconcile_php_application','reconcile_php_workers", "application_id", "php_application"},
		{"wordpress_operation','cleanup_wordpress_removal", "instance_id", "wordpress"},
		{"converge_application", "application_id", "application"},
		{"configure_webmail", "webmail_id", "webmail"},
		{"configure_dns_zone", "zone_id", "dns_zone"},
		{"create_database','system_database_mutation", "database_id", "database"},
		{"restore_backup", "backup_id", "backup"},
		{"maintenance_delete_backup", "backup_id", "backup_proof"},
		{"run_staging_operation", "operation_id", "staging"},
	} {
		values := resourceIDs[rule.resource]
		if len(values) == 0 {
			continue
		}
		args = append(args, pq.Array(values))
		parts = append(parts, fmt.Sprintf("(kind IN ('%s') AND args->>'%s'=ANY($%d::text[]))", rule.kind, rule.field, len(args)))
	}
	if values := resourceIDs["task"]; len(values) > 0 {
		args = append(args, pq.Array(values))
		parts = append(parts, fmt.Sprintf("(kind='run_scheduled_task' AND args->>'run_id' IN (SELECT id::text FROM scheduled_task_runs WHERE task_id::text=ANY($%d::text[])))", len(args)))
	}
	return "(" + strings.Join(parts, " OR ") + ")", args
}
