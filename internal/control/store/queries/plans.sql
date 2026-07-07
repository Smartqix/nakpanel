-- name: ListPlans :many
SELECT id, name, description, price_cents, disk_mb, max_sites, max_databases, bandwidth_mb,
       max_mailboxes, allow_ssh, allow_dns, backup_retention_days, php_allowlist,
       php_fpm_max_children, php_memory_mb, site_disk_quota_mb, max_backups,
       backup_storage_mb, is_active, created_at, updated_at
FROM plans
ORDER BY id;

-- name: GetPlan :one
SELECT id, name, description, price_cents, disk_mb, max_sites, max_databases, bandwidth_mb,
       max_mailboxes, allow_ssh, allow_dns, backup_retention_days, php_allowlist,
       php_fpm_max_children, php_memory_mb, site_disk_quota_mb, max_backups,
       backup_storage_mb, is_active, created_at, updated_at
FROM plans
WHERE id = $1;

-- name: GetActiveSubscription :one
SELECT s.id, s.customer_user_id, s.reseller_user_id, s.plan_id, s.status, s.created_at, s.updated_at
FROM subscriptions s
WHERE s.customer_user_id = $1
  AND s.status = 'active';

-- name: ListActiveSubscriptions :many
SELECT s.id, s.customer_user_id, s.reseller_user_id, s.plan_id, s.status, s.created_at, s.updated_at
FROM subscriptions s
WHERE s.status = 'active'
ORDER BY s.customer_user_id;

-- name: GetSettings :one
SELECT id, oversell_policy, server_disk_capacity_mb, created_at, updated_at
FROM settings
WHERE id = true;
