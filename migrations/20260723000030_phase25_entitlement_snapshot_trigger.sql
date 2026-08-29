-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION seed_subscription_entitlements_from_plan()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.plan_id IS NOT NULL THEN
        INSERT INTO subscription_entitlements (
            subscription_id, plan_name, disk_mb, max_sites, max_databases, bandwidth_mb,
            max_mailboxes, allow_ssh, allow_dns, backup_retention_days, php_allowlist,
            php_fpm_max_children, php_memory_mb, site_disk_quota_mb, max_backups,
            backup_storage_mb, source_revision, overuse_policy, disk_warning_percent,
            traffic_warning_percent, max_subdomains, max_domain_aliases, max_ftp_accounts,
            validity_days, hosting_enabled, default_php_version, allow_tls, allow_backups,
            allow_php_settings, service_presets, hosting_policy
        )
        SELECT NEW.id, p.name, p.disk_mb, p.max_sites, p.max_databases, p.bandwidth_mb,
               p.max_mailboxes, p.allow_ssh, p.allow_dns, p.backup_retention_days,
               p.php_allowlist, p.php_fpm_max_children, p.php_memory_mb,
               p.site_disk_quota_mb, p.max_backups, p.backup_storage_mb, p.revision,
               p.overuse_policy, p.disk_warning_percent, p.traffic_warning_percent,
               p.max_subdomains, p.max_domain_aliases, p.max_ftp_accounts,
               p.validity_days, p.hosting_enabled, p.default_php_version,
               p.allow_tls, p.allow_backups, p.allow_php_settings,
               jsonb_build_object(
                   'schema_version', COALESCE(ps.schema_version, 1),
                   'hosting', COALESCE(ps.hosting, '{}'::jsonb),
                   'php', COALESCE(ps.php, '{}'::jsonb),
                   'mail', COALESCE(ps.mail, '{}'::jsonb),
                   'dns', COALESCE(ps.dns, '{}'::jsonb),
                   'performance', COALESCE(ps.performance, '{}'::jsonb),
                   'logs', COALESCE(ps.logs, '{}'::jsonb),
                   'applications', COALESCE(ps.applications, '{}'::jsonb)
               ),
               p.hosting_policy
        FROM plans p
        LEFT JOIN plan_service_presets ps ON ps.plan_id = p.id
        WHERE p.id = NEW.plan_id
        ON CONFLICT (subscription_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TABLE phase25_entitlement_snapshot_backup (
    subscription_id BIGINT PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
    hosting_policy JSONB NOT NULL
);

INSERT INTO phase25_entitlement_snapshot_backup(subscription_id,hosting_policy)
SELECT entitlement.subscription_id,entitlement.hosting_policy
FROM subscription_entitlements entitlement
JOIN subscriptions subscription ON subscription.id=entitlement.subscription_id
WHERE subscription.sync_mode='synced'
  AND entitlement.hosting_policy='{"schema_version":1}'::jsonb;

UPDATE subscription_entitlements entitlement
SET hosting_policy = plan.hosting_policy
FROM subscriptions subscription
JOIN plans plan ON plan.id = subscription.plan_id
WHERE entitlement.subscription_id = subscription.id
  AND subscription.sync_mode = 'synced'
  AND entitlement.hosting_policy = '{"schema_version":1}'::jsonb;

-- +goose Down
UPDATE subscription_entitlements entitlement
SET hosting_policy=backup.hosting_policy
FROM phase25_entitlement_snapshot_backup backup
WHERE entitlement.subscription_id=backup.subscription_id;

DROP TABLE phase25_entitlement_snapshot_backup;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION seed_subscription_entitlements_from_plan()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.plan_id IS NOT NULL THEN
        INSERT INTO subscription_entitlements (
            subscription_id, plan_name, disk_mb, max_sites, max_databases, bandwidth_mb,
            max_mailboxes, allow_ssh, allow_dns, backup_retention_days, php_allowlist,
            php_fpm_max_children, php_memory_mb, site_disk_quota_mb, max_backups,
            backup_storage_mb, source_revision, overuse_policy, disk_warning_percent,
            traffic_warning_percent, max_subdomains, max_domain_aliases, max_ftp_accounts,
            validity_days, hosting_enabled, default_php_version, allow_tls, allow_backups,
            allow_php_settings, service_presets
        )
        SELECT NEW.id, p.name, p.disk_mb, p.max_sites, p.max_databases, p.bandwidth_mb,
               p.max_mailboxes, p.allow_ssh, p.allow_dns, p.backup_retention_days,
               p.php_allowlist, p.php_fpm_max_children, p.php_memory_mb,
               p.site_disk_quota_mb, p.max_backups, p.backup_storage_mb, p.revision,
               p.overuse_policy, p.disk_warning_percent, p.traffic_warning_percent,
               p.max_subdomains, p.max_domain_aliases, p.max_ftp_accounts,
               p.validity_days, p.hosting_enabled, p.default_php_version,
               p.allow_tls, p.allow_backups, p.allow_php_settings,
               jsonb_build_object(
                   'schema_version', COALESCE(ps.schema_version, 1),
                   'hosting', COALESCE(ps.hosting, '{}'::jsonb),
                   'php', COALESCE(ps.php, '{}'::jsonb),
                   'mail', COALESCE(ps.mail, '{}'::jsonb),
                   'dns', COALESCE(ps.dns, '{}'::jsonb),
                   'performance', COALESCE(ps.performance, '{}'::jsonb),
                   'logs', COALESCE(ps.logs, '{}'::jsonb),
                   'applications', COALESCE(ps.applications, '{}'::jsonb)
               )
        FROM plans p
        LEFT JOIN plan_service_presets ps ON ps.plan_id = p.id
        WHERE p.id = NEW.plan_id
        ON CONFLICT (subscription_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
