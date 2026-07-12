-- +goose Up
ALTER TABLE plans DROP CONSTRAINT IF EXISTS plans_name_key;
WITH ranked AS (
    SELECT id, row_number() OVER (
        PARTITION BY COALESCE(reseller_id, 0), lower(name)
        ORDER BY id
    ) AS duplicate_number
    FROM plans
)
UPDATE plans p
SET name = p.name || ' (legacy ' || p.id || ')'
FROM ranked r
WHERE p.id = r.id AND r.duplicate_number > 1;
CREATE UNIQUE INDEX plans_provider_name_admin_idx
    ON plans (lower(name)) WHERE reseller_id IS NULL;
CREATE UNIQUE INDEX plans_provider_name_reseller_idx
    ON plans (reseller_id, lower(name)) WHERE reseller_id IS NOT NULL;

ALTER TABLE reseller_plans
    ADD COLUMN max_subdomains INTEGER NOT NULL DEFAULT 0 CHECK (max_subdomains >= -1),
    ADD COLUMN max_domain_aliases INTEGER NOT NULL DEFAULT 0 CHECK (max_domain_aliases >= -1),
    ADD COLUMN max_ftp_accounts INTEGER NOT NULL DEFAULT 0 CHECK (max_ftp_accounts >= -1),
    ADD COLUMN allow_tls BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN allow_backups BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN allow_php_settings BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE plans
    ADD COLUMN overuse_policy TEXT NOT NULL DEFAULT 'block'
        CHECK (overuse_policy IN ('block', 'normal', 'notify', 'not_suspend', 'not_suspend_notify')),
    ADD COLUMN disk_warning_percent INTEGER NOT NULL DEFAULT 80
        CHECK (disk_warning_percent BETWEEN 1 AND 100),
    ADD COLUMN traffic_warning_percent INTEGER NOT NULL DEFAULT 80
        CHECK (traffic_warning_percent BETWEEN 1 AND 100),
    ADD COLUMN max_subdomains INTEGER NOT NULL DEFAULT 0 CHECK (max_subdomains >= -1),
    ADD COLUMN max_domain_aliases INTEGER NOT NULL DEFAULT 0 CHECK (max_domain_aliases >= -1),
    ADD COLUMN max_ftp_accounts INTEGER NOT NULL DEFAULT 0 CHECK (max_ftp_accounts >= -1),
    ADD COLUMN validity_days INTEGER NOT NULL DEFAULT -1 CHECK (validity_days >= -1),
    ADD COLUMN hosting_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN default_php_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN allow_tls BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN allow_backups BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN allow_php_settings BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE plan_service_presets (
    plan_id BIGINT PRIMARY KEY REFERENCES plans(id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version > 0),
    hosting JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(hosting) = 'object'),
    php JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(php) = 'object'),
    mail JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(mail) = 'object'),
    dns JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(dns) = 'object'),
    performance JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(performance) = 'object'),
    logs JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(logs) = 'object'),
    applications JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(applications) = 'object'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO plan_service_presets (plan_id, hosting, php, dns, logs)
SELECT id,
       jsonb_build_object('web_server', 'nginx', 'preferred_domain', 'none', 'hosting_enabled', hosting_enabled),
       jsonb_build_object('default_version', COALESCE(NULLIF(default_php_version, ''), split_part(php_allowlist, ',', 1)),
                          'allowed_versions', php_allowlist, 'fpm_max_children', php_fpm_max_children,
                          'memory_limit_mb', php_memory_mb),
       jsonb_build_object('management_allowed', allow_dns, 'mode', 'primary'),
       jsonb_build_object('rotation_enabled', true, 'retention_days', 14)
FROM plans;

UPDATE plans
SET default_php_version = split_part(php_allowlist, ',', 1)
WHERE default_php_version = '' AND php_allowlist <> '';

ALTER TABLE addon_plans
    ADD COLUMN max_subdomains INTEGER NOT NULL DEFAULT 0 CHECK (max_subdomains >= -1),
    ADD COLUMN max_domain_aliases INTEGER NOT NULL DEFAULT 0 CHECK (max_domain_aliases >= -1),
    ADD COLUMN max_ftp_accounts INTEGER NOT NULL DEFAULT 0 CHECK (max_ftp_accounts >= -1),
    ADD COLUMN allow_tls BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN allow_backups BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN allow_php_settings BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN service_presets JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(service_presets) = 'object');

ALTER TABLE subscription_entitlements
    ADD COLUMN overuse_policy TEXT NOT NULL DEFAULT 'block'
        CHECK (overuse_policy IN ('block', 'normal', 'notify', 'not_suspend', 'not_suspend_notify')),
    ADD COLUMN disk_warning_percent INTEGER NOT NULL DEFAULT 80
        CHECK (disk_warning_percent BETWEEN 1 AND 100),
    ADD COLUMN traffic_warning_percent INTEGER NOT NULL DEFAULT 80
        CHECK (traffic_warning_percent BETWEEN 1 AND 100),
    ADD COLUMN max_subdomains INTEGER NOT NULL DEFAULT 0 CHECK (max_subdomains >= -1),
    ADD COLUMN max_domain_aliases INTEGER NOT NULL DEFAULT 0 CHECK (max_domain_aliases >= -1),
    ADD COLUMN max_ftp_accounts INTEGER NOT NULL DEFAULT 0 CHECK (max_ftp_accounts >= -1),
    ADD COLUMN validity_days INTEGER NOT NULL DEFAULT -1 CHECK (validity_days >= -1),
    ADD COLUMN hosting_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN default_php_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN allow_tls BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN allow_backups BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN allow_php_settings BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN service_presets JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(service_presets) = 'object');

UPDATE subscription_entitlements e
SET overuse_policy = p.overuse_policy,
    disk_warning_percent = p.disk_warning_percent,
    traffic_warning_percent = p.traffic_warning_percent,
    max_subdomains = p.max_subdomains,
    max_domain_aliases = p.max_domain_aliases,
    max_ftp_accounts = p.max_ftp_accounts,
    validity_days = p.validity_days,
    hosting_enabled = p.hosting_enabled,
    default_php_version = p.default_php_version,
    allow_tls = p.allow_tls,
    allow_backups = p.allow_backups,
    allow_php_settings = p.allow_php_settings,
    service_presets = jsonb_build_object(
        'schema_version', ps.schema_version,
        'hosting', ps.hosting,
        'php', ps.php,
        'mail', ps.mail,
        'dns', ps.dns,
        'performance', ps.performance,
        'logs', ps.logs,
        'applications', ps.applications
    )
FROM subscriptions s
JOIN plans p ON p.id = s.plan_id
LEFT JOIN plan_service_presets ps ON ps.plan_id = p.id
WHERE s.id = e.subscription_id;

ALTER TABLE subscriptions
    ADD COLUMN suspension_reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN expires_at TIMESTAMPTZ;
CREATE INDEX subscriptions_expires_at_idx ON subscriptions(expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE subscription_usage_current (
    subscription_id BIGINT PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
    period_start DATE NOT NULL,
    site_bytes BIGINT NOT NULL DEFAULT 0 CHECK (site_bytes >= 0),
    database_bytes BIGINT NOT NULL DEFAULT 0 CHECK (database_bytes >= 0),
    backup_bytes BIGINT NOT NULL DEFAULT 0 CHECK (backup_bytes >= 0),
    disk_bytes BIGINT NOT NULL DEFAULT 0 CHECK (disk_bytes >= 0),
    traffic_bytes BIGINT NOT NULL DEFAULT 0 CHECK (traffic_bytes >= 0),
    is_complete BOOLEAN NOT NULL DEFAULT false,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE subscription_usage_history (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    period_start DATE NOT NULL,
    site_bytes BIGINT NOT NULL,
    database_bytes BIGINT NOT NULL,
    backup_bytes BIGINT NOT NULL,
    disk_bytes BIGINT NOT NULL,
    traffic_bytes BIGINT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX subscription_usage_history_subscription_idx
    ON subscription_usage_history(subscription_id, recorded_at DESC);

CREATE TABLE site_traffic_cursors (
    site_id BIGINT PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    device_id BIGINT NOT NULL DEFAULT 0,
    inode BIGINT NOT NULL DEFAULT 0,
    byte_offset BIGINT NOT NULL DEFAULT 0 CHECK (byte_offset >= 0),
    period_start DATE NOT NULL,
    traffic_bytes BIGINT NOT NULL DEFAULT 0 CHECK (traffic_bytes >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE notifications (
    id BIGSERIAL PRIMARY KEY,
    recipient_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    customer_id BIGINT REFERENCES customers(id) ON DELETE CASCADE,
    reseller_id BIGINT REFERENCES reseller_accounts(id) ON DELETE CASCADE,
    subscription_id BIGINT REFERENCES subscriptions(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed')),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    read_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX notifications_open_dedupe_idx ON notifications(dedupe_key) WHERE resolved_at IS NULL;
CREATE INDEX notifications_recipient_idx ON notifications(recipient_user_id, created_at DESC);
CREATE INDEX notifications_subscription_idx ON notifications(subscription_id, created_at DESC);

CREATE TABLE notification_deliveries (
    id BIGSERIAL PRIMARY KEY,
    notification_id BIGINT NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    channel TEXT NOT NULL CHECK (channel IN ('smtp')),
    recipient TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error TEXT NOT NULL DEFAULT '',
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (notification_id, channel, recipient)
);

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

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION seed_subscription_entitlements_from_plan()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.plan_id IS NOT NULL THEN
        INSERT INTO subscription_entitlements (
            subscription_id, plan_name, disk_mb, max_sites, max_databases, bandwidth_mb,
            max_mailboxes, allow_ssh, allow_dns, backup_retention_days, php_allowlist,
            php_fpm_max_children, php_memory_mb, site_disk_quota_mb, max_backups,
            backup_storage_mb, source_revision
        )
        SELECT NEW.id, p.name, p.disk_mb, p.max_sites, p.max_databases, p.bandwidth_mb,
               p.max_mailboxes, p.allow_ssh, p.allow_dns, p.backup_retention_days,
               p.php_allowlist, p.php_fpm_max_children, p.php_memory_mb,
               p.site_disk_quota_mb, p.max_backups, p.backup_storage_mb, p.revision
        FROM plans p WHERE p.id = NEW.plan_id
        ON CONFLICT (subscription_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

DROP TABLE IF EXISTS notification_deliveries;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS site_traffic_cursors;
DROP TABLE IF EXISTS subscription_usage_history;
DROP TABLE IF EXISTS subscription_usage_current;
DROP INDEX IF EXISTS subscriptions_expires_at_idx;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS expires_at, DROP COLUMN IF EXISTS suspension_reason;

ALTER TABLE subscription_entitlements
    DROP COLUMN IF EXISTS service_presets,
    DROP COLUMN IF EXISTS allow_php_settings,
    DROP COLUMN IF EXISTS allow_backups,
    DROP COLUMN IF EXISTS allow_tls,
    DROP COLUMN IF EXISTS default_php_version,
    DROP COLUMN IF EXISTS hosting_enabled,
    DROP COLUMN IF EXISTS validity_days,
    DROP COLUMN IF EXISTS max_ftp_accounts,
    DROP COLUMN IF EXISTS max_domain_aliases,
    DROP COLUMN IF EXISTS max_subdomains,
    DROP COLUMN IF EXISTS traffic_warning_percent,
    DROP COLUMN IF EXISTS disk_warning_percent,
    DROP COLUMN IF EXISTS overuse_policy;

ALTER TABLE addon_plans
    DROP COLUMN IF EXISTS service_presets,
    DROP COLUMN IF EXISTS allow_php_settings,
    DROP COLUMN IF EXISTS allow_backups,
    DROP COLUMN IF EXISTS allow_tls,
    DROP COLUMN IF EXISTS max_ftp_accounts,
    DROP COLUMN IF EXISTS max_domain_aliases,
    DROP COLUMN IF EXISTS max_subdomains;

DROP TABLE IF EXISTS plan_service_presets;
ALTER TABLE reseller_plans
    DROP COLUMN IF EXISTS allow_php_settings,
    DROP COLUMN IF EXISTS allow_backups,
    DROP COLUMN IF EXISTS allow_tls,
    DROP COLUMN IF EXISTS max_ftp_accounts,
    DROP COLUMN IF EXISTS max_domain_aliases,
    DROP COLUMN IF EXISTS max_subdomains;
ALTER TABLE plans
    DROP COLUMN IF EXISTS allow_php_settings,
    DROP COLUMN IF EXISTS allow_backups,
    DROP COLUMN IF EXISTS allow_tls,
    DROP COLUMN IF EXISTS default_php_version,
    DROP COLUMN IF EXISTS hosting_enabled,
    DROP COLUMN IF EXISTS validity_days,
    DROP COLUMN IF EXISTS max_ftp_accounts,
    DROP COLUMN IF EXISTS max_domain_aliases,
    DROP COLUMN IF EXISTS max_subdomains,
    DROP COLUMN IF EXISTS traffic_warning_percent,
    DROP COLUMN IF EXISTS disk_warning_percent,
    DROP COLUMN IF EXISTS overuse_policy;

DROP INDEX IF EXISTS plans_provider_name_reseller_idx;
DROP INDEX IF EXISTS plans_provider_name_admin_idx;
WITH ranked AS (
    SELECT id, row_number() OVER (PARTITION BY name ORDER BY id) AS duplicate_number
    FROM plans
)
UPDATE plans p
SET name = p.name || ' (provider ' || p.id || ')'
FROM ranked r
WHERE p.id = r.id AND r.duplicate_number > 1;
ALTER TABLE plans ADD CONSTRAINT plans_name_key UNIQUE (name);
