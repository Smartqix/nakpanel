-- +goose Up
CREATE TABLE reseller_accounts (
    id BIGSERIAL PRIMARY KEY,
    login_user_id BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    company TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX reseller_accounts_email_lower_idx ON reseller_accounts(lower(email));
CREATE INDEX reseller_accounts_status_idx ON reseller_accounts(status);

CREATE TABLE reseller_plans (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    max_customers INTEGER NOT NULL DEFAULT 0,
    max_subscriptions INTEGER NOT NULL DEFAULT 0,
    disk_mb INTEGER NOT NULL DEFAULT 0,
    max_sites INTEGER NOT NULL DEFAULT 0,
    max_databases INTEGER NOT NULL DEFAULT 0,
    bandwidth_mb INTEGER NOT NULL DEFAULT -1,
    max_mailboxes INTEGER NOT NULL DEFAULT 0,
    max_backups INTEGER NOT NULL DEFAULT 0,
    backup_storage_mb INTEGER NOT NULL DEFAULT 0,
    allow_custom_plans BOOLEAN NOT NULL DEFAULT true,
    allow_ssh BOOLEAN NOT NULL DEFAULT false,
    allow_dns BOOLEAN NOT NULL DEFAULT true,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT reseller_plans_limit_floor_check CHECK (
        max_customers >= -1 AND max_subscriptions >= -1 AND disk_mb >= -1
        AND max_sites >= -1 AND max_databases >= -1 AND bandwidth_mb >= -1
        AND max_mailboxes >= -1 AND max_backups >= -1 AND backup_storage_mb >= -1
    )
);

CREATE TABLE reseller_subscriptions (
    id BIGSERIAL PRIMARY KEY,
    reseller_id BIGINT NOT NULL REFERENCES reseller_accounts(id) ON DELETE RESTRICT,
    reseller_plan_id BIGINT NOT NULL REFERENCES reseller_plans(id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'cancelled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX reseller_subscriptions_one_active_idx ON reseller_subscriptions(reseller_id) WHERE status = 'active';
CREATE INDEX reseller_subscriptions_plan_idx ON reseller_subscriptions(reseller_plan_id);

ALTER TABLE customers ADD COLUMN reseller_id BIGINT REFERENCES reseller_accounts(id) ON DELETE RESTRICT;
CREATE INDEX customers_reseller_id_idx ON customers(reseller_id);

ALTER TABLE plans
    ADD COLUMN reseller_id BIGINT REFERENCES reseller_accounts(id) ON DELETE RESTRICT,
    ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;
CREATE INDEX plans_reseller_id_idx ON plans(reseller_id);

ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_status_check;
ALTER TABLE sites ADD CONSTRAINT sites_status_check
    CHECK (status IN ('pending', 'active', 'failed', 'suspending', 'suspended', 'activating'));

CREATE TABLE addon_plans (
    id BIGSERIAL PRIMARY KEY,
    reseller_id BIGINT REFERENCES reseller_accounts(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    disk_mb INTEGER NOT NULL DEFAULT 0,
    max_sites INTEGER NOT NULL DEFAULT 0,
    max_databases INTEGER NOT NULL DEFAULT 0,
    bandwidth_mb INTEGER NOT NULL DEFAULT 0,
    max_mailboxes INTEGER NOT NULL DEFAULT 0,
    backup_retention_days INTEGER NOT NULL DEFAULT 0,
    php_allowlist TEXT NOT NULL DEFAULT '',
    php_fpm_max_children INTEGER NOT NULL DEFAULT 0,
    php_memory_mb INTEGER NOT NULL DEFAULT 0,
    site_disk_quota_mb INTEGER NOT NULL DEFAULT 0,
    max_backups INTEGER NOT NULL DEFAULT 0,
    backup_storage_mb INTEGER NOT NULL DEFAULT 0,
    allow_ssh BOOLEAN NOT NULL DEFAULT false,
    allow_dns BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (reseller_id, name),
    CONSTRAINT addon_plans_limit_floor_check CHECK (
        disk_mb >= -1 AND max_sites >= -1 AND max_databases >= -1 AND bandwidth_mb >= -1
        AND max_mailboxes >= -1 AND backup_retention_days >= -1
        AND php_fpm_max_children >= -1 AND php_memory_mb >= -1 AND site_disk_quota_mb >= -1
        AND max_backups >= -1 AND backup_storage_mb >= -1
    )
);

ALTER TABLE subscriptions
    ALTER COLUMN plan_id DROP NOT NULL,
    ADD COLUMN sync_mode TEXT NOT NULL DEFAULT 'synced' CHECK (sync_mode IN ('synced', 'locked', 'custom')),
    ADD COLUMN sync_status TEXT NOT NULL DEFAULT 'in_sync' CHECK (sync_status IN ('in_sync', 'pending', 'out_of_sync', 'failed')),
    ADD COLUMN plan_revision INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN sync_error TEXT NOT NULL DEFAULT '';

CREATE TABLE subscription_addons (
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    addon_plan_id BIGINT NOT NULL REFERENCES addon_plans(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subscription_id, addon_plan_id)
);

CREATE TABLE subscription_entitlements (
    subscription_id BIGINT PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
    plan_name TEXT NOT NULL DEFAULT 'Custom',
    disk_mb INTEGER NOT NULL,
    max_sites INTEGER NOT NULL,
    max_databases INTEGER NOT NULL,
    bandwidth_mb INTEGER NOT NULL,
    max_mailboxes INTEGER NOT NULL,
    allow_ssh BOOLEAN NOT NULL,
    allow_dns BOOLEAN NOT NULL,
    backup_retention_days INTEGER NOT NULL,
    php_allowlist TEXT NOT NULL,
    php_fpm_max_children INTEGER NOT NULL,
    php_memory_mb INTEGER NOT NULL,
    site_disk_quota_mb INTEGER NOT NULL,
    max_backups INTEGER NOT NULL,
    backup_storage_mb INTEGER NOT NULL,
    source_revision INTEGER NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT subscription_entitlements_limit_floor_check CHECK (
        disk_mb >= -1 AND max_sites >= -1 AND max_databases >= -1 AND bandwidth_mb >= -1
        AND max_mailboxes >= -1 AND backup_retention_days >= -1
        AND php_fpm_max_children >= -1 AND php_memory_mb >= -1 AND site_disk_quota_mb >= -1
        AND max_backups >= -1 AND backup_storage_mb >= -1
    )
);

INSERT INTO subscription_entitlements (
    subscription_id, plan_name, disk_mb, max_sites, max_databases, bandwidth_mb,
    max_mailboxes, allow_ssh, allow_dns, backup_retention_days, php_allowlist,
    php_fpm_max_children, php_memory_mb, site_disk_quota_mb, max_backups,
    backup_storage_mb, source_revision
)
SELECT s.id, p.name, p.disk_mb, p.max_sites, p.max_databases, p.bandwidth_mb,
       p.max_mailboxes, p.allow_ssh, p.allow_dns, p.backup_retention_days,
       p.php_allowlist, p.php_fpm_max_children, p.php_memory_mb,
       p.site_disk_quota_mb, p.max_backups, p.backup_storage_mb, p.revision
FROM subscriptions s JOIN plans p ON p.id = s.plan_id;

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

CREATE TRIGGER subscriptions_seed_entitlements
AFTER INSERT OR UPDATE OF plan_id ON subscriptions
FOR EACH ROW EXECUTE FUNCTION seed_subscription_entitlements_from_plan();

INSERT INTO reseller_accounts (login_user_id, email, display_name)
SELECT id, email, email FROM users WHERE role = 'reseller'
ON CONFLICT (login_user_id) DO NOTHING;

INSERT INTO reseller_plans (
    name, description, max_customers, max_subscriptions, disk_mb, max_sites,
    max_databases, bandwidth_mb, max_mailboxes, max_backups, backup_storage_mb,
    allow_custom_plans, allow_ssh, allow_dns, is_active
) VALUES (
    'Legacy Unlimited Reseller', 'Migration-only allocation preserving existing reseller access.',
    -1, -1, -1, -1, -1, -1, -1, -1, -1, true, true, true, false
) ON CONFLICT (name) DO NOTHING;

INSERT INTO reseller_subscriptions (reseller_id, reseller_plan_id, status)
SELECT r.id, p.id, 'active'
FROM reseller_accounts r CROSS JOIN reseller_plans p
WHERE p.name = 'Legacy Unlimited Reseller'
ON CONFLICT (reseller_id) WHERE status = 'active' DO NOTHING;

UPDATE customers c SET reseller_id = candidate.reseller_id
FROM (
    SELECT s.customer_id, MIN(r.id) AS reseller_id
    FROM subscriptions s
    JOIN reseller_accounts r ON r.login_user_id = s.reseller_user_id
    WHERE s.reseller_user_id IS NOT NULL
    GROUP BY s.customer_id
    HAVING COUNT(DISTINCT r.id) = 1
) candidate
WHERE c.id = candidate.customer_id AND c.reseller_id IS NULL;

-- +goose Down
DROP TRIGGER IF EXISTS subscriptions_seed_entitlements ON subscriptions;
DROP FUNCTION IF EXISTS seed_subscription_entitlements_from_plan();
DROP TABLE IF EXISTS subscription_entitlements;
DROP TABLE IF EXISTS subscription_addons;
ALTER TABLE subscriptions
    DROP COLUMN IF EXISTS sync_error,
    DROP COLUMN IF EXISTS plan_revision,
    DROP COLUMN IF EXISTS sync_status,
    DROP COLUMN IF EXISTS sync_mode;
UPDATE subscriptions
SET plan_id = (SELECT id FROM plans WHERE name = 'Legacy Unlimited' ORDER BY id LIMIT 1)
WHERE plan_id IS NULL;
ALTER TABLE subscriptions ALTER COLUMN plan_id SET NOT NULL;
DROP TABLE IF EXISTS addon_plans;
UPDATE sites SET status = 'active' WHERE status IN ('suspending', 'suspended', 'activating');
ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_status_check;
ALTER TABLE sites ADD CONSTRAINT sites_status_check CHECK (status IN ('pending', 'active', 'failed'));
DROP INDEX IF EXISTS plans_reseller_id_idx;
ALTER TABLE plans DROP COLUMN IF EXISTS revision, DROP COLUMN IF EXISTS reseller_id;
DROP INDEX IF EXISTS customers_reseller_id_idx;
ALTER TABLE customers DROP COLUMN IF EXISTS reseller_id;
DROP TABLE IF EXISTS reseller_subscriptions;
DROP TABLE IF EXISTS reseller_plans;
DROP TABLE IF EXISTS reseller_accounts;
