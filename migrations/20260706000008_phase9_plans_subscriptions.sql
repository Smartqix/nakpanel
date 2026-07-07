-- +goose Up
CREATE TABLE plans (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    price_cents INTEGER CHECK (price_cents IS NULL OR price_cents >= 0),
    disk_mb INTEGER NOT NULL DEFAULT 0,
    max_sites INTEGER NOT NULL DEFAULT 0,
    max_databases INTEGER NOT NULL DEFAULT 0,
    bandwidth_mb INTEGER NOT NULL DEFAULT -1,
    max_mailboxes INTEGER NOT NULL DEFAULT 0,
    allow_ssh BOOLEAN NOT NULL DEFAULT false,
    allow_dns BOOLEAN NOT NULL DEFAULT true,
    backup_retention_days INTEGER NOT NULL DEFAULT 0,
    php_allowlist TEXT NOT NULL DEFAULT '',
    php_fpm_max_children INTEGER NOT NULL DEFAULT 0,
    php_memory_mb INTEGER NOT NULL DEFAULT 0,
    site_disk_quota_mb INTEGER NOT NULL DEFAULT 0,
    max_backups INTEGER NOT NULL DEFAULT 0,
    backup_storage_mb INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT plans_limit_floor_check CHECK (
        disk_mb >= -1
        AND max_sites >= -1
        AND max_databases >= -1
        AND bandwidth_mb >= -1
        AND max_mailboxes >= -1
        AND backup_retention_days >= -1
        AND php_fpm_max_children >= -1
        AND php_memory_mb >= -1
        AND site_disk_quota_mb >= -1
        AND max_backups >= -1
        AND backup_storage_mb >= -1
    )
);

CREATE TABLE subscriptions (
    id BIGSERIAL PRIMARY KEY,
    customer_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reseller_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    plan_id BIGINT NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'cancelled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX subscriptions_one_active_per_customer_idx ON subscriptions(customer_user_id)
WHERE status = 'active';
CREATE INDEX subscriptions_customer_user_id_idx ON subscriptions(customer_user_id);
CREATE INDEX subscriptions_reseller_user_id_idx ON subscriptions(reseller_user_id);
CREATE INDEX subscriptions_plan_id_idx ON subscriptions(plan_id);
CREATE INDEX subscriptions_status_idx ON subscriptions(status);

CREATE TABLE settings (
    id BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    oversell_policy TEXT NOT NULL DEFAULT 'warn' CHECK (oversell_policy IN ('warn', 'cap')),
    server_disk_capacity_mb INTEGER NOT NULL DEFAULT 0 CHECK (server_disk_capacity_mb >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO settings (id, oversell_policy, server_disk_capacity_mb)
VALUES (true, 'warn', 0);

ALTER TABLE sites
    ADD COLUMN subscription_id BIGINT REFERENCES subscriptions(id) ON DELETE SET NULL;

ALTER TABLE databases
    ADD COLUMN subscription_id BIGINT REFERENCES subscriptions(id) ON DELETE SET NULL;

ALTER TABLE backups
    ADD COLUMN subscription_id BIGINT REFERENCES subscriptions(id) ON DELETE SET NULL;

CREATE INDEX sites_subscription_id_idx ON sites(subscription_id);
CREATE INDEX databases_subscription_id_idx ON databases(subscription_id);
CREATE INDEX backups_subscription_id_idx ON backups(subscription_id);

INSERT INTO plans (
    name,
    description,
    price_cents,
    disk_mb,
    max_sites,
    max_databases,
    bandwidth_mb,
    max_mailboxes,
    allow_ssh,
    allow_dns,
    backup_retention_days,
    php_allowlist,
    php_fpm_max_children,
    php_memory_mb,
    site_disk_quota_mb,
    max_backups,
    backup_storage_mb,
    is_active
) VALUES
    ('Starter', 'Starter hosting plan for a single small site.', NULL, 5120, 1, 2, -1, 0, false, true, 7, '8.3,8.2', 3, 128, 5120, 7, 5120, true),
    ('Business', 'Business hosting plan for several production sites.', NULL, 25600, 5, 15, -1, 0, true, true, 30, '8.3,8.2', 8, 256, 10240, 30, 25600, true),
    ('Pro', 'Pro hosting plan for larger accounts.', NULL, 81920, 20, -1, -1, 0, true, true, 30, '8.3,8.2', 16, 512, 20480, -1, 81920, true),
    ('Legacy Unlimited', 'Migration-only plan preserving pre-subscription unlimited accounts.', NULL, -1, -1, -1, -1, -1, true, true, -1, '8.3,8.2', -1, -1, -1, -1, -1, false);

-- +goose StatementBegin
DO $$
DECLARE
    account RECORD;
    selected_plan_id BIGINT;
    selected_subscription_id BIGINT;
BEGIN
    FOR account IN
        SELECT
            u.id AS user_id,
            q.user_id IS NOT NULL AS has_quota,
            q.max_sites,
            q.max_databases,
            q.storage_mb,
            q.max_backups,
            q.backup_storage_mb,
            q.site_disk_quota_mb,
            q.php_fpm_max_children,
            q.php_memory_mb
        FROM users u
        LEFT JOIN account_quotas q ON q.user_id = u.id
        ORDER BY u.id
    LOOP
        IF NOT account.has_quota THEN
            SELECT id INTO selected_plan_id FROM plans WHERE name = 'Legacy Unlimited';
        ELSE
            SELECT id INTO selected_plan_id
            FROM plans
            WHERE disk_mb = account.storage_mb
              AND max_sites = account.max_sites
              AND max_databases = account.max_databases
              AND max_backups = account.max_backups
              AND backup_storage_mb = account.backup_storage_mb
              AND site_disk_quota_mb = account.site_disk_quota_mb
              AND php_fpm_max_children = account.php_fpm_max_children
              AND php_memory_mb = account.php_memory_mb
            ORDER BY id
            LIMIT 1;

            IF selected_plan_id IS NULL THEN
                INSERT INTO plans (
                    name,
                    description,
                    disk_mb,
                    max_sites,
                    max_databases,
                    bandwidth_mb,
                    max_mailboxes,
                    allow_ssh,
                    allow_dns,
                    backup_retention_days,
                    php_allowlist,
                    php_fpm_max_children,
                    php_memory_mb,
                    site_disk_quota_mb,
                    max_backups,
                    backup_storage_mb,
                    is_active
                ) VALUES (
                    'Legacy quota user ' || account.user_id,
                    'Migration-only plan copied from account_quotas for user ' || account.user_id || '.',
                    account.storage_mb,
                    account.max_sites,
                    account.max_databases,
                    -1,
                    0,
                    false,
                    true,
                    0,
                    '8.3,8.2',
                    account.php_fpm_max_children,
                    account.php_memory_mb,
                    account.site_disk_quota_mb,
                    account.max_backups,
                    account.backup_storage_mb,
                    false
                )
                RETURNING id INTO selected_plan_id;
            END IF;
        END IF;

        INSERT INTO subscriptions (customer_user_id, plan_id, status)
        VALUES (account.user_id, selected_plan_id, 'active')
        RETURNING id INTO selected_subscription_id;

        UPDATE sites
        SET subscription_id = selected_subscription_id
        WHERE owner_user_id = account.user_id
          AND subscription_id IS NULL;

        UPDATE databases
        SET subscription_id = selected_subscription_id
        WHERE owner_user_id = account.user_id
          AND subscription_id IS NULL;

        UPDATE backups
        SET subscription_id = selected_subscription_id
        WHERE owner_user_id = account.user_id
          AND subscription_id IS NULL;
    END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
ALTER TABLE backups DROP COLUMN IF EXISTS subscription_id;
ALTER TABLE databases DROP COLUMN IF EXISTS subscription_id;
ALTER TABLE sites DROP COLUMN IF EXISTS subscription_id;

DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS subscriptions;
DROP TABLE IF EXISTS plans;
