-- +goose Up
ALTER TABLE reseller_quotas RENAME TO account_quotas;

ALTER TABLE account_quotas
    ADD COLUMN max_backups INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN backup_storage_mb INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN site_disk_quota_mb INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN php_fpm_max_children INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN php_memory_mb INTEGER NOT NULL DEFAULT 0,
    ADD CONSTRAINT account_quotas_nonnegative_check CHECK (
        max_sites >= 0
        AND max_databases >= 0
        AND storage_mb >= 0
        AND max_backups >= 0
        AND backup_storage_mb >= 0
        AND site_disk_quota_mb >= 0
        AND php_fpm_max_children >= 0
        AND php_memory_mb >= 0
    );

-- +goose Down
ALTER TABLE account_quotas
    DROP CONSTRAINT IF EXISTS account_quotas_nonnegative_check,
    DROP COLUMN IF EXISTS php_memory_mb,
    DROP COLUMN IF EXISTS php_fpm_max_children,
    DROP COLUMN IF EXISTS site_disk_quota_mb,
    DROP COLUMN IF EXISTS backup_storage_mb,
    DROP COLUMN IF EXISTS max_backups;

ALTER TABLE account_quotas RENAME TO reseller_quotas;
