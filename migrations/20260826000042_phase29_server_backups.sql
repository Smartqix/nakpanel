-- +goose Up
CREATE TABLE server_backup_destinations (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (name ~ '^[a-z][a-z0-9-]{0,63}$'),
    kind TEXT NOT NULL CHECK (kind IN ('local','sftp','s3')),
    enabled BOOLEAN NOT NULL DEFAULT true,
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    credential_secret_name TEXT NOT NULL DEFAULT '',
    schedule_cron TEXT NOT NULL DEFAULT '0 2 * * *',
    retention_count INTEGER NOT NULL DEFAULT 7 CHECK (retention_count >= 1),
    retention_days INTEGER NOT NULL DEFAULT 30 CHECK (retention_days >= 0),
    include_mail_data BOOLEAN NOT NULL DEFAULT true,
    notify_email TEXT NOT NULL DEFAULT '',
    last_started_at TIMESTAMPTZ,
    last_succeeded_at TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE server_backups (
    id BIGSERIAL PRIMARY KEY,
    destination_id BIGINT REFERENCES server_backup_destinations(id) ON DELETE SET NULL,
    operation_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN
      ('pending','running','uploading','verifying','active','failed','deleting','delete_failed')),
    archive_name TEXT NOT NULL DEFAULT '',
    remote_path TEXT NOT NULL DEFAULT '',
    local_path TEXT NOT NULL DEFAULT '',
    size_bytes BIGINT NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    checksum_sha256 TEXT NOT NULL DEFAULT '',
    key_fingerprint TEXT NOT NULL DEFAULT '',
    manifest JSONB NOT NULL DEFAULT '{}'::jsonb,
    verified_at TIMESTAMPTZ,
    verify_detail JSONB,
    scheduled BOOLEAN NOT NULL DEFAULT false,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX server_backups_dest_status_idx
    ON server_backups(destination_id, status, created_at DESC);

ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed',
                    'maintenance_failed', 'certificate_expiring', 'mail_outbound_spike',
                    'scheduled_task_failed', 'server_backup_failed'));

-- +goose Down
DELETE FROM notifications WHERE kind='server_backup_failed';
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed',
                    'maintenance_failed', 'certificate_expiring', 'mail_outbound_spike',
                    'scheduled_task_failed'));
DROP INDEX IF EXISTS server_backups_dest_status_idx;
DROP TABLE IF EXISTS server_backups;
DROP TABLE IF EXISTS server_backup_destinations;
