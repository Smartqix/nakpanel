-- +goose Up
ALTER TABLE users ADD COLUMN login_disabled BOOLEAN NOT NULL DEFAULT false;

INSERT INTO users (email, password_hash, role, login_disabled)
VALUES ('scheduler@nakpanel.internal', '!disabled-system-account', 'admin', true)
ON CONFLICT (email) DO UPDATE
SET login_disabled = true, updated_at = now();

ALTER TABLE sites ADD COLUMN tls_auto_renew BOOLEAN NOT NULL DEFAULT true;
CREATE INDEX sites_tls_renewal_idx
    ON sites (tls_expires_at, id)
    WHERE status = 'active' AND tls_status = 'active' AND tls_auto_renew = true;

ALTER TABLE backups DROP CONSTRAINT backups_status_check;
ALTER TABLE backups ADD CONSTRAINT backups_status_check
    CHECK (status IN ('pending', 'active', 'failed', 'deleting', 'delete_failed'));
ALTER TABLE backups ADD COLUMN scheduled_for DATE;
CREATE UNIQUE INDEX backups_site_scheduled_for_idx
    ON backups (site_id, scheduled_for) WHERE scheduled_for IS NOT NULL;
CREATE INDEX backups_site_retention_idx
    ON backups (site_id, created_at DESC, id DESC)
    WHERE status = 'active' AND archive_path <> '';

ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed', 'maintenance_failed'));

-- +goose Down
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
UPDATE notifications SET kind = 'sync_failed' WHERE kind = 'maintenance_failed';
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed'));

DROP INDEX IF EXISTS backups_site_retention_idx;
DROP INDEX IF EXISTS backups_site_scheduled_for_idx;
ALTER TABLE backups DROP COLUMN scheduled_for;
UPDATE backups SET status = 'failed' WHERE status IN ('deleting', 'delete_failed');
ALTER TABLE backups DROP CONSTRAINT backups_status_check;
ALTER TABLE backups ADD CONSTRAINT backups_status_check
    CHECK (status IN ('pending', 'active', 'failed'));

DROP INDEX IF EXISTS sites_tls_renewal_idx;
ALTER TABLE sites DROP COLUMN tls_auto_renew;

DELETE FROM audit_events
WHERE actor_user_id = (SELECT id FROM users WHERE email = 'scheduler@nakpanel.internal');
DELETE FROM sessions
WHERE user_id = (SELECT id FROM users WHERE email = 'scheduler@nakpanel.internal');
DELETE FROM users WHERE email = 'scheduler@nakpanel.internal';
ALTER TABLE users DROP COLUMN login_disabled;
