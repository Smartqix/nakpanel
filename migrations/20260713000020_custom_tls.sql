-- +goose Up
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed', 'maintenance_failed', 'certificate_expiring'));

-- +goose Down
UPDATE notifications SET kind = 'maintenance_failed' WHERE kind = 'certificate_expiring';
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed', 'maintenance_failed'));
