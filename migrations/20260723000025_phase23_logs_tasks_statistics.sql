-- +goose Up
ALTER TABLE scheduled_tasks
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'command' CHECK (kind IN ('command','url','php')),
    ADD COLUMN url TEXT NOT NULL DEFAULT '',
    ADD COLUMN script_path TEXT NOT NULL DEFAULT '',
    ADD COLUMN timezone TEXT NOT NULL DEFAULT 'UTC',
    ADD COLUMN phase23_legacy_site_backfill BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN phase23_legacy_enabled BOOLEAN;

WITH legacy AS (
    SELECT task.id, MIN(site.id) AS site_id
    FROM scheduled_tasks task
    LEFT JOIN sites site ON site.subscription_id=task.subscription_id
    WHERE task.site_id IS NULL
    GROUP BY task.id
)
UPDATE scheduled_tasks task
SET site_id=legacy.site_id,
    enabled=CASE WHEN legacy.site_id IS NULL THEN false ELSE task.enabled END,
    phase23_legacy_site_backfill=true,
    phase23_legacy_enabled=task.enabled
FROM legacy
WHERE task.id=legacy.id;

ALTER TABLE scheduled_task_runs
    ADD COLUMN scheduled_for TIMESTAMPTZ;
CREATE UNIQUE INDEX scheduled_task_runs_schedule_idx
ON scheduled_task_runs(task_id,scheduled_for) WHERE scheduled_for IS NOT NULL;

ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed',
                    'maintenance_failed', 'certificate_expiring', 'mail_outbound_spike',
                    'scheduled_task_failed'));

CREATE TABLE site_usage_current (
    site_id BIGINT PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    period_start DATE NOT NULL DEFAULT date_trunc('month', now())::date,
    document_root_bytes BIGINT NOT NULL DEFAULT 0 CHECK (document_root_bytes >= 0),
    traffic_bytes BIGINT NOT NULL DEFAULT 0 CHECK (traffic_bytes >= 0),
    request_count BIGINT NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    error_count BIGINT NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    php_state TEXT NOT NULL DEFAULT 'unknown',
    collected_at TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX scheduled_task_runs_task_created_idx
ON scheduled_task_runs(task_id,created_at DESC);

-- +goose Down
DROP INDEX IF EXISTS scheduled_task_runs_task_created_idx;
DROP TABLE IF EXISTS site_usage_current;
DELETE FROM notifications WHERE kind='scheduled_task_failed';
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed',
                    'maintenance_failed', 'certificate_expiring', 'mail_outbound_spike'));
DROP INDEX IF EXISTS scheduled_task_runs_schedule_idx;
ALTER TABLE scheduled_task_runs DROP COLUMN IF EXISTS scheduled_for;
UPDATE scheduled_tasks
SET site_id=NULL,
    enabled=COALESCE(phase23_legacy_enabled,enabled)
WHERE phase23_legacy_site_backfill;
ALTER TABLE scheduled_tasks
    DROP COLUMN IF EXISTS phase23_legacy_enabled,
    DROP COLUMN IF EXISTS phase23_legacy_site_backfill,
    DROP COLUMN IF EXISTS timezone,
    DROP COLUMN IF EXISTS script_path,
    DROP COLUMN IF EXISTS url,
    DROP COLUMN IF EXISTS kind;
