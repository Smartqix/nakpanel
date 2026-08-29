-- +goose Up
ALTER TABLE application_instances
    ADD COLUMN IF NOT EXISTS catalog_revision BIGINT NOT NULL DEFAULT 0
        CHECK (catalog_revision >= 0),
    ADD COLUMN IF NOT EXISTS manifest JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(manifest) = 'object');

ALTER TABLE application_volumes
    ADD COLUMN IF NOT EXISTS read_only BOOLEAN NOT NULL DEFAULT false;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION nakpanel_application_desired_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.site_id,NEW.name,NEW.runtime,NEW.catalog_slug,NEW.image_ref,
           NEW.desired_state,NEW.environment,NEW.healthcheck,NEW.delete_requested,
           NEW.route_mode,NEW.route_prefix,NEW.container_port,NEW.health_kind,
           NEW.health_path,NEW.health_timeout_seconds,NEW.catalog_revision,NEW.manifest)
       IS DISTINCT FROM
       ROW(OLD.site_id,OLD.name,OLD.runtime,OLD.catalog_slug,OLD.image_ref,
           OLD.desired_state,OLD.environment,OLD.healthcheck,OLD.delete_requested,
           OLD.route_mode,OLD.route_prefix,OLD.container_port,OLD.health_kind,
           OLD.health_path,OLD.health_timeout_seconds,OLD.catalog_revision,OLD.manifest) THEN
        NEW.desired_revision := OLD.desired_revision + 1;
        NEW.convergence_status := 'pending';
        NEW.observed_state := 'unknown';
        NEW.observed_message := '';
        NEW.last_error := '';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- The compatibility migration intentionally leaves Phase 28 columns in place
-- because they may have originated in migration 36 on a fresh installation.
