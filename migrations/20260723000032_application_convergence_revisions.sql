-- +goose Up
ALTER TABLE application_instances
    ADD COLUMN desired_revision BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN applied_revision BIGINT NOT NULL DEFAULT 0;

UPDATE application_instances
SET applied_revision=desired_revision
WHERE convergence_status='in_sync';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION nakpanel_application_desired_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.site_id,NEW.name,NEW.runtime,NEW.catalog_slug,NEW.image_ref,
           NEW.desired_state,NEW.environment,NEW.healthcheck,NEW.delete_requested)
       IS DISTINCT FROM
       ROW(OLD.site_id,OLD.name,OLD.runtime,OLD.catalog_slug,OLD.image_ref,
           OLD.desired_state,OLD.environment,OLD.healthcheck,OLD.delete_requested) THEN
        NEW.desired_revision := OLD.desired_revision + 1;
        NEW.convergence_status := 'pending';
        NEW.last_error := '';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER application_instances_desired_revision
BEFORE UPDATE ON application_instances
FOR EACH ROW EXECUTE FUNCTION nakpanel_application_desired_revision();

CREATE INDEX application_instances_pending_revision_idx
    ON application_instances(convergence_status, desired_revision, id);

-- +goose Down
DROP INDEX IF EXISTS application_instances_pending_revision_idx;
DROP TRIGGER IF EXISTS application_instances_desired_revision ON application_instances;
DROP FUNCTION IF EXISTS nakpanel_application_desired_revision();
ALTER TABLE application_instances
    DROP COLUMN IF EXISTS applied_revision,
    DROP COLUMN IF EXISTS desired_revision;
