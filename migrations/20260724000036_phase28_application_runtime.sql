-- +goose Up
ALTER TABLE application_presets
    ADD COLUMN manifest_revision BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN manifest JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(manifest) = 'object');

ALTER TABLE application_instances
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'container'
        CHECK (kind IN ('container','managed')),
    ADD COLUMN catalog_revision BIGINT NOT NULL DEFAULT 0 CHECK (catalog_revision >= 0),
    ADD COLUMN manifest JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(manifest)='object'),
    ADD COLUMN route_mode TEXT NOT NULL DEFAULT 'prefix'
        CHECK (route_mode IN ('domain','prefix')),
    ADD COLUMN route_prefix TEXT NOT NULL DEFAULT '/',
    ADD COLUMN container_port INTEGER NOT NULL DEFAULT 8080
        CHECK (container_port BETWEEN 1 AND 65535),
    ADD COLUMN endpoint_port INTEGER,
    ADD COLUMN health_kind TEXT NOT NULL DEFAULT 'http'
        CHECK (health_kind IN ('http','tcp')),
    ADD COLUMN health_path TEXT NOT NULL DEFAULT '/healthz',
    ADD COLUMN health_timeout_seconds INTEGER NOT NULL DEFAULT 30
        CHECK (health_timeout_seconds BETWEEN 1 AND 300),
    ADD COLUMN active_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN observed_state TEXT NOT NULL DEFAULT 'unknown'
        CHECK (observed_state IN ('unknown','starting','healthy','unhealthy','stopped','missing','failed')),
    ADD COLUMN observed_message TEXT NOT NULL DEFAULT '',
    ADD COLUMN observed_at TIMESTAMPTZ,
    ADD COLUMN last_reconciled_at TIMESTAMPTZ,
    ADD CONSTRAINT application_route_prefix_check CHECK (
        route_prefix LIKE '/%' AND
        route_prefix !~ '(^|/)\.\.(/|$)' AND
        route_prefix !~ '[\r\n]'
    ),
    ADD CONSTRAINT application_health_path_check CHECK (
        health_path LIKE '/%' AND
        health_path !~ '(^|/)\.\.(/|$)' AND
        health_path !~ '[\r\n]'
    );

ALTER TABLE application_volumes
    ADD COLUMN read_only BOOLEAN NOT NULL DEFAULT false;

WITH numbered AS (
    SELECT id, row_number() OVER (ORDER BY id) - 1 AS slot
    FROM application_instances
)
UPDATE application_instances instance
SET endpoint_port = 20000 + (numbered.slot % 5000)
FROM numbered
WHERE numbered.id = instance.id;

ALTER TABLE application_instances
    ALTER COLUMN endpoint_port SET NOT NULL,
    ADD CONSTRAINT application_endpoint_port_check
        CHECK (endpoint_port BETWEEN 20000 AND 29999);

CREATE UNIQUE INDEX application_instances_endpoint_port_idx
    ON application_instances(endpoint_port)
    WHERE NOT delete_requested;
CREATE UNIQUE INDEX application_instances_domain_route_idx
    ON application_instances(site_id)
    WHERE route_mode='domain' AND NOT delete_requested;
CREATE UNIQUE INDEX application_instances_prefix_route_idx
    ON application_instances(site_id,route_prefix)
    WHERE route_mode='prefix' AND NOT delete_requested;

UPDATE application_instances
SET desired_state='stopped',
    applied_state=CASE WHEN applied_state='running' THEN 'stopped' ELSE applied_state END,
    convergence_status='failed',
    observed_state='stopped',
    observed_message='Runtime adapter is not available. Phase 28 supports OCI containers only.',
    last_error='Runtime adapter is not available. Phase 28 supports OCI containers only.'
WHERE runtime <> 'oci';

CREATE TABLE application_manifest_revisions (
    id BIGSERIAL PRIMARY KEY,
    preset_id BIGINT NOT NULL REFERENCES application_presets(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL CHECK (revision > 0),
    manifest JSONB NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
    image_ref TEXT NOT NULL CHECK (image_ref ~ '@sha256:[a-f0-9]{64}$'),
    created_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(preset_id,revision)
);

INSERT INTO application_manifest_revisions(preset_id,revision,manifest,image_ref)
SELECT id,manifest_revision,manifest,image_ref
FROM application_presets
WHERE image_ref ~ '@sha256:[a-f0-9]{64}$';

CREATE TABLE application_generations (
    id BIGSERIAL PRIMARY KEY,
    application_id BIGINT NOT NULL REFERENCES application_instances(id) ON DELETE CASCADE,
    desired_revision BIGINT NOT NULL CHECK (desired_revision > 0),
    image_ref TEXT NOT NULL CHECK (image_ref ~ '@sha256:[a-f0-9]{64}$'),
    endpoint_port INTEGER NOT NULL CHECK (endpoint_port BETWEEN 20000 AND 29999),
    unit_name TEXT NOT NULL DEFAULT '',
    container_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','starting','healthy','failed','retired','rolled_back')),
    health_message TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ,
    healthy_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(application_id,desired_revision)
);
CREATE INDEX application_generations_status_idx
    ON application_generations(application_id,status,created_at DESC);

CREATE TABLE application_secret_bindings (
    application_id BIGINT NOT NULL REFERENCES application_instances(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (name ~ '^[A-Z_][A-Z0-9_]{0,127}$'),
    secret_id BIGINT NOT NULL REFERENCES service_secrets(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(application_id,name),
    UNIQUE(secret_id)
);

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
DROP TABLE IF EXISTS application_secret_bindings;
DROP INDEX IF EXISTS application_generations_status_idx;
DROP TABLE IF EXISTS application_generations;
DROP TABLE IF EXISTS application_manifest_revisions;
DROP INDEX IF EXISTS application_instances_prefix_route_idx;
DROP INDEX IF EXISTS application_instances_domain_route_idx;
DROP INDEX IF EXISTS application_instances_endpoint_port_idx;
ALTER TABLE application_instances
    DROP CONSTRAINT IF EXISTS application_health_path_check,
    DROP CONSTRAINT IF EXISTS application_route_prefix_check,
    DROP CONSTRAINT IF EXISTS application_endpoint_port_check,
    DROP COLUMN IF EXISTS last_reconciled_at,
    DROP COLUMN IF EXISTS observed_at,
    DROP COLUMN IF EXISTS observed_message,
    DROP COLUMN IF EXISTS observed_state,
    DROP COLUMN IF EXISTS active_generation,
    DROP COLUMN IF EXISTS health_timeout_seconds,
    DROP COLUMN IF EXISTS health_path,
    DROP COLUMN IF EXISTS health_kind,
    DROP COLUMN IF EXISTS endpoint_port,
    DROP COLUMN IF EXISTS container_port,
    DROP COLUMN IF EXISTS route_prefix,
    DROP COLUMN IF EXISTS route_mode,
    DROP COLUMN IF EXISTS manifest,
    DROP COLUMN IF EXISTS catalog_revision,
    DROP COLUMN IF EXISTS kind;
ALTER TABLE application_volumes DROP COLUMN IF EXISTS read_only;
ALTER TABLE application_presets
    DROP COLUMN IF EXISTS manifest,
    DROP COLUMN IF EXISTS manifest_revision;
