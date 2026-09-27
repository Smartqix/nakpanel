-- +goose Up
ALTER TABLE plans
    ADD COLUMN lifecycle_status TEXT NOT NULL DEFAULT 'draft',
    ADD COLUMN last_validated_at TIMESTAMPTZ,
    ADD COLUMN readiness_error TEXT NOT NULL DEFAULT '';

UPDATE plans
SET lifecycle_status = CASE WHEN is_active THEN 'active' ELSE 'retired' END;

ALTER TABLE plans
    ADD CONSTRAINT plans_lifecycle_status_check
        CHECK (lifecycle_status IN ('draft', 'active', 'retired')),
    ADD CONSTRAINT plans_lifecycle_active_compatibility_check
        CHECK (is_active = (lifecycle_status = 'active'));

ALTER TABLE plans ALTER COLUMN is_active SET DEFAULT false;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION nakpanel_sync_plan_lifecycle()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.lifecycle_status = 'draft' AND NEW.is_active THEN
            NEW.lifecycle_status := 'active';
        END IF;
        NEW.is_active := NEW.lifecycle_status = 'active';
    ELSIF NEW.lifecycle_status IS DISTINCT FROM OLD.lifecycle_status THEN
        NEW.is_active := NEW.lifecycle_status = 'active';
    ELSIF NEW.is_active IS DISTINCT FROM OLD.is_active THEN
        NEW.lifecycle_status := CASE WHEN NEW.is_active THEN 'active' ELSE 'retired' END;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER plans_lifecycle_compatibility
BEFORE INSERT OR UPDATE OF lifecycle_status, is_active ON plans
FOR EACH ROW EXECUTE FUNCTION nakpanel_sync_plan_lifecycle();

CREATE TABLE plan_revisions (
    id BIGSERIAL PRIMARY KEY,
    plan_id BIGINT NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision > 0),
    lifecycle_status TEXT NOT NULL CHECK (lifecycle_status IN ('draft', 'active', 'retired')),
    definition JSONB NOT NULL,
    definition_hash TEXT NOT NULL CHECK (definition_hash ~ '^[0-9a-f]{64}$'),
    actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    actor_label TEXT NOT NULL DEFAULT '',
    change_reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (plan_id, revision),
    CONSTRAINT plan_revisions_actor_check CHECK (actor_user_id IS NOT NULL OR btrim(actor_label) <> '')
);
CREATE INDEX plan_revisions_plan_created_idx ON plan_revisions(plan_id, created_at DESC);

WITH revision_definitions AS (
    SELECT p.id,
           GREATEST(p.revision, 1) AS revision,
           p.lifecycle_status,
           p.updated_at,
           jsonb_build_object(
               'plan', to_jsonb(p) - 'created_at' - 'updated_at' - 'last_validated_at' - 'readiness_error',
               'presets', jsonb_build_object(
                   'schema_version', COALESCE(ps.schema_version, 1),
                   'hosting', COALESCE(ps.hosting, '{}'::jsonb),
                   'php', COALESCE(ps.php, '{}'::jsonb),
                   'mail', COALESCE(ps.mail, '{}'::jsonb),
                   'dns', COALESCE(ps.dns, '{}'::jsonb),
                   'performance', COALESCE(ps.performance, '{}'::jsonb),
                   'logs', COALESCE(ps.logs, '{}'::jsonb),
                   'applications', COALESCE(ps.applications, '{}'::jsonb)
               )
           ) AS definition
    FROM plans p
    LEFT JOIN plan_service_presets ps ON ps.plan_id = p.id
)
INSERT INTO plan_revisions(
    plan_id, revision, lifecycle_status, definition, definition_hash,
    actor_label, change_reason, created_at
)
SELECT d.id,
       d.revision,
       d.lifecycle_status,
       d.definition,
       encode(sha256(convert_to(d.definition::text, 'UTF8')), 'hex'),
       'migration',
       'Phase 31 lifecycle and immutable revision backfill',
       d.updated_at
FROM revision_definitions d;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION nakpanel_reject_plan_revision_mutation()
RETURNS TRIGGER AS $$
BEGIN
	-- Preserve the immutable definition while allowing the users FK to retain
	-- actor attribution by label after an operator account is removed.
	IF TG_OP = 'UPDATE' THEN
		IF OLD.actor_user_id IS NOT NULL
		   AND NEW.actor_user_id IS NULL
		   AND (to_jsonb(NEW) - 'actor_user_id') = (to_jsonb(OLD) - 'actor_user_id') THEN
			RETURN NEW;
		END IF;
	END IF;
    RAISE EXCEPTION 'plan revisions are immutable';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER plan_revisions_immutable_update
BEFORE UPDATE ON plan_revisions
FOR EACH ROW EXECUTE FUNCTION nakpanel_reject_plan_revision_mutation();
CREATE TRIGGER plan_revisions_immutable_delete
BEFORE DELETE ON plan_revisions
FOR EACH ROW EXECUTE FUNCTION nakpanel_reject_plan_revision_mutation();

ALTER TABLE subscriptions
    ADD COLUMN compliance_status TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN compliance_error TEXT NOT NULL DEFAULT '',
    ADD COLUMN compliance_checked_at TIMESTAMPTZ;
ALTER TABLE subscriptions
    ADD CONSTRAINT subscriptions_compliance_status_check
        CHECK (compliance_status IN ('compliant', 'over_limit', 'capability_blocked', 'unknown'));
CREATE INDEX subscriptions_compliance_status_idx ON subscriptions(compliance_status)
WHERE compliance_status <> 'compliant';

-- +goose Down
DROP INDEX IF EXISTS subscriptions_compliance_status_idx;
ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS subscriptions_compliance_status_check;
ALTER TABLE subscriptions
    DROP COLUMN IF EXISTS compliance_checked_at,
    DROP COLUMN IF EXISTS compliance_error,
    DROP COLUMN IF EXISTS compliance_status;

DROP TRIGGER IF EXISTS plan_revisions_immutable_delete ON plan_revisions;
DROP TRIGGER IF EXISTS plan_revisions_immutable_update ON plan_revisions;
DROP FUNCTION IF EXISTS nakpanel_reject_plan_revision_mutation();
DROP TABLE IF EXISTS plan_revisions;

DROP TRIGGER IF EXISTS plans_lifecycle_compatibility ON plans;
DROP FUNCTION IF EXISTS nakpanel_sync_plan_lifecycle();
ALTER TABLE plans DROP CONSTRAINT IF EXISTS plans_lifecycle_active_compatibility_check;
ALTER TABLE plans DROP CONSTRAINT IF EXISTS plans_lifecycle_status_check;
ALTER TABLE plans ALTER COLUMN is_active SET DEFAULT true;
ALTER TABLE plans
    DROP COLUMN IF EXISTS readiness_error,
    DROP COLUMN IF EXISTS last_validated_at,
    DROP COLUMN IF EXISTS lifecycle_status;
