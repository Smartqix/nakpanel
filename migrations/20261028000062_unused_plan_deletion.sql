-- +goose Up
-- A plan owns its revisions. Subscriptions still reference plans with RESTRICT,
-- so removing a plan (and its history) is possible only after it is unused.
ALTER TABLE plan_revisions DROP CONSTRAINT plan_revisions_plan_id_fkey;
ALTER TABLE plan_revisions ADD CONSTRAINT plan_revisions_plan_id_fkey
    FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE CASCADE;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION nakpanel_reject_plan_revision_mutation()
RETURNS TRIGGER AS $$
BEGIN
    -- The parent has already been removed when its FK cascade runs. Direct
    -- deletion of a revision belonging to an existing plan remains forbidden.
    IF TG_OP = 'DELETE' THEN
        IF NOT EXISTS (SELECT 1 FROM plans WHERE id = OLD.plan_id) THEN
            RETURN OLD;
        END IF;
    ELSIF OLD.actor_user_id IS NOT NULL
       AND NEW.actor_user_id IS NULL
       AND (to_jsonb(NEW) - 'actor_user_id') = (to_jsonb(OLD) - 'actor_user_id') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'plan revisions are immutable';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
ALTER TABLE plan_revisions DROP CONSTRAINT plan_revisions_plan_id_fkey;
ALTER TABLE plan_revisions ADD CONSTRAINT plan_revisions_plan_id_fkey
    FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE RESTRICT;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION nakpanel_reject_plan_revision_mutation()
RETURNS TRIGGER AS $$
BEGIN
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
