-- +goose Up
ALTER TABLE addon_plans DROP CONSTRAINT IF EXISTS addon_plans_reseller_id_name_key;
CREATE UNIQUE INDEX addon_plans_provider_name_idx
    ON addon_plans (COALESCE(reseller_id, 0), lower(name));
CREATE INDEX subscription_addons_addon_plan_id_idx
    ON subscription_addons (addon_plan_id);

-- +goose Down
DROP INDEX IF EXISTS subscription_addons_addon_plan_id_idx;
DROP INDEX IF EXISTS addon_plans_provider_name_idx;
ALTER TABLE addon_plans ADD CONSTRAINT addon_plans_reseller_id_name_key UNIQUE (reseller_id, name);
