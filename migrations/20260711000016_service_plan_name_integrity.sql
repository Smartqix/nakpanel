-- +goose Up
ALTER TABLE addon_plans DROP CONSTRAINT IF EXISTS addon_plans_reseller_id_name_key;
ALTER TABLE reseller_plans DROP CONSTRAINT IF EXISTS reseller_plans_name_key;

WITH ranked AS (
    SELECT id, row_number() OVER (
        PARTITION BY COALESCE(reseller_id, 0), lower(name)
        ORDER BY id
    ) AS duplicate_number
    FROM addon_plans
)
UPDATE addon_plans a
SET name = a.name || ' (legacy ' || a.id || ')'
FROM ranked r
WHERE a.id = r.id AND r.duplicate_number > 1;

WITH ranked AS (
    SELECT id, row_number() OVER (PARTITION BY lower(name) ORDER BY id) AS duplicate_number
    FROM reseller_plans
)
UPDATE reseller_plans p
SET name = p.name || ' (legacy ' || p.id || ')'
FROM ranked r
WHERE p.id = r.id AND r.duplicate_number > 1;

CREATE UNIQUE INDEX addon_plans_provider_name_admin_idx
    ON addon_plans (lower(name)) WHERE reseller_id IS NULL;
CREATE UNIQUE INDEX addon_plans_provider_name_reseller_idx
    ON addon_plans (reseller_id, lower(name)) WHERE reseller_id IS NOT NULL;
CREATE UNIQUE INDEX reseller_plans_name_ci_idx ON reseller_plans (lower(name));

-- +goose Down
DROP INDEX IF EXISTS reseller_plans_name_ci_idx;
DROP INDEX IF EXISTS addon_plans_provider_name_reseller_idx;
DROP INDEX IF EXISTS addon_plans_provider_name_admin_idx;
ALTER TABLE reseller_plans ADD CONSTRAINT reseller_plans_name_key UNIQUE (name);
ALTER TABLE addon_plans ADD CONSTRAINT addon_plans_reseller_id_name_key UNIQUE (reseller_id, name);
