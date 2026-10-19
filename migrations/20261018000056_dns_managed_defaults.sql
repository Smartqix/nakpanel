-- +goose Up
ALTER TABLE dns_template_sync_runs ADD COLUMN adopt_matching BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE dns_template_sync_items ADD COLUMN adopted_count INTEGER NOT NULL DEFAULT 0 CHECK (adopted_count >= 0);
ALTER TABLE dns_template_sync_items ADD COLUMN plan_fingerprint TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE dns_template_sync_items DROP COLUMN adopted_count;
ALTER TABLE dns_template_sync_items DROP COLUMN plan_fingerprint;
ALTER TABLE dns_template_sync_runs DROP COLUMN adopt_matching;
