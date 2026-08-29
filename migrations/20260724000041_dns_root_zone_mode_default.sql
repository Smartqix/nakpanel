-- +goose Up
ALTER TABLE sites
    ALTER COLUMN dns_zone_mode SET DEFAULT 'separate';

UPDATE sites
SET dns_zone_mode='separate',updated_at=now()
WHERE parent_site_id IS NULL
  AND dns_zone_mode='parent';

-- +goose Down
ALTER TABLE sites
    ALTER COLUMN dns_zone_mode SET DEFAULT 'parent';
