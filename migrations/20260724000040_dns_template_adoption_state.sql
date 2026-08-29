-- +goose Up
ALTER TABLE sites
    ADD COLUMN dns_template_adoption_completed BOOLEAN NOT NULL DEFAULT false;

UPDATE sites site
SET dns_template_adoption_completed=true
WHERE EXISTS (
    SELECT 1
    FROM dns_records record
    WHERE record.owner_site_id=site.id
      AND record.origin='template'
)
OR EXISTS (
    SELECT 1
    FROM dns_template_sync_items item
    JOIN dns_template_sync_runs run ON run.id=item.run_id
    JOIN dns_zones zone ON zone.id=item.zone_id
    WHERE item.outcome='applied'
      AND (
          item.owner_site_id=site.id
          OR (
              run.scope<>'zone'
              AND (
                  zone.site_id=site.id
                  OR (site.parent_site_id=zone.site_id AND site.dns_zone_mode='parent')
              )
          )
      )
);

-- +goose Down
ALTER TABLE sites
    DROP COLUMN dns_template_adoption_completed;
