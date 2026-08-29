-- +goose Up
UPDATE dns_zones zone
SET template_revision=revision.revision
FROM dns_template_state state
JOIN dns_template_revisions revision ON revision.id=state.default_revision_id
WHERE zone.template_revision IS NULL;

ALTER TABLE dns_zones
    ALTER COLUMN template_revision SET NOT NULL,
    ADD CONSTRAINT dns_zones_template_revision_fk
        FOREIGN KEY (template_revision) REFERENCES dns_template_revisions(revision) ON DELETE RESTRICT;

ALTER TABLE dns_zones
    DROP CONSTRAINT dns_zones_template_status_check,
    ADD CONSTRAINT dns_zones_template_status_check
        CHECK (template_status IN ('in_sync', 'out_of_sync', 'customized', 'pending', 'failed'));

-- +goose Down
ALTER TABLE dns_zones
    DROP CONSTRAINT dns_zones_template_status_check;

UPDATE dns_zones SET template_status='pending' WHERE template_status='out_of_sync';

ALTER TABLE dns_zones
    ADD CONSTRAINT dns_zones_template_status_check
        CHECK (template_status IN ('in_sync', 'customized', 'pending', 'failed')),
    DROP CONSTRAINT dns_zones_template_revision_fk,
    ALTER COLUMN template_revision DROP NOT NULL;
