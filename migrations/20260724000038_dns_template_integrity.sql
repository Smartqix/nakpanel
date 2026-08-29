-- +goose Up
ALTER TABLE dns_records
    DROP CONSTRAINT dns_records_zone_id_host_record_type_value_priority_key,
    ADD CONSTRAINT dns_records_identity_key
        UNIQUE NULLS NOT DISTINCT (zone_id, host, record_type, value, priority, weight, port);

CREATE UNIQUE INDEX dns_records_template_owner_key_idx
    ON dns_records(zone_id, owner_site_id, template_record_key)
    WHERE origin='template';

-- +goose Down
DROP INDEX IF EXISTS dns_records_template_owner_key_idx;

ALTER TABLE dns_records
    DROP CONSTRAINT dns_records_identity_key,
    ADD CONSTRAINT dns_records_zone_id_host_record_type_value_priority_key
        UNIQUE NULLS NOT DISTINCT (zone_id, host, record_type, value, priority);
