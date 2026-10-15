-- +goose Up
CREATE TABLE dns_template_deletions (
    zone_id bigint NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
    owner_site_id bigint NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    template_record_key text NOT NULL CHECK (template_record_key <> ''),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (zone_id, owner_site_id, template_record_key)
);

-- +goose Down
DROP TABLE dns_template_deletions;
