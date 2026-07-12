-- +goose Up
ALTER TABLE sites
    ADD COLUMN desired_status TEXT NOT NULL DEFAULT 'active'
        CHECK (desired_status IN ('active', 'suspended')),
    ADD COLUMN desired_php_version TEXT NOT NULL DEFAULT '8.3'
        CHECK (length(btrim(desired_php_version)) > 0),
    ADD COLUMN https_redirect BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN desired_https_redirect BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN settings_status TEXT NOT NULL DEFAULT 'in_sync'
        CHECK (settings_status IN ('in_sync', 'pending', 'failed')),
    ADD COLUMN settings_error TEXT NOT NULL DEFAULT '';

UPDATE sites SET desired_php_version = php_version;

ALTER TABLE databases
    ADD COLUMN site_id BIGINT REFERENCES sites(id) ON DELETE SET NULL;
CREATE INDEX databases_site_id_idx ON databases(site_id);

CREATE TABLE dns_records (
    id BIGSERIAL PRIMARY KEY,
    zone_id BIGINT NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    record_type TEXT NOT NULL CHECK (record_type IN ('A', 'AAAA', 'CNAME', 'MX', 'TXT')),
    value TEXT NOT NULL,
    priority INTEGER,
    ttl INTEGER NOT NULL DEFAULT 3600 CHECK (ttl BETWEEN 60 AND 86400),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT dns_records_host_not_blank CHECK (length(btrim(host)) > 0),
    CONSTRAINT dns_records_value_not_blank CHECK (length(btrim(value)) > 0),
    CONSTRAINT dns_records_mx_priority_check CHECK (
        (record_type = 'MX' AND priority BETWEEN 0 AND 65535)
        OR (record_type <> 'MX' AND priority IS NULL)
    ),
    UNIQUE NULLS NOT DISTINCT (zone_id, host, record_type, value, priority)
);
CREATE INDEX dns_records_zone_id_idx ON dns_records(zone_id);

INSERT INTO dns_records(zone_id, host, record_type, value, ttl)
SELECT id, '@', 'A', address, 3600
FROM dns_zones
WHERE address <> ''
ON CONFLICT DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS dns_records;
DROP INDEX IF EXISTS databases_site_id_idx;
ALTER TABLE databases DROP COLUMN IF EXISTS site_id;
ALTER TABLE sites
    DROP COLUMN IF EXISTS settings_error,
    DROP COLUMN IF EXISTS settings_status,
    DROP COLUMN IF EXISTS desired_https_redirect,
    DROP COLUMN IF EXISTS https_redirect,
    DROP COLUMN IF EXISTS desired_php_version,
    DROP COLUMN IF EXISTS desired_status;
