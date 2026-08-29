-- +goose Up
ALTER TABLE sites
    ADD COLUMN parent_site_id BIGINT REFERENCES sites(id) ON DELETE SET NULL,
    ADD COLUMN dns_zone_mode TEXT NOT NULL DEFAULT 'parent'
        CHECK (dns_zone_mode IN ('parent', 'separate'));

UPDATE sites child
SET parent_site_id = (
    SELECT candidate.id
    FROM sites candidate
    WHERE candidate.subscription_id=child.subscription_id
      AND candidate.id<>child.id
      AND child.domain LIKE '%.' || candidate.domain
    ORDER BY length(candidate.domain) DESC, candidate.id
    LIMIT 1
)
WHERE EXISTS (
    SELECT 1 FROM sites candidate
    WHERE candidate.subscription_id=child.subscription_id
      AND candidate.id<>child.id
      AND child.domain LIKE '%.' || candidate.domain
);

-- Existing authoritative zones keep their current independent behavior.
UPDATE sites site
SET dns_zone_mode='separate'
WHERE site.parent_site_id IS NULL
   OR EXISTS (SELECT 1 FROM dns_zones zone WHERE zone.site_id=site.id);

CREATE INDEX sites_parent_site_id_idx ON sites(parent_site_id);

CREATE TABLE dns_template_revisions (
    id BIGSERIAL PRIMARY KEY,
    revision BIGINT NOT NULL UNIQUE,
    primary_nameserver TEXT NOT NULL,
    responsible_mailbox TEXT NOT NULL,
    serial_format TEXT NOT NULL DEFAULT 'unix'
        CHECK (serial_format IN ('unix', 'date-counter')),
    default_ttl INTEGER NOT NULL DEFAULT 3600 CHECK (default_ttl BETWEEN 60 AND 86400),
    refresh_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (refresh_seconds BETWEEN 300 AND 86400),
    retry_seconds INTEGER NOT NULL DEFAULT 900 CHECK (retry_seconds BETWEEN 60 AND 86400),
    expire_seconds INTEGER NOT NULL DEFAULT 604800 CHECK (expire_seconds BETWEEN 86400 AND 2419200),
    minimum_ttl INTEGER NOT NULL DEFAULT 300 CHECK (minimum_ttl BETWEEN 60 AND 86400),
    zone_status TEXT NOT NULL DEFAULT 'active' CHECK (zone_status IN ('active', 'disabled')),
    subdomain_policy TEXT NOT NULL DEFAULT 'parent' CHECK (subdomain_policy IN ('parent', 'separate')),
    transfer_cidrs CIDR[] NOT NULL DEFAULT '{}',
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE dns_template_records (
    id BIGSERIAL PRIMARY KEY,
    revision_id BIGINT NOT NULL REFERENCES dns_template_revisions(id) ON DELETE RESTRICT,
    stable_key TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'all' CHECK (scope IN ('all', 'root', 'subdomain')),
    host_template TEXT NOT NULL,
    record_type TEXT NOT NULL CHECK (record_type IN ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'DS')),
    value_template TEXT NOT NULL,
    priority INTEGER,
    weight INTEGER,
    port INTEGER,
    ttl INTEGER NOT NULL CHECK (ttl BETWEEN 60 AND 86400),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT dns_template_records_stable_key_not_blank CHECK (length(btrim(stable_key)) > 0),
    CONSTRAINT dns_template_records_host_not_blank CHECK (length(btrim(host_template)) > 0),
    CONSTRAINT dns_template_records_value_not_blank CHECK (length(btrim(value_template)) > 0),
    UNIQUE (revision_id, stable_key)
);

CREATE TABLE dns_template_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    active_revision_id BIGINT NOT NULL REFERENCES dns_template_revisions(id) ON DELETE RESTRICT,
    default_revision_id BIGINT NOT NULL REFERENCES dns_template_revisions(id) ON DELETE RESTRICT,
    optimistic_revision BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE dns_zones
    ADD COLUMN ipv6_address TEXT NOT NULL DEFAULT '',
    ADD COLUMN mode TEXT NOT NULL DEFAULT 'primary'
        CHECK (mode IN ('primary', 'secondary', 'disabled')),
    ADD COLUMN upstream_primaries TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN parent_zone_id BIGINT REFERENCES dns_zones(id) ON DELETE SET NULL,
    ADD COLUMN template_revision BIGINT,
    ADD COLUMN template_status TEXT NOT NULL DEFAULT 'customized'
        CHECK (template_status IN ('in_sync', 'customized', 'pending', 'failed')),
    ADD COLUMN desired_revision BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN applied_revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN soa_override JSONB,
    ADD COLUMN transfer_cidrs CIDR[];

CREATE INDEX dns_zones_parent_zone_id_idx ON dns_zones(parent_zone_id);
CREATE INDEX dns_zones_template_revision_idx ON dns_zones(template_revision);
CREATE INDEX dns_zones_desired_revision_idx ON dns_zones(desired_revision, applied_revision);

ALTER TABLE dns_records
    DROP CONSTRAINT dns_records_record_type_check,
    DROP CONSTRAINT dns_records_mx_priority_check,
    ADD COLUMN weight INTEGER,
    ADD COLUMN port INTEGER,
    ADD COLUMN origin TEXT NOT NULL DEFAULT 'custom'
        CHECK (origin IN ('template', 'system', 'custom')),
    ADD COLUMN template_record_key TEXT,
    ADD COLUMN template_revision BIGINT,
    ADD COLUMN owner_site_id BIGINT REFERENCES sites(id) ON DELETE CASCADE,
    ADD COLUMN locally_modified BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT dns_records_record_type_check
        CHECK (record_type IN ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'DS')),
    ADD CONSTRAINT dns_records_priority_fields_check CHECK (
        (record_type IN ('MX', 'SRV') AND priority BETWEEN 0 AND 65535)
        OR (record_type NOT IN ('MX', 'SRV') AND priority IS NULL)
    ),
    ADD CONSTRAINT dns_records_srv_fields_check CHECK (
        (record_type='SRV' AND weight BETWEEN 0 AND 65535 AND port BETWEEN 1 AND 65535)
        OR (record_type<>'SRV' AND weight IS NULL AND port IS NULL)
    ),
    ADD CONSTRAINT dns_records_template_link_check CHECK (
        (origin='template' AND template_record_key IS NOT NULL AND template_revision IS NOT NULL)
        OR origin<>'template'
    );

UPDATE dns_records record
SET owner_site_id=zone.site_id
FROM dns_zones zone
WHERE zone.id=record.zone_id;

CREATE INDEX dns_records_owner_site_id_idx ON dns_records(owner_site_id);
CREATE INDEX dns_records_template_key_idx ON dns_records(zone_id, template_record_key)
    WHERE template_record_key IS NOT NULL;

CREATE TABLE dns_template_sync_runs (
    id BIGSERIAL PRIMARY KEY,
    template_revision BIGINT NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('unmodified', 'all', 'zone')),
    target_zone_id BIGINT REFERENCES dns_zones(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'preview'
        CHECK (status IN ('preview', 'pending', 'running', 'active', 'partial', 'failed', 'stale')),
    preview_token TEXT NOT NULL UNIQUE,
    expected_template_state_revision BIGINT NOT NULL,
    confirmation TEXT NOT NULL DEFAULT '',
    actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    total_zones INTEGER NOT NULL DEFAULT 0,
    changed_zones INTEGER NOT NULL DEFAULT 0,
    failed_zones INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE TABLE dns_template_sync_items (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT NOT NULL REFERENCES dns_template_sync_runs(id) ON DELETE CASCADE,
    zone_id BIGINT NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
    owner_site_id BIGINT REFERENCES sites(id) ON DELETE CASCADE,
    expected_zone_revision BIGINT NOT NULL,
    desired_revision BIGINT,
    outcome TEXT NOT NULL DEFAULT 'unchanged'
        CHECK (outcome IN ('unchanged', 'added', 'updated', 'removed', 'overridden', 'conflict', 'applied', 'failed')),
    added_count INTEGER NOT NULL DEFAULT 0,
    updated_count INTEGER NOT NULL DEFAULT 0,
    removed_count INTEGER NOT NULL DEFAULT 0,
    override_count INTEGER NOT NULL DEFAULT 0,
    conflict_count INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (run_id, zone_id)
);

CREATE INDEX dns_template_sync_runs_created_at_idx ON dns_template_sync_runs(created_at DESC);
CREATE INDEX dns_template_sync_items_zone_id_idx ON dns_template_sync_items(zone_id, created_at DESC);

INSERT INTO dns_template_revisions(
    revision, primary_nameserver, responsible_mailbox, serial_format,
    default_ttl, refresh_seconds, retry_seconds, expire_seconds, minimum_ttl,
    zone_status, subdomain_policy, transfer_cidrs
) VALUES (
    1, 'ns1.<domain>', 'hostmaster.<domain>', 'unix',
    3600, 3600, 900, 604800, 300, 'active', 'parent', '{}'
);

INSERT INTO dns_template_records(
    revision_id, stable_key, scope, host_template, record_type, value_template, priority, weight, port, ttl
)
SELECT revision.id, record.stable_key, record.scope, record.host_template, record.record_type,
       record.value_template, record.priority, NULL, NULL, record.ttl
FROM dns_template_revisions revision
CROSS JOIN (VALUES
    ('apex-a', 'all', '@', 'A', '<ip.web>', NULL::INTEGER, 3600),
    ('www-a', 'root', 'www', 'A', '<ip.web>', NULL::INTEGER, 3600),
    ('primary-ns', 'root', '@', 'NS', 'ns1.<domain>', NULL::INTEGER, 3600),
    ('ns1-a', 'root', 'ns1', 'A', '<ip.dns>', NULL::INTEGER, 3600)
) AS record(stable_key, scope, host_template, record_type, value_template, priority, ttl)
WHERE revision.revision=1;

INSERT INTO dns_template_state(active_revision_id, default_revision_id)
SELECT id, id FROM dns_template_revisions WHERE revision=1;

-- Materialize records that the legacy BIND renderer used to synthesize. They
-- are system-owned so template synchronization and customer reset preserve
-- them until the corresponding service explicitly changes them.
INSERT INTO dns_records(
    zone_id, host, record_type, value, ttl, origin, owner_site_id
)
SELECT zone.id, '@', 'NS', 'ns1.' || zone.domain, 3600, 'system', zone.site_id
FROM dns_zones zone
ON CONFLICT DO NOTHING;

INSERT INTO dns_records(
    zone_id, host, record_type, value, ttl, origin, owner_site_id
)
SELECT zone.id, 'ns1', 'A', zone.address, 3600, 'system', zone.site_id
FROM dns_zones zone
WHERE zone.address<>''
ON CONFLICT DO NOTHING;

INSERT INTO dns_records(
    zone_id, host, record_type, value, ttl, origin, owner_site_id
)
SELECT zone.id, 'webmail', 'A', zone.address, 3600, 'system', zone.site_id
FROM dns_zones zone
WHERE zone.address<>''
ON CONFLICT DO NOTHING;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION nakpanel_dns_template_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'DNS template revisions are immutable';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER dns_template_revisions_immutable
BEFORE UPDATE OR DELETE ON dns_template_revisions
FOR EACH ROW EXECUTE FUNCTION nakpanel_dns_template_immutable();

CREATE TRIGGER dns_template_records_immutable
BEFORE UPDATE OR DELETE ON dns_template_records
FOR EACH ROW EXECUTE FUNCTION nakpanel_dns_template_immutable();

-- +goose Down
DROP TRIGGER IF EXISTS dns_template_records_immutable ON dns_template_records;
DROP TRIGGER IF EXISTS dns_template_revisions_immutable ON dns_template_revisions;
DROP FUNCTION IF EXISTS nakpanel_dns_template_immutable();

DROP TABLE IF EXISTS dns_template_sync_items;
DROP TABLE IF EXISTS dns_template_sync_runs;
DROP TABLE IF EXISTS dns_template_state;
DROP TABLE IF EXISTS dns_template_records;
DROP TABLE IF EXISTS dns_template_revisions;

DROP INDEX IF EXISTS dns_records_template_key_idx;
DROP INDEX IF EXISTS dns_records_owner_site_id_idx;
DELETE FROM dns_records
WHERE record_type IN ('NS','SRV','CAA','DS')
   OR (origin='system' AND host IN ('ns1','webmail'));
ALTER TABLE dns_records
    DROP CONSTRAINT IF EXISTS dns_records_template_link_check,
    DROP CONSTRAINT IF EXISTS dns_records_srv_fields_check,
    DROP CONSTRAINT IF EXISTS dns_records_priority_fields_check,
    DROP CONSTRAINT IF EXISTS dns_records_record_type_check,
    DROP COLUMN IF EXISTS locally_modified,
    DROP COLUMN IF EXISTS owner_site_id,
    DROP COLUMN IF EXISTS template_revision,
    DROP COLUMN IF EXISTS template_record_key,
    DROP COLUMN IF EXISTS origin,
    DROP COLUMN IF EXISTS port,
    DROP COLUMN IF EXISTS weight,
    ADD CONSTRAINT dns_records_record_type_check CHECK (record_type IN ('A', 'AAAA', 'CNAME', 'MX', 'TXT')),
    ADD CONSTRAINT dns_records_mx_priority_check CHECK (
        (record_type = 'MX' AND priority BETWEEN 0 AND 65535)
        OR (record_type <> 'MX' AND priority IS NULL)
    );

DROP INDEX IF EXISTS dns_zones_desired_revision_idx;
DROP INDEX IF EXISTS dns_zones_template_revision_idx;
DROP INDEX IF EXISTS dns_zones_parent_zone_id_idx;
ALTER TABLE dns_zones
    DROP COLUMN IF EXISTS transfer_cidrs,
    DROP COLUMN IF EXISTS soa_override,
    DROP COLUMN IF EXISTS applied_revision,
    DROP COLUMN IF EXISTS desired_revision,
    DROP COLUMN IF EXISTS template_status,
    DROP COLUMN IF EXISTS template_revision,
    DROP COLUMN IF EXISTS parent_zone_id,
    DROP COLUMN IF EXISTS upstream_primaries,
    DROP COLUMN IF EXISTS mode,
    DROP COLUMN IF EXISTS ipv6_address;

DROP INDEX IF EXISTS sites_parent_site_id_idx;
ALTER TABLE sites
    DROP COLUMN IF EXISTS dns_zone_mode,
    DROP COLUMN IF EXISTS parent_site_id;
