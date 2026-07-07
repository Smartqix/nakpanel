-- +goose Up
CREATE TABLE backups (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    site_id BIGINT REFERENCES sites(id) ON DELETE SET NULL,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('site')),
    target_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'failed')) DEFAULT 'pending',
    archive_path TEXT NOT NULL DEFAULT '',
    size_bytes BIGINT NOT NULL DEFAULT 0,
    checksum_sha256 TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE adminer_tokens (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE restore_runs (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    backup_id BIGINT REFERENCES backups(id) ON DELETE SET NULL,
    target_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'failed', 'blocked')) DEFAULT 'pending',
    restored_at TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE webmail_hosts (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'failed')) DEFAULT 'pending',
    config_path TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE dns_zones (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    domain TEXT NOT NULL UNIQUE,
    address TEXT NOT NULL,
    serial BIGINT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'failed')) DEFAULT 'pending',
    zone_path TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE reconciliation_runs (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'failed')) DEFAULT 'pending',
    sites_total INTEGER NOT NULL DEFAULT 0,
    sites_ok INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE reseller_quotas (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    max_sites INTEGER NOT NULL DEFAULT 0,
    max_databases INTEGER NOT NULL DEFAULT 0,
    storage_mb INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX backups_owner_user_id_idx ON backups(owner_user_id);
CREATE INDEX backups_status_idx ON backups(status);
CREATE INDEX adminer_tokens_owner_user_id_idx ON adminer_tokens(owner_user_id);
CREATE INDEX adminer_tokens_expires_at_idx ON adminer_tokens(expires_at);
CREATE INDEX restore_runs_backup_id_idx ON restore_runs(backup_id);
CREATE INDEX restore_runs_status_idx ON restore_runs(status);
CREATE INDEX webmail_hosts_site_id_idx ON webmail_hosts(site_id);
CREATE INDEX webmail_hosts_status_idx ON webmail_hosts(status);
CREATE INDEX dns_zones_site_id_idx ON dns_zones(site_id);
CREATE INDEX dns_zones_status_idx ON dns_zones(status);
CREATE INDEX reconciliation_runs_status_idx ON reconciliation_runs(status);

-- +goose Down
DROP TABLE IF EXISTS reseller_quotas;
DROP TABLE IF EXISTS reconciliation_runs;
DROP TABLE IF EXISTS dns_zones;
DROP TABLE IF EXISTS webmail_hosts;
DROP TABLE IF EXISTS restore_runs;
DROP TABLE IF EXISTS adminer_tokens;
DROP TABLE IF EXISTS backups;
