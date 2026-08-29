-- +goose Up
CREATE TABLE git_repositories (
    id BIGSERIAL PRIMARY KEY,
    site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK (mode IN ('remote','hosted')),
    remote_url TEXT NOT NULL DEFAULT '',
    branch TEXT NOT NULL DEFAULT 'main',
    deploy_target TEXT NOT NULL DEFAULT '.',
    automatic BOOLEAN NOT NULL DEFAULT false,
    deploy_key_ciphertext BYTEA,
    known_host_key TEXT NOT NULL DEFAULT '',
    deploy_public_key TEXT NOT NULL DEFAULT '',
    webhook_secret_hash TEXT NOT NULL DEFAULT '',
    convergence_status TEXT NOT NULL DEFAULT 'pending' CHECK (convergence_status IN ('pending','in_sync','failed')),
    last_revision TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(site_id)
);

CREATE TABLE git_deployments (
    id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES git_repositories(id) ON DELETE CASCADE,
    revision TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','failed','rolled_back')),
    output TEXT NOT NULL DEFAULT '',
    rollback_revision TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);

CREATE TABLE protected_directories (
    id BIGSERIAL PRIMARY KEY,
    site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL CHECK (relative_path !~ '(^|/)\.\.(/|$)' AND relative_path !~ '^/'),
    realm TEXT NOT NULL,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(site_id,relative_path)
);

CREATE TABLE application_presets (
    id BIGSERIAL PRIMARY KEY,
    reseller_id BIGINT REFERENCES reseller_accounts(id) ON DELETE CASCADE,
    slug TEXT NOT NULL CHECK (slug ~ '^[a-z][a-z0-9-]{1,47}$'),
    name TEXT NOT NULL,
    runtime TEXT NOT NULL CHECK (runtime IN ('php','node','python','oci')),
    image_ref TEXT NOT NULL CHECK (image_ref ~ '@sha256:[a-f0-9]{64}$'),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX application_presets_admin_slug_idx
ON application_presets(slug) WHERE reseller_id IS NULL;
CREATE UNIQUE INDEX application_presets_reseller_slug_idx
ON application_presets(reseller_id,slug) WHERE reseller_id IS NOT NULL;

CREATE TABLE staging_operations (
    id BIGSERIAL PRIMARY KEY,
    source_site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    target_site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    direction TEXT NOT NULL CHECK (direction IN ('copy_to_staging','promote')),
    include_database BOOLEAN NOT NULL DEFAULT false,
    backup_id BIGINT REFERENCES backups(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed','rolled_back')),
    snapshot_path TEXT NOT NULL DEFAULT '',
    database_snapshot_paths TEXT[] NOT NULL DEFAULT '{}',
    copied_bytes BIGINT NOT NULL DEFAULT 0 CHECK (copied_bytes >= 0),
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    CHECK(source_site_id<>target_site_id)
);
CREATE UNIQUE INDEX staging_operations_active_target_idx
ON staging_operations(target_site_id) WHERE status IN ('pending','running');

-- +goose Down
DROP INDEX IF EXISTS staging_operations_active_target_idx;
DROP TABLE IF EXISTS staging_operations;
DROP TABLE IF EXISTS application_presets;
DROP TABLE IF EXISTS protected_directories;
DROP TABLE IF EXISTS git_deployments;
DROP TABLE IF EXISTS git_repositories;
