-- +goose Up
-- Phase 26 stores typed desired/applied state. Privileged configuration
-- fragments remain outside PostgreSQL and are never accepted from the panel.
CREATE TABLE server_settings (
    category TEXT PRIMARY KEY
        CHECK (category ~ '^[a-z][a-z0-9_]{0,63}$'),
    desired JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(desired) = 'object'),
    applied JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(applied) = 'object'),
    desired_revision BIGINT NOT NULL DEFAULT 1
        CHECK (desired_revision >= 1),
    applied_revision BIGINT NOT NULL DEFAULT 0
        CHECK (applied_revision >= 0),
    convergence_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (convergence_status IN ('pending', 'applying', 'applied', 'failed')),
    last_good_config_hash BYTEA
        CHECK (last_good_config_hash IS NULL OR octet_length(last_good_config_hash) = 32),
    last_error TEXT NOT NULL DEFAULT '',
    updated_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (applied_revision <= desired_revision)
);
CREATE INDEX server_settings_status_idx
    ON server_settings (convergence_status, category);

CREATE TABLE server_inventory (
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]{0,63}$'),
    resource_key TEXT NOT NULL
        CHECK (length(resource_key) BETWEEN 1 AND 255),
    health_status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (health_status IN ('healthy', 'warning', 'critical', 'pending', 'unavailable', 'unknown')),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(payload) = 'object'),
    last_error TEXT NOT NULL DEFAULT '',
    checked_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kind, resource_key),
    CHECK (expires_at >= checked_at)
);
CREATE INDEX server_inventory_freshness_idx
    ON server_inventory (expires_at, kind, resource_key);
CREATE INDEX server_inventory_health_idx
    ON server_inventory (health_status, kind, resource_key);

CREATE TABLE server_operations (
    id BIGSERIAL PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE
        CHECK (operation_id ~ '^op_[A-Za-z0-9_-]{20,64}$'),
    category TEXT NOT NULL
        CHECK (category ~ '^[a-z][a-z0-9_]{0,63}$'),
    action TEXT NOT NULL
        CHECK (action ~ '^[a-z][a-z0-9_.-]{0,95}$'),
    target_type TEXT NOT NULL
        CHECK (target_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    target_key TEXT NOT NULL
        CHECK (length(target_key) BETWEEN 1 AND 255),
    request JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(request) = 'object'),
    result JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(result) = 'object'),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN (
            'pending', 'running', 'awaiting_confirmation', 'succeeded',
            'failed', 'rolled_back', 'cancelled'
        )),
    desired_revision BIGINT CHECK (desired_revision IS NULL OR desired_revision >= 1),
    idempotency_key TEXT CHECK (
        idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 128
    ),
    confirmation_deadline TIMESTAMPTZ,
    confirmed_at TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    actor_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (confirmed_at IS NULL OR confirmation_deadline IS NOT NULL)
);
CREATE UNIQUE INDEX server_operations_idempotency_idx
    ON server_operations (category, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX server_operations_status_idx
    ON server_operations (status, created_at, id);
CREATE INDEX server_operations_target_idx
    ON server_operations (target_type, target_key, created_at DESC, id DESC);

-- Each service secret is encrypted with a random data-encryption key. The data
-- key is itself wrapped by the versioned key loaded from NAKPANEL_SECRET_KEY_FILE.
CREATE TABLE service_secrets (
    id BIGSERIAL PRIMARY KEY,
    secret_id TEXT NOT NULL UNIQUE
        CHECK (secret_id ~ '^sec_[A-Za-z0-9_-]{20,64}$'),
    scope TEXT NOT NULL
        CHECK (scope ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    name TEXT NOT NULL
        CHECK (name ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM'
        CHECK (algorithm = 'AES-256-GCM'),
    key_version INTEGER NOT NULL CHECK (key_version >= 1),
    wrapped_key_nonce BYTEA NOT NULL
        CHECK (octet_length(wrapped_key_nonce) = 12),
    wrapped_data_key BYTEA NOT NULL
        CHECK (octet_length(wrapped_data_key) = 48),
    value_nonce BYTEA NOT NULL
        CHECK (octet_length(value_nonce) = 12),
    ciphertext BYTEA NOT NULL
        CHECK (octet_length(ciphertext) >= 16),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object'),
    updated_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope, name)
);
CREATE INDEX service_secrets_key_version_idx
    ON service_secrets (key_version, id);

-- These columns are backfilled so existing sessions keep working. Phase 26
-- authorization may then enforce recent authentication and revocation without
-- invalidating the deployed session format.
ALTER TABLE sessions ADD COLUMN authenticated_at TIMESTAMPTZ;
UPDATE sessions SET authenticated_at = created_at;
ALTER TABLE sessions ALTER COLUMN authenticated_at SET NOT NULL;
ALTER TABLE sessions ALTER COLUMN authenticated_at SET DEFAULT now();

ALTER TABLE sessions ADD COLUMN last_seen_at TIMESTAMPTZ;
UPDATE sessions SET last_seen_at = created_at;
ALTER TABLE sessions ALTER COLUMN last_seen_at SET NOT NULL;
ALTER TABLE sessions ALTER COLUMN last_seen_at SET DEFAULT now();

ALTER TABLE sessions ADD COLUMN revoked_at TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN revoked_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD CONSTRAINT sessions_revocation_reason_check
    CHECK (revoked_at IS NOT NULL OR revoked_reason = '');
CREATE INDEX sessions_active_user_idx
    ON sessions (user_id, expires_at)
    WHERE revoked_at IS NULL;

-- +goose Down
-- Refuse to discard the only copy of an encrypted relay credential. Operators
-- must restore the legacy value with a key-aware tool before rolling back to a
-- build that cannot read service_secrets.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM service_secrets ss
        JOIN mail_settings ms ON ms.id IS TRUE
        WHERE ss.scope = 'mail'
          AND ss.name = 'smarthost'
          AND ms.smarthost_host <> ''
          AND ms.smarthost_password = ''
    ) THEN
        RAISE EXCEPTION
            'cannot roll back Phase 26: restore the legacy smarthost credential before dropping service_secrets';
    END IF;
END;
$$;
-- +goose StatementEnd

DROP INDEX IF EXISTS sessions_active_user_idx;
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_revocation_reason_check;
ALTER TABLE sessions DROP COLUMN IF EXISTS revoked_reason;
ALTER TABLE sessions DROP COLUMN IF EXISTS revoked_at;
ALTER TABLE sessions DROP COLUMN IF EXISTS last_seen_at;
ALTER TABLE sessions DROP COLUMN IF EXISTS authenticated_at;

DROP TABLE IF EXISTS service_secrets;
DROP TABLE IF EXISTS server_operations;
DROP TABLE IF EXISTS server_inventory;
DROP TABLE IF EXISTS server_settings;
