-- +goose Up
CREATE TABLE database_manager_grants (
    token_hash TEXT PRIMARY KEY CHECK (token_hash ~ '^[a-f0-9]{64}$'),
    session_hash TEXT NOT NULL,
    actor_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    database_id BIGINT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    credential_revision TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX database_manager_grants_database_idx ON database_manager_grants(database_id);
-- +goose Down
DROP TABLE database_manager_grants;
