-- +goose Up
CREATE TABLE databases (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    engine TEXT NOT NULL CHECK (engine IN ('mariadb', 'mysql', 'pgsql')),
    db_name TEXT NOT NULL UNIQUE,
    db_user TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'failed')) DEFAULT 'pending',
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX databases_owner_user_id_idx ON databases(owner_user_id);
CREATE INDEX databases_status_idx ON databases(status);
CREATE INDEX databases_engine_idx ON databases(engine);

-- +goose Down
DROP TABLE IF EXISTS databases;
