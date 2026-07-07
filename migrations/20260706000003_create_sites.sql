-- +goose Up
CREATE TABLE sites (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    username TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL UNIQUE,
    php_version TEXT NOT NULL CHECK (php_version IN ('8.2', '8.3')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'failed')) DEFAULT 'pending',
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX sites_owner_user_id_idx ON sites(owner_user_id);
CREATE INDEX sites_status_idx ON sites(status);

-- +goose Down
DROP TABLE IF EXISTS sites;
