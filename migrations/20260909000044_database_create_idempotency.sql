-- +goose Up
CREATE TABLE database_create_requests (
    scope_hash TEXT NOT NULL,
    request_key TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    database_id BIGINT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_hash, request_key)
);

-- +goose Down
DROP TABLE IF EXISTS database_create_requests;
