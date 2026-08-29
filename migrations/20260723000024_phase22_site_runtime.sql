-- +goose Up
CREATE TABLE site_runtime_generations (
    id BIGSERIAL PRIMARY KEY,
    site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK (generation > 0),
    php_version TEXT NOT NULL,
    policy JSONB NOT NULL CHECK (jsonb_typeof(policy)='object'),
    nginx_sha256 TEXT NOT NULL CHECK (nginx_sha256 ~ '^[a-f0-9]{64}$'),
    php_sha256 TEXT NOT NULL CHECK (php_sha256 ~ '^[a-f0-9]{64}$'),
    status TEXT NOT NULL DEFAULT 'candidate' CHECK (status IN ('candidate','active','failed','retired')),
    last_error TEXT NOT NULL DEFAULT '',
    activated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(site_id,generation)
);

CREATE UNIQUE INDEX site_runtime_active_generation_idx
ON site_runtime_generations(site_id) WHERE status='active';

-- Existing v1 policy documents intentionally remain v1. The control plane
-- upgrades them in memory with safe defaults, preserving their stored
-- entitlement values until an operator explicitly saves a v2 definition.

-- +goose Down
DROP TABLE IF EXISTS site_runtime_generations;
