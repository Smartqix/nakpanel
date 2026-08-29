-- +goose Up
CREATE TABLE valkey_instances (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL UNIQUE REFERENCES subscriptions(id) ON DELETE CASCADE,
    desired_state TEXT NOT NULL DEFAULT 'disabled' CHECK (desired_state IN ('enabled','disabled','suspended')),
    applied_state TEXT NOT NULL DEFAULT 'pending' CHECK (applied_state IN ('pending','running','stopped','failed')),
    memory_mb INTEGER NOT NULL CHECK (memory_mb >= 0),
    max_clients INTEGER NOT NULL DEFAULT 64 CHECK (max_clients BETWEEN 1 AND 10000),
    idle_timeout_seconds INTEGER NOT NULL DEFAULT 300 CHECK (idle_timeout_seconds BETWEEN 0 AND 86400),
    cpu_percent INTEGER NOT NULL DEFAULT 25 CHECK (cpu_percent BETWEEN 1 AND 1000),
    process_limit INTEGER NOT NULL DEFAULT 64 CHECK (process_limit BETWEEN 8 AND 4096),
    acl_hash TEXT NOT NULL CHECK (acl_hash ~ '^[a-f0-9]{64}$'),
    flush_requested BOOLEAN NOT NULL DEFAULT false,
    socket_path TEXT NOT NULL DEFAULT '',
    convergence_status TEXT NOT NULL DEFAULT 'pending' CHECK (convergence_status IN ('pending','in_sync','failed')),
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE settings ADD COLUMN valkey_capacity_mb INTEGER NOT NULL DEFAULT 0 CHECK (valkey_capacity_mb >= 0);

-- +goose Down
ALTER TABLE settings DROP COLUMN IF EXISTS valkey_capacity_mb;
DROP TABLE IF EXISTS valkey_instances;
