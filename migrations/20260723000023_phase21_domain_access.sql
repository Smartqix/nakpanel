-- +goose Up
CREATE TABLE ftp_accounts (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    site_id BIGINT REFERENCES sites(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (name ~ '^[a-z][a-z0-9._-]{2,31}$'),
    password_hash TEXT NOT NULL CHECK (password_hash LIKE '$6$%'),
    enabled BOOLEAN NOT NULL DEFAULT true,
    convergence_status TEXT NOT NULL DEFAULT 'pending' CHECK (convergence_status IN ('pending','in_sync','failed')),
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name)
);

CREATE UNIQUE INDEX ftp_accounts_primary_subscription_idx
ON ftp_accounts(subscription_id) WHERE site_id IS NULL;
CREATE INDEX ftp_accounts_site_idx ON ftp_accounts(site_id);

-- +goose Down
DROP TABLE IF EXISTS ftp_accounts;
