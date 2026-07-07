-- +goose Up
ALTER TABLE sites
    ADD COLUMN tls_status TEXT NOT NULL CHECK (tls_status IN ('none', 'pending', 'active', 'failed')) DEFAULT 'none',
    ADD COLUMN tls_issuer TEXT NOT NULL DEFAULT '',
    ADD COLUMN tls_cert_path TEXT NOT NULL DEFAULT '',
    ADD COLUMN tls_key_path TEXT NOT NULL DEFAULT '',
    ADD COLUMN tls_expires_at TIMESTAMPTZ,
    ADD COLUMN tls_last_error TEXT NOT NULL DEFAULT '';

CREATE INDEX sites_tls_status_idx ON sites(tls_status);

-- +goose Down
DROP INDEX IF EXISTS sites_tls_status_idx;
ALTER TABLE sites
    DROP COLUMN IF EXISTS tls_last_error,
    DROP COLUMN IF EXISTS tls_expires_at,
    DROP COLUMN IF EXISTS tls_key_path,
    DROP COLUMN IF EXISTS tls_cert_path,
    DROP COLUMN IF EXISTS tls_issuer,
    DROP COLUMN IF EXISTS tls_status;
