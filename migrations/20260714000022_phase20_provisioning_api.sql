-- +goose Up
ALTER TABLE plans ADD COLUMN api_slug TEXT;

WITH normalized AS (
    SELECT id,
           trim(both '-' FROM regexp_replace(lower(name), '[^a-z0-9]+', '-', 'g')) AS base_slug
    FROM plans
), ranked AS (
    SELECT p.id,
           CASE WHEN n.base_slug = '' THEN 'plan-' || p.id::text ELSE left(n.base_slug, 56) END AS base_slug,
           row_number() OVER (
               PARTITION BY p.reseller_id,
                            CASE WHEN n.base_slug = '' THEN 'plan-' || p.id::text ELSE left(n.base_slug, 56) END
               ORDER BY p.id
           ) AS duplicate_number
    FROM plans p JOIN normalized n ON n.id = p.id
)
UPDATE plans p
SET api_slug = r.base_slug || CASE WHEN r.duplicate_number > 1 THEN '-' || p.id::text ELSE '' END
FROM ranked r
WHERE r.id = p.id;

ALTER TABLE plans ALTER COLUMN api_slug SET NOT NULL;
ALTER TABLE plans ADD CONSTRAINT plans_api_slug_format_check
    CHECK (api_slug ~ '^[a-z0-9][a-z0-9-]{0,63}$');
CREATE UNIQUE INDEX plans_api_slug_admin_idx
    ON plans (api_slug) WHERE reseller_id IS NULL;
CREATE UNIQUE INDEX plans_api_slug_reseller_idx
    ON plans (reseller_id, api_slug) WHERE reseller_id IS NOT NULL;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION assign_plan_api_slug() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    base_slug TEXT;
BEGIN
    IF NEW.api_slug IS NULL OR btrim(NEW.api_slug) = '' THEN
        base_slug := trim(both '-' FROM regexp_replace(lower(NEW.name), '[^a-z0-9]+', '-', 'g'));
        IF base_slug = '' THEN
            base_slug := 'plan';
        END IF;
        base_slug := left(base_slug, 48);
        -- The sequence-backed suffix makes concurrent plan creation collision-safe.
        NEW.api_slug := base_slug || '-' || NEW.id::text;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER plans_assign_api_slug
BEFORE INSERT ON plans
FOR EACH ROW EXECUTE FUNCTION assign_plan_api_slug();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION protect_plan_api_slug() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.api_slug IS DISTINCT FROM OLD.api_slug THEN
        RAISE EXCEPTION 'plan API slug is immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER plans_api_slug_immutable
BEFORE UPDATE ON plans
FOR EACH ROW EXECUTE FUNCTION protect_plan_api_slug();

CREATE TABLE api_keys (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 120),
    key_prefix TEXT NOT NULL UNIQUE CHECK (key_prefix ~ '^[A-Za-z0-9_-]{10,24}$'),
    key_salt BYTEA NOT NULL CHECK (octet_length(key_salt) >= 16),
    key_hash BYTEA NOT NULL CHECK (octet_length(key_hash) = 32),
    scope TEXT NOT NULL DEFAULT 'provisioning' CHECK (scope = 'provisioning'),
    ip_allowlist CIDR[] NOT NULL DEFAULT '{}'::cidr[],
    rate_limit_per_minute INTEGER NOT NULL DEFAULT 120 CHECK (rate_limit_per_minute BETWEEN 1 AND 100000),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX api_keys_active_idx ON api_keys (key_prefix) WHERE revoked_at IS NULL;

CREATE TABLE billing_accounts (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL UNIQUE REFERENCES subscriptions(id) ON DELETE RESTRICT,
    public_id TEXT NOT NULL UNIQUE CHECK (public_id ~ '^acc_[A-Za-z0-9_-]{20,64}$'),
    external_ref TEXT NOT NULL UNIQUE CHECK (external_ref ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    provider_reseller_id BIGINT REFERENCES reseller_accounts(id) ON DELETE RESTRICT,
    primary_site_id BIGINT REFERENCES sites(id) ON DELETE SET NULL,
    provisioning_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (provisioning_state IN ('pending', 'active', 'failed', 'terminating', 'terminated')),
    over_limit BOOLEAN NOT NULL DEFAULT false,
    last_error TEXT NOT NULL DEFAULT '',
    cancelled_at TIMESTAMPTZ,
    purge_eligible_at TIMESTAMPTZ,
    purge_requested_at TIMESTAMPTZ,
    terminated_at TIMESTAMPTZ,
    created_by_api_key_id BIGINT REFERENCES api_keys(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX billing_accounts_provider_idx ON billing_accounts (provider_reseller_id, id);
CREATE INDEX billing_accounts_state_idx ON billing_accounts (provisioning_state, id);

CREATE TABLE api_idempotency_records (
    id BIGSERIAL PRIMARY KEY,
    api_key_id BIGINT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
    response_status INTEGER CHECK (response_status BETWEEN 100 AND 599),
    response_body JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '7 days'),
    UNIQUE (api_key_id, idempotency_key)
);
CREATE INDEX api_idempotency_expiry_idx ON api_idempotency_records (expires_at);

CREATE TABLE customer_login_tokens (
    id BIGSERIAL PRIMARY KEY,
    billing_account_id BIGINT NOT NULL REFERENCES billing_accounts(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX customer_login_tokens_active_idx ON customer_login_tokens (expires_at)
    WHERE used_at IS NULL;

CREATE TABLE billing_webhook_outbox (
    id BIGSERIAL PRIMARY KEY,
    delivery_id TEXT NOT NULL UNIQUE,
    billing_account_id BIGINT NOT NULL REFERENCES billing_accounts(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'account.provisioned', 'account.provision_failed', 'account.suspended',
        'account.unsuspended', 'account.terminated', 'account.usage_exceeded'
    )),
    dedupe_key TEXT NOT NULL UNIQUE,
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivering', 'sent', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    response_status INTEGER,
    last_error TEXT NOT NULL DEFAULT '',
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX billing_webhook_outbox_pending_idx
    ON billing_webhook_outbox (status, created_at, id) WHERE status IN ('pending', 'failed');

ALTER TABLE subscription_system_accounts DROP CONSTRAINT subscription_system_accounts_desired_state_check;
ALTER TABLE subscription_system_accounts ADD CONSTRAINT subscription_system_accounts_desired_state_check
    CHECK (desired_state IN ('active', 'suspended', 'terminated'));
ALTER TABLE subscription_system_accounts DROP CONSTRAINT subscription_system_accounts_applied_state_check;
ALTER TABLE subscription_system_accounts ADD CONSTRAINT subscription_system_accounts_applied_state_check
    CHECK (applied_state IN ('pending', 'active', 'suspended', 'failed', 'terminated'));

-- +goose Down
UPDATE subscription_system_accounts SET desired_state='suspended' WHERE desired_state='terminated';
UPDATE subscription_system_accounts SET applied_state='suspended' WHERE applied_state='terminated';
ALTER TABLE subscription_system_accounts DROP CONSTRAINT subscription_system_accounts_applied_state_check;
ALTER TABLE subscription_system_accounts ADD CONSTRAINT subscription_system_accounts_applied_state_check
    CHECK (applied_state IN ('pending', 'active', 'suspended', 'failed'));
ALTER TABLE subscription_system_accounts DROP CONSTRAINT subscription_system_accounts_desired_state_check;
ALTER TABLE subscription_system_accounts ADD CONSTRAINT subscription_system_accounts_desired_state_check
    CHECK (desired_state IN ('active', 'suspended'));

DROP TABLE IF EXISTS billing_webhook_outbox;
DROP TABLE IF EXISTS customer_login_tokens;
DROP TABLE IF EXISTS api_idempotency_records;
DROP TABLE IF EXISTS billing_accounts;
DROP TABLE IF EXISTS api_keys;
DROP TRIGGER IF EXISTS plans_assign_api_slug ON plans;
DROP FUNCTION IF EXISTS assign_plan_api_slug();
DROP TRIGGER IF EXISTS plans_api_slug_immutable ON plans;
DROP FUNCTION IF EXISTS protect_plan_api_slug();
DROP INDEX IF EXISTS plans_api_slug_reseller_idx;
DROP INDEX IF EXISTS plans_api_slug_admin_idx;
ALTER TABLE plans DROP CONSTRAINT IF EXISTS plans_api_slug_format_check;
ALTER TABLE plans DROP COLUMN IF EXISTS api_slug;
