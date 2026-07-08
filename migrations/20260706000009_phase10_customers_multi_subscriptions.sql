-- +goose Up
CREATE TABLE customers (
    id BIGSERIAL PRIMARY KEY,
    login_user_id BIGINT UNIQUE REFERENCES users(id) ON DELETE SET NULL,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    company TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX customers_email_lower_idx ON customers(lower(email));
CREATE INDEX customers_status_idx ON customers(status);

INSERT INTO customers (login_user_id, email, display_name, status)
SELECT id, email, email, 'active'
FROM users
ON CONFLICT (login_user_id) DO NOTHING;

ALTER TABLE subscriptions
    ADD COLUMN customer_id BIGINT REFERENCES customers(id) ON DELETE RESTRICT,
    ADD COLUMN name TEXT NOT NULL DEFAULT '';

UPDATE subscriptions s
SET
    customer_id = (SELECT c.id FROM customers c WHERE c.login_user_id = s.customer_user_id),
    name = COALESCE(NULLIF(s.name, ''), (SELECT p.name FROM plans p WHERE p.id = s.plan_id) || ' subscription')
WHERE s.customer_id IS NULL;

ALTER TABLE subscriptions
    ALTER COLUMN customer_id SET NOT NULL,
    ALTER COLUMN customer_user_id DROP NOT NULL;

DROP INDEX IF EXISTS subscriptions_one_active_per_customer_idx;
CREATE INDEX subscriptions_customer_id_idx ON subscriptions(customer_id);
CREATE INDEX subscriptions_customer_status_idx ON subscriptions(customer_id, status);

ALTER TABLE sites
    ADD COLUMN customer_id BIGINT REFERENCES customers(id) ON DELETE RESTRICT;

ALTER TABLE databases
    ADD COLUMN customer_id BIGINT REFERENCES customers(id) ON DELETE RESTRICT;

ALTER TABLE backups
    ADD COLUMN customer_id BIGINT REFERENCES customers(id) ON DELETE RESTRICT;

UPDATE sites r
SET customer_id = COALESCE(
    (SELECT s.customer_id FROM subscriptions s WHERE s.id = r.subscription_id),
    (SELECT c.id FROM customers c WHERE c.login_user_id = r.owner_user_id)
)
WHERE r.customer_id IS NULL;

UPDATE databases r
SET customer_id = COALESCE(
    (SELECT s.customer_id FROM subscriptions s WHERE s.id = r.subscription_id),
    (SELECT c.id FROM customers c WHERE c.login_user_id = r.owner_user_id)
)
WHERE r.customer_id IS NULL;

UPDATE backups r
SET customer_id = COALESCE(
    (SELECT s.customer_id FROM subscriptions s WHERE s.id = r.subscription_id),
    (SELECT c.id FROM customers c WHERE c.login_user_id = r.owner_user_id)
)
WHERE r.customer_id IS NULL;

CREATE INDEX sites_customer_id_idx ON sites(customer_id);
CREATE INDEX databases_customer_id_idx ON databases(customer_id);
CREATE INDEX backups_customer_id_idx ON backups(customer_id);

-- +goose Down
DROP INDEX IF EXISTS backups_customer_id_idx;
DROP INDEX IF EXISTS databases_customer_id_idx;
DROP INDEX IF EXISTS sites_customer_id_idx;
ALTER TABLE backups DROP COLUMN IF EXISTS customer_id;
ALTER TABLE databases DROP COLUMN IF EXISTS customer_id;
ALTER TABLE sites DROP COLUMN IF EXISTS customer_id;

DROP INDEX IF EXISTS subscriptions_customer_status_idx;
DROP INDEX IF EXISTS subscriptions_customer_id_idx;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS name;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS customer_id;
ALTER TABLE subscriptions ALTER COLUMN customer_user_id SET NOT NULL;
CREATE UNIQUE INDEX subscriptions_one_active_per_customer_idx ON subscriptions(customer_user_id)
WHERE status = 'active';

DROP TABLE IF EXISTS customers;
