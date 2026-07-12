-- +goose Up
CREATE UNIQUE INDEX users_email_lower_idx ON users(lower(email));

ALTER TABLE subscriptions ADD CONSTRAINT subscriptions_id_customer_id_key UNIQUE (id, customer_id);

ALTER TABLE sites
    ALTER COLUMN subscription_id SET NOT NULL,
    ALTER COLUMN customer_id SET NOT NULL,
    ADD CONSTRAINT sites_subscription_customer_fk
        FOREIGN KEY (subscription_id, customer_id)
        REFERENCES subscriptions(id, customer_id) ON UPDATE CASCADE ON DELETE RESTRICT;

ALTER TABLE databases
    ALTER COLUMN subscription_id SET NOT NULL,
    ALTER COLUMN customer_id SET NOT NULL,
    ADD CONSTRAINT databases_subscription_customer_fk
        FOREIGN KEY (subscription_id, customer_id)
        REFERENCES subscriptions(id, customer_id) ON UPDATE CASCADE ON DELETE RESTRICT;

ALTER TABLE backups
    ALTER COLUMN subscription_id SET NOT NULL,
    ALTER COLUMN customer_id SET NOT NULL,
    ADD CONSTRAINT backups_subscription_customer_fk
        FOREIGN KEY (subscription_id, customer_id)
        REFERENCES subscriptions(id, customer_id) ON UPDATE CASCADE ON DELETE RESTRICT;

-- +goose Down
ALTER TABLE backups DROP CONSTRAINT IF EXISTS backups_subscription_customer_fk;
ALTER TABLE backups ALTER COLUMN customer_id DROP NOT NULL, ALTER COLUMN subscription_id DROP NOT NULL;
ALTER TABLE databases DROP CONSTRAINT IF EXISTS databases_subscription_customer_fk;
ALTER TABLE databases ALTER COLUMN customer_id DROP NOT NULL, ALTER COLUMN subscription_id DROP NOT NULL;
ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_subscription_customer_fk;
ALTER TABLE sites ALTER COLUMN customer_id DROP NOT NULL, ALTER COLUMN subscription_id DROP NOT NULL;
ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS subscriptions_id_customer_id_key;
DROP INDEX IF EXISTS users_email_lower_idx;
