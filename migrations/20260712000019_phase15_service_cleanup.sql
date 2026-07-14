-- +goose Up
ALTER TABLE mail_domains ADD COLUMN delete_requested BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE application_instances ADD COLUMN delete_requested BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX mail_domains_delete_requested_idx
    ON mail_domains(subscription_id, id) WHERE delete_requested;
CREATE INDEX application_instances_delete_requested_idx
    ON application_instances(subscription_id, id) WHERE delete_requested;

-- +goose Down
DROP INDEX IF EXISTS application_instances_delete_requested_idx;
DROP INDEX IF EXISTS mail_domains_delete_requested_idx;
ALTER TABLE application_instances DROP COLUMN IF EXISTS delete_requested;
ALTER TABLE mail_domains DROP COLUMN IF EXISTS delete_requested;
