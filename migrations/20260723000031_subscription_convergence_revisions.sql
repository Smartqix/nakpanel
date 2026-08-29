-- +goose Up
ALTER TABLE subscription_system_accounts
    ADD COLUMN desired_revision BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN applied_revision BIGINT NOT NULL DEFAULT 0;

UPDATE subscription_system_accounts
SET applied_revision=desired_revision
WHERE convergence_status='in_sync';

CREATE INDEX subscription_system_accounts_pending_revision_idx
    ON subscription_system_accounts(convergence_status, desired_revision, id);

-- +goose Down
DROP INDEX IF EXISTS subscription_system_accounts_pending_revision_idx;
ALTER TABLE subscription_system_accounts
    DROP COLUMN IF EXISTS applied_revision,
    DROP COLUMN IF EXISTS desired_revision;
