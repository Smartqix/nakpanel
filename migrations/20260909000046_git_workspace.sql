-- +goose Up
ALTER TABLE git_repositories
 ADD COLUMN deployment_mode TEXT NOT NULL DEFAULT 'manual' CHECK (deployment_mode IN ('manual','automatic','disabled')),
 ADD COLUMN connection_status TEXT NOT NULL DEFAULT 'not_connected',
 ADD COLUMN fetched_revision TEXT NOT NULL DEFAULT '',
 ADD COLUMN deployed_revision TEXT NOT NULL DEFAULT '',
 ADD COLUMN previous_revision TEXT NOT NULL DEFAULT '',
 ADD COLUMN branches JSONB NOT NULL DEFAULT '[]',
 ADD COLUMN commits JSONB NOT NULL DEFAULT '[]',
 ADD COLUMN conflicts JSONB NOT NULL DEFAULT '[]',
 ADD COLUMN operation_revision BIGINT NOT NULL DEFAULT 1;
UPDATE git_repositories SET deployment_mode=CASE WHEN automatic THEN 'automatic' ELSE 'manual' END,
 deployed_revision=last_revision;
ALTER TABLE git_deployments
 ADD COLUMN action TEXT NOT NULL DEFAULT 'deploy',
 ADD COLUMN operation_revision BIGINT NOT NULL DEFAULT 1,
 ADD COLUMN confirm_overwrite BOOLEAN NOT NULL DEFAULT false,
 ADD COLUMN idempotency_key TEXT NOT NULL DEFAULT '';
-- Legacy jobs have no immutable target and must not become surprise deployments.
UPDATE git_deployments SET status='failed',output='Requeue with a fetched immutable commit.',finished_at=now()
 WHERE status IN ('pending','running');
CREATE UNIQUE INDEX git_workspace_active_operation ON git_deployments(repository_id) WHERE status IN ('pending','running');
CREATE UNIQUE INDEX git_workspace_idempotency ON git_deployments(repository_id,idempotency_key) WHERE idempotency_key<>'';
CREATE TABLE git_webhook_deliveries (
 repository_id BIGINT NOT NULL REFERENCES git_repositories(id) ON DELETE CASCADE,
 delivery_id TEXT NOT NULL,
 received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(repository_id,delivery_id)
);

-- +goose Down
DROP TABLE git_webhook_deliveries;
DROP INDEX git_workspace_active_operation;
DROP INDEX git_workspace_idempotency;
ALTER TABLE git_deployments DROP COLUMN action,DROP COLUMN operation_revision,DROP COLUMN confirm_overwrite,DROP COLUMN idempotency_key;
ALTER TABLE git_repositories DROP COLUMN deployment_mode,DROP COLUMN connection_status,DROP COLUMN fetched_revision,
 DROP COLUMN deployed_revision,DROP COLUMN previous_revision,DROP COLUMN branches,DROP COLUMN commits,DROP COLUMN conflicts,DROP COLUMN operation_revision;
