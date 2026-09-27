-- +goose Up
ALTER TABLE wordpress_instances
    ADD COLUMN database_managed BOOLEAN NOT NULL DEFAULT false;
UPDATE wordpress_instances SET database_managed=true WHERE database_id IS NOT NULL;

ALTER TABLE wordpress_instances DROP CONSTRAINT wordpress_instances_desired_state_check;
ALTER TABLE wordpress_instances ADD CONSTRAINT wordpress_instances_desired_state_check
    CHECK (desired_state IN ('present','detached','absent'));
ALTER TABLE wordpress_instances DROP CONSTRAINT wordpress_instances_observed_state_check;
ALTER TABLE wordpress_instances ADD CONSTRAINT wordpress_instances_observed_state_check
    CHECK (observed_state IN ('pending','installing','healthy','failed','missing','detached','removing','removed'));

ALTER TABLE wordpress_operations
    ADD COLUMN backup_requested BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN database_removal_requested BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE wordpress_operations DROP CONSTRAINT wordpress_operations_kind_check;
ALTER TABLE wordpress_operations ADD CONSTRAINT wordpress_operations_kind_check
    CHECK (kind IN ('install','discover','refresh','update','verify','harden','maintenance',
                    'password_reset','settings','detach','uninstall'));

ALTER TABLE backups ADD COLUMN database_names TEXT[] NOT NULL DEFAULT '{}';

-- +goose Down
DELETE FROM wordpress_operations WHERE kind='uninstall';
UPDATE wordpress_instances
SET desired_state='present', observed_state='failed', convergence_status='failed',
    last_error=CASE WHEN last_error='' THEN 'WordPress uninstall state requires Phase 33' ELSE last_error END,
    updated_at=now()
WHERE desired_state='absent' OR observed_state IN ('removing','removed');

ALTER TABLE backups DROP COLUMN database_names;
ALTER TABLE wordpress_operations DROP CONSTRAINT wordpress_operations_kind_check;
ALTER TABLE wordpress_operations ADD CONSTRAINT wordpress_operations_kind_check
    CHECK (kind IN ('install','discover','refresh','update','verify','harden',
                    'maintenance','password_reset','settings','detach'));
ALTER TABLE wordpress_operations
    DROP COLUMN database_removal_requested,
    DROP COLUMN backup_requested;

ALTER TABLE wordpress_instances DROP CONSTRAINT wordpress_instances_observed_state_check;
ALTER TABLE wordpress_instances ADD CONSTRAINT wordpress_instances_observed_state_check
    CHECK (observed_state IN ('pending','installing','healthy','failed','missing','detached'));
ALTER TABLE wordpress_instances DROP CONSTRAINT wordpress_instances_desired_state_check;
ALTER TABLE wordpress_instances ADD CONSTRAINT wordpress_instances_desired_state_check
    CHECK (desired_state IN ('present','detached'));
ALTER TABLE wordpress_instances DROP COLUMN database_managed;
