-- +goose Up
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check CHECK(kind IN ('threshold','over_limit','collection_failed','suspended','sync_failed','maintenance_failed','certificate_expiring','mail_outbound_spike','scheduled_task_failed','server_backup_failed','login_new_device','login_failed_burst','php_deployment_failed','php_runtime_unsupported','php_reconciliation_failed','php_worker_failed','php_composer_security','php_runtime_missing','php_end_of_support','wordpress_operation_failed','wordpress_security_failed','wordpress_update_available','operation_failed','issue_recovered'));
ALTER TABLE backups ADD COLUMN completed_at TIMESTAMPTZ;
CREATE TABLE backup_readiness_checks(
 backup_id BIGINT PRIMARY KEY REFERENCES backups(id) ON DELETE CASCADE,
 checksum TEXT NOT NULL,
 size_bytes BIGINT NOT NULL,
 verified_at TIMESTAMPTZ,
 data_scope_hash TEXT NOT NULL,
 last_check_status TEXT NOT NULL CHECK(last_check_status IN ('verified','unknown')),
 last_checked_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE operation_condition_observations(
 resource_kind TEXT NOT NULL,
 resource_id BIGINT NOT NULL,
 kind TEXT NOT NULL,
 condition TEXT NOT NULL,
 signature TEXT NOT NULL,
 unhealthy BOOLEAN NOT NULL,
 generation BIGINT NOT NULL DEFAULT 1,
 observed_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(resource_kind,resource_id,kind,condition)
);

-- +goose Down
DROP TABLE operation_condition_observations;
DROP TABLE backup_readiness_checks;
ALTER TABLE backups DROP COLUMN completed_at;
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check CHECK(kind IN ('threshold','over_limit','collection_failed','suspended','sync_failed','maintenance_failed','certificate_expiring','mail_outbound_spike','scheduled_task_failed','server_backup_failed','login_new_device','login_failed_burst','php_deployment_failed','php_runtime_unsupported','php_reconciliation_failed','php_worker_failed','php_composer_security','php_runtime_missing','php_end_of_support','wordpress_operation_failed','wordpress_security_failed','wordpress_update_available'));
