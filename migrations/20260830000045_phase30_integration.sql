-- +goose Up
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed',
                    'maintenance_failed', 'certificate_expiring', 'mail_outbound_spike',
                    'scheduled_task_failed', 'server_backup_failed',
                    'login_new_device', 'login_failed_burst',
                    'php_deployment_failed', 'php_runtime_unsupported', 'php_reconciliation_failed',
                    'php_worker_failed', 'php_composer_security', 'php_runtime_missing',
                    'php_end_of_support'));

-- +goose Down
DELETE FROM notifications WHERE kind IN
    ('php_worker_failed', 'php_composer_security', 'php_runtime_missing', 'php_end_of_support');
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed',
                    'maintenance_failed', 'certificate_expiring', 'mail_outbound_spike',
                    'scheduled_task_failed', 'server_backup_failed',
                    'login_new_device', 'login_failed_burst',
                    'php_deployment_failed', 'php_runtime_unsupported', 'php_reconciliation_failed'));
