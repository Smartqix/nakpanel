-- +goose Up
ALTER TABLE databases
    ADD CONSTRAINT databases_phase32_site_identity_key UNIQUE(id,subscription_id,site_id);
ALTER TABLE backups
    ADD CONSTRAINT backups_phase32_subscription_identity_key UNIQUE(id,subscription_id);

CREATE TABLE wordpress_instances (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    database_id BIGINT,
    admin_user TEXT NOT NULL DEFAULT ''
        CHECK (admin_user = '' OR admin_user ~ '^[A-Za-z0-9_.@-]{1,60}$'),
    admin_email TEXT NOT NULL DEFAULT ''
        CHECK (admin_email = '' OR (length(admin_email) <= 254 AND admin_email !~ '[\r\n]')),
	 site_title TEXT NOT NULL DEFAULT ''
	     CHECK (length(site_title) <= 200 AND site_title !~ '[\r\n]'),
    admin_secret_id BIGINT,
    admin_secret_scope TEXT,
    installed_version TEXT NOT NULL DEFAULT ''
        CHECK (installed_version = '' OR installed_version ~ '^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[A-Za-z0-9.-]+)?$'),
    update_policy TEXT NOT NULL DEFAULT 'manual'
        CHECK (update_policy IN ('manual','maintenance')),
    maintenance_mode BOOLEAN NOT NULL DEFAULT false,
    inventory JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(inventory)='object'),
    plugins JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(plugins)='array'),
    themes JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(themes)='array'),
    security JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(security)='object'),
    checksum_status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (checksum_status IN ('unknown','valid','failed')),
    desired_state TEXT NOT NULL DEFAULT 'present'
        CHECK (desired_state IN ('present','detached')),
    observed_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (observed_state IN ('pending','installing','healthy','failed','missing','detached')),
    desired_revision BIGINT NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
    applied_revision BIGINT NOT NULL DEFAULT 0 CHECK (applied_revision >= 0),
    convergence_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (convergence_status IN ('pending','in_sync','failed')),
    last_error TEXT NOT NULL DEFAULT '',
    last_scanned_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(site_id),
    UNIQUE(id,subscription_id),
    CHECK ((admin_secret_id IS NULL) = (admin_secret_scope IS NULL)),
    CHECK (admin_secret_scope IS NULL OR admin_secret_scope = 'wordpress.instance.' || id::TEXT),
    FOREIGN KEY (site_id,subscription_id) REFERENCES sites(id,subscription_id) ON DELETE CASCADE,
    FOREIGN KEY (database_id,subscription_id,site_id)
        REFERENCES databases(id,subscription_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY (admin_secret_id,admin_secret_scope)
        REFERENCES service_secrets(id,scope) ON DELETE RESTRICT
);
CREATE INDEX wordpress_instances_subscription_idx
    ON wordpress_instances(subscription_id,observed_state,site_id);
CREATE INDEX wordpress_instances_scan_idx
    ON wordpress_instances(convergence_status,last_scanned_at,id)
    WHERE desired_state='present';

CREATE TABLE wordpress_operations (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL,
    instance_id BIGINT NOT NULL,
    requested_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    kind TEXT NOT NULL CHECK (kind IN (
        'install','discover','refresh','update','verify','harden',
        'maintenance','password_reset','settings','detach')),
    target_type TEXT NOT NULL DEFAULT ''
        CHECK (target_type IN ('','core','plugin','theme','all')),
    target_slug TEXT NOT NULL DEFAULT ''
        CHECK (target_slug = '' OR target_slug ~ '^[a-z0-9][a-z0-9._-]{0,127}$'),
    requested_version TEXT NOT NULL DEFAULT ''
        CHECK (requested_version = '' OR requested_version = 'latest'
               OR requested_version ~ '^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[A-Za-z0-9.-]+)?$'),
	maintenance_enabled BOOLEAN NOT NULL DEFAULT false,
    backup_id BIGINT,
    desired_revision BIGINT NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','waiting_backup','running','succeeded','failed','cancelled')),
    result JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(result)='object'),
    output TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(id,instance_id),
    FOREIGN KEY (instance_id,subscription_id)
        REFERENCES wordpress_instances(id,subscription_id) ON DELETE CASCADE,
    FOREIGN KEY (backup_id,subscription_id)
        REFERENCES backups(id,subscription_id) ON DELETE RESTRICT
);
CREATE INDEX wordpress_operations_instance_idx
    ON wordpress_operations(instance_id,created_at DESC,id DESC);
CREATE UNIQUE INDEX wordpress_operations_active_idx
    ON wordpress_operations(instance_id)
    WHERE status IN ('pending','waiting_backup','running');

CREATE TRIGGER wordpress_instances_account_teardown_guard
    BEFORE INSERT OR UPDATE OR DELETE ON wordpress_instances
    FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_php_account_teardown();
CREATE TRIGGER wordpress_operations_account_teardown_guard
    BEFORE INSERT OR UPDATE OR DELETE ON wordpress_operations
    FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_php_account_teardown();

ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed',
                    'maintenance_failed', 'certificate_expiring', 'mail_outbound_spike',
                    'scheduled_task_failed', 'server_backup_failed',
                    'login_new_device', 'login_failed_burst',
                    'php_deployment_failed', 'php_runtime_unsupported', 'php_reconciliation_failed',
                    'php_worker_failed', 'php_composer_security', 'php_runtime_missing',
                    'php_end_of_support', 'wordpress_operation_failed',
                    'wordpress_security_failed', 'wordpress_update_available'));

-- +goose Down
DELETE FROM notifications WHERE kind IN
    ('wordpress_operation_failed','wordpress_security_failed','wordpress_update_available');
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed',
                    'maintenance_failed', 'certificate_expiring', 'mail_outbound_spike',
                    'scheduled_task_failed', 'server_backup_failed',
                    'login_new_device', 'login_failed_burst',
                    'php_deployment_failed', 'php_runtime_unsupported', 'php_reconciliation_failed',
                    'php_worker_failed', 'php_composer_security', 'php_runtime_missing',
                    'php_end_of_support'));
DROP TRIGGER IF EXISTS wordpress_operations_account_teardown_guard ON wordpress_operations;
DROP TRIGGER IF EXISTS wordpress_instances_account_teardown_guard ON wordpress_instances;
DROP TABLE IF EXISTS wordpress_operations;
DROP TABLE IF EXISTS wordpress_instances;
ALTER TABLE backups DROP CONSTRAINT IF EXISTS backups_phase32_subscription_identity_key;
ALTER TABLE databases DROP CONSTRAINT IF EXISTS databases_phase32_site_identity_key;
