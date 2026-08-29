-- +goose Up
CREATE TABLE php_applications (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    hosting_mode TEXT NOT NULL DEFAULT 'classic'
        CHECK (hosting_mode IN ('classic','managed')),
    php_version TEXT NOT NULL CHECK (php_version ~ '^[0-9]+\.[0-9]+$'),
    repository_id BIGINT REFERENCES git_repositories(id) ON DELETE SET NULL,
    repository_ref TEXT NOT NULL DEFAULT 'main'
        CHECK (repository_ref <> '' AND repository_ref !~ '[\r\n]'),
    public_path TEXT NOT NULL DEFAULT ''
        CHECK (public_path !~ '^/' AND public_path !~ '(^|/)\.\.(/|$)' AND public_path !~ '[\r\n]'),
    composer_install BOOLEAN NOT NULL DEFAULT false,
    composer_allow_scripts BOOLEAN NOT NULL DEFAULT false,
    composer_allow_plugins BOOLEAN NOT NULL DEFAULT false,
    desired_state TEXT NOT NULL DEFAULT 'active'
        CHECK (desired_state IN ('active','suspended')),
    observed_state TEXT NOT NULL DEFAULT 'classic'
        CHECK (observed_state IN ('classic','pending','deploying','healthy','unhealthy','suspended','failed')),
    active_deployment_id BIGINT,
    previous_deployment_id BIGINT,
    desired_revision BIGINT NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
    applied_revision BIGINT NOT NULL DEFAULT 0 CHECK (applied_revision >= 0),
    convergence_status TEXT NOT NULL DEFAULT 'in_sync'
        CHECK (convergence_status IN ('pending','in_sync','failed')),
    observed_message TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    last_reconciled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(site_id)
);
CREATE INDEX php_applications_subscription_idx
    ON php_applications(subscription_id,hosting_mode,site_id);
CREATE INDEX php_applications_convergence_idx
    ON php_applications(convergence_status,updated_at,id);

CREATE TABLE php_deployments (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    application_id BIGINT NOT NULL REFERENCES php_applications(id) ON DELETE CASCADE,
    requested_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    requested_revision TEXT NOT NULL CHECK (requested_revision <> '' AND requested_revision !~ '[\r\n]'),
    resolved_revision TEXT NOT NULL DEFAULT ''
        CHECK (resolved_revision = '' OR resolved_revision ~ '^[a-f0-9]{40,64}$'),
    release_number BIGINT NOT NULL CHECK (release_number > 0),
    previous_deployment_id BIGINT REFERENCES php_deployments(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','preparing','validating','activating','healthy','failed','rolled_back','retired')),
    composer_audit JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(composer_audit)='object'),
    health_message TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ,
    activated_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(application_id,release_number)
);
CREATE INDEX php_deployments_status_idx
    ON php_deployments(application_id,status,created_at DESC,id DESC);
CREATE UNIQUE INDEX php_deployments_active_idx
    ON php_deployments(application_id)
    WHERE status='healthy';

ALTER TABLE php_applications
    ADD CONSTRAINT php_applications_active_deployment_fk
        FOREIGN KEY (active_deployment_id) REFERENCES php_deployments(id) ON DELETE SET NULL,
    ADD CONSTRAINT php_applications_previous_deployment_fk
        FOREIGN KEY (previous_deployment_id) REFERENCES php_deployments(id) ON DELETE SET NULL;

CREATE TABLE php_environment_bindings (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    application_id BIGINT NOT NULL REFERENCES php_applications(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (name ~ '^[A-Z_][A-Z0-9_]{0,127}$'),
    plain_value TEXT,
    secret_id BIGINT REFERENCES service_secrets(id) ON DELETE RESTRICT,
    desired_revision BIGINT NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((plain_value IS NOT NULL) <> (secret_id IS NOT NULL)),
    UNIQUE(application_id,name),
    UNIQUE(secret_id)
);
CREATE INDEX php_environment_bindings_subscription_idx
    ON php_environment_bindings(subscription_id,application_id);

CREATE TABLE php_workers (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    application_id BIGINT NOT NULL REFERENCES php_applications(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,47}$'),
    script TEXT NOT NULL
        CHECK (script <> '' AND script !~ '^/' AND script !~ '(^|/)\.\.(/|$)' AND script !~ '[\r\n]'),
    arguments JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(arguments)='array'),
    processes INTEGER NOT NULL DEFAULT 1 CHECK (processes BETWEEN 1 AND 64),
    desired_state TEXT NOT NULL DEFAULT 'running'
        CHECK (desired_state IN ('running','stopped')),
    observed_state TEXT NOT NULL DEFAULT 'unknown'
        CHECK (observed_state IN ('unknown','running','stopped','failed','missing')),
    desired_revision BIGINT NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
    applied_revision BIGINT NOT NULL DEFAULT 0 CHECK (applied_revision >= 0),
    convergence_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (convergence_status IN ('pending','in_sync','failed')),
    last_error TEXT NOT NULL DEFAULT '',
    last_reconciled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(application_id,name)
);
CREATE INDEX php_workers_subscription_idx
    ON php_workers(subscription_id,application_id);
CREATE INDEX php_workers_convergence_idx
    ON php_workers(convergence_status,updated_at,id);

INSERT INTO php_applications(subscription_id,site_id,hosting_mode,php_version,
                             desired_state,observed_state,desired_revision,
                             applied_revision,convergence_status)
SELECT site.subscription_id,site.id,'classic',site.php_version,
       site.desired_status,
       'classic',1,1,'in_sync'
FROM sites site;

ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed',
                    'maintenance_failed', 'certificate_expiring', 'mail_outbound_spike',
                    'scheduled_task_failed', 'server_backup_failed',
                    'login_new_device', 'login_failed_burst',
                    'php_deployment_failed', 'php_runtime_unsupported', 'php_reconciliation_failed'));

-- Every Phase 30 row carries its subscription owner so teardown fencing does
-- not need to infer ownership from a mutable parent row.
-- +goose StatementBegin
CREATE FUNCTION nakpanel_guard_php_account_teardown()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_subscription_id BIGINT;
    new_subscription_id BIGINT;
BEGIN
    IF current_setting('nakpanel.account_teardown', true) = 'on' THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP <> 'INSERT' THEN
        old_subscription_id := NULLIF(to_jsonb(OLD)->>'subscription_id','')::BIGINT;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        new_subscription_id := NULLIF(to_jsonb(NEW)->>'subscription_id','')::BIGINT;
    END IF;

    IF old_subscription_id IS NOT NULL AND new_subscription_id IS NOT NULL
       AND old_subscription_id <> new_subscription_id THEN
        IF old_subscription_id < new_subscription_id THEN
            PERFORM nakpanel_assert_account_mutable(old_subscription_id);
            PERFORM nakpanel_assert_account_mutable(new_subscription_id);
        ELSE
            PERFORM nakpanel_assert_account_mutable(new_subscription_id);
            PERFORM nakpanel_assert_account_mutable(old_subscription_id);
        END IF;
    ELSE
        PERFORM nakpanel_assert_account_mutable(COALESCE(new_subscription_id,old_subscription_id));
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER php_applications_account_teardown_guard
    BEFORE INSERT OR UPDATE OR DELETE ON php_applications
    FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_php_account_teardown();
CREATE TRIGGER php_deployments_account_teardown_guard
    BEFORE INSERT OR UPDATE OR DELETE ON php_deployments
    FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_php_account_teardown();
CREATE TRIGGER php_environment_bindings_account_teardown_guard
    BEFORE INSERT OR UPDATE OR DELETE ON php_environment_bindings
    FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_php_account_teardown();
CREATE TRIGGER php_workers_account_teardown_guard
    BEFORE INSERT OR UPDATE OR DELETE ON php_workers
    FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_php_account_teardown();

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM php_applications WHERE hosting_mode <> 'classic')
       OR EXISTS (SELECT 1 FROM php_deployments)
       OR EXISTS (SELECT 1 FROM php_environment_bindings)
       OR EXISTS (SELECT 1 FROM php_workers) THEN
        RAISE EXCEPTION 'cannot roll back Phase 30 while managed PHP state exists';
    END IF;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS php_workers_account_teardown_guard ON php_workers;
DROP TRIGGER IF EXISTS php_environment_bindings_account_teardown_guard ON php_environment_bindings;
DROP TRIGGER IF EXISTS php_deployments_account_teardown_guard ON php_deployments;
DROP TRIGGER IF EXISTS php_applications_account_teardown_guard ON php_applications;
DROP FUNCTION IF EXISTS nakpanel_guard_php_account_teardown();

DELETE FROM notifications WHERE kind IN ('php_deployment_failed','php_runtime_unsupported','php_reconciliation_failed');
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed',
                    'maintenance_failed', 'certificate_expiring', 'mail_outbound_spike',
                    'scheduled_task_failed', 'server_backup_failed',
                    'login_new_device', 'login_failed_burst'));

ALTER TABLE php_applications
    DROP CONSTRAINT IF EXISTS php_applications_previous_deployment_fk,
    DROP CONSTRAINT IF EXISTS php_applications_active_deployment_fk;
DROP TABLE IF EXISTS php_workers;
DROP TABLE IF EXISTS php_environment_bindings;
DROP TABLE IF EXISTS php_deployments;
DROP TABLE IF EXISTS php_applications;
