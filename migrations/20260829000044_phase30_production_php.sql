-- +goose Up
ALTER TABLE sites
    ADD CONSTRAINT sites_phase30_identity_key UNIQUE(id,subscription_id);
ALTER TABLE git_repositories
    ADD CONSTRAINT git_repositories_phase30_identity_key UNIQUE(id,site_id);
ALTER TABLE service_secrets
    ADD CONSTRAINT service_secrets_phase30_identity_key UNIQUE(id,scope);

CREATE TABLE php_applications (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    hosting_mode TEXT NOT NULL DEFAULT 'classic'
        CHECK (hosting_mode IN ('classic','managed')),
    php_version TEXT NOT NULL CHECK (php_version ~ '^[0-9]+\.[0-9]+$'),
    repository_id BIGINT,
    repository_ref TEXT NOT NULL DEFAULT 'main'
        CHECK (repository_ref <> '' AND repository_ref !~ '[\r\n]'),
    framework_profile TEXT NOT NULL DEFAULT 'plain'
        CHECK (framework_profile IN ('plain','laravel','symfony','custom')),
    public_path TEXT NOT NULL DEFAULT ''
        CHECK (public_path !~ '^/' AND public_path !~ '(^|/)\.\.(/|$)' AND public_path !~ '[\r\n]'),
    health_path TEXT NOT NULL DEFAULT '/'
        CHECK (health_path ~ '^/' AND health_path !~ '(^|/)\.\.(/|$)' AND health_path !~ '[\r\n]'),
    shared_paths JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(shared_paths)='array'
               AND jsonb_array_length(shared_paths) <= 16
               AND NOT jsonb_path_exists(shared_paths, '$[*] ? (@.type() != "string")')
               AND shared_paths::TEXT !~ '"/'
               AND shared_paths::TEXT !~ '"([^"/]*/)*\.\.(/|"|\\)'
               AND shared_paths::TEXT !~ '[\r\n]'),
    composer_install BOOLEAN NOT NULL DEFAULT false,
    composer_allow_scripts BOOLEAN NOT NULL DEFAULT false,
    composer_allow_plugins BOOLEAN NOT NULL DEFAULT false,
    release_retention INTEGER NOT NULL DEFAULT 5 CHECK (release_retention BETWEEN 1 AND 100),
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
    UNIQUE(site_id),
    UNIQUE(id,subscription_id),
    FOREIGN KEY (site_id,subscription_id) REFERENCES sites(id,subscription_id) ON DELETE CASCADE,
    FOREIGN KEY (repository_id,site_id) REFERENCES git_repositories(id,site_id)
);
CREATE INDEX php_applications_subscription_idx
    ON php_applications(subscription_id,hosting_mode,site_id);
CREATE INDEX php_applications_convergence_idx
    ON php_applications(convergence_status,updated_at,id);

CREATE TABLE php_deployments (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL,
    application_id BIGINT NOT NULL,
    requested_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    requested_revision TEXT NOT NULL CHECK (requested_revision <> '' AND requested_revision !~ '[\r\n]'),
    resolved_revision TEXT NOT NULL DEFAULT ''
        CHECK (resolved_revision = '' OR resolved_revision ~ '^[a-f0-9]{40}([a-f0-9]{24})?$'),
    release_number BIGINT NOT NULL CHECK (release_number > 0),
    previous_deployment_id BIGINT,
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
    UNIQUE(application_id,release_number),
    UNIQUE(id,application_id),
    FOREIGN KEY (application_id,subscription_id) REFERENCES php_applications(id,subscription_id) ON DELETE CASCADE,
    FOREIGN KEY (previous_deployment_id,application_id) REFERENCES php_deployments(id,application_id)
);
CREATE INDEX php_deployments_status_idx
    ON php_deployments(application_id,status,created_at DESC,id DESC);
CREATE UNIQUE INDEX php_deployments_active_idx
    ON php_deployments(application_id)
    WHERE status='healthy';

ALTER TABLE php_applications
    ADD CONSTRAINT php_applications_active_deployment_fk
        FOREIGN KEY (active_deployment_id,id) REFERENCES php_deployments(id,application_id),
    ADD CONSTRAINT php_applications_previous_deployment_fk
        FOREIGN KEY (previous_deployment_id,id) REFERENCES php_deployments(id,application_id);

CREATE TABLE php_environment_bindings (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL,
    application_id BIGINT NOT NULL,
    name TEXT NOT NULL CHECK (name ~ '^[A-Z_][A-Z0-9_]{0,127}$'),
    plain_value TEXT,
    secret_id BIGINT,
    secret_scope TEXT GENERATED ALWAYS AS ('php.application.' || application_id::TEXT) STORED,
    desired_revision BIGINT NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((plain_value IS NOT NULL) <> (secret_id IS NOT NULL)),
    UNIQUE(application_id,name),
    UNIQUE(secret_id),
    FOREIGN KEY (application_id,subscription_id) REFERENCES php_applications(id,subscription_id) ON DELETE CASCADE,
    FOREIGN KEY (secret_id,secret_scope) REFERENCES service_secrets(id,scope) ON DELETE RESTRICT
);
CREATE INDEX php_environment_bindings_subscription_idx
    ON php_environment_bindings(subscription_id,application_id);

CREATE TABLE php_workers (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL,
    application_id BIGINT NOT NULL,
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
    UNIQUE(application_id,name),
    FOREIGN KEY (application_id,subscription_id) REFERENCES php_applications(id,subscription_id) ON DELETE CASCADE
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

-- Keep the one-application-per-site invariant for every site creation path,
-- including provisioning APIs and future import/recovery workflows.
-- +goose StatementBegin
CREATE FUNCTION nakpanel_create_php_application_for_site()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO php_applications(subscription_id,site_id,hosting_mode,php_version,
                                 desired_state,observed_state,desired_revision,
                                 applied_revision,convergence_status)
    VALUES(NEW.subscription_id,NEW.id,'classic',NEW.php_version,
           NEW.desired_status,'classic',1,1,'in_sync');
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER sites_create_php_application
    AFTER INSERT ON sites
    FOR EACH ROW EXECUTE FUNCTION nakpanel_create_php_application_for_site();

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
DROP TRIGGER IF EXISTS sites_create_php_application ON sites;
DROP FUNCTION IF EXISTS nakpanel_create_php_application_for_site();

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM php_applications application
        JOIN sites site ON site.id=application.site_id
        WHERE application.subscription_id <> site.subscription_id
           OR application.hosting_mode <> 'classic'
           OR application.php_version <> site.php_version
           OR application.repository_id IS NOT NULL
           OR application.repository_ref <> 'main'
           OR application.framework_profile <> 'plain'
           OR application.public_path <> ''
           OR application.health_path <> '/'
           OR application.shared_paths <> '[]'::jsonb
           OR application.composer_install
           OR application.composer_allow_scripts
           OR application.composer_allow_plugins
           OR application.release_retention <> 5
           OR application.desired_state <> site.desired_status
           OR application.observed_state <> 'classic'
           OR application.active_deployment_id IS NOT NULL
           OR application.previous_deployment_id IS NOT NULL
           OR application.desired_revision <> 1
           OR application.applied_revision <> 1
           OR application.convergence_status <> 'in_sync'
           OR application.observed_message <> ''
           OR application.last_error <> ''
           OR application.last_reconciled_at IS NOT NULL
    )
       OR EXISTS (
           SELECT 1
           FROM sites site
           LEFT JOIN php_applications application ON application.site_id=site.id
           WHERE application.id IS NULL
       )
       OR EXISTS (SELECT 1 FROM php_deployments)
       OR EXISTS (SELECT 1 FROM php_environment_bindings)
       OR EXISTS (SELECT 1 FROM php_workers) THEN
        RAISE EXCEPTION 'cannot roll back Phase 30 unless application rows equal the canonical Classic backfill';
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
ALTER TABLE service_secrets DROP CONSTRAINT IF EXISTS service_secrets_phase30_identity_key;
ALTER TABLE git_repositories DROP CONSTRAINT IF EXISTS git_repositories_phase30_identity_key;
ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_phase30_identity_key;
