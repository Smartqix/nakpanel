-- +goose Up
CREATE TABLE subscription_system_accounts (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL UNIQUE REFERENCES subscriptions(id) ON DELETE CASCADE,
    username TEXT NOT NULL UNIQUE CHECK (username ~ '^[a-z][a-z0-9_-]{2,31}$'),
    home_path TEXT NOT NULL UNIQUE CHECK (home_path LIKE '/home/%'),
    linux_uid INTEGER,
    shell_mode TEXT NOT NULL DEFAULT 'disabled' CHECK (shell_mode IN ('disabled', 'sftp', 'nspawn')),
    desired_state TEXT NOT NULL DEFAULT 'active' CHECK (desired_state IN ('active', 'suspended')),
    applied_state TEXT NOT NULL DEFAULT 'pending' CHECK (applied_state IN ('pending', 'active', 'suspended', 'failed')),
    convergence_status TEXT NOT NULL DEFAULT 'pending' CHECK (convergence_status IN ('pending', 'in_sync', 'failed')),
    last_error TEXT NOT NULL DEFAULT '',
    migration_status TEXT NOT NULL DEFAULT 'pending' CHECK (migration_status IN ('pending', 'preflight', 'copying', 'cutover', 'complete', 'failed', 'legacy')),
    migration_error TEXT NOT NULL DEFAULT '',
    legacy_homes JSONB NOT NULL DEFAULT '[]'::jsonb,
    migrated_at TIMESTAMPTZ,
    cleanup_after TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose StatementBegin
CREATE FUNCTION protect_subscription_system_account_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.subscription_id IS DISTINCT FROM OLD.subscription_id OR NEW.username IS DISTINCT FROM OLD.username OR NEW.home_path IS DISTINCT FROM OLD.home_path THEN
        RAISE EXCEPTION 'subscription system account identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER subscription_system_account_identity_immutable
BEFORE UPDATE ON subscription_system_accounts
FOR EACH ROW EXECUTE FUNCTION protect_subscription_system_account_identity();

WITH legacy AS (
    SELECT s.id AS subscription_id,
           COUNT(site.id) AS site_count,
           MIN(site.username) AS single_username,
           COALESCE(jsonb_agg(DISTINCT '/home/' || site.username) FILTER (WHERE site.id IS NOT NULL), '[]'::jsonb) AS legacy_homes
    FROM subscriptions s
    LEFT JOIN sites site ON site.subscription_id = s.id
    GROUP BY s.id
), candidates AS (
    SELECT subscription_id,
           CASE WHEN site_count = 1 THEN single_username ELSE 'nps' || subscription_id::text || substr(md5('nakpanel:' || subscription_id::text), 1, 8) END AS username,
           site_count,
           legacy_homes
    FROM legacy
)
INSERT INTO subscription_system_accounts (subscription_id, username, home_path, migration_status, legacy_homes)
SELECT subscription_id,
       CASE WHEN EXISTS (SELECT 1 FROM candidates preserved WHERE preserved.site_count=1 AND preserved.username=candidates.username AND preserved.subscription_id<>candidates.subscription_id)
            THEN 'npa' || subscription_id::text || substr(md5('collision:' || subscription_id::text), 1, 8)
            ELSE username END,
       '/home/' || CASE WHEN EXISTS (SELECT 1 FROM candidates preserved WHERE preserved.site_count=1 AND preserved.username=candidates.username AND preserved.subscription_id<>candidates.subscription_id)
            THEN 'npa' || subscription_id::text || substr(md5('collision:' || subscription_id::text), 1, 8)
            ELSE username END,
       CASE WHEN site_count = 0 THEN 'pending' ELSE 'legacy' END,
       legacy_homes
FROM candidates;

ALTER TABLE sites ADD COLUMN system_account_id BIGINT REFERENCES subscription_system_accounts(id) ON DELETE RESTRICT;
ALTER TABLE sites ADD COLUMN document_root TEXT;

UPDATE sites site
SET system_account_id = account.id,
    document_root = '/home/' || site.username || '/public_html'
FROM subscription_system_accounts account
WHERE account.subscription_id = site.subscription_id;

ALTER TABLE sites ALTER COLUMN system_account_id SET NOT NULL;
ALTER TABLE sites ALTER COLUMN document_root SET NOT NULL;
ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_username_key;
CREATE INDEX sites_system_account_id_idx ON sites(system_account_id);

ALTER TABLE plans ADD COLUMN hosting_policy JSONB NOT NULL DEFAULT '{"schema_version":1}'::jsonb;
ALTER TABLE addon_plans ADD COLUMN hosting_policy JSONB NOT NULL DEFAULT '{"schema_version":1}'::jsonb;
ALTER TABLE reseller_plans ADD COLUMN hosting_policy JSONB NOT NULL DEFAULT '{"schema_version":1}'::jsonb;
ALTER TABLE subscription_entitlements ADD COLUMN hosting_policy JSONB NOT NULL DEFAULT '{"schema_version":1}'::jsonb;

UPDATE plans p SET hosting_policy=jsonb_build_object(
    'schema_version',1,
    'resources',jsonb_build_object('disk_mb',p.disk_mb,'traffic_mb',p.bandwidth_mb,'cpu_percent',0,'memory_mb',0,'io_read_mbps',0,'io_write_mbps',0,'max_tasks',0,'max_sites',p.max_sites,'max_databases',p.max_databases,'max_database_users',0,'max_mailboxes',p.max_mailboxes,'max_mail_aliases',0,'max_sftp_identities',p.max_ftp_accounts,'max_scheduled_tasks',0,'max_backups',p.max_backups,'backup_storage_mb',p.backup_storage_mb,'max_applications',0,'container_storage_mb',0),
    'permissions',jsonb_build_object('hosting',p.hosting_enabled,'ssh',p.allow_ssh,'sftp',p.max_ftp_accounts<>0,'scheduled_tasks',false,'dns',p.allow_dns,'tls',p.allow_tls,'mail',p.max_mailboxes<>0,'databases',p.max_databases<>0,'backups',p.allow_backups,'php_settings',p.allow_php_settings,'cgi',false,'applications',false,'custom_oci_images',false,'application_egress',false),
    'web',jsonb_build_object('preferred_domain','none','https_redirect',false,'request_rate_per_second',0,'request_burst',0,'max_connections',0,'static_cache',false,'fastcgi_microcache',false),
    'php',jsonb_build_object('default_version',p.default_php_version,'allowed_versions',to_jsonb(array_remove(string_to_array(replace(p.php_allowlist,' ',''),','),'')),'fpm_max_children',p.php_fpm_max_children,'fpm_max_requests',500,'memory_limit_mb',p.php_memory_mb,'max_execution_seconds',30,'max_input_seconds',60,'post_max_mb',128,'upload_max_mb',128,'display_errors',false,'log_errors',true,'allow_url_fopen',false,'exec_enabled',false),
    'mail',jsonb_build_object('enabled',p.max_mailboxes<>0,'mailbox_quota_mb',-1,'dkim',false,'dmarc_policy','none','spam_filter',false,'webmail',false,'autoresponders',false,'catch_all',false),
    'dns',jsonb_build_object('enabled',p.allow_dns,'mode','authoritative','default_ttl',3600,'dnssec',false),
    'access',jsonb_build_object('shell_mode','disabled','nspawn_image','','sftp_only',true,'ssh_idle_timeout_minutes',30),
    'backups',jsonb_build_object('enabled',p.allow_backups,'retention_days',p.backup_retention_days,'schedule','','remote_target',''),
    'applications',jsonb_build_object('catalog_enabled',false,'allowed_catalog_slugs','[]'::jsonb,'allowed_registries','[]'::jsonb,'allowed_runtimes','[]'::jsonb,'rootless',true,'egress_enabled',false)
);

UPDATE subscription_entitlements e SET hosting_policy=jsonb_build_object(
    'schema_version',1,
    'resources',jsonb_build_object('disk_mb',e.disk_mb,'traffic_mb',e.bandwidth_mb,'cpu_percent',0,'memory_mb',0,'io_read_mbps',0,'io_write_mbps',0,'max_tasks',0,'max_sites',e.max_sites,'max_databases',e.max_databases,'max_database_users',0,'max_mailboxes',e.max_mailboxes,'max_mail_aliases',0,'max_sftp_identities',e.max_ftp_accounts,'max_scheduled_tasks',0,'max_backups',e.max_backups,'backup_storage_mb',e.backup_storage_mb,'max_applications',0,'container_storage_mb',0),
    'permissions',jsonb_build_object('hosting',e.hosting_enabled,'ssh',e.allow_ssh,'sftp',e.max_ftp_accounts<>0,'scheduled_tasks',false,'dns',e.allow_dns,'tls',e.allow_tls,'mail',e.max_mailboxes<>0,'databases',e.max_databases<>0,'backups',e.allow_backups,'php_settings',e.allow_php_settings,'cgi',false,'applications',false,'custom_oci_images',false,'application_egress',false),
    'web',jsonb_build_object('preferred_domain',COALESCE(e.service_presets#>>'{hosting,preferred_domain}','none'),'https_redirect',false,'request_rate_per_second',0,'request_burst',0,'max_connections',COALESCE((e.service_presets#>>'{performance,max_connections}')::int,0),'static_cache',COALESCE((e.service_presets#>>'{performance,static_file_cache}')::boolean,false),'fastcgi_microcache',false),
    'php',jsonb_build_object('default_version',e.default_php_version,'allowed_versions',to_jsonb(array_remove(string_to_array(replace(e.php_allowlist,' ',''),','),'')),'fpm_max_children',e.php_fpm_max_children,'fpm_max_requests',COALESCE((e.service_presets#>>'{php,fpm_max_requests}')::int,500),'memory_limit_mb',e.php_memory_mb,'max_execution_seconds',COALESCE((e.service_presets#>>'{php,max_execution_seconds}')::int,30),'max_input_seconds',COALESCE((e.service_presets#>>'{php,max_input_seconds}')::int,60),'post_max_mb',COALESCE((e.service_presets#>>'{php,post_max_mb}')::int,128),'upload_max_mb',COALESCE((e.service_presets#>>'{php,upload_max_mb}')::int,128),'display_errors',COALESCE((e.service_presets#>>'{php,display_errors}')::boolean,false),'log_errors',COALESCE((e.service_presets#>>'{php,log_errors}')::boolean,true),'allow_url_fopen',COALESCE((e.service_presets#>>'{php,allow_url_fopen}')::boolean,false),'exec_enabled',false),
    'mail',jsonb_build_object('enabled',e.max_mailboxes<>0,'mailbox_quota_mb',-1,'dkim',COALESCE((e.service_presets#>>'{mail,dkim}')::boolean,false),'dmarc_policy',COALESCE(e.service_presets#>>'{mail,dmarc_policy}','none'),'spam_filter',COALESCE((e.service_presets#>>'{mail,spam_filter}')::boolean,false),'webmail',COALESCE((e.service_presets#>>'{mail,webmail_enabled}')::boolean,false),'autoresponders',false,'catch_all',false),
    'dns',jsonb_build_object('enabled',e.allow_dns,'mode',CASE WHEN COALESCE(e.service_presets#>>'{dns,mode}','primary') IN ('secondary','external') THEN 'external' ELSE 'authoritative' END,'default_ttl',COALESCE((e.service_presets#>>'{dns,default_ttl}')::int,3600),'dnssec',false),
    'access',jsonb_build_object('shell_mode','disabled','nspawn_image','','sftp_only',true,'ssh_idle_timeout_minutes',30),
    'backups',jsonb_build_object('enabled',e.allow_backups,'retention_days',e.backup_retention_days,'schedule','','remote_target',''),
    'applications',jsonb_build_object('catalog_enabled',COALESCE((e.service_presets#>>'{applications,catalog_enabled}')::boolean,false),'allowed_catalog_slugs',COALESCE(e.service_presets#>'{applications,allowed}','[]'::jsonb),'allowed_registries','[]'::jsonb,'allowed_runtimes','[]'::jsonb,'rootless',true,'egress_enabled',false)
);

CREATE TABLE subscription_policy_overrides (
    subscription_id BIGINT PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version > 0),
    policy_patch JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(policy_patch) = 'object'),
    updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE site_policy_overrides (
    site_id BIGINT PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version > 0),
    policy_patch JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(policy_patch) = 'object'),
    updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sftp_access_identities (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    relative_root TEXT NOT NULL DEFAULT '.' CHECK (relative_root !~ '(^|/)\.\.(/|$)' AND relative_root !~ '^/'),
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (subscription_id, name)
);

CREATE TABLE scheduled_tasks (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    site_id BIGINT REFERENCES sites(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    schedule TEXT NOT NULL,
    command TEXT NOT NULL,
    working_directory TEXT NOT NULL DEFAULT '.',
    timeout_seconds INTEGER NOT NULL DEFAULT 300 CHECK (timeout_seconds BETWEEN 1 AND 86400),
    enabled BOOLEAN NOT NULL DEFAULT true,
    convergence_status TEXT NOT NULL DEFAULT 'pending' CHECK (convergence_status IN ('pending', 'in_sync', 'failed')),
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (subscription_id, name)
);

CREATE TABLE scheduled_task_runs (
    id BIGSERIAL PRIMARY KEY,
    task_id BIGINT NOT NULL REFERENCES scheduled_tasks(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'timed_out')),
    exit_code INTEGER,
    output TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE mail_domains (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    site_id BIGINT REFERENCES sites(id) ON DELETE SET NULL,
    domain TEXT NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    dkim_enabled BOOLEAN NOT NULL DEFAULT true,
    dmarc_policy TEXT NOT NULL DEFAULT 'none' CHECK (dmarc_policy IN ('none', 'quarantine', 'reject')),
    catch_all TEXT NOT NULL DEFAULT '',
    convergence_status TEXT NOT NULL DEFAULT 'pending' CHECK (convergence_status IN ('pending', 'in_sync', 'failed')),
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE mailboxes (
    id BIGSERIAL PRIMARY KEY,
    mail_domain_id BIGINT NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
    local_part TEXT NOT NULL CHECK (local_part ~ '^[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+$'),
    password_ciphertext BYTEA NOT NULL,
    quota_mb INTEGER NOT NULL DEFAULT -1 CHECK (quota_mb >= -1),
    enabled BOOLEAN NOT NULL DEFAULT true,
    autoresponder JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (mail_domain_id, local_part)
);

CREATE TABLE mail_aliases (
    id BIGSERIAL PRIMARY KEY,
    mail_domain_id BIGINT NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
    local_part TEXT NOT NULL,
    destinations TEXT[] NOT NULL CHECK (cardinality(destinations) > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (mail_domain_id, local_part)
);

CREATE TABLE application_instances (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    site_id BIGINT REFERENCES sites(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    runtime TEXT NOT NULL CHECK (runtime IN ('php', 'python', 'node', 'oci')),
    catalog_slug TEXT NOT NULL DEFAULT '',
    image_ref TEXT NOT NULL DEFAULT '',
    desired_state TEXT NOT NULL DEFAULT 'running' CHECK (desired_state IN ('running', 'stopped')),
    applied_state TEXT NOT NULL DEFAULT 'pending' CHECK (applied_state IN ('pending', 'running', 'stopped', 'failed')),
    environment JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(environment) = 'object'),
    healthcheck JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(healthcheck) = 'object'),
    convergence_status TEXT NOT NULL DEFAULT 'pending' CHECK (convergence_status IN ('pending', 'in_sync', 'failed')),
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (subscription_id, name)
);

CREATE TABLE application_ports (
    id BIGSERIAL PRIMARY KEY,
    application_id BIGINT NOT NULL REFERENCES application_instances(id) ON DELETE CASCADE,
    container_port INTEGER NOT NULL CHECK (container_port BETWEEN 1 AND 65535),
    host_port INTEGER CHECK (host_port BETWEEN 1024 AND 65535),
    protocol TEXT NOT NULL DEFAULT 'tcp' CHECK (protocol IN ('tcp', 'udp')),
    route_host TEXT NOT NULL DEFAULT '',
    UNIQUE (application_id, container_port, protocol),
    UNIQUE (host_port, protocol)
);

CREATE TABLE application_volumes (
    id BIGSERIAL PRIMARY KEY,
    application_id BIGINT NOT NULL REFERENCES application_instances(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    container_path TEXT NOT NULL CHECK (container_path LIKE '/%'),
    size_mb INTEGER NOT NULL DEFAULT -1 CHECK (size_mb >= -1),
    UNIQUE (application_id, name)
);

CREATE INDEX subscription_system_accounts_convergence_idx ON subscription_system_accounts(convergence_status, id);
CREATE INDEX scheduled_tasks_subscription_idx ON scheduled_tasks(subscription_id, enabled);
CREATE INDEX mail_domains_subscription_idx ON mail_domains(subscription_id, enabled);
CREATE INDEX application_instances_subscription_idx ON application_instances(subscription_id, desired_state);

-- +goose Down
DROP TABLE IF EXISTS application_volumes;
DROP TABLE IF EXISTS application_ports;
DROP TABLE IF EXISTS application_instances;
DROP TABLE IF EXISTS mail_aliases;
DROP TABLE IF EXISTS mailboxes;
DROP TABLE IF EXISTS mail_domains;
DROP TABLE IF EXISTS scheduled_task_runs;
DROP TABLE IF EXISTS scheduled_tasks;
DROP TABLE IF EXISTS sftp_access_identities;
DROP TABLE IF EXISTS site_policy_overrides;
DROP TABLE IF EXISTS subscription_policy_overrides;
ALTER TABLE subscription_entitlements DROP COLUMN IF EXISTS hosting_policy;
ALTER TABLE reseller_plans DROP COLUMN IF EXISTS hosting_policy;
ALTER TABLE addon_plans DROP COLUMN IF EXISTS hosting_policy;
ALTER TABLE plans DROP COLUMN IF EXISTS hosting_policy;
DROP INDEX IF EXISTS sites_system_account_id_idx;
ALTER TABLE sites DROP COLUMN IF EXISTS document_root;
ALTER TABLE sites DROP COLUMN IF EXISTS system_account_id;
ALTER TABLE sites ADD CONSTRAINT sites_username_key UNIQUE (username);
DROP TABLE IF EXISTS subscription_system_accounts;
DROP FUNCTION IF EXISTS protect_subscription_system_account_identity();
