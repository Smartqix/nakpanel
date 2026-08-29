-- +goose Up
-- Every subscription-scoped intent mutation takes the same transaction-level
-- advisory lock as account purge. This closes the window where a resource
-- transaction could enqueue after teardown had already cancelled child jobs.
-- Teardown sets nakpanel.account_teardown locally so its intentional cascade
-- deletes can pass while the billing account is terminating.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION nakpanel_resource_subscription(table_name_value TEXT, row_value JSONB)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    subscription_id_value BIGINT;
BEGIN
    CASE table_name_value
        WHEN 'sites', 'databases', 'backups', 'ftp_accounts',
             'sftp_access_identities', 'scheduled_tasks', 'mail_domains',
             'application_instances', 'valkey_instances',
             'subscription_addons', 'subscription_entitlements',
             'subscription_policy_overrides'
            THEN subscription_id_value := NULLIF(row_value->>'subscription_id', '')::BIGINT;
        WHEN 'restore_runs'
            THEN SELECT subscription_id INTO subscription_id_value
                 FROM backups WHERE id=NULLIF(row_value->>'backup_id', '')::BIGINT;
        WHEN 'webmail_hosts', 'dns_zones', 'protected_directories',
             'git_repositories', 'site_runtime_generations',
             'site_policy_overrides'
            THEN SELECT subscription_id INTO subscription_id_value
                 FROM sites WHERE id=NULLIF(row_value->>'site_id', '')::BIGINT;
        WHEN 'dns_records'
            THEN SELECT site.subscription_id INTO subscription_id_value
                 FROM dns_zones zone JOIN sites site ON site.id=zone.site_id
                 WHERE zone.id=NULLIF(row_value->>'zone_id', '')::BIGINT;
        WHEN 'mailboxes', 'mail_aliases'
            THEN SELECT subscription_id INTO subscription_id_value
                 FROM mail_domains WHERE id=NULLIF(row_value->>'mail_domain_id', '')::BIGINT;
        WHEN 'scheduled_task_runs'
            THEN SELECT subscription_id INTO subscription_id_value
                 FROM scheduled_tasks WHERE id=NULLIF(row_value->>'task_id', '')::BIGINT;
        WHEN 'application_ports', 'application_volumes'
            THEN SELECT subscription_id INTO subscription_id_value
                 FROM application_instances WHERE id=NULLIF(row_value->>'application_id', '')::BIGINT;
        WHEN 'git_deployments'
            THEN SELECT site.subscription_id INTO subscription_id_value
                 FROM git_repositories repository
                 JOIN sites site ON site.id=repository.site_id
                 WHERE repository.id=NULLIF(row_value->>'repository_id', '')::BIGINT;
        WHEN 'staging_operations'
            THEN SELECT subscription_id INTO subscription_id_value
                 FROM sites WHERE id=NULLIF(row_value->>'source_site_id', '')::BIGINT;
        WHEN 'server_operations'
            THEN
                IF row_value->>'target_type' = 'database' AND row_value->>'target_key' ~ '^[0-9]+$' THEN
                    SELECT subscription_id INTO subscription_id_value
                    FROM databases WHERE id=(row_value->>'target_key')::BIGINT;
                END IF;
        ELSE
            RAISE EXCEPTION 'unsupported account teardown guard table %', table_name_value;
    END CASE;
    RETURN subscription_id_value;
END;
$$;

CREATE OR REPLACE FUNCTION nakpanel_assert_account_mutable(subscription_id_value BIGINT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    provisioning_state_value TEXT;
BEGIN
    IF subscription_id_value IS NULL THEN
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended('nakpanel:subscription:' || subscription_id_value::TEXT, 0)
    );
    SELECT provisioning_state INTO provisioning_state_value
    FROM billing_accounts
    WHERE subscription_id=subscription_id_value
    FOR SHARE;

    IF provisioning_state_value IN ('terminating','terminated') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'billing account teardown has started';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION nakpanel_guard_account_teardown()
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
        old_subscription_id := nakpanel_resource_subscription(TG_TABLE_NAME, to_jsonb(OLD));
    END IF;
    IF TG_OP <> 'DELETE' THEN
        new_subscription_id := nakpanel_resource_subscription(TG_TABLE_NAME, to_jsonb(NEW));
    END IF;

    -- Resource transfers must guard both owners. Taking locks in numeric order
    -- makes concurrent cross-account moves deterministic and avoids deadlocks.
    IF old_subscription_id IS NOT NULL
       AND new_subscription_id IS NOT NULL
       AND old_subscription_id <> new_subscription_id THEN
        IF old_subscription_id < new_subscription_id THEN
            PERFORM nakpanel_assert_account_mutable(old_subscription_id);
            PERFORM nakpanel_assert_account_mutable(new_subscription_id);
        ELSE
            PERFORM nakpanel_assert_account_mutable(new_subscription_id);
            PERFORM nakpanel_assert_account_mutable(old_subscription_id);
        END IF;
    ELSE
        PERFORM nakpanel_assert_account_mutable(COALESCE(new_subscription_id, old_subscription_id));
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER sites_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON sites FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER databases_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON databases FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER backups_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON backups FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER restore_runs_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON restore_runs FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER webmail_hosts_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON webmail_hosts FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER dns_zones_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON dns_zones FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER dns_records_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON dns_records FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER ftp_accounts_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON ftp_accounts FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER sftp_access_identities_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON sftp_access_identities FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER scheduled_tasks_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON scheduled_tasks FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER scheduled_task_runs_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON scheduled_task_runs FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER mail_domains_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON mail_domains FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER mailboxes_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON mailboxes FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER mail_aliases_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON mail_aliases FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER application_instances_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON application_instances FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER application_ports_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON application_ports FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER application_volumes_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON application_volumes FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER valkey_instances_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON valkey_instances FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER git_repositories_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON git_repositories FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER git_deployments_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON git_deployments FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER protected_directories_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON protected_directories FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER staging_operations_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON staging_operations FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER site_runtime_generations_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON site_runtime_generations FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER site_policy_overrides_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON site_policy_overrides FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER subscription_policy_overrides_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON subscription_policy_overrides FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER subscription_addons_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON subscription_addons FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER subscription_entitlements_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON subscription_entitlements FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();
CREATE TRIGGER server_operations_account_teardown_guard BEFORE INSERT OR UPDATE OR DELETE ON server_operations FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_account_teardown();

-- +goose Down
DROP TRIGGER IF EXISTS server_operations_account_teardown_guard ON server_operations;
DROP TRIGGER IF EXISTS subscription_entitlements_account_teardown_guard ON subscription_entitlements;
DROP TRIGGER IF EXISTS subscription_addons_account_teardown_guard ON subscription_addons;
DROP TRIGGER IF EXISTS subscription_policy_overrides_account_teardown_guard ON subscription_policy_overrides;
DROP TRIGGER IF EXISTS site_policy_overrides_account_teardown_guard ON site_policy_overrides;
DROP TRIGGER IF EXISTS site_runtime_generations_account_teardown_guard ON site_runtime_generations;
DROP TRIGGER IF EXISTS staging_operations_account_teardown_guard ON staging_operations;
DROP TRIGGER IF EXISTS protected_directories_account_teardown_guard ON protected_directories;
DROP TRIGGER IF EXISTS git_deployments_account_teardown_guard ON git_deployments;
DROP TRIGGER IF EXISTS git_repositories_account_teardown_guard ON git_repositories;
DROP TRIGGER IF EXISTS valkey_instances_account_teardown_guard ON valkey_instances;
DROP TRIGGER IF EXISTS application_volumes_account_teardown_guard ON application_volumes;
DROP TRIGGER IF EXISTS application_ports_account_teardown_guard ON application_ports;
DROP TRIGGER IF EXISTS application_instances_account_teardown_guard ON application_instances;
DROP TRIGGER IF EXISTS mail_aliases_account_teardown_guard ON mail_aliases;
DROP TRIGGER IF EXISTS mailboxes_account_teardown_guard ON mailboxes;
DROP TRIGGER IF EXISTS mail_domains_account_teardown_guard ON mail_domains;
DROP TRIGGER IF EXISTS scheduled_task_runs_account_teardown_guard ON scheduled_task_runs;
DROP TRIGGER IF EXISTS scheduled_tasks_account_teardown_guard ON scheduled_tasks;
DROP TRIGGER IF EXISTS sftp_access_identities_account_teardown_guard ON sftp_access_identities;
DROP TRIGGER IF EXISTS ftp_accounts_account_teardown_guard ON ftp_accounts;
DROP TRIGGER IF EXISTS dns_records_account_teardown_guard ON dns_records;
DROP TRIGGER IF EXISTS dns_zones_account_teardown_guard ON dns_zones;
DROP TRIGGER IF EXISTS webmail_hosts_account_teardown_guard ON webmail_hosts;
DROP TRIGGER IF EXISTS restore_runs_account_teardown_guard ON restore_runs;
DROP TRIGGER IF EXISTS backups_account_teardown_guard ON backups;
DROP TRIGGER IF EXISTS databases_account_teardown_guard ON databases;
DROP TRIGGER IF EXISTS sites_account_teardown_guard ON sites;
DROP FUNCTION IF EXISTS nakpanel_guard_account_teardown();
DROP FUNCTION IF EXISTS nakpanel_assert_account_mutable(BIGINT);
DROP FUNCTION IF EXISTS nakpanel_resource_subscription(TEXT, JSONB);
